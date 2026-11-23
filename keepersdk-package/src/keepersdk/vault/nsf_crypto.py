from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional

from .. import crypto, utils
from ..authentication import keeper_auth
from ..proto import folder_pb2
from . import nsf_storage_types as nsf
from .nsf_vault_storage import INSFStorage

_FOLDER_KEY_ENCRYPTION = folder_pb2.FolderKeyEncryptionType
_ENCRYPTED_KEY_TYPE = folder_pb2.EncryptedKeyType
_ACCESS_TYPE = folder_pb2.AccessType


@dataclass(frozen=True)
class TeamKeyMaterial:
    """Decrypted team keys used to unwrap team-shared NSF folder keys."""
    team_key: bytes
    rsa_private_key: Optional[Any] = None
    ec_private_key: Optional[Any] = None


def try_decrypt_symmetric(encrypted_key: bytes, symmetric_key: bytes) -> Optional[bytes]:
    try:
        return crypto.decrypt_aes_v2(encrypted_key, symmetric_key)
    except Exception:
        pass
    try:
        return crypto.decrypt_aes_v1(encrypted_key, symmetric_key)
    except Exception:
        pass
    return None


def folder_key_opens_data(row: Optional[nsf.NSFFolder], folder_key: Optional[bytes]) -> bool:
    """Return False when *folder_key* is proven wrong for the folder *row*.

    A legacy AES-CBC fallback can "decrypt" a key with the wrong wrapping key and still
    yield 32 bytes. Folder data is authenticated AES-GCM, so failing to open it proves the
    key is wrong. A folder without data cannot be checked, so its key is accepted.
    """
    if not folder_key or len(folder_key) != 32:
        return False
    if row is None or not row.data:
        return True
    return _decrypt_folder_data(row.data, folder_key) is not None


def _decrypt_folder_data(encrypted_data_b64: str, folder_key: bytes) -> Optional[Dict[str, Any]]:
    """Decrypt NSF folder data (AES-GCM JSON object), or None if the key does not open it."""
    try:
        data_bytes = crypto.decrypt_aes_v2(utils.base64_url_decode(encrypted_data_b64), folder_key)
        payload = json.loads(data_bytes.decode('utf-8'))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def try_decrypt_with_user_keys(encrypted_key: bytes, auth_context: keeper_auth.AuthContext) -> Optional[bytes]:
    result = try_decrypt_symmetric(encrypted_key, auth_context.data_key)
    if result is not None:
        return result
    if auth_context.rsa_private_key is not None:
        try:
            return crypto.decrypt_rsa(encrypted_key, auth_context.rsa_private_key)
        except Exception:
            pass
    if auth_context.ec_private_key is not None:
        try:
            return crypto.decrypt_ec(encrypted_key, auth_context.ec_private_key)
        except Exception:
            pass
    return None


def try_decrypt_with_typed_key(
        encrypted_key: bytes,
        key_type: int,
        *,
        aes_key: Optional[bytes] = None,
        rsa_key: Optional[Any] = None,
        ecc_key: Optional[Any] = None) -> Optional[bytes]:
    """Decrypt using the algorithm indicated by *key_type* (Vault decryptFolderKeyByType)."""
    try:
        if key_type == int(_ENCRYPTED_KEY_TYPE.encrypted_by_data_key_gcm):
            if aes_key is not None:
                return crypto.decrypt_aes_v2(encrypted_key, aes_key)
        elif key_type == int(_ENCRYPTED_KEY_TYPE.encrypted_by_data_key):
            if aes_key is not None:
                return crypto.decrypt_aes_v1(encrypted_key, aes_key)
        elif key_type == int(_ENCRYPTED_KEY_TYPE.encrypted_by_public_key):
            if rsa_key is not None:
                return crypto.decrypt_rsa(encrypted_key, rsa_key)
        elif key_type == int(_ENCRYPTED_KEY_TYPE.encrypted_by_public_key_ecc):
            if ecc_key is not None:
                return crypto.decrypt_ec(encrypted_key, ecc_key)
    except Exception:
        return None
    return None


def try_decrypt_from_folder_access(
        folder_uid: str,
        storage: INSFStorage,
        auth_context: keeper_auth.AuthContext,
        teams: Optional[Mapping[str, TeamKeyMaterial]] = None,
        folder_row: Optional[nsf.NSFFolder] = None) -> Optional[bytes]:
    """Unwrap folder key from folderAccesses (user or team), mirroring Web Vault.

    Pass *folder_row* to skip access entries whose key does not open the folder data.
    """
    teams = teams or {}
    for fa in storage.folder_accesses.get_links_by_subject(folder_uid):
        if not fa.folder_key_encrypted:
            continue
        try:
            enc_key = utils.base64_url_decode(fa.folder_key_encrypted)
            key_type = fa.folder_key_type
            access_uid = fa.access_type_uid
            use_team = (
                fa.access_type == int(_ACCESS_TYPE.AT_TEAM)
                or (access_uid in teams)
            )

            folder_key: Optional[bytes] = None
            if use_team and access_uid in teams:
                team = teams[access_uid]
                folder_key = try_decrypt_with_typed_key(
                    enc_key, key_type,
                    aes_key=team.team_key,
                    rsa_key=team.rsa_private_key,
                    ecc_key=team.ec_private_key,
                )
                if folder_key is None:
                    folder_key = try_decrypt_symmetric(enc_key, team.team_key)
                if folder_key is None and team.rsa_private_key is not None:
                    try:
                        folder_key = crypto.decrypt_rsa(enc_key, team.rsa_private_key)
                    except Exception:
                        pass
                if folder_key is None and team.ec_private_key is not None:
                    try:
                        folder_key = crypto.decrypt_ec(enc_key, team.ec_private_key)
                    except Exception:
                        pass

            if folder_key is None:
                folder_key = try_decrypt_with_typed_key(
                    enc_key, key_type,
                    aes_key=auth_context.data_key,
                    rsa_key=auth_context.rsa_private_key,
                    ecc_key=auth_context.ec_private_key,
                )
            if folder_key is None:
                folder_key = try_decrypt_with_user_keys(enc_key, auth_context)

            if folder_key_opens_data(folder_row, folder_key):
                return folder_key
        except Exception:
            continue
    return None


def try_decrypt_folder_key(
        fk: nsf.NSFFolderKey,
        auth_context: keeper_auth.AuthContext,
        decrypted_folder_keys: Dict[str, bytes],
        teams: Optional[Mapping[str, TeamKeyMaterial]] = None,
        folder_row: Optional[nsf.NSFFolder] = None) -> Optional[bytes]:
    """
    Attempt decrypt from a FolderKey link.

    Returns None for ENCRYPTED_BY_TEAM_KEY (caller must use folderAccesses).
    For PARENT_KEY without a decrypted parent, returns None so caller can fall back.
    With *folder_row*, a key that does not open the folder data is rejected, and for
    PARENT_KEY the folder's own parent is tried before the key entry's (which can go
    stale after a move), mirroring Web Vault.
    """
    enc_key_type = fk.encrypted_by
    if enc_key_type == int(_FOLDER_KEY_ENCRYPTION.ENCRYPTED_BY_TEAM_KEY):
        return None  # key lives in folderAccesses
    if not fk.folder_key:
        return None
    try:
        encrypted_key = utils.base64_url_decode(fk.folder_key)
        if enc_key_type == int(_FOLDER_KEY_ENCRYPTION.ENCRYPTED_BY_USER_KEY):
            key = try_decrypt_with_user_keys(encrypted_key, auth_context)
            return key if folder_key_opens_data(folder_row, key) else None
        if enc_key_type == int(_FOLDER_KEY_ENCRYPTION.ENCRYPTED_BY_PARENT_KEY):
            parent_uids = [fk.parent_uid]
            if folder_row is not None and folder_row.parent_uid and folder_row.parent_uid != fk.parent_uid:
                parent_uids.insert(0, folder_row.parent_uid)
            for parent_uid in parent_uids:
                if not parent_uid:
                    continue
                parent_key = decrypted_folder_keys.get(parent_uid)
                if parent_key is None:
                    continue
                key = try_decrypt_symmetric(encrypted_key, parent_key)
                if folder_key_opens_data(folder_row, key):
                    return key
            return None
    except Exception:
        return None
    return None


def try_decrypt_folder_entity_key(
        row: nsf.NSFFolder,
        auth_context: keeper_auth.AuthContext,
        decrypted_folder_keys: Dict[str, bytes]) -> Optional[bytes]:
    if not row.folder_key:
        return None
    try:
        encrypted_key = utils.base64_url_decode(row.folder_key)
        key = try_decrypt_with_user_keys(encrypted_key, auth_context)
        if folder_key_opens_data(row, key):
            return key
        if row.parent_uid:
            parent_key = decrypted_folder_keys.get(row.parent_uid)
            if parent_key is not None:
                key = try_decrypt_symmetric(encrypted_key, parent_key)
                if folder_key_opens_data(row, key):
                    return key
    except Exception:
        pass
    return None


def _folder_needs_access_fallback(
        folder_uid: str,
        keys_by_folder: Mapping[str, List[nsf.NSFFolderKey]],
        decrypted_keys: Mapping[str, bytes]) -> bool:
    """True when FolderKey links require folderAccesses (TEAM_KEY or failed PARENT/USER)."""
    if folder_uid in decrypted_keys:
        return False
    folder_keys = keys_by_folder.get(folder_uid, [])
    if not folder_keys:
        # No FolderKey links — still try folderAccesses (bare sync rows).
        return True
    for fk in folder_keys:
        if fk.encrypted_by == int(_FOLDER_KEY_ENCRYPTION.ENCRYPTED_BY_TEAM_KEY):
            return True
        if fk.encrypted_by == int(_FOLDER_KEY_ENCRYPTION.ENCRYPTED_BY_PARENT_KEY):
            # Parent missing, not yet unwrapped, or its key did not open this folder
            # (the PARENT_KEY path already ran this pass) — try accesses (Vault fallback).
            return True
        if fk.encrypted_by == int(_FOLDER_KEY_ENCRYPTION.ENCRYPTED_BY_USER_KEY):
            return True  # USER_KEY already tried; fall back to accesses
    return False


def decrypt_folder_keys(
        storage: INSFStorage,
        auth_context: keeper_auth.AuthContext,
        teams: Optional[Mapping[str, TeamKeyMaterial]] = None) -> Dict[str, bytes]:
    """Decrypt NSF folder keys. Pass *teams* for team-shared folder unwrap.

    Mirrors Commander / Web Vault: folderAccesses unwrap runs inside the progress
    loop so TEAM_KEY parents unlock first, then ENCRYPTED_BY_PARENT_KEY children
    continue on the next pass (team-shared NSF sub-folders).
    """
    teams = teams or {}
    decrypted_keys: Dict[str, bytes] = {}
    keys_by_folder: Dict[str, List[nsf.NSFFolderKey]] = {}
    for fk in storage.folder_keys.get_all_links():
        keys_by_folder.setdefault(fk.folder_uid, []).append(fk)
    folder_rows = list(storage.folders.get_all_entities())
    rows_by_uid = {row.folder_uid: row for row in folder_rows}
    candidates = set(keys_by_folder.keys()) | set(rows_by_uid)

    progress = True
    while progress:
        progress = False
        for folder_uid, folder_keys in keys_by_folder.items():
            if folder_uid in decrypted_keys:
                continue
            for fk in folder_keys:
                key = try_decrypt_folder_key(fk, auth_context, decrypted_keys, teams,
                                             folder_row=rows_by_uid.get(folder_uid))
                if key is not None:
                    decrypted_keys[folder_uid] = key
                    progress = True
                    break
        for row in folder_rows:
            if row.folder_uid in decrypted_keys:
                continue
            key = try_decrypt_folder_entity_key(row, auth_context, decrypted_keys)
            if key is not None:
                decrypted_keys[row.folder_uid] = key
                progress = True

        # folderAccesses inside the loop (TEAM_KEY / missing parent / USER miss).
        # After a team parent unlocks here, the next iteration unwraps PARENT_KEY children.
        for folder_uid in candidates:
            if folder_uid in decrypted_keys:
                continue
            if not _folder_needs_access_fallback(folder_uid, keys_by_folder, decrypted_keys):
                continue
            key = try_decrypt_from_folder_access(folder_uid, storage, auth_context, teams,
                                                 folder_row=rows_by_uid.get(folder_uid))
            if key is not None:
                decrypted_keys[folder_uid] = key
                progress = True

    return decrypted_keys


def decrypt_record_keys(
        storage: INSFStorage,
        decrypted_folder_keys: Dict[str, bytes],
        auth_context: keeper_auth.AuthContext) -> Dict[str, bytes]:
    decrypted_keys: Dict[str, bytes] = {}
    for rk in storage.record_keys.get_all_links():
        if rk.record_uid in decrypted_keys or not rk.record_key:
            continue
        try:
            encrypted_key = utils.base64_url_decode(rk.record_key)
            enc_key_type = rk.record_key_type
            folder_enc_type = rk.folder_key_encryption_type
            record_key: Optional[bytes] = None

            if enc_key_type == int(_ENCRYPTED_KEY_TYPE.encrypted_by_public_key):
                if auth_context.rsa_private_key is not None:
                    record_key = crypto.decrypt_rsa(encrypted_key, auth_context.rsa_private_key)
            elif enc_key_type == int(_ENCRYPTED_KEY_TYPE.encrypted_by_public_key_ecc):
                if auth_context.ec_private_key is not None:
                    record_key = crypto.decrypt_ec(encrypted_key, auth_context.ec_private_key)
            else:
                folder_key = decrypted_folder_keys.get(rk.folder_uid) if rk.folder_uid else None
                if (folder_enc_type == int(_FOLDER_KEY_ENCRYPTION.ENCRYPTED_BY_USER_KEY)
                        or not rk.folder_uid):
                    record_key = try_decrypt_symmetric(encrypted_key, auth_context.data_key)
                    if record_key is None and folder_key is not None:
                        record_key = try_decrypt_symmetric(encrypted_key, folder_key)
                else:
                    if folder_key is not None:
                        record_key = try_decrypt_symmetric(encrypted_key, folder_key)
                    if record_key is None:
                        record_key = try_decrypt_symmetric(encrypted_key, auth_context.data_key)
                if record_key is None and auth_context.rsa_private_key is not None:
                    try:
                        record_key = crypto.decrypt_rsa(encrypted_key, auth_context.rsa_private_key)
                    except Exception:
                        pass
                if record_key is None and auth_context.ec_private_key is not None:
                    try:
                        record_key = crypto.decrypt_ec(encrypted_key, auth_context.ec_private_key)
                    except Exception:
                        pass

            if record_key is not None:
                decrypted_keys[rk.record_uid] = record_key
        except Exception:
            continue
    return decrypted_keys


def decrypt_folder_name(encrypted_data_b64: str, folder_key: bytes) -> Optional[str]:
    if not encrypted_data_b64:
        return None
    payload = _decrypt_folder_data(encrypted_data_b64, folder_key)
    name = payload.get('name') if payload is not None else None
    return str(name) if name is not None else None


def decrypt_record_data(
        encrypted_data_b64: str,
        record_key: bytes,
        *,
        version: int = 3) -> Optional[str]:
    if not encrypted_data_b64:
        return None
    try:
        encrypted = utils.base64_url_decode(encrypted_data_b64)
        if version <= 2:
            data_bytes = crypto.decrypt_aes_v1(encrypted, record_key)
        else:
            data_bytes = crypto.decrypt_aes_v2(encrypted, record_key)
        return data_bytes.decode('utf-8')
    except Exception:
        return None
