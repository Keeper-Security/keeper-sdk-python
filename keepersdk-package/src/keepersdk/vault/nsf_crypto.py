from __future__ import annotations

import json
from typing import Dict, List, Optional

from .. import crypto, utils
from ..authentication import keeper_auth
from ..proto import folder_pb2
from . import nsf_storage_types as nsf
from .nsf_vault_storage import INSFStorage

_FOLDER_KEY_ENCRYPTION = folder_pb2.FolderKeyEncryptionType
_ENCRYPTED_KEY_TYPE = folder_pb2.EncryptedKeyType


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


def try_decrypt_from_folder_access(
        folder_uid: str,
        storage: INSFStorage,
        auth_context: keeper_auth.AuthContext) -> Optional[bytes]:
    for fa in storage.folder_accesses.get_links_by_subject(folder_uid):
        if not fa.folder_key_encrypted:
            continue
        try:
            enc_key = utils.base64_url_decode(fa.folder_key_encrypted)
            key_type = fa.folder_key_type
            if key_type == int(_ENCRYPTED_KEY_TYPE.encrypted_by_data_key_gcm):
                return crypto.decrypt_aes_v2(enc_key, auth_context.data_key)
            if key_type == int(_ENCRYPTED_KEY_TYPE.encrypted_by_data_key):
                return crypto.decrypt_aes_v1(enc_key, auth_context.data_key)
            if key_type == int(_ENCRYPTED_KEY_TYPE.encrypted_by_public_key):
                if auth_context.rsa_private_key is not None:
                    return crypto.decrypt_rsa(enc_key, auth_context.rsa_private_key)
            elif key_type == int(_ENCRYPTED_KEY_TYPE.encrypted_by_public_key_ecc):
                if auth_context.ec_private_key is not None:
                    return crypto.decrypt_ec(enc_key, auth_context.ec_private_key)
            else:
                result = try_decrypt_with_user_keys(enc_key, auth_context)
                if result is not None:
                    return result
        except Exception:
            continue
    return None


def try_decrypt_folder_key(
        fk: nsf.NSFFolderKey,
        auth_context: keeper_auth.AuthContext,
        decrypted_folder_keys: Dict[str, bytes]) -> Optional[bytes]:
    if not fk.folder_key:
        return None
    try:
        enc_key_type = fk.encrypted_by
        encrypted_key = utils.base64_url_decode(fk.folder_key)
        if enc_key_type == int(_FOLDER_KEY_ENCRYPTION.ENCRYPTED_BY_USER_KEY):
            return try_decrypt_with_user_keys(encrypted_key, auth_context)
        if enc_key_type == int(_FOLDER_KEY_ENCRYPTION.ENCRYPTED_BY_PARENT_KEY):
            if not fk.parent_uid:
                return None
            parent_key = decrypted_folder_keys.get(fk.parent_uid)
            if parent_key is None:
                return None
            return try_decrypt_symmetric(encrypted_key, parent_key)
    except Exception:
        return None
    return None


def decrypt_folder_keys(
        storage: INSFStorage,
        auth_context: keeper_auth.AuthContext) -> Dict[str, bytes]:
    decrypted_keys: Dict[str, bytes] = {}
    keys_by_folder: Dict[str, List[nsf.NSFFolderKey]] = {}
    for fk in storage.folder_keys.get_all_links():
        keys_by_folder.setdefault(fk.folder_uid, []).append(fk)

    progress = True
    while progress:
        progress = False
        for folder_uid, folder_keys in keys_by_folder.items():
            if folder_uid in decrypted_keys:
                continue
            for fk in folder_keys:
                key = try_decrypt_folder_key(fk, auth_context, decrypted_keys)
                if key is not None:
                    decrypted_keys[folder_uid] = key
                    progress = True
                    break

    for folder_uid in keys_by_folder:
        if folder_uid not in decrypted_keys:
            key = try_decrypt_from_folder_access(folder_uid, storage, auth_context)
            if key is not None:
                decrypted_keys[folder_uid] = key

    for row in storage.folders.get_all_entities():
        if row.folder_uid not in decrypted_keys:
            key = try_decrypt_from_folder_access(row.folder_uid, storage, auth_context)
            if key is not None:
                decrypted_keys[row.folder_uid] = key

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
    try:
        data_bytes = crypto.decrypt_aes_v2(utils.base64_url_decode(encrypted_data_b64), folder_key)
        payload = json.loads(data_bytes.decode('utf-8'))
        if isinstance(payload, dict):
            name = payload.get('name')
            return str(name) if name is not None else None
    except Exception:
        return None
    return None


def decrypt_record_data(encrypted_data_b64: str, record_key: bytes) -> Optional[str]:
    if not encrypted_data_b64:
        return None
    try:
        data_bytes = crypto.decrypt_aes_v2(utils.base64_url_decode(encrypted_data_b64), record_key)
        return data_bytes.decode('utf-8')
    except Exception:
        return None
