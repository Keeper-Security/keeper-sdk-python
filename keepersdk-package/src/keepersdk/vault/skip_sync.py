from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .. import crypto, utils
from ..authentication import keeper_auth
from ..proto import folder_pb2, record_pb2
from . import sync_down, vault_types, vault_utils


_GET_SHARED_FOLDERS_COMMAND = "get_shared_folders"
_SHARED_FOLDER_UPDATE_V3_ENDPOINT = "vault/shared_folder_update_v3"
_RECORD_DETAILS_URL = "vault/get_records_details"
_RECORD_DETAILS_CHUNK = 999
_MAX_V2_RECORD_VERSION = 2


def _coerce_shared_folder_header_key_type(raw) -> Optional[int]:
    """
    Parse get_shared_folders ``key_type`` into an int compatible with
    ``record_pb2.RecordKeyType`` / ``sync_down.decrypt_keeper_key``.

    The protobuf Python ``RecordKeyType`` wrapper is not callable (do not use
    ``RecordKeyType(n)``); values are plain ints. The API may return an int or
    a string (digits or protobuf-style enum name in snake_case).
    """
    if raw is None:
        return None
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str):
        s = raw.strip()
        if not s:
            return None
        if s.isdigit() or (s.startswith("-") and s[1:].isdigit()):
            return int(s)
        try:
            return record_pb2.RecordKeyType.Value(s.upper())
        except ValueError:
            return None
    return None


@dataclass(frozen=True)
class SharedFolderRecordDisplay:
    """Decrypted display row for a record in a shared folder (skip-sync path)."""

    record_uid: str
    name: str


def _ensure_auth(auth: Optional[keeper_auth.KeeperAuth]) -> keeper_auth.KeeperAuth:
    if auth is None:
        raise ValueError("Authenticated KeeperAuth instance is required.")
    return auth


def load_shared_folder_raw(
    auth: keeper_auth.KeeperAuth, shared_folder_uid: str
) -> Optional[Dict]:
    auth = _ensure_auth(auth)
    if not shared_folder_uid or not shared_folder_uid.strip():
        raise ValueError("shared_folder_uid is required.")

    rq = {
        "command": _GET_SHARED_FOLDERS_COMMAND,
        "shared_folders": [{"shared_folder_uid": shared_folder_uid}],
        "include": ["sfheaders", "sfusers", "sfrecords", "sfteams"],
    }
    rs = auth.execute_auth_command(rq, throw_on_error=False)
    if not rs or rs.get("result") != "success":
        return None

    folders = rs.get("shared_folders") or []
    if not folders:
        return None

    uid = shared_folder_uid.strip()
    for sf in folders:
        if isinstance(sf, dict) and sf.get("shared_folder_uid", "").strip() == uid:
            return sf
    return folders[0]


def _decrypt_shared_folder_key(
    auth: keeper_auth.KeeperAuth, sf: Dict
) -> Optional[bytes]:
    """
    Decrypt shared folder AES key from a get_shared_folders row.
    """
    if not sf:
        return None

    key_type = _coerce_shared_folder_header_key_type(sf.get("key_type"))
    shared_folder_key_b64 = sf.get("shared_folder_key")

    if key_type is None:
        return None

    auth_context = auth.auth_context

    if shared_folder_key_b64:
        try:
            encrypted = utils.base64_url_decode(shared_folder_key_b64)
        except Exception:
            return None
        try:
            return sync_down.decrypt_keeper_key(auth_context, encrypted, key_type)
        except Exception:
            return None

    if key_type == record_pb2.NO_KEY:
        try:
            return sync_down.decrypt_keeper_key(auth_context, b"", key_type)
        except Exception:
            return None

    return None


def _decrypt_shared_folder_name(sf: Dict, sf_key: Optional[bytes]) -> str:
    if not sf_key:
        return "Shared Folder"
    name_b64 = sf.get("name")
    if not name_b64:
        return "Shared Folder"
    try:
        encrypted = utils.base64_url_decode(name_b64)
        if not encrypted:
            return "Shared Folder"
        decrypted = crypto.decrypt_aes_v1(encrypted, sf_key)
        return decrypted.decode("utf-8") or "Shared Folder"
    except Exception:
        raise ValueError("Failed to decrypt shared folder name.")


def get_record_uids_from_shared_folder(
    auth: keeper_auth.KeeperAuth, shared_folder_uid: str
) -> List[str]:
    """
    Return distinct record UIDs from get_shared_folders -> records for a single
    shared folder without syncing the vault.
    """
    sf = load_shared_folder_raw(auth, shared_folder_uid)
    if not sf:
        return []
    records = sf.get("records") or []
    uids: List[str] = []
    seen = set()
    for r in records:
        if not isinstance(r, dict):
            continue
        uid = r.get("record_uid")
        if uid and uid not in seen:
            seen.add(uid)
            uids.append(uid)
    return uids


def _unwrap_record_key_from_shared_folder_record(
    encrypted_record_key_b64: str, shared_folder_key: bytes
) -> Optional[bytes]:
    if not encrypted_record_key_b64 or not shared_folder_key:
        return None
    try:
        encrypted = utils.base64_url_decode(encrypted_record_key_b64)
    except Exception:
        return None
    if not encrypted:
        return None
    use_v2_first = len(encrypted) == 60
    for first_v2 in (use_v2_first, not use_v2_first):
        try:
            if first_v2:
                return crypto.decrypt_aes_v2(encrypted, shared_folder_key)
            return crypto.decrypt_aes_v1(encrypted, shared_folder_key)
        except Exception:
            continue
    return None


def get_record_keys_from_shared_folder(
    auth: keeper_auth.KeeperAuth, shared_folder_uid: str
) -> Dict[str, bytes]:
    """
    Return a mapping record_uid -> decrypted AES record key for all records in
    a shared folder, using get_shared_folders and without syncing the vault.
    """
    sf = load_shared_folder_raw(auth, shared_folder_uid)
    if not sf:
        return {}

    sf_key = _decrypt_shared_folder_key(auth, sf)
    if not sf_key:
        return {}

    records = sf.get("records") or []
    result: Dict[str, bytes] = {}
    for r in records:
        if not isinstance(r, dict):
            continue
        record_uid = r.get("record_uid")
        record_key_b64 = r.get("record_key")
        if not record_uid or not record_key_b64:
            continue
        try:
            plain = _unwrap_record_key_from_shared_folder_record(record_key_b64, sf_key)
        except Exception:
            plain = None
        if plain:
            result[record_uid] = plain
    return result


def _build_record_details_request(uids: List[str]) -> record_pb2.GetRecordDataWithAccessInfoRequest:
    rq = record_pb2.GetRecordDataWithAccessInfoRequest()
    rq.clientTime = utils.current_milli_time()
    rq.recordDetailsInclude = record_pb2.DATA_PLUS_SHARE
    for uid in uids:
        try:
            rq.recordUid.append(utils.base64_url_decode(uid))
        except Exception:
            pass
    return rq


def _process_record_owner_key_details(
    record_data: record_pb2.RecordData, record_uid: str, record_keys: Dict[str, bytes]
) -> None:
    if record_data.recordUid and record_data.recordKey:
        owner_id = utils.base64_url_encode(record_data.recordUid)
        if owner_id in record_keys:
            try:
                record_keys[record_uid] = crypto.decrypt_aes_v2(
                    record_data.recordKey, record_keys[owner_id]
                )
            except Exception:
                pass


def _resolve_record_key_for_details(
    auth: keeper_auth.KeeperAuth,
    record_data: record_pb2.RecordData,
    record_uid: str,
    record_keys: Dict[str, bytes],
) -> Optional[bytes]:
    _process_record_owner_key_details(record_data, record_uid, record_keys)
    if record_uid in record_keys:
        k = record_keys[record_uid]
        if k:
            return k
    try:
        return sync_down.decrypt_keeper_key(
            auth.auth_context, record_data.recordKey or b"", record_data.recordKeyType
        )
    except Exception:
        return None


def _decrypt_record_payload(
    record_data: record_pb2.RecordData, record_key: bytes
) -> Optional[bytes]:
    if not record_data.encryptedRecordData:
        return None
    try:
        data_decoded = utils.base64_url_decode(record_data.encryptedRecordData)
    except Exception:
        return None
    version = record_data.version
    try:
        if version <= _MAX_V2_RECORD_VERSION:
            return crypto.decrypt_aes_v1(data_decoded, record_key)
        return crypto.decrypt_aes_v2(data_decoded, record_key)
    except Exception:
        return None


def _record_display_name_from_payload(data: bytes) -> str:
    try:
        d = json.loads(data.decode("utf-8"))
        title = d.get("title")
        return title if isinstance(title, str) else ""
    except Exception:
        return ""


def get_shared_folder_records_display(
    auth: keeper_auth.KeeperAuth, shared_folder_uid: str
) -> List[SharedFolderRecordDisplay]:
    """
    Analog of .NET RecordSkipSyncDown.GetSharedFolderRecordsAsync: load keys via
    get_shared_folders, call vault/get_records_details, decrypt payloads, return
    only record UID and decrypted title (name) for each row.
    """
    auth = _ensure_auth(auth)
    keys = get_record_keys_from_shared_folder(auth, shared_folder_uid)
    if not keys:
        return []

    uid_list = list(keys.keys())
    working_keys = dict(keys)
    out: List[SharedFolderRecordDisplay] = []

    for i in range(0, len(uid_list), _RECORD_DETAILS_CHUNK):
        chunk = uid_list[i : i + _RECORD_DETAILS_CHUNK]
        rq = _build_record_details_request(chunk)
        if len(rq.recordUid) == 0:
            continue
        rs = auth.execute_auth_rest(
            _RECORD_DETAILS_URL,
            rq,
            response_type=record_pb2.GetRecordDataWithAccessInfoResponse,
        )
        if not rs:
            continue
        for item in rs.recordDataWithAccessInfo:
            if not item.recordUid:
                continue
            uid = utils.base64_url_encode(item.recordUid)
            rd = item.recordData
            if rd is None or not rd.encryptedRecordData:
                continue
            rk = _resolve_record_key_for_details(auth, rd, uid, working_keys)
            if not rk:
                continue
            payload = _decrypt_record_payload(rd, rk)
            if not payload:
                continue
            name = _record_display_name_from_payload(payload)
            out.append(SharedFolderRecordDisplay(record_uid=uid, name=name))

    return out


def get_available_teams_for_share(
    auth: keeper_auth.KeeperAuth,
) -> List[vault_types.TeamInfo]:
    """
    Return teams that the current user may share with, without loading the vault.
    Thin wrapper over get_available_teams.
    """
    return list(vault_utils.load_available_teams(auth))


def _shared_folder_user_matches(user_row: Dict, user_id: str) -> bool:
    if not user_row or not user_id:
        return False
    email = user_row.get("email") or user_row.get("username") or ""
    return email.strip().casefold() == user_id.strip().casefold()


def _is_shared_folder_user_member(sf: Dict, user_id: str) -> bool:
    for u in sf.get("users") or []:
        if _shared_folder_user_matches(u, user_id):
            return True
    return False


def _find_shared_folder_team(sf: Dict, team_uid: str) -> Optional[Dict]:
    if not team_uid:
        return None
    for t in sf.get("teams") or []:
        if t.get("team_uid", "").strip() == team_uid.strip():
            return t
    return None


def _has_no_share_option_changes(
    manage_users: Optional[bool], manage_records: Optional[bool], expiration: Optional[int]
) -> bool:
    return manage_users is None and manage_records is None and expiration is None


def _is_put_status_ok(status: str) -> bool:
    if not status:
        return False
    s = status.lower()
    return s in ("success", "duplicate")


def _is_remove_status_ok(status: str) -> bool:
    if not status:
        return False
    s = status.lower()
    return s in ("success", "not_member", "not_in_shared_folder")


def _encrypt_shared_folder_key_for_team(
    auth: keeper_auth.KeeperAuth, team_uid: str, shared_folder_key: bytes
) -> Tuple[bytes, int]:
    """Match ``shares_management.FolderShares._encrypt_shared_folder_key_for_team``."""
    ac = auth.auth_context
    auth.load_team_keys([team_uid])
    keys = auth.get_team_keys(team_uid)
    if keys is None:
        raise ValueError(f'Cannot retrieve team "{team_uid}" keys for sharing.')

    if keys.aes:
        if ac.forbid_rsa:
            encrypted = crypto.encrypt_aes_v2(shared_folder_key, keys.aes)
            return encrypted, folder_pb2.encrypted_by_data_key_gcm
        encrypted = crypto.encrypt_aes_v1(shared_folder_key, keys.aes)
        return encrypted, folder_pb2.encrypted_by_data_key
    elif ac.forbid_rsa and keys.ec:
        pub = crypto.load_ec_public_key(keys.ec)
        encrypted = crypto.encrypt_ec(shared_folder_key, pub)
        return encrypted, folder_pb2.encrypted_by_public_key_ecc
    elif not ac.forbid_rsa and keys.rsa:
        pub = crypto.load_rsa_public_key(keys.rsa)
        encrypted = crypto.encrypt_rsa(shared_folder_key, pub)
        return encrypted, folder_pb2.encrypted_by_public_key

    raise ValueError(f'Cannot retrieve team "{team_uid}" keys for sharing.')


def _encrypt_shared_folder_key_for_user(
    auth: keeper_auth.KeeperAuth, username: str, shared_folder_key: bytes
) -> Tuple[bytes, int]:
    ac = auth.auth_context
    if username.strip().casefold() == ac.username.strip().casefold():
        encrypted = crypto.encrypt_aes_v1(shared_folder_key, ac.data_key)
        return encrypted, folder_pb2.encrypted_by_data_key

    auth.load_user_public_keys([username], send_invites=False)
    keys = auth.get_user_keys(username)
    if keys is None:
        raise ValueError(f'Cannot retrieve user "{username}" public key for sharing.')

    elif ac.forbid_rsa and keys.ec:
        pub = crypto.load_ec_public_key(keys.ec)
        encrypted = crypto.encrypt_ec(shared_folder_key, pub)
        return encrypted, folder_pb2.encrypted_by_public_key_ecc
    elif not ac.forbid_rsa and keys.rsa:
        pub = crypto.load_rsa_public_key(keys.rsa)
        encrypted = crypto.encrypt_rsa(shared_folder_key, pub)
        return encrypted, folder_pb2.encrypted_by_public_key

    raise ValueError(f'Cannot retrieve user "{username}" public key for sharing.')


def _build_shared_folder_update_request(
    auth: keeper_auth.KeeperAuth, shared_folder_uid: str, sf: Dict, sf_key: bytes
) -> Tuple[folder_pb2.SharedFolderUpdateV3Request, str]:
    display_name = _decrypt_shared_folder_name(sf, sf_key)
    rq = folder_pb2.SharedFolderUpdateV3Request()
    rq.sharedFolderUid = utils.base64_url_decode(shared_folder_uid)
    rq.encryptedSharedFolderName = crypto.encrypt_aes_v1(display_name.encode("utf-8"), sf_key)
    rq.forceUpdate = True
    return rq, display_name


def share_shared_folder_to_team(
    auth: keeper_auth.KeeperAuth,
    shared_folder_uid: str,
    team_name_or_uid: str,
    *,
    manage_users: Optional[bool] = None,
    manage_records: Optional[bool] = None,
    expiration: Optional[int] = None,
) -> List[SharedFolderRecordDisplay]:
    """
    Share a shared folder to a team without requiring a synced vault.

    Returns decrypted record UID and title (name) for each record in the folder.
    """
    auth = _ensure_auth(auth)
    if not shared_folder_uid:
        raise ValueError("shared_folder_uid is required.")
    if not team_name_or_uid:
        raise ValueError("team_name_or_uid is required.")

    # Resolve team UID from name or UID using existing helper
    team_uid = None
    for t in vault_utils.load_available_teams(auth):
        if team_name_or_uid.strip().casefold() in (
            t.team_uid.strip().casefold(),
            t.name.strip().casefold(),
        ):
            team_uid = t.team_uid
            break
    if not team_uid:
        raise ValueError(f'Team "{team_name_or_uid}" not found.')

    sf = load_shared_folder_raw(auth, shared_folder_uid)
    if not sf:
        raise ValueError(f'Shared folder "{shared_folder_uid}" not found.')

    sf_key = _decrypt_shared_folder_key(auth, sf)
    if not sf_key:
        raise ValueError(f'Shared folder "{shared_folder_uid}" key could not be decrypted.')

    rq, display_name = _build_shared_folder_update_request(auth, shared_folder_uid, sf, sf_key)

    existing_team = _find_shared_folder_team(sf, team_uid)
    team_is_member = existing_team is not None

    if _has_no_share_option_changes(manage_users, manage_records, expiration) and team_is_member:
        return get_shared_folder_records_display(auth, shared_folder_uid)

    sfut = folder_pb2.SharedFolderUpdateTeam()
    sfut.teamUid = utils.base64_url_decode(team_uid)
    sfut.expiration = expiration or 0

    if team_is_member:
        sfut.manageUsers = manage_users if manage_users is not None else existing_team.get("manage_users", False)
        sfut.manageRecords = manage_records if manage_records is not None else existing_team.get(
            "manage_records", False
        )
        rq.sharedFolderUpdateTeam.append(sfut)
    else:
        sfut.manageUsers = manage_users if manage_users is not None else sf.get("default_manage_users", False)
        sfut.manageRecords = manage_records if manage_records is not None else sf.get("default_manage_records", False)

        encrypted_key, key_type = _encrypt_shared_folder_key_for_team(auth, team_uid, sf_key)
        sfut.typedSharedFolderKey.encryptedKey = encrypted_key
        sfut.typedSharedFolderKey.encryptedKeyType = key_type
        rq.sharedFolderAddTeam.append(sfut)

    rs = auth.execute_auth_rest(
        _SHARED_FOLDER_UPDATE_V3_ENDPOINT, rq, response_type=folder_pb2.SharedFolderUpdateV3Response
    )
    assert rs is not None

    for arr in (rs.sharedFolderAddTeamStatus, rs.sharedFolderUpdateTeamStatus):
        for st in arr:
            if not _is_put_status_ok(st.status):
                raise ValueError(
                    f'Put Team "{utils.base64_url_encode(st.teamUid)}" to Shared Folder "{display_name}" error: {st.status}'
                )

    return get_shared_folder_records_display(auth, shared_folder_uid)


def revoke_shared_folder_from_team(
    auth: keeper_auth.KeeperAuth,
    shared_folder_uid: str,
    team_name_or_uid: str,
) -> None:
    """
    Remove a team from a shared folder without requiring a synced vault.
    """
    auth = _ensure_auth(auth)
    if not shared_folder_uid:
        raise ValueError("shared_folder_uid is required.")
    if not team_name_or_uid:
        raise ValueError("team_name_or_uid is required.")

    team_uid = None
    for t in vault_utils.load_available_teams(auth):
        if team_name_or_uid.strip().casefold() in (
            t.team_uid.strip().casefold(),
            t.name.strip().casefold(),
        ):
            team_uid = t.team_uid
            break
    if not team_uid:
        return

    sf = load_shared_folder_raw(auth, shared_folder_uid)
    if not sf:
        return

    if sf.get("teams") and _find_shared_folder_team(sf, team_uid) is None:
        return

    sf_key = _decrypt_shared_folder_key(auth, sf)
    if not sf_key:
        raise ValueError(f'Shared folder "{shared_folder_uid}" key could not be decrypted.')

    rq, display_name = _build_shared_folder_update_request(auth, shared_folder_uid, sf, sf_key)
    rq.sharedFolderRemoveTeam.append(utils.base64_url_decode(team_uid))

    rs = auth.execute_auth_rest(
        _SHARED_FOLDER_UPDATE_V3_ENDPOINT, rq, response_type=folder_pb2.SharedFolderUpdateV3Response
    )
    assert rs is not None
    for st in rs.sharedFolderRemoveTeamStatus:
        if not _is_remove_status_ok(st.status):
            raise ValueError(
                f'Remove Team "{utils.base64_url_encode(st.teamUid)}" from Shared Folder "{display_name}" error: {st.status}'
            )


def share_shared_folder_to_user(
    auth: keeper_auth.KeeperAuth,
    shared_folder_uid: str,
    username: str,
    *,
    manage_users: Optional[bool] = None,
    manage_records: Optional[bool] = None,
    expiration: Optional[int] = None,
) -> List[SharedFolderRecordDisplay]:
    """
    Share a shared folder to a user (email) without requiring a synced vault.

    Returns decrypted record UID and title (name) for each record in the folder.
    """
    auth = _ensure_auth(auth)
    if not shared_folder_uid:
        raise ValueError("shared_folder_uid is required.")
    if not username:
        raise ValueError("username is required.")

    sf = load_shared_folder_raw(auth, shared_folder_uid)
    if not sf:
        raise ValueError(f'Shared folder "{shared_folder_uid}" not found.')

    sf_key = _decrypt_shared_folder_key(auth, sf)
    if not sf_key:
        raise ValueError(f'Shared folder "{shared_folder_uid}" key could not be decrypted.')

    rq, display_name = _build_shared_folder_update_request(auth, shared_folder_uid, sf, sf_key)

    user_is_member = _is_shared_folder_user_member(sf, username)
    if _has_no_share_option_changes(manage_users, manage_records, expiration) and user_is_member:
        return get_shared_folder_records_display(auth, shared_folder_uid)

    sfu = folder_pb2.SharedFolderUpdateUser()
    sfu.username = username
    sfu.expiration = expiration or 0

    if user_is_member:
        sfu.manageUsers = (
            folder_pb2.BOOLEAN_NO_CHANGE
            if manage_users is None
            else (folder_pb2.BOOLEAN_TRUE if manage_users else folder_pb2.BOOLEAN_FALSE)
        )
        sfu.manageRecords = (
            folder_pb2.BOOLEAN_NO_CHANGE
            if manage_records is None
            else (folder_pb2.BOOLEAN_TRUE if manage_records else folder_pb2.BOOLEAN_FALSE)
        )
        rq.sharedFolderUpdateUser.append(sfu)
    else:
        default_mu = sf.get("default_manage_users", False)
        default_mr = sf.get("default_manage_records", False)
        sfu.manageUsers = (
            folder_pb2.BOOLEAN_TRUE if (manage_users if manage_users is not None else default_mu) else folder_pb2.BOOLEAN_FALSE
        )
        sfu.manageRecords = (
            folder_pb2.BOOLEAN_TRUE if (manage_records if manage_records is not None else default_mr) else folder_pb2.BOOLEAN_FALSE
        )

        encrypted_key, key_type = _encrypt_shared_folder_key_for_user(auth, username, sf_key)
        sfu.typedSharedFolderKey.encryptedKey = encrypted_key
        sfu.typedSharedFolderKey.encryptedKeyType = key_type
        rq.sharedFolderAddUser.append(sfu)

    rs = auth.execute_auth_rest(
        _SHARED_FOLDER_UPDATE_V3_ENDPOINT, rq, response_type=folder_pb2.SharedFolderUpdateV3Response
    )
    assert rs is not None
    for arr in (rs.sharedFolderAddUserStatus, rs.sharedFolderUpdateUserStatus):
        for st in arr:
            if not _is_put_status_ok(st.status):
                raise ValueError(
                    f'Put "{st.username}" to Shared Folder "{display_name}" error: {st.status}'
                )

    return get_shared_folder_records_display(auth, shared_folder_uid)


def revoke_shared_folder_from_user(
    auth: keeper_auth.KeeperAuth,
    shared_folder_uid: str,
    username: str,
) -> None:
    """
    Remove a user from a shared folder without requiring a synced vault.
    """
    auth = _ensure_auth(auth)
    if not shared_folder_uid:
        raise ValueError("shared_folder_uid is required.")
    if not username:
        raise ValueError("username is required.")

    sf = load_shared_folder_raw(auth, shared_folder_uid)
    if not sf:
        return
    if not _is_shared_folder_user_member(sf, username):
        return

    sf_key = _decrypt_shared_folder_key(auth, sf)
    if not sf_key:
        raise ValueError(f'Shared folder "{shared_folder_uid}" key could not be decrypted.')

    rq, display_name = _build_shared_folder_update_request(auth, shared_folder_uid, sf, sf_key)
    rq.sharedFolderRemoveUser.append(username)

    rs = auth.execute_auth_rest(
        _SHARED_FOLDER_UPDATE_V3_ENDPOINT, rq, response_type=folder_pb2.SharedFolderUpdateV3Response
    )
    assert rs is not None
    for st in rs.sharedFolderRemoveUserStatus:
        if not _is_remove_status_ok(st.status):
            raise ValueError(
                f'Remove user "{st.username}" from Shared Folder "{display_name}" error: {st.status}'
            )

