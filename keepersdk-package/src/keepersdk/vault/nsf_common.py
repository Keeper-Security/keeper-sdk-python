"""Shared NSF crypto, role, and recipient-resolution helpers."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

from .. import crypto, utils
from ..proto import folder_pb2, record_pb2, record_sharing_pb2
from .vault_online import VaultOnline

ROLE_NAME_MAP: Dict[str, int] = {
    'contributor': 1,
    'requestor': 1,
    'viewer': 2,
    'shared_manager': 3,
    'share-manager': 3,
    'share_manager': 3,
    'content_manager': 4,
    'content-manager': 4,
    'content_share_manager': 5,
    'content-share-manager': 5,
    'full-manager': 6,
    'full_manager': 6,
}

_FOLDER_ROLE_PERMISSIONS: Dict[int, Dict[str, bool]] = {
    2: {
        'canAdd': False, 'canRemove': False, 'canDelete': False,
        'canListAccess': True, 'canUpdateAccess': False, 'canChangeOwnership': False,
        'canEditRecords': False, 'canViewRecords': True,
        'canApproveAccess': False, 'canRequestAccess': False,
        'canUpdateSetting': False, 'canListRecords': True, 'canListFolders': True,
    },
    3: {
        'canAdd': False, 'canRemove': False, 'canDelete': False,
        'canListAccess': True, 'canUpdateAccess': True, 'canChangeOwnership': False,
        'canEditRecords': False, 'canViewRecords': True,
        'canApproveAccess': True, 'canRequestAccess': False,
        'canUpdateSetting': False, 'canListRecords': True, 'canListFolders': True,
    },
    4: {
        'canAdd': True, 'canRemove': False, 'canDelete': False,
        'canListAccess': True, 'canUpdateAccess': False, 'canChangeOwnership': False,
        'canEditRecords': True, 'canViewRecords': True,
        'canApproveAccess': False, 'canRequestAccess': False,
        'canUpdateSetting': False, 'canListRecords': True, 'canListFolders': True,
    },
    5: {
        'canAdd': True, 'canRemove': True, 'canDelete': False,
        'canListAccess': True, 'canUpdateAccess': True, 'canChangeOwnership': False,
        'canEditRecords': True, 'canViewRecords': True,
        'canApproveAccess': True, 'canRequestAccess': False,
        'canUpdateSetting': True, 'canListRecords': True, 'canListFolders': True,
    },
    6: {
        'canAdd': True, 'canRemove': True, 'canDelete': True,
        'canListAccess': True, 'canUpdateAccess': True, 'canChangeOwnership': True,
        'canEditRecords': True, 'canViewRecords': True,
        'canApproveAccess': True, 'canRequestAccess': False,
        'canUpdateSetting': True, 'canListRecords': True, 'canListFolders': True,
    },
}


def resolve_nsf_role(role: str) -> int:
    value = ROLE_NAME_MAP.get(role.strip().lower())
    if value is None:
        raise ValueError(
            f"Invalid role '{role}'. Accepted: {', '.join(sorted(set(ROLE_NAME_MAP.keys())))}")
    return value


def get_folder_permissions_for_role(role_type: int) -> folder_pb2.FolderPermissions:
    perms_dict = _FOLDER_ROLE_PERMISSIONS.get(role_type)
    if perms_dict is None:
        raise ValueError(f'Unknown AccessRoleType {role_type}')
    perms = folder_pb2.FolderPermissions()
    for field, value in perms_dict.items():
        setattr(perms, field, value)
    return perms


def encrypt_for_recipient(plaintext_key: bytes, public_key, use_ecc: bool) -> bytes:
    if use_ecc:
        return crypto.encrypt_ec(plaintext_key, public_key)
    return crypto.encrypt_rsa(plaintext_key, public_key)


def encrypt_record_key_for_folder(
        record_key: bytes,
        encryption_key: bytes,
        record_key_type: Optional[int]) -> Tuple[bytes, int]:
    if record_key_type == folder_pb2.encrypted_by_data_key:
        return crypto.encrypt_aes_v1(record_key, encryption_key), folder_pb2.encrypted_by_data_key
    if record_key_type == folder_pb2.encrypted_by_data_key_gcm:
        return crypto.encrypt_aes_v2(record_key, encryption_key), folder_pb2.encrypted_by_data_key_gcm
    return crypto.encrypt_aes_v2(record_key, encryption_key), folder_pb2.encrypted_by_data_key_gcm


def _valid_team_aes_key(aes: Optional[bytes]) -> bool:
    return aes is not None and len(aes) == 32


def encrypt_for_team(
        plaintext_key: bytes,
        team_keys,
        *,
        forbid_rsa: bool = False) -> Tuple[bytes, int]:
    aes = getattr(team_keys, 'aes', None)
    ec_bytes = getattr(team_keys, 'ec', None)
    rsa_bytes = getattr(team_keys, 'rsa', None)
    if rsa_bytes and not forbid_rsa:
        rsa_key = crypto.load_rsa_public_key(rsa_bytes)
        return crypto.encrypt_rsa(plaintext_key, rsa_key), folder_pb2.encrypted_by_public_key
    if ec_bytes:
        ec_key = crypto.load_ec_public_key(ec_bytes)
        return crypto.encrypt_ec(plaintext_key, ec_key), folder_pb2.encrypted_by_public_key_ecc
    if _valid_team_aes_key(aes):
        if forbid_rsa:
            return crypto.encrypt_aes_v2(plaintext_key, aes), folder_pb2.encrypted_by_data_key_gcm
        return crypto.encrypt_aes_v1(plaintext_key, aes), folder_pb2.encrypted_by_data_key
    raise ValueError('No public key found for team')


def parse_sharing_status(status) -> Dict[str, Any]:
    try:
        status_name = record_sharing_pb2.SharingStatus.Name(status.status)
    except Exception:
        status_name = str(status.status)
    is_success = status.status == record_sharing_pb2.SUCCESS
    is_pending = status.status == record_sharing_pb2.PENDING_ACCEPT
    return {
        'record_uid': utils.base64_url_encode(status.recordUid),
        'recipient_uid': utils.base64_url_encode(status.recipientUid),
        'status': status_name,
        'message': status.message,
        'success': is_success or is_pending,
        'pending': is_pending,
    }


def parse_folder_access_result(
        response: folder_pb2.FolderAccessResponse,
        folder_uid: str,
        accessor_label: str,
        default_message: str) -> Dict[str, Any]:
    if response.folderAccessResults:
        result = response.folderAccessResults[0]
        status_value = result.status
        is_failure = (status_value != 0) or bool(result.message)
        status_name = (
            folder_pb2.FolderModifyStatus.Name(status_value)
            if status_value != 0 else 'SUCCESS')
        return {
            'folder_uid': folder_uid,
            'accessor': accessor_label,
            'status': 'ERROR' if is_failure and status_value == 0 else status_name,
            'message': result.message or default_message,
            'success': not is_failure,
        }
    return {
        'folder_uid': folder_uid,
        'accessor': accessor_label,
        'status': 'SUCCESS',
        'message': default_message,
        'success': True,
    }


def load_user_public_key(vault: VaultOnline, user_email: str):
    auth = vault.keeper_auth
    keys = auth.get_user_keys(user_email)
    if not keys:
        auth.load_user_public_keys([user_email], send_invites=False)
        keys = auth.get_user_keys(user_email)
    if not keys:
        raise ValueError(f'Public key not found for user {user_email}')
    if keys.rsa:
        return crypto.load_rsa_public_key(keys.rsa), False
    if keys.ec:
        return crypto.load_ec_public_key(keys.ec), True
    raise ValueError(f'No valid public key for user {user_email}')


def resolve_user_uid_bytes(vault: VaultOnline, identifier: str) -> Optional[bytes]:
    if '@' in identifier:
        lower = identifier.casefold()
        rq = record_pb2.GetShareObjectsRequest()
        rs = vault.keeper_auth.execute_auth_rest(
            'vault/get_share_objects', rq, response_type=record_pb2.GetShareObjectsResponse)
        if rs is not None:
            for users in (
                    rs.shareRelationships, rs.shareFamilyUsers,
                    rs.shareEnterpriseUsers, rs.shareMCEnterpriseUsers):
                for su in users:
                    if su.username.casefold() == lower and su.userAccountUid:
                        uid = su.userAccountUid
                        return uid if isinstance(uid, bytes) else utils.base64_url_decode(uid)
        return None
    try:
        return utils.base64_url_decode(identifier)
    except Exception:
        return None


def get_user_public_key(
        vault: VaultOnline,
        recipient_email: str,
        *,
        require_uid: bool = True) -> Tuple[Any, bool, Optional[bytes], bool]:
    auth = vault.keeper_auth
    needs_invite = False
    recipient_uid_bytes = resolve_user_uid_bytes(vault, recipient_email)
    try:
        public_key, use_ecc = load_user_public_key(vault, recipient_email)
    except ValueError:
        public_key, use_ecc = None, False
        if '@' in recipient_email:
            pending = auth.load_user_public_keys([recipient_email], send_invites=True)
            if pending:
                needs_invite = True
            try:
                public_key, use_ecc = load_user_public_key(vault, recipient_email)
            except ValueError:
                pass
    if not public_key:
        if needs_invite:
            raise ValueError(
                f"Share invitation sent to '{recipient_email}'. "
                f"Repeat after the invitation is accepted.")
        raise ValueError(f"User {recipient_email} has no public key or user not found")
    if not recipient_uid_bytes:
        recipient_uid_bytes = resolve_user_uid_bytes(vault, recipient_email)
    if require_uid and not recipient_uid_bytes:
        raise ValueError(f"User {recipient_email} not found")
    return public_key, use_ecc, recipient_uid_bytes, needs_invite


def resolve_team_uid_bytes(vault: VaultOnline, team_identifier: str) -> Optional[bytes]:
    from . import share_management_utils

    share_objects = share_management_utils.get_share_objects(vault)
    teams = share_objects.get('teams') or {}
    if team_identifier in teams:
        return utils.base64_url_decode(team_identifier)
    lower = team_identifier.casefold()
    for uid, team in teams.items():
        name = team.get('name') if isinstance(team, dict) else ''
        if name and name.casefold() == lower:
            return utils.base64_url_decode(uid)
    try:
        return utils.base64_url_decode(team_identifier)
    except Exception:
        return None


def get_team_keys(vault: VaultOnline, team_uid_b64: str):
    """Return cached team keys, loading asymmetric public keys if needed."""
    from ..authentication.keeper_auth import UserKeys, parse_team_asymmetric_key_entry

    auth = vault.keeper_auth
    auth.load_team_keys([team_uid_b64])
    keys = auth.get_team_keys(team_uid_b64)

    has_asym = bool(keys and (keys.rsa or keys.ec))
    if not has_asym:
        try:
            rq = {'command': 'team_get_keys', 'teams': [team_uid_b64]}
            rs = auth.execute_auth_command(rq)
            existing_aes = keys.aes if keys else None
            rsa_pub = b''
            ec_pub = b''
            for tk in (rs or {}).get('keys', []):
                if tk.get('team_uid') != team_uid_b64:
                    continue
                pub_rsa, pub_ec = parse_team_asymmetric_key_entry(tk)
                if pub_rsa:
                    rsa_pub = pub_rsa
                if pub_ec:
                    ec_pub = pub_ec
            if rsa_pub or ec_pub:
                if auth._key_cache is None:
                    auth._key_cache = {}
                auth._key_cache[team_uid_b64] = UserKeys(
                    aes=existing_aes,
                    rsa=rsa_pub or (keys.rsa if keys else None),
                    ec=ec_pub or (keys.ec if keys else None))
                keys = auth._key_cache[team_uid_b64]
        except Exception as exc:
            utils.get_logger().debug(
                'team_get_keys fallback failed for %s: %s', team_uid_b64, exc)

    if not keys:
        raise ValueError(f'Team key not found for team {team_uid_b64}')
    return keys


def resolve_team_identifier(vault: VaultOnline, team_identifier: str) -> Optional[Tuple[str, bytes]]:
    uid_bytes = resolve_team_uid_bytes(vault, team_identifier)
    if not uid_bytes:
        return None
    return utils.base64_url_encode(uid_bytes), uid_bytes


_FOLDER_ACCESS_ROLE_DISPLAY = {
    'NAVIGATOR': 'contributor',
    'REQUESTOR': 'contributor',
    'VIEWER': 'viewer',
    'SHARED_MANAGER': 'share-manager',
    'CONTENT_MANAGER': 'content-manager',
    'CONTENT_SHARE_MANAGER': 'content-share-manager',
    'MANAGER': 'full-manager',
    'UNRESOLVED': 'unresolved',
}


def is_nsf_folder_owner(
        accessor: Dict[str, Any],
        owner_username: Optional[str] = None,
        owner_account_uid: Optional[str] = None) -> bool:
    """Return True when *accessor* matches folder ownerInfo from sync-down."""
    if not accessor:
        return False
    if accessor.get('access_type') == 'AT_OWNER':
        return True
    if owner_username:
        username = (accessor.get('username') or '').lower()
        if username and username == owner_username.lower():
            return True
    if owner_account_uid:
        accessor_uid = accessor.get('accessor_uid') or ''
        if accessor_uid and accessor_uid == owner_account_uid:
            return True
    return False


def folder_access_role_label(
        accessor: Dict[str, Any],
        owner_username: Optional[str] = None,
        owner_account_uid: Optional[str] = None) -> str:
    """Display label for an NSF folder accessor (``owner``, ``full-manager``, etc.)."""
    if accessor.get('owner') or is_nsf_folder_owner(
            accessor, owner_username, owner_account_uid):
        return 'owner'
    role_name = accessor.get('role')
    if role_name:
        key = str(role_name).upper().replace('-', '_')
        return _FOLDER_ACCESS_ROLE_DISPLAY.get(
            key, str(role_name).lower().replace('_', '-'))
    role_type = accessor.get('access_role_type')
    if isinstance(role_type, int):
        try:
            name = folder_pb2.AccessRoleType.Name(role_type)
            return _FOLDER_ACCESS_ROLE_DISPLAY.get(
                name, name.lower().replace('_', '-'))
        except Exception:
            pass
    perms = accessor.get('permissions') or {}
    if perms.get('can_change_ownership'):
        return 'full-manager'
    if perms.get('can_update_access'):
        return 'share-manager'
    if perms.get('can_edit_records'):
        return 'content-manager'
    if perms.get('can_view_records'):
        return 'viewer'
    return 'unknown'


_PERMISSION_CAMEL_KEYS: Dict[str, str] = {
    'can_update_access': 'canUpdateAccess',
    'can_update_setting': 'canUpdateSetting',
    'can_delete': 'canDelete',
    'can_change_ownership': 'canChangeOwnership',
    'can_edit': 'canEdit',
    'can_view': 'canView',
    'can_list_access': 'canListAccess',
}


def _current_user_account_uid_b64(vault: VaultOnline) -> str:
    account_uid = vault.keeper_auth.auth_context.account_uid
    return utils.base64_url_encode(account_uid) if account_uid else ''


def _parse_permissions_blob(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw:
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except (TypeError, ValueError):
            return {}
    return {}


def _permission_value(perms: Dict[str, Any], key: str) -> bool:
    if not perms:
        return False
    if key in perms:
        return bool(perms[key])
    camel = _PERMISSION_CAMEL_KEYS.get(key)
    if camel and camel in perms:
        return bool(perms[camel])
    return False


def _access_type_is_owner(access_type: Any) -> bool:
    if access_type == folder_pb2.AT_OWNER:
        return True
    return isinstance(access_type, str) and access_type == 'AT_OWNER'


def is_current_user_nsf_accessor(
        accessor: Dict[str, Any],
        vault: VaultOnline,
        account_uid_b64: str) -> bool:
    """Return True when *accessor* belongs to the logged-in user."""
    username = vault.keeper_auth.auth_context.username
    accessor_username = accessor.get('username') or accessor.get('accessor_name')
    if accessor_username and username:
        return accessor_username.casefold() == username.casefold()
    accessor_uid = accessor.get('access_type_uid') or accessor.get('accessor_uid')
    return bool(accessor_uid and account_uid_b64 and accessor_uid == account_uid_b64)


def _folder_owner_info(vault: VaultOnline, folder_uid: str) -> Tuple[Optional[str], Optional[str]]:
    view = vault.nsf_data
    if view is None:
        return None, None
    row = view.storage.folders.get_entity(folder_uid)
    if row is None:
        return None, None
    return row.owner_username or None, row.owner_account_uid or None


def is_nsf_folder_owner_user(vault: VaultOnline, folder_uid: str) -> bool:
    """Return True when the logged-in user owns *folder_uid*."""
    account_uid_b64 = _current_user_account_uid_b64(vault)
    username = vault.keeper_auth.auth_context.username
    owner_username, owner_account_uid = _folder_owner_info(vault, folder_uid)
    if owner_account_uid and account_uid_b64 and owner_account_uid == account_uid_b64:
        return True
    if owner_username and username and owner_username.casefold() == username.casefold():
        return True
    return False


def _folder_accessor_from_storage(fa: Any) -> Dict[str, Any]:
    return {
        'access_type_uid': fa.access_type_uid,
        'access_type': fa.access_type,
        'permissions': _parse_permissions_blob(fa.permissions_json),
    }


def collect_nsf_folder_accessors(vault: VaultOnline, folder_uid: str) -> List[Dict[str, Any]]:
    """Folder accessor rows from sync cache, falling back to the access API."""
    accessors: List[Dict[str, Any]] = []
    view = vault.nsf_data
    if view is not None:
        for fa in view.storage.folder_accesses.get_links_by_subject(folder_uid):
            accessors.append(_folder_accessor_from_storage(fa))
    if accessors:
        return accessors
    from .nsf_management import get_nsf_folder_access
    try:
        info = get_nsf_folder_access(vault, [folder_uid])
        for result in info.get('results', []):
            if result.get('success'):
                accessors.extend(result.get('accessors', []))
    except Exception:
        pass
    return accessors


def _record_accessor_from_storage(ra: Any) -> Dict[str, Any]:
    return {
        'access_type_uid': ra.access_type_uid,
        'owner': ra.owner,
        'inherited': ra.inherited,
        'denied_access': ra.denied_access,
        'can_update_access': ra.can_update_access,
        'can_change_ownership': ra.can_change_ownership,
        'can_delete': ra.can_delete,
        'can_edit': ra.can_edit,
    }


def find_record_user_accesses(
        vault: VaultOnline,
        record_uid: str,
        recipient_email: str) -> List[Dict[str, Any]]:
    """Return non-owner AT_USER accessor rows for *recipient_email* on *record_uid*."""
    email_cf = recipient_email.casefold()
    matches: List[Dict[str, Any]] = []
    for accessor in collect_nsf_record_accessors(vault, record_uid):
        if accessor.get('owner'):
            continue
        access_type = accessor.get('access_type') or 'AT_USER'
        if access_type not in ('AT_USER', ''):
            continue
        accessor_name = accessor.get('accessor_name') or accessor.get('username') or ''
        if accessor_name.casefold() != email_cf:
            continue
        matches.append(accessor)
    return matches


def record_user_has_direct_access(accesses: List[Dict[str, Any]]) -> bool:
    return any(not accessor.get('inherited') for accessor in accesses)


def record_user_has_inherited_access(accesses: List[Dict[str, Any]]) -> bool:
    return any(accessor.get('inherited') for accessor in accesses)


def collect_nsf_record_accessors(vault: VaultOnline, record_uid: str) -> List[Dict[str, Any]]:
    """Record accessor rows from sync cache, falling back to the access API."""
    accessors: List[Dict[str, Any]] = []
    view = vault.nsf_data
    if view is not None:
        for ra in view.storage.record_accesses.get_links_by_subject(record_uid):
            accessors.append(_record_accessor_from_storage(ra))
    if accessors:
        return accessors
    from .nsf_management import get_nsf_record_accesses
    try:
        info = get_nsf_record_accesses(vault, [record_uid])
        accessors.extend(info.get('record_accesses', []))
    except Exception:
        pass
    return accessors


def _record_permission_value(accessor: Dict[str, Any], key: str) -> bool:
    if key in accessor:
        return bool(accessor[key])
    return _permission_value(accessor.get('permissions') or {}, key)


def require_nsf_folder_permission(
        vault: VaultOnline,
        folder_uid: str,
        permission_key: str,
        error_message: str) -> None:
    """Raise ValueError when the current user lacks *permission_key* on a folder."""
    if is_nsf_folder_owner_user(vault, folder_uid):
        return

    accessors = collect_nsf_folder_accessors(vault, folder_uid)
    if not accessors:
        raise ValueError("No accessors data found for folder {folder_uid}")

    account_uid_b64 = _current_user_account_uid_b64(vault)
    owner_username, owner_account_uid = _folder_owner_info(vault, folder_uid)
    for accessor in accessors:
        if not is_current_user_nsf_accessor(accessor, vault, account_uid_b64):
            continue
        if (accessor.get('owner')
                or _access_type_is_owner(accessor.get('access_type'))
                or is_nsf_folder_owner(accessor, owner_username, owner_account_uid)):
            return
        perms = accessor.get('permissions') or {}
        if _permission_value(perms, permission_key):
            return
        raise ValueError(error_message)

    raise ValueError(error_message)


def require_nsf_folder_share_permission(vault: VaultOnline, folder_uid: str) -> None:
    """Raise ValueError when the current user cannot share or manage folder access."""
    require_nsf_folder_permission(
        vault,
        folder_uid,
        'can_update_access',
        'You do not have permission to share this folder.')


def require_nsf_record_permission(
        vault: VaultOnline,
        record_uid: str,
        permission_key: str,
        error_message: str) -> None:
    """Raise ValueError when the current user lacks *permission_key* on a record."""
    accessors = collect_nsf_record_accessors(vault, record_uid)
    if not accessors:
        raise ValueError("No accessors data found for record {record_uid}")

    account_uid_b64 = _current_user_account_uid_b64(vault)
    for accessor in accessors:
        if not is_current_user_nsf_accessor(accessor, vault, account_uid_b64):
            continue
        if accessor.get('owner'):
            return
        if _record_permission_value(accessor, permission_key):
            return
        raise ValueError(error_message)

    raise ValueError(error_message)


def require_nsf_record_share_permission(vault: VaultOnline, record_uid: str) -> None:
    """Raise ValueError when the current user cannot share or manage record access."""
    require_nsf_record_permission(
        vault,
        record_uid,
        'can_update_access',
        'You do not have permission to share this record.')


def require_nsf_record_ownership_permission(vault: VaultOnline, record_uid: str) -> None:
    """Raise ValueError when the current user cannot transfer record ownership."""
    require_nsf_record_permission(
        vault,
        record_uid,
        'can_change_ownership',
        'You do not have permission to transfer ownership of this record.')


def folder_inherits_parent_permissions(vault: VaultOnline, folder_uid: str) -> bool:
    """Return True when *folder_uid* has a parent and still inherits its access list."""
    from .nsf_management import ROOT_FOLDER_UID

    view = vault.nsf_data
    if view is None:
        return False
    node = view.get_folder(folder_uid)
    parent_uid = node.parent_uid if node else None
    if not parent_uid:
        row = view.storage.folders.get_entity(folder_uid)
        parent_uid = row.parent_uid if row else None
    if not parent_uid or parent_uid == ROOT_FOLDER_UID:
        return False
    row = view.storage.folders.get_entity(folder_uid)
    if row is None:
        return True
    return row.inherit_user_permissions != int(folder_pb2.BOOLEAN_FALSE)


def ensure_folder_direct_permissions(
        vault: VaultOnline,
        folder_uid: str,
        *,
        request_sync: bool = False) -> bool:
    """Disable parent permission inheritance so folder access changes apply locally."""
    if not folder_inherits_parent_permissions(vault, folder_uid):
        return False
    from .nsf_management import update_nsf_folder
    update_nsf_folder(vault, folder_uid, inherit_permissions=False, request_sync=request_sync)
    return True


def access_role_label(access: Dict[str, Any]) -> str:
    if access.get('owner'):
        return 'owner'
    role_type = access.get('access_role_type')
    if isinstance(role_type, int):
        try:
            name = folder_pb2.AccessRoleType.Name(role_type)
            return name.lower().replace('_', '-')
        except Exception:
            pass
    role = access.get('access_type') or access.get('role')
    if isinstance(role, str) and role:
        return role.lower().replace('_', '-')
    if access.get('can_edit'):
        return 'content-manager'
    if access.get('can_view') or access.get('can_view_title'):
        return 'viewer'
    return 'unknown'
