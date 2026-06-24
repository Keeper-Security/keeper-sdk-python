"""Shared NSF crypto, role, and recipient-resolution helpers."""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

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
    if aes:
        return crypto.encrypt_aes_v2(plaintext_key, aes), folder_pb2.encrypted_by_data_key_gcm
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
