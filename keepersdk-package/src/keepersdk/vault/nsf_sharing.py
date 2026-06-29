"""NSF sharing, bulk record permissions, and ownership transfer."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .. import utils
from ..errors import KeeperApiError
from ..proto import folder_pb2, record_pb2, record_sharing_pb2
from . import nsf_common
from .nsf_management import (
    NsfError,
    ROOT_FOLDER_UID,
    _get_folder_key,
    _get_record_key,
    _nsf_view,
    _request_sync,
    get_nsf_folder_access,
    get_nsf_record_accesses,
    is_nsf_folder,
    resolve_nsf_folder_uid,
    resolve_nsf_record_uid,
)
from .vault_online import VaultOnline

_SHARE_BATCH_SIZE = 200


def _ensure_folder_share_permission(vault: VaultOnline, folder_uid: str) -> None:
    try:
        nsf_common.require_nsf_folder_share_permission(vault, folder_uid)
    except ValueError as exc:
        raise NsfError(str(exc)) from exc


def _ensure_record_share_permission(vault: VaultOnline, record_uid: str) -> None:
    try:
        nsf_common.require_nsf_record_share_permission(vault, record_uid)
    except ValueError as exc:
        raise NsfError(str(exc)) from exc


def _ensure_record_ownership_permission(vault: VaultOnline, record_uid: str) -> None:
    try:
        nsf_common.require_nsf_record_ownership_permission(vault, record_uid)
    except ValueError as exc:
        raise NsfError(str(exc)) from exc


def _prepare_folder_for_access_change(vault: VaultOnline, folder_uid: str) -> None:
    """Break parent permission inheritance before changing folder accessors."""
    nsf_common.ensure_folder_direct_permissions(vault, folder_uid, request_sync=False)


@dataclass
class NsfShareResult:
    success: bool
    results: List[Dict[str, Any]] = field(default_factory=list)
    message: str = ''


@dataclass
class NsfRecordPermissionPlan:
    updates: List[Dict[str, Any]] = field(default_factory=list)
    creates: List[Dict[str, Any]] = field(default_factory=list)
    revokes: List[Dict[str, Any]] = field(default_factory=list)
    denies: List[Dict[str, Any]] = field(default_factory=list)
    skipped: List[Dict[str, Any]] = field(default_factory=list)


def _folder_access_update(
        vault: VaultOnline,
        *,
        adds: Optional[List[folder_pb2.FolderAccessData]] = None,
        updates: Optional[List[folder_pb2.FolderAccessData]] = None,
        removes: Optional[List[folder_pb2.FolderAccessData]] = None) -> folder_pb2.FolderAccessResponse:
    rq = folder_pb2.FolderAccessRequest()
    if adds:
        rq.folderAccessAdds.extend(adds)
    if updates:
        rq.folderAccessUpdates.extend(updates)
    if removes:
        rq.folderAccessRemoves.extend(removes)
    response = vault.keeper_auth.execute_auth_rest(
        'vault/folders/v3/access_update',
        rq,
        response_type=folder_pb2.FolderAccessResponse)
    assert response is not None
    return response


def _resolve_folder_accessor(
        vault: VaultOnline,
        recipient: str,
        *,
        as_team: bool) -> Tuple[bytes, str, int]:
    """Return (uid_bytes, label, access_type_enum) for a folder accessor."""
    if as_team:
        resolved = nsf_common.resolve_team_identifier(vault, recipient)
        if not resolved:
            raise NsfError(f"Team '{recipient}' not found")
        team_uid_b64, uid_bytes = resolved
        return uid_bytes, team_uid_b64, folder_pb2.AT_TEAM

    if '@' in recipient:
        _, _, uid_bytes, _ = nsf_common.get_user_public_key(vault, recipient)
        if not uid_bytes:
            raise NsfError(f"User '{recipient}' not found")
        return uid_bytes, recipient, folder_pb2.AT_USER

    uid_bytes = nsf_common.resolve_user_uid_bytes(vault, recipient)
    if not uid_bytes:
        raise NsfError(f"User '{recipient}' not found")
    return uid_bytes, recipient, folder_pb2.AT_USER


def _check_existing_nsf_folder_access(
        vault: VaultOnline,
        folder_uid: str,
        uid_bytes: bytes,
        access_type_label: str) -> Optional[str]:
    """Return the existing AccessRoleType name for an accessor, or None."""
    try:
        uid_encoded = utils.base64_url_encode(uid_bytes)
        info = get_nsf_folder_access(vault, [folder_uid])
        for result in info.get('results', []):
            if not result.get('success'):
                continue
            for accessor in result.get('accessors', []):
                if (accessor.get('access_type') == access_type_label
                        and accessor.get('accessor_uid') == uid_encoded):
                    return accessor.get('role')
    except Exception:
        pass
    return None


def collect_nsf_records_in_folder(
        vault: VaultOnline,
        folder_identifier: Optional[str],
        *,
        recursive: bool = False) -> Set[str]:
    view = _nsf_view(vault)
    record_uids: Set[str] = set()
    known = {f.folder_uid for f in view.folders()}

    def walk(folder_uid: str, visited: Set[str]) -> None:
        if folder_uid in visited:
            return
        visited.add(folder_uid)
        folder = view.get_folder(folder_uid)
        if folder is None:
            return
        record_uids.update(folder.record_uids)
        if recursive:
            for child_uid in folder.subfolder_uids:
                if child_uid in known:
                    walk(child_uid, visited)

    if folder_identifier:
        folder_uid = resolve_nsf_folder_uid(vault, folder_identifier) or folder_identifier
        if folder_uid == ROOT_FOLDER_UID or is_nsf_folder(vault, folder_uid):
            walk(folder_uid, set())
    else:
        for folder in view.folders():
            walk(folder.folder_uid, set())
    return record_uids


def grant_nsf_folder_access(
        vault: VaultOnline,
        folder_identifier: str,
        recipient: str,
        *,
        role: str = 'viewer',
        expiration_timestamp: Optional[int] = None,
        as_team: bool = False,
        request_sync: bool = True) -> Dict[str, Any]:
    """Grant user or team access to an NSF folder."""
    folder_uid = resolve_nsf_folder_uid(vault, folder_identifier) or folder_identifier
    if not is_nsf_folder(vault, folder_uid):
        raise NsfError(f'NSF folder not found: {folder_identifier}')
    _ensure_folder_share_permission(vault, folder_uid)
    _prepare_folder_for_access_change(vault, folder_uid)

    access_role = nsf_common.resolve_nsf_role(role)
    target_role_name = folder_pb2.AccessRoleType.Name(access_role)
    access_type_label = 'AT_TEAM' if as_team else 'AT_USER'

    uid_bytes, label, access_type_enum = _resolve_folder_accessor(
        vault, recipient, as_team=as_team)

    existing_role = _check_existing_nsf_folder_access(
        vault, folder_uid, uid_bytes, access_type_label)
    if existing_role is not None:
        if existing_role == target_role_name and expiration_timestamp is None:
            return {
                'folder_uid': folder_uid,
                'accessor': label,
                'access_type': access_type_label,
                'status': 'SUCCESS',
                'message': f"{'Team' if as_team else 'User'} already has {role} access",
                'success': True,
                'action_taken': 'already_had_access',
            }
        result = update_nsf_folder_access(
            vault, folder_uid, recipient, role=role, as_team=as_team,
            expiration_timestamp=expiration_timestamp, request_sync=request_sync)
        result['action_taken'] = 'updated'
        return result

    ad = folder_pb2.FolderAccessData()
    ad.folderUid = utils.base64_url_decode(folder_uid)
    ad.accessTypeUid = uid_bytes
    ad.accessType = access_type_enum
    ad.accessRoleType = access_role
    ad.permissions.CopyFrom(nsf_common.get_folder_permissions_for_role(access_role))

    if expiration_timestamp is not None:
        ad.tlaProperties.expiration = expiration_timestamp

    fk = _get_folder_key(vault, folder_uid)
    ek = folder_pb2.EncryptedDataKey()
    if as_team:
        team_uid_b64 = utils.base64_url_encode(uid_bytes)
        try:
            team_keys = nsf_common.get_team_keys(vault, team_uid_b64)
        except ValueError as exc:
            raise NsfError(f'Team keys not available for {recipient}') from exc
        efk, key_type = nsf_common.encrypt_for_team(
            fk, team_keys,
            forbid_rsa=vault.keeper_auth.auth_context.forbid_rsa)
    else:
        pub_key, use_ecc, _, _ = nsf_common.get_user_public_key(vault, recipient)
        efk = nsf_common.encrypt_for_recipient(fk, pub_key, use_ecc)
        key_type = (
            folder_pb2.encrypted_by_public_key_ecc if use_ecc
            else folder_pb2.encrypted_by_public_key)
    ek.encryptedKey = efk
    ek.encryptedKeyType = key_type
    ad.folderKey.CopyFrom(ek)

    response = _folder_access_update(vault, adds=[ad])
    result = nsf_common.parse_folder_access_result(
        response, folder_uid, label, 'Access granted successfully')
    result['access_type'] = access_type_label
    result.setdefault('action_taken', 'granted' if result['success'] else 'grant_failed')
    if not result['success']:
        raise KeeperApiError(result['status'], result['message'])
    _request_sync(vault, request_sync)
    return result


def update_nsf_folder_access(
        vault: VaultOnline,
        folder_identifier: str,
        recipient: str,
        *,
        role: Optional[str] = None,
        hidden: Optional[bool] = None,
        expiration_timestamp: Optional[int] = None,
        as_team: bool = False,
        request_sync: bool = True) -> Dict[str, Any]:
    """Update role, visibility, or expiration for an existing NSF folder accessor."""
    if role is None and hidden is None and expiration_timestamp is None:
        raise NsfError('At least one field (role, hidden, or expiration) is required')

    folder_uid = resolve_nsf_folder_uid(vault, folder_identifier) or folder_identifier
    if not is_nsf_folder(vault, folder_uid):
        raise NsfError(f'NSF folder not found: {folder_identifier}')
    _ensure_folder_share_permission(vault, folder_uid)
    _prepare_folder_for_access_change(vault, folder_uid)

    uid_bytes, label, access_type_enum = _resolve_folder_accessor(
        vault, recipient, as_team=as_team)

    ad = folder_pb2.FolderAccessData()
    ad.folderUid = utils.base64_url_decode(folder_uid)
    ad.accessTypeUid = uid_bytes
    ad.accessType = access_type_enum
    if role is not None:
        access_role = nsf_common.resolve_nsf_role(role)
        ad.accessRoleType = access_role
        ad.permissions.CopyFrom(nsf_common.get_folder_permissions_for_role(access_role))
    if hidden is not None:
        ad.hidden = hidden
    if expiration_timestamp is not None:
        ad.tlaProperties.expiration = expiration_timestamp

    response = _folder_access_update(vault, updates=[ad])
    result = nsf_common.parse_folder_access_result(
        response, folder_uid, label, 'Access updated successfully')
    result['access_type'] = 'AT_TEAM' if as_team else 'AT_USER'
    if not result['success']:
        raise KeeperApiError(result['status'], result['message'])
    _request_sync(vault, request_sync)
    return result


def revoke_nsf_folder_access(
        vault: VaultOnline,
        folder_identifier: str,
        recipient: str,
        *,
        as_team: bool = False,
        request_sync: bool = True) -> Dict[str, Any]:
    """Revoke user or team access from an NSF folder."""
    folder_uid = resolve_nsf_folder_uid(vault, folder_identifier) or folder_identifier
    if not is_nsf_folder(vault, folder_uid):
        raise NsfError(f'NSF folder not found: {folder_identifier}')
    _ensure_folder_share_permission(vault, folder_uid)
    _prepare_folder_for_access_change(vault, folder_uid)

    uid_bytes, label, access_type_enum = _resolve_folder_accessor(
        vault, recipient, as_team=as_team)

    ad = folder_pb2.FolderAccessData()
    ad.folderUid = utils.base64_url_decode(folder_uid)
    ad.accessTypeUid = uid_bytes
    ad.accessType = access_type_enum

    response = _folder_access_update(vault, removes=[ad])
    result = nsf_common.parse_folder_access_result(
        response, folder_uid, label, 'Access revoked successfully')
    result['access_type'] = 'AT_TEAM' if as_team else 'AT_USER'
    if not result['success']:
        raise KeeperApiError(result['status'], result['message'])
    _request_sync(vault, request_sync)
    return result


def _build_share_permission(
        vault: VaultOnline,
        record_uid: str,
        recipient_email: str,
        access_role_type: Optional[int],
        expiration_timestamp: Optional[int],
        *,
        include_role: bool,
        denied_access: bool = False) -> record_sharing_pb2.Permissions:
    record_key = _get_record_key(vault, record_uid)
    pub_key, use_ecc, uid_bytes, _ = nsf_common.get_user_public_key(vault, recipient_email)
    enc_rk = nsf_common.encrypt_for_recipient(record_key, pub_key, use_ecc)
    uid_b = utils.base64_url_decode(record_uid)
    perm = record_sharing_pb2.Permissions()
    perm.recipientUid = uid_bytes
    perm.recordUid = uid_b
    perm.recordKey = enc_rk
    perm.useEccKey = use_ecc
    perm.rules.accessTypeUid = uid_bytes
    perm.rules.accessType = folder_pb2.AT_USER
    perm.rules.recordUid = uid_b
    perm.rules.owner = False
    if denied_access:
        perm.rules.deniedAccess = True
    elif include_role and access_role_type is not None:
        perm.rules.accessRoleType = access_role_type
    if expiration_timestamp:
        perm.rules.tlaProperties.expiration = expiration_timestamp
    return perm


def _build_revoke_share_permission(
        vault: VaultOnline,
        record_uid: str,
        recipient_email: str) -> record_sharing_pb2.Permissions:
    uid_bytes = nsf_common.resolve_user_uid_bytes(vault, recipient_email)
    if not uid_bytes:
        raise NsfError(f"User '{recipient_email}' not found")
    uid_b = utils.base64_url_decode(record_uid)
    perm = record_sharing_pb2.Permissions()
    perm.recipientUid = uid_bytes
    perm.recordUid = uid_b
    perm.rules.accessTypeUid = uid_bytes
    perm.rules.accessType = folder_pb2.AT_USER
    perm.rules.recordUid = uid_b
    return perm


def _revoke_direct_record_share(
        vault: VaultOnline,
        record_uid: str,
        recipient_email: str) -> NsfShareResult:
    perm = _build_revoke_share_permission(vault, record_uid, recipient_email)
    rq = record_sharing_pb2.Request()
    rq.revokeSharingPermissions.append(perm)
    return _share_rest(vault, rq, 'revokedSharingStatus')


def _deny_inherited_record_share(
        vault: VaultOnline,
        record_uid: str,
        recipient_email: str) -> NsfShareResult:
    """Add a direct deny row so inherited folder access no longer applies."""
    perm = _build_share_permission(
        vault, record_uid, recipient_email, None, None,
        include_role=False, denied_access=True)
    rq = record_sharing_pb2.Request()
    rq.createSharingPermissions.append(perm)
    return _share_rest(vault, rq, 'createdSharingStatus')


def _share_rest(
        vault: VaultOnline,
        rq: record_sharing_pb2.Request,
        status_attr: str) -> NsfShareResult:
    rs = vault.keeper_auth.execute_auth_rest(
        'vault/records/v3/share', rq, response_type=record_sharing_pb2.Response)
    assert rs is not None
    statuses = getattr(rs, status_attr, [])
    results = [nsf_common.parse_sharing_status(s) for s in statuses]
    return NsfShareResult(
        success=all(r['success'] for r in results) if results else True,
        results=results,
    )


def share_nsf_record(
        vault: VaultOnline,
        record_uid: str,
        recipient_email: str,
        *,
        role: str,
        expiration_timestamp: Optional[int] = None,
        request_sync: bool = True) -> NsfShareResult:
    """Grant record share."""
    resolved = resolve_nsf_record_uid(vault, record_uid) or record_uid
    _ensure_record_share_permission(vault, resolved)
    role_type = nsf_common.resolve_nsf_role(role)
    perm = _build_share_permission(
        vault, resolved, recipient_email, role_type, expiration_timestamp, include_role=True)
    rq = record_sharing_pb2.Request()
    rq.createSharingPermissions.append(perm)
    result = _share_rest(vault, rq, 'createdSharingStatus')
    if not result.success:
        msg = result.results[0]['message'] if result.results else 'Share failed'
        raise KeeperApiError('share_failed', msg)
    _request_sync(vault, request_sync)
    return result


def update_nsf_record_share(
        vault: VaultOnline,
        record_uid: str,
        recipient_email: str,
        *,
        role: str,
        expiration_timestamp: Optional[int] = None,
        request_sync: bool = True) -> NsfShareResult:
    resolved = resolve_nsf_record_uid(vault, record_uid) or record_uid
    _ensure_record_share_permission(vault, resolved)
    user_accesses = nsf_common.find_record_user_accesses(vault, resolved, recipient_email)
    if not nsf_common.record_user_has_direct_access(user_accesses):
        return share_nsf_record(
            vault, resolved, recipient_email, role=role,
            expiration_timestamp=expiration_timestamp, request_sync=request_sync)
    role_type = nsf_common.resolve_nsf_role(role)
    perm = _build_share_permission(
        vault, resolved, recipient_email, role_type, expiration_timestamp, include_role=True)
    rq = record_sharing_pb2.Request()
    rq.updateSharingPermissions.append(perm)
    result = _share_rest(vault, rq, 'updatedSharingStatus')
    if not result.success:
        msg = result.results[0]['message'] if result.results else 'Update failed'
        raise KeeperApiError('share_update_failed', msg)
    _request_sync(vault, request_sync)
    return result


def unshare_nsf_record(
        vault: VaultOnline,
        record_uid: str,
        recipient_email: str,
        *,
        request_sync: bool = True) -> NsfShareResult:
    resolved = resolve_nsf_record_uid(vault, record_uid) or record_uid
    _ensure_record_share_permission(vault, resolved)
    user_accesses = nsf_common.find_record_user_accesses(vault, resolved, recipient_email)
    has_direct = nsf_common.record_user_has_direct_access(user_accesses)
    has_inherited = nsf_common.record_user_has_inherited_access(user_accesses)
    results: List[Dict[str, Any]] = []

    if has_direct:
        revoke_result = _revoke_direct_record_share(vault, resolved, recipient_email)
        results.extend(revoke_result.results)
        if not revoke_result.success:
            msg = revoke_result.results[0]['message'] if revoke_result.results else 'Revoke failed'
            raise KeeperApiError('share_revoke_failed', msg)

    if has_inherited:
        deny_result = _deny_inherited_record_share(vault, resolved, recipient_email)
        results.extend(deny_result.results)
        if not deny_result.success:
            msg = deny_result.results[0]['message'] if deny_result.results else 'Deny failed'
            raise KeeperApiError('share_revoke_failed', msg)

    if not has_direct and not has_inherited:
        revoke_result = _revoke_direct_record_share(vault, resolved, recipient_email)
        results.extend(revoke_result.results)
        if not revoke_result.success:
            msg = revoke_result.results[0]['message'] if revoke_result.results else 'Revoke failed'
            raise KeeperApiError('share_revoke_failed', msg)

    _request_sync(vault, request_sync)
    return NsfShareResult(
        success=all(r.get('success', False) for r in results) if results else True,
        results=results,
    )


def transfer_nsf_record_ownership(
        vault: VaultOnline,
        record_identifier: str,
        new_owner_email: str,
        *,
        request_sync: bool = True) -> NsfShareResult:
    """Transfer NSF record ownership."""
    record_uid = resolve_nsf_record_uid(vault, record_identifier)
    if not record_uid:
        raise NsfError(f'NSF record not found: {record_identifier}')
    _ensure_record_ownership_permission(vault, record_uid)
    record_key = _get_record_key(vault, record_uid)
    pub_key, use_ecc, _, _ = nsf_common.get_user_public_key(
        vault, new_owner_email, require_uid=False)
    enc_rk = nsf_common.encrypt_for_recipient(record_key, pub_key, use_ecc)
    tr = record_pb2.TransferRecord()
    tr.username = new_owner_email
    tr.recordUid = utils.base64_url_decode(record_uid)
    tr.recordKey = enc_rk
    tr.useEccKey = use_ecc
    rq = record_pb2.RecordsOnwershipTransferRequest()
    rq.transferRecords.append(tr)
    rs = vault.keeper_auth.execute_auth_rest(
        'vault/records/v3/transfer',
        rq,
        response_type=record_pb2.RecordsOnwershipTransferResponse)
    assert rs is not None
    results = [{
        'record_uid': utils.base64_url_encode(s.recordUid),
        'username': s.username,
        'status': s.status,
        'message': s.message,
        'success': 'success' in s.status.lower(),
    } for s in rs.transferRecordStatus]
    result = NsfShareResult(
        success=all(r['success'] for r in results) if results else False,
        results=results,
    )
    if not result.success:
        msg = results[0]['message'] if results else 'Transfer failed'
        raise KeeperApiError('transfer_failed', msg)
    _request_sync(vault, request_sync)
    return result


def resolve_nsf_share_record_uids(
        vault: VaultOnline,
        record_arg: str,
        *,
        recursive: bool = False) -> List[str]:
    resolved = resolve_nsf_record_uid(vault, record_arg)
    if resolved:
        return [resolved]
    folder_uid = resolve_nsf_folder_uid(vault, record_arg)
    if folder_uid:
        uids = collect_nsf_records_in_folder(vault, folder_uid, recursive=recursive)
        if not uids:
            raise NsfError('No records found in the specified folder')
        return sorted(uids)
    raise NsfError(f"Record or folder '{record_arg}' not found")


def share_nsf_record_with_action(
        vault: VaultOnline,
        record_uid: str,
        recipient_email: str,
        *,
        action: str = 'grant',
        role: Optional[str] = None,
        expiration_timestamp: Optional[int] = None,
        request_sync: bool = True) -> Tuple[NsfShareResult, str]:
    """Dispatch grant/update/revoke/owner for a single record share.
    
    Returns (result, action) tuple where:
    - result: NsfShareResult with success status and results
    - action: 'grant', 'update', 'revoke', or 'owner'
    """
    resolved = resolve_nsf_record_uid(vault, record_uid) or record_uid
    if action != 'owner':
        _ensure_record_share_permission(vault, resolved)
    if action == 'owner':
        return transfer_nsf_record_ownership(
            vault, resolved, recipient_email, request_sync=request_sync), 'owner'
    if action == 'revoke':
        return unshare_nsf_record(
            vault, resolved, recipient_email, request_sync=request_sync), 'revoke'
    if not role:
        raise NsfError('Role is required for grant action')
    user_accesses = nsf_common.find_record_user_accesses(vault, resolved, recipient_email)
    already_shared = nsf_common.record_user_has_direct_access(user_accesses)
    if already_shared:
        return update_nsf_record_share(
            vault, resolved, recipient_email, role=role,
            expiration_timestamp=expiration_timestamp, request_sync=request_sync), 'update'
    return share_nsf_record(
        vault, resolved, recipient_email, role=role,
        expiration_timestamp=expiration_timestamp, request_sync=request_sync), 'grant'


def plan_nsf_record_permissions(
        vault: VaultOnline,
        folder_identifier: Optional[str],
        *,
        action: str,
        role: Optional[str],
        recursive: bool,
        current_user: str) -> NsfRecordPermissionPlan:
    """Compute bulk permission changes for nsf-record-permission."""
    folder_uid = None
    if folder_identifier:
        folder_uid = resolve_nsf_folder_uid(vault, folder_identifier) or folder_identifier
        if not is_nsf_folder(vault, folder_uid):
            raise NsfError(f'NSF folder not found: {folder_identifier}')

    record_uids = collect_nsf_records_in_folder(vault, folder_uid, recursive=recursive)
    if not record_uids:
        raise NsfError('No records found in the specified folder')

    accesses_result = get_nsf_record_accesses(vault, list(record_uids))
    role_map = {name: nsf_common.resolve_nsf_role(name) for name in (
        'viewer', 'share-manager', 'content-manager', 'content-share-manager', 'full-manager')}

    plan = NsfRecordPermissionPlan()
    forbidden = set(accesses_result.get('forbidden_records', []))
    owner_flags = {
        a.get('record_uid'): a.get('can_update_access', False)
        for a in accesses_result.get('record_accesses', [])
        if a.get('accessor_name', '') == current_user
    }

    for rec_uid in record_uids:
        if rec_uid in forbidden:
            plan.skipped.append({
                'record_uid': rec_uid, 'email': '', 'cur_role': '',
                'reason': 'No access — record is forbidden',
            })

    for access in accesses_result.get('record_accesses', []):
        rec_uid = access.get('record_uid')
        if not rec_uid or rec_uid not in record_uids or access.get('owner'):
            continue
        email = access.get('accessor_name', '')
        if not email or email == current_user:
            continue
        cur_role = nsf_common.access_role_label(access)
        if not owner_flags.get(rec_uid, False):
            plan.skipped.append({
                'record_uid': rec_uid, 'email': email, 'cur_role': cur_role,
                'reason': 'Insufficient permission (can_update_access is false)',
            })
            continue
        if action == 'grant':
            if role and cur_role != role:
                entry = {
                    'record_uid': rec_uid, 'email': email,
                    'cur_role': cur_role, 'new_role': role,
                    'access_role_type': role_map.get(role),
                }
                if access.get('inherited'):
                    plan.creates.append(entry)
                else:
                    plan.updates.append(entry)
        elif not role or cur_role == role:
            if access.get('inherited'):
                plan.denies.append({
                    'record_uid': rec_uid, 'email': email, 'cur_role': cur_role,
                })
            else:
                plan.revokes.append({'record_uid': rec_uid, 'email': email, 'cur_role': cur_role})
    return plan


def _batch_share(
        vault: VaultOnline,
        items: List[Dict[str, Any]],
        *,
        mode: str) -> List[Tuple[Dict[str, Any], Dict[str, Any]]]:
    outcomes: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
    for i in range(0, len(items), _SHARE_BATCH_SIZE):
        chunk = items[i:i + _SHARE_BATCH_SIZE]
        rq = record_sharing_pb2.Request()
        built: List[Dict[str, Any]] = []
        for item in chunk:
            try:
                if mode == 'revoke':
                    perm = _build_revoke_share_permission(vault, item['record_uid'], item['email'])
                    rq.revokeSharingPermissions.append(perm)
                elif mode == 'deny':
                    perm = _build_share_permission(
                        vault, item['record_uid'], item['email'],
                        None, None, include_role=False, denied_access=True)
                    rq.createSharingPermissions.append(perm)
                else:
                    perm = _build_share_permission(
                        vault, item['record_uid'], item['email'],
                        item['access_role_type'], None,
                        include_role=True)
                    if mode == 'create':
                        rq.createSharingPermissions.append(perm)
                    else:
                        rq.updateSharingPermissions.append(perm)
                built.append(item)
            except Exception as exc:
                outcomes.append((item, {'success': False, 'skipped': True, 'message': str(exc)}))
        if not built:
            continue
        status_attr = {
            'create': 'createdSharingStatus',
            'update': 'updatedSharingStatus',
            'revoke': 'revokedSharingStatus',
            'deny': 'createdSharingStatus',
        }[mode]
        try:
            result = _share_rest(vault, rq, status_attr)
            by_uid = {r['record_uid']: r for r in result.results}
            for item in built:
                outcomes.append((item, by_uid.get(
                    item['record_uid'], {'success': False, 'message': 'No status returned'})))
        except Exception as exc:
            for item in built:
                outcomes.append((item, {'success': False, 'message': str(exc)}))
    return outcomes


def apply_nsf_record_permissions(
        vault: VaultOnline,
        plan: NsfRecordPermissionPlan,
        *,
        request_sync: bool = True) -> Dict[str, List[Tuple[Dict[str, Any], Dict[str, Any]]]]:
    """Apply a permission plan from plan_nsf_record_permissions."""
    results = {
        'updates': _batch_share(vault, plan.updates, mode='update'),
        'creates': _batch_share(vault, plan.creates, mode='create'),
        'revokes': _batch_share(vault, plan.revokes, mode='revoke'),
        'denies': _batch_share(vault, plan.denies, mode='deny'),
    }
    _request_sync(vault, request_sync)
    return results
