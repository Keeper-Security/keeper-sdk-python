from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional

from .. import crypto, utils
from ..errors import KeeperApiError
from ..proto import folder_pb2, record_pb2, remove_pb2
from . import nsf_data, vault_extensions
from .vault_online import VaultOnline

ROOT_FOLDER_UID = 'AAAAAAAAAAAAAAAAAPmtNA'
"""Sentinel UID the server uses for the NSF root folder."""


class NsfError(ValueError):
    """Raised when NSF operations cannot proceed (missing cache, bad identifier, etc.)."""


@dataclass(frozen=True)
class NsfListRow:
    item_type: str
    uid: str
    title: str
    record_type: str = ''
    description: str = ''
    parent_or_folder: str = ''


@dataclass
class NsfModifyResult:
    record_uid: str
    success: bool
    status: str = ''
    message: str = ''
    revision: int = 0


@dataclass
class NsfFolderModifyResult:
    folder_uid: str
    success: bool
    status: str = ''
    message: str = ''


@dataclass
class NsfRemovePreviewItem:
    item_uid: str
    folder_uid: str = ''
    status: str = ''
    impact: Optional[Dict[str, Any]] = None
    error: Optional[Dict[str, str]] = None


@dataclass
class NsfRemoveResult:
    preview_results: List[NsfRemovePreviewItem]
    confirmed: bool = False
    confirmation_token_expires_at: Optional[int] = None


_RECORD_REMOVE_OPS = {
    'unlink': remove_pb2.UNLINK_FROM_FOLDER,
    'folder-trash': remove_pb2.MOVE_TO_FOLDER_TRASH,
    'owner-trash': remove_pb2.MOVE_TO_OWNER_TRASH,
}

_FOLDER_REMOVE_OPS = {
    'folder-trash': remove_pb2.FOLDER_MOVE_TO_FOLDER_TRASH,
    'delete-permanent': remove_pb2.FOLDER_DELETE_PERMANENT,
}


def _nsf_view(vault: VaultOnline) -> nsf_data.NSFData:
    view = vault.nsf_data
    if view is None:
        raise NsfError('NSF storage is not available on this vault')
    return view


def _normalize_parent_uid(parent_uid: Optional[str]) -> str:
    if not parent_uid or parent_uid == ROOT_FOLDER_UID:
        return 'root'
    return parent_uid


def is_nsf_folder(vault: VaultOnline, folder_uid: str) -> bool:
    if folder_uid == ROOT_FOLDER_UID:
        return True
    return _nsf_view(vault).get_folder(folder_uid) is not None


def is_nsf_record(vault: VaultOnline, record_uid: str) -> bool:
    return _nsf_view(vault).get_record(record_uid) is not None


def resolve_nsf_folder_uid(vault: VaultOnline, identifier: str) -> Optional[str]:
    """Resolve folder UID or exact name (case-insensitive) from the NSF cache."""
    if not identifier:
        return None
    view = _nsf_view(vault)
    if identifier in {f.folder_uid for f in view.folders()}:
        return identifier
    if identifier.lower() in ('root', 'my drive'):
        return ROOT_FOLDER_UID
    lower = identifier.casefold()
    matches = [f.folder_uid for f in view.folders()
               if (f.name or '').casefold() == lower]
    if len(matches) == 1:
        return matches[0]
    return None


def resolve_nsf_record_uid(vault: VaultOnline, identifier: str) -> Optional[str]:
    """Resolve record UID or title from decrypted NSF cache."""
    if not identifier:
        return None
    view = _nsf_view(vault)
    if view.get_record(identifier) is not None:
        return identifier
    lower = identifier.casefold()
    matches: List[str] = []
    for entry in view.records():
        title = _record_title_from_decrypted(entry)
        if title.casefold() == lower:
            matches.append(entry.record_uid)
    if len(matches) == 1:
        return matches[0]
    return None


def _record_title_from_decrypted(entry: nsf_data.NSFRecordEntry) -> str:
    if not entry.decrypted_data:
        return entry.record_uid
    try:
        payload = json.loads(entry.decrypted_data)
        if isinstance(payload, dict):
            title = payload.get('title')
            if title:
                return str(title)
    except json.JSONDecodeError:
        pass
    return entry.record_uid


def _parse_record_payload(decrypted: Optional[str]) -> Dict[str, Any]:
    if not decrypted:
        return {}
    try:
        payload = json.loads(decrypted)
        return payload if isinstance(payload, dict) else {}
    except json.JSONDecodeError:
        return {}


def find_nsf_folders_for_record(vault: VaultOnline, record_uid: str) -> List[str]:
    folders: List[str] = []
    for folder in _nsf_view(vault).folders():
        if record_uid in folder.record_uids:
            folders.append(folder.folder_uid)
    return folders


def list_nsf_items(
        vault: VaultOnline,
        *,
        include_folders: bool = True,
        include_records: bool = True) -> List[NsfListRow]:
    """List NSF folders and records (``nsf-list``)."""
    if not include_folders and not include_records:
        include_folders = include_records = True

    view = _nsf_view(vault)
    rows: List[NsfListRow] = []

    if include_folders:
        for folder in view.folders():
            rows.append(NsfListRow(
                item_type='Folder',
                uid=folder.folder_uid,
                title=folder.name or '(NSF Folder)',
                parent_or_folder=_normalize_parent_uid(folder.parent_uid),
            ))

    if include_records:
        folder_names = {f.folder_uid: f.name or f.folder_uid for f in view.folders()}
        for entry in view.records():
            payload = _parse_record_payload(entry.decrypted_data)
            title = str(payload.get('title') or entry.record_uid)
            rec_type = str(payload.get('type') or '')
            description = ''
            for fld in payload.get('fields') or []:
                if isinstance(fld, dict) and fld.get('type') in ('note', 'multiline'):
                    values = fld.get('value') or []
                    if isinstance(values, list) and values:
                        description = str(values[0])
                        break
            location = ''
            for fuid in find_nsf_folders_for_record(vault, entry.record_uid):
                location = 'root' if fuid == ROOT_FOLDER_UID else folder_names.get(fuid, fuid)
                break
            rows.append(NsfListRow(
                item_type='Record',
                uid=entry.record_uid,
                title=title,
                record_type=rec_type,
                description=description,
                parent_or_folder=location or 'root',
            ))

    rows.sort(key=lambda r: (r.item_type, r.title.casefold()))
    return rows


def load_nsf_record_metadata(vault: VaultOnline, record_uid: str) -> Dict[str, Any]:
    """Load title, fields, notes from cache; optional API fallback for title/type only."""
    entry = _nsf_view(vault).get_record(record_uid)
    if entry is None:
        raise NsfError(f'NSF record not found: {record_uid}')

    payload = _parse_record_payload(entry.decrypted_data)
    folder_location = ''
    for fuid in find_nsf_folders_for_record(vault, record_uid):
        if fuid == ROOT_FOLDER_UID:
            folder_location = 'root'
        else:
            folder = _nsf_view(vault).get_folder(fuid)
            folder_location = folder.name if folder else fuid
        break

    meta = {
        'title': str(payload.get('title') or record_uid),
        'type': str(payload.get('type') or ''),
        'fields': list(payload.get('fields') or []),
        'notes': str(payload.get('notes') or ''),
        'revision': entry.revision,
        'version': entry.version,
        'folder_location': folder_location,
    }

    if meta['title'] == record_uid:
        details = get_nsf_record_details(vault, [record_uid])
        if details.get('data'):
            d = details['data'][0]
            meta['title'] = d.get('title', record_uid)
            meta['type'] = d.get('type', meta['type'])
            meta['revision'] = d.get('revision', meta['revision'])
            meta['version'] = d.get('version', meta['version'])
    return meta


def get_nsf_folder_detail(
        vault: VaultOnline,
        folder_uid: str,
        *,
        include_access: bool = True) -> Dict[str, Any]:
    """Folder detail payload for ``nsf-get`` (folder branch)."""
    folder = _nsf_view(vault).get_folder(folder_uid)
    if folder is None:
        raise NsfError(f'NSF folder not found: {folder_uid}')

    row = _nsf_view(vault).storage.folders.get_entity(folder_uid)
    result: Dict[str, Any] = {
        'nsf_folder_uid': folder_uid,
        'name': folder.name or folder_uid,
        'parent_uid': _normalize_parent_uid(folder.parent_uid),
        'subfolder_uids': list(folder.subfolder_uids),
        'record_uids': list(folder.record_uids),
    }
    if row is not None:
        result['owner_username'] = row.owner_username
        result['owner_account_uid'] = row.owner_account_uid

    if include_access:
        try:
            result['access'] = get_nsf_folder_access(vault, [folder_uid])
        except Exception:
            result['access'] = {'results': []}
    return result


def get_nsf_record_detail(
        vault: VaultOnline,
        record_uid: str,
        *,
        include_access: bool = True) -> Dict[str, Any]:
    """Record detail payload for ``nsf-get`` (record branch)."""
    meta = load_nsf_record_metadata(vault, record_uid)
    entry = _nsf_view(vault).get_record(record_uid)
    result: Dict[str, Any] = {
        'record_uid': record_uid,
        'title': meta['title'],
        'type': meta['type'],
        'revision': meta['revision'],
        'version': meta['version'],
        'shared': entry.shared if entry else False,
        'file_size': entry.file_size if entry else 0,
        'thumbnail_size': entry.thumbnail_size if entry else 0,
        'fields': meta['fields'],
        'notes': meta['notes'],
    }
    if meta['folder_location']:
        result['folder'] = meta['folder_location']
    if include_access:
        try:
            result['record_accesses'] = get_nsf_record_accesses(vault, [record_uid]).get(
                'record_accesses', [])
        except Exception:
            result['record_accesses'] = []
    return result


def get_nsf_item(
        vault: VaultOnline,
        uid_or_title: str,
        *,
        include_access: bool = True) -> Dict[str, Any]:
    """Resolve and return folder or record detail."""
    folder_uid = resolve_nsf_folder_uid(vault, uid_or_title)
    if folder_uid:
        return {'item_type': 'folder', **get_nsf_folder_detail(
            vault, folder_uid, include_access=include_access)}
    record_uid = resolve_nsf_record_uid(vault, uid_or_title)
    if record_uid:
        return {'item_type': 'record', **get_nsf_record_detail(
            vault, record_uid, include_access=include_access)}
    raise NsfError(f'Cannot find NSF folder or record: {uid_or_title}')


def _get_folder_key(vault: VaultOnline, folder_uid: str) -> bytes:
    folder = _nsf_view(vault).get_folder(folder_uid)
    if folder is None or not folder.folder_key:
        raise NsfError(
            f'Folder key not available for {folder_uid}. Run sync-down and rebuild NSF cache.')
    return folder.folder_key


def _get_record_key(vault: VaultOnline, record_uid: str) -> bytes:
    entry = _nsf_view(vault).get_record(record_uid)
    if entry is None or not entry.record_key:
        raise NsfError(
            f'Record key not available for {record_uid}. Run sync-down and rebuild NSF cache.')
    return entry.record_key


def _build_record_data(
        record_type: str,
        title: str,
        fields: Optional[Mapping[str, Any]] = None,
        notes: Optional[str] = None,
        record_data: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    if record_data is not None:
        return dict(record_data)
    data: Dict[str, Any] = {'type': record_type, 'title': title, 'fields': []}
    if fields:
        for ft, fv in fields.items():
            data['fields'].append({
                'type': ft,
                'value': fv if isinstance(fv, list) else [fv],
            })
    if notes is not None:
        data['notes'] = notes
    return data


def _build_record_add_message(
        record_uid: str,
        record_key: bytes,
        data: Dict[str, Any],
        auth_data_key: bytes,
        folder_uid: Optional[str],
        folder_key: Optional[bytes]) -> record_pb2.RecordAdd:
    ra = record_pb2.RecordAdd()
    ra.record_uid = utils.base64_url_decode(record_uid)
    ra.client_modified_time = utils.current_milli_time()
    json_bytes = vault_extensions.get_padded_json_bytes(data)
    if folder_uid and folder_key:
        ra.folder_uid = utils.base64_url_decode(folder_uid)
        ra.record_key = crypto.encrypt_aes_v2(record_key, folder_key)
    else:
        ra.record_key = crypto.encrypt_aes_v2(record_key, auth_data_key)
    ra.data = crypto.encrypt_aes_v2(json_bytes, record_key)
    return ra


def _parse_modify_response(
        response: record_pb2.RecordsModifyResponse,
        record_uid: str) -> NsfModifyResult:
    if not response.records:
        raise KeeperApiError('no_results', 'No results from record modify response')
    for row in response.records:
        if utils.base64_url_encode(row.record_uid) == record_uid:
            status_name = record_pb2.RecordModifyResult.Name(row.status)
            return NsfModifyResult(
                record_uid=record_uid,
                success=row.status == record_pb2.RS_SUCCESS,
                status=status_name,
                message=row.message,
                revision=getattr(response, 'revision', 0),
            )
    raise KeeperApiError('no_results', f'Record {record_uid} not present in modify response')


def create_nsf_record(
        vault: VaultOnline,
        *,
        title: str,
        record_type: str,
        folder_uid: Optional[str] = None,
        fields: Optional[Mapping[str, Any]] = None,
        notes: Optional[str] = None,
        record_data: Optional[Mapping[str, Any]] = None,
        request_sync: bool = True) -> NsfModifyResult:
    """Create an NSF record."""
    if folder_uid:
        resolved = resolve_nsf_folder_uid(vault, folder_uid) or folder_uid
        if not is_nsf_folder(vault, resolved):
            raise NsfError(f'NSF folder not found: {folder_uid}')
        folder_uid = resolved

    data = _build_record_data(record_type, title, fields, notes, record_data)
    record_uid = utils.generate_uid()
    record_key = os.urandom(32)
    auth = vault.keeper_auth
    folder_key = _get_folder_key(vault, folder_uid) if folder_uid else None

    ra = _build_record_add_message(
        record_uid, record_key, data, auth.auth_context.data_key, folder_uid, folder_key)
    rq = record_pb2.RecordsAddRequest()
    rq.client_time = utils.current_milli_time()
    rq.records.append(ra)

    response = auth.execute_auth_rest(
        'vault/records/v3/add', rq, response_type=record_pb2.RecordsModifyResponse)
    if response is None:
        response = auth.execute_auth_rest(
            'vault/records_add', rq, response_type=record_pb2.RecordsModifyResponse)
    assert response is not None

    result = _parse_modify_response(response, record_uid)
    if not result.success:
        raise KeeperApiError(result.status, result.message)
    if request_sync:
        vault.sync_requested = True
        vault.run_pending_jobs()
    return result


def update_nsf_record(
        vault: VaultOnline,
        record_uid: str,
        *,
        title: Optional[str] = None,
        record_type: Optional[str] = None,
        fields: Optional[Mapping[str, Any]] = None,
        notes: Optional[str] = None,
        record_data: Optional[Mapping[str, Any]] = None,
        request_sync: bool = True) -> NsfModifyResult:
    """Update an NSF record."""
    resolved = resolve_nsf_record_uid(vault, record_uid) or record_uid
    if not is_nsf_record(vault, resolved):
        raise NsfError(f'NSF record not found: {record_uid}')
    record_uid = resolved

    record_key = _get_record_key(vault, record_uid)
    storage_row = _nsf_view(vault).storage.records.get_entity(record_uid)
    revision = storage_row.revision if storage_row else 0

    if record_data is not None:
        data = dict(record_data)
    else:
        entry = _nsf_view(vault).get_record(record_uid)
        data = _parse_record_payload(entry.decrypted_data if entry else None)
        if not data:
            data = {'fields': []}
        if title is not None:
            data['title'] = title
        if record_type is not None:
            data['type'] = record_type
        if fields is not None:
            by_type: Dict[str, List[Any]] = {}
            for existing in data.get('fields') or []:
                if isinstance(existing, dict):
                    by_type.setdefault(existing.get('type', ''), []).append(existing)
            for ft, fv in fields.items():
                val = fv if isinstance(fv, list) else [fv]
                if ft in by_type and by_type[ft]:
                    by_type[ft][0]['value'] = val
                else:
                    data.setdefault('fields', []).append({'type': ft, 'value': val})
        if notes is not None:
            data['notes'] = notes

    ru = record_pb2.RecordUpdate()
    ru.record_uid = utils.base64_url_decode(record_uid)
    ru.client_modified_time = utils.current_milli_time()
    ru.revision = revision
    ru.data = crypto.encrypt_aes_v2(vault_extensions.get_padded_json_bytes(data), record_key)

    rq = record_pb2.RecordsUpdateRequest()
    rq.client_time = utils.current_milli_time()
    rq.records.append(ru)

    auth = vault.keeper_auth
    response = auth.execute_auth_rest(
        'vault/records/v3/update', rq, response_type=record_pb2.RecordsModifyResponse)
    if response is None:
        response = auth.execute_auth_rest(
            'vault/records_update', rq, response_type=record_pb2.RecordsModifyResponse)
    assert response is not None

    result = _parse_modify_response(response, record_uid)
    if not result.success:
        raise KeeperApiError(result.status, result.message)
    if request_sync:
        vault.sync_requested = True
        vault.run_pending_jobs()
    return result


def get_nsf_record_details(
        vault: VaultOnline,
        record_uids: Iterable[str]) -> Dict[str, Any]:
    """``vault/records/v3/details/data`` — title/type when cache lacks decrypted payload."""
    uids = [resolve_nsf_record_uid(vault, u) or u for u in record_uids]
    uids = [u for u in uids if u]
    if not uids:
        raise NsfError('At least one record UID is required')

    payload = {
        'clientTime': utils.current_milli_time(),
        'recordUids': uids,
    }
    rs = vault.keeper_auth.execute_router_json('vault/records/v3/details/data', payload)
    if not isinstance(rs, dict):
        return {'data': [], 'forbidden_records': []}

    out_data: List[Dict[str, Any]] = []
    for item in rs.get('data') or []:
        if not isinstance(item, dict):
            continue
        out_data.append({
            'record_uid': str(item.get('recordUid', '')),
            'title': str(item.get('title', 'Unknown')),
            'type': str(item.get('type', 'Unknown')),
            'revision': int(item.get('revision') or 0),
            'version': int(item.get('version') or 0),
        })
    forbidden = [str(x) for x in (rs.get('forbiddenRecords') or [])]
    return {'data': out_data, 'forbidden_records': forbidden}


def get_nsf_record_accesses(
        vault: VaultOnline,
        record_uids: Iterable[str]) -> Dict[str, Any]:
    """``vault/records/v3/details/access``."""
    uids = [resolve_nsf_record_uid(vault, u) or u for u in record_uids]
    uids = [u for u in uids if u]
    if not uids:
        raise NsfError('At least one record UID is required')

    payload = {'recordUids': uids}
    rs = vault.keeper_auth.execute_router_json('vault/records/v3/details/access', payload)
    if not isinstance(rs, dict):
        return {'record_accesses': [], 'forbidden_records': []}

    accesses: List[Dict[str, Any]] = []
    for item in rs.get('recordAccesses') or []:
        if not isinstance(item, dict):
            continue
        data = item.get('data') or {}
        info = item.get('accessorInfo') or {}
        entry = {
            'record_uid': str(data.get('recordUid', '')),
            'accessor_name': str(info.get('name', '')),
            'access_type_uid': str(data.get('accessTypeUid', '')),
            'access_type': str(data.get('accessType', '')),
            'owner': bool(data.get('owner')),
            'inherited': bool(data.get('inherited')),
        }
        for flag in (
                'can_view_title', 'can_edit', 'can_view', 'can_list_access',
                'can_update_access', 'can_delete', 'can_change_ownership',
                'can_request_access', 'can_approve_access',
        ):
            entry[flag] = bool(data.get(flag))
        accesses.append(entry)

    forbidden = [str(x) for x in (rs.get('forbiddenRecords') or [])]
    return {'record_accesses': accesses, 'forbidden_records': forbidden}


def get_nsf_folder_access(
        vault: VaultOnline,
        folder_uids: Iterable[str]) -> Dict[str, Any]:
    """``vault/folders/v3/access``."""
    uids: List[str] = []
    for raw in folder_uids:
        resolved = resolve_nsf_folder_uid(vault, raw) or raw
        if resolved:
            uids.append(resolved)
    if not uids:
        raise NsfError('At least one folder UID is required')

    payload = {'folderUid': uids}
    rs = vault.keeper_auth.execute_router_json('vault/folders/v3/access', payload)
    if not isinstance(rs, dict):
        return {'results': []}

    results: List[Dict[str, Any]] = []
    for fr in rs.get('folderAccessResults') or []:
        if not isinstance(fr, dict):
            continue
        fuid = str(fr.get('folderUid', ''))
        if fr.get('error'):
            err = fr['error']
            results.append({
                'folder_uid': fuid,
                'success': False,
                'error': {
                    'status': str(err.get('status', '')),
                    'message': str(err.get('message', '')),
                },
            })
            continue
        accessors = []
        for a in fr.get('accessors') or []:
            if not isinstance(a, dict):
                continue
            accessors.append({
                'accessor_uid': str(a.get('accessTypeUid', '')),
                'username': a.get('username'),
                'access_type': str(a.get('accessType', '')),
                'role': str(a.get('accessRoleType', '')),
                'inherited': bool(a.get('inherited')),
                'hidden': bool(a.get('hidden')),
                'permissions': a.get('permissions'),
            })
        results.append({
            'folder_uid': fuid,
            'success': True,
            'accessors': accessors,
        })
    return {'results': results}


def _request_sync(vault: VaultOnline, request_sync: bool) -> None:
    if request_sync:
        vault.sync_requested = True
        vault.run_pending_jobs()


def _api_parent_uid(parent_uid: Optional[str]) -> Optional[str]:
    if not parent_uid or parent_uid == ROOT_FOLDER_UID:
        return None
    return parent_uid


def find_nsf_child_folder(
        vault: VaultOnline,
        folder_name: str,
        parent_uid: Optional[str] = None) -> Optional[str]:
    """Return child folder UID matching name under parent (case-insensitive)."""
    expected_parent = _api_parent_uid(parent_uid) or ''
    name_lower = folder_name.casefold()
    for folder in _nsf_view(vault).folders():
        if (folder.name or '').casefold() != name_lower:
            continue
        existing_parent = folder.parent_uid or ''
        if existing_parent == ROOT_FOLDER_UID:
            existing_parent = ''
        if existing_parent == expected_parent:
            return folder.folder_uid
    return None


def _decrypt_folder_payload(encrypted_data_b64: str, folder_key: bytes) -> Dict[str, Any]:
    if not encrypted_data_b64:
        return {}
    try:
        data_bytes = crypto.decrypt_aes_v2(utils.base64_url_decode(encrypted_data_b64), folder_key)
        payload = json.loads(data_bytes.decode('utf-8'))
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def _encrypt_folder_key(folder_key: bytes, parent_key: bytes) -> bytes:
    return crypto.encrypt_aes_v2(folder_key, parent_key)


def _create_folder_data_message(
        folder_uid: str,
        folder_name: str,
        encryption_key: bytes,
        *,
        parent_uid: Optional[str] = None,
        inherit_permissions: bool = True,
        color: Optional[str] = None,
        owner_username: Optional[str] = None,
        owner_account_uid: Optional[bytes] = None) -> folder_pb2.FolderData:
    fd = folder_pb2.FolderData()
    fd.folderUid = utils.base64_url_decode(folder_uid)
    data_dict: Dict[str, Any] = {'name': folder_name}
    if color and color != 'none':
        data_dict['color'] = color
    fd.data = crypto.encrypt_aes_v2(json.dumps(data_dict).encode('utf-8'), encryption_key)
    api_parent = _api_parent_uid(parent_uid)
    if api_parent:
        fd.parentUid = utils.base64_url_decode(api_parent)
    fd.type = folder_pb2.UT_NORMAL
    fd.inheritUserPermissions = (
        folder_pb2.BOOLEAN_TRUE if inherit_permissions else folder_pb2.BOOLEAN_FALSE)
    if owner_username or owner_account_uid:
        oi = folder_pb2.UserInfo()
        if owner_username:
            oi.username = owner_username
        if owner_account_uid:
            oi.accountUid = owner_account_uid
        fd.ownerInfo.CopyFrom(oi)
    return fd


def _prepare_folder_for_creation(
        vault: VaultOnline,
        folder_uid: str,
        folder_name: str,
        parent_uid: Optional[str],
        color: Optional[str],
        inherit_permissions: bool) -> folder_pb2.FolderData:
    folder_key = os.urandom(32)
    auth = vault.keeper_auth.auth_context
    enc_key = auth.data_key
    api_parent = _api_parent_uid(parent_uid)
    if api_parent:
        try:
            parent_key = _get_folder_key(vault, api_parent)
            enc_key = parent_key
        except NsfError:
            pass
    encrypted_fk = _encrypt_folder_key(folder_key, enc_key)
    username = getattr(vault.keeper_auth, 'login', None) or ''
    fd = _create_folder_data_message(
        folder_uid, folder_name, folder_key,
        parent_uid=parent_uid,
        inherit_permissions=inherit_permissions,
        color=color,
        owner_username=username or None,
        owner_account_uid=auth.account_uid or None,
    )
    fd.folderKey = encrypted_fk
    return fd


def _parse_folder_modify_result(
        response: Any,
        folder_uid: str,
        results_attr: str) -> NsfFolderModifyResult:
    results = getattr(response, results_attr, None) or []
    if not results:
        raise KeeperApiError('no_results', 'No results from folder modify response')
    row = results[0]
    status_name = folder_pb2.FolderModifyStatus.Name(row.status)
    return NsfFolderModifyResult(
        folder_uid=folder_uid,
        success=row.status == folder_pb2.SUCCESS,
        status=status_name,
        message=row.message,
    )


def create_nsf_folder(
        vault: VaultOnline,
        folder_name: str,
        *,
        parent_uid: Optional[str] = None,
        color: Optional[str] = None,
        inherit_permissions: bool = True,
        request_sync: bool = True) -> NsfFolderModifyResult:
    """Create an NSF folder."""
    if parent_uid:
        resolved = resolve_nsf_folder_uid(vault, parent_uid) or parent_uid
        if resolved and resolved != ROOT_FOLDER_UID and not is_nsf_folder(vault, resolved):
            raise NsfError(f'NSF parent folder not found: {parent_uid}')
        parent_uid = resolved

    folder_uid = utils.generate_uid()
    fd = _prepare_folder_for_creation(
        vault, folder_uid, folder_name, parent_uid, color, inherit_permissions)
    rq = folder_pb2.FolderAddRequest()
    rq.folderData.append(fd)
    response = vault.keeper_auth.execute_auth_rest(
        'vault/folders/v3/add', rq, response_type=folder_pb2.FolderAddResponse)
    assert response is not None
    result = _parse_folder_modify_result(response, folder_uid, 'folderAddResults')
    if not result.success:
        raise KeeperApiError(result.status, result.message)
    _request_sync(vault, request_sync)
    return result


def update_nsf_folder(
        vault: VaultOnline,
        folder_identifier: str,
        *,
        folder_name: Optional[str] = None,
        color: Optional[str] = None,
        inherit_permissions: Optional[bool] = None,
        request_sync: bool = True) -> NsfFolderModifyResult:
    """Rename or recolor an NSF folder."""
    if folder_name is None and color is None and inherit_permissions is None:
        raise NsfError('At least one of folder_name, color, or inherit_permissions is required')

    folder_uid = resolve_nsf_folder_uid(vault, folder_identifier) or folder_identifier
    if not is_nsf_folder(vault, folder_uid):
        raise NsfError(f'NSF folder not found: {folder_identifier}')

    folder_key = _get_folder_key(vault, folder_uid)
    row = _nsf_view(vault).storage.folders.get_entity(folder_uid)
    payload = _decrypt_folder_payload(row.data if row else '', folder_key)
    node = _nsf_view(vault).get_folder(folder_uid)

    dd: Dict[str, Any] = {}
    dd['name'] = folder_name if folder_name is not None else (node.name if node else payload.get('name', ''))
    if color is not None:
        if color not in ('none', ''):
            dd['color'] = color
    elif payload.get('color') and payload.get('color') != 'none':
        dd['color'] = payload['color']

    fd = folder_pb2.FolderData()
    fd.folderUid = utils.base64_url_decode(folder_uid)
    fd.data = crypto.encrypt_aes_v2(json.dumps(dd).encode('utf-8'), folder_key)
    if inherit_permissions is not None:
        fd.inheritUserPermissions = (
            folder_pb2.BOOLEAN_TRUE if inherit_permissions else folder_pb2.BOOLEAN_FALSE)

    rq = folder_pb2.FolderUpdateRequest()
    rq.folderData.append(fd)
    response = vault.keeper_auth.execute_auth_rest(
        'vault/folders/v3/update', rq, response_type=folder_pb2.FolderUpdateResponse)
    assert response is not None
    result = _parse_folder_modify_result(response, folder_uid, 'folderUpdateResults')
    if not result.success:
        raise KeeperApiError(result.status, result.message)
    _request_sync(vault, request_sync)
    return result


def _parse_remove_impact(impact_msg: Any) -> Optional[Dict[str, Any]]:
    if impact_msg is None or not impact_msg:
        return None
    return {
        'folders_count': getattr(impact_msg, 'folders_count', 0),
        'records_count': getattr(impact_msg, 'records_count', 0),
        'affected_users_count': getattr(impact_msg, 'affected_users_count', 0),
        'affected_teams_count': getattr(impact_msg, 'affected_teams_count', 0),
        'record_info': [
            {
                'record_uid': utils.base64_url_encode(ri.record_uid),
                'locations_count': ri.locations_count,
            }
            for ri in getattr(impact_msg, 'record_info', [])
        ],
        'warnings': list(getattr(impact_msg, 'warnings', [])),
    }


def _parse_remove_error(error_msg: Any) -> Optional[Dict[str, str]]:
    if error_msg is None or not error_msg:
        return None
    return {
        'code': remove_pb2.RemoveErrorCode.Name(error_msg.code),
        'message': error_msg.message,
    }


def _parse_record_remove_preview(response: remove_pb2.RemoveResponse) -> List[NsfRemovePreviewItem]:
    items: List[NsfRemovePreviewItem] = []
    for res in response.results:
        item_uid = utils.base64_url_encode(res.item_uid) if res.item_uid else ''
        folder_uid = utils.base64_url_encode(res.folder_uid) if res.folder_uid else ''
        items.append(NsfRemovePreviewItem(
            item_uid=item_uid,
            folder_uid=folder_uid,
            status=remove_pb2.RemoveStatus.Name(res.status),
            impact=_parse_remove_impact(res.impact if res.HasField('impact') else None),
            error=_parse_remove_error(res.error if res.HasField('error') else None),
        ))
    return items


def remove_nsf_records(
        vault: VaultOnline,
        removals: List[Dict[str, str]],
        *,
        dry_run: bool = False,
        request_sync: bool = True) -> NsfRemoveResult:
    """Remove NSF records — preview or confirm."""
    if not removals:
        raise NsfError('At least one record removal is required')
    if len(removals) > 500:
        raise NsfError('Maximum 500 records per request')

    preview_rq = remove_pb2.RemoveRecordRequest()
    preview_rq.action = remove_pb2.REMOVE_ACTION_PREVIEW
    for item in removals:
        op = item.get('operation_type', 'owner-trash')
        if op not in _RECORD_REMOVE_OPS:
            raise NsfError(
                f"Invalid operation_type '{op}'. Use: {', '.join(_RECORD_REMOVE_OPS)}")
        record_uid = resolve_nsf_record_uid(vault, item['record_uid']) or item['record_uid']
        rr = remove_pb2.RecordRemoval()
        rr.record_uid = utils.base64_url_decode(record_uid)
        fuid = item.get('folder_uid')
        if fuid:
            resolved_folder = resolve_nsf_folder_uid(vault, fuid) or fuid
            rr.folder_uid = utils.base64_url_decode(resolved_folder)
        rr.operation_type = _RECORD_REMOVE_OPS[op]
        preview_rq.records.append(rr)

    preview_rs = vault.keeper_auth.execute_auth_rest(
        'vault/folders/v3/remove_record',
        preview_rq,
        response_type=remove_pb2.RemoveResponse)
    assert preview_rs is not None

    preview_items = _parse_record_remove_preview(preview_rs)
    token_expires = preview_rs.token_expires_at or None

    if dry_run or not preview_rs.confirmation_token:
        return NsfRemoveResult(
            preview_results=preview_items,
            confirmed=False,
            confirmation_token_expires_at=token_expires,
        )

    confirm_rq = remove_pb2.RemoveRecordRequest()
    confirm_rq.action = remove_pb2.REMOVE_ACTION_CONFIRM
    confirm_rq.confirmation_token = preview_rs.confirmation_token
    confirm_rq.records.extend(preview_rq.records)
    vault.keeper_auth.execute_auth_rest(
        'vault/folders/v3/remove_record',
        confirm_rq,
        response_type=remove_pb2.RemoveResponse)
    _request_sync(vault, request_sync)
    return NsfRemoveResult(
        preview_results=preview_items,
        confirmed=True,
        confirmation_token_expires_at=token_expires,
    )


def remove_nsf_folders(
        vault: VaultOnline,
        removals: List[Dict[str, str]],
        *,
        dry_run: bool = False,
        request_sync: bool = True) -> NsfRemoveResult:
    """Remove NSF folders — preview or confirm."""
    if not removals:
        raise NsfError('At least one folder removal is required')
    if len(removals) > 100:
        raise NsfError('Maximum 100 folders per request')

    preview_rq = remove_pb2.RemoveFolderRequest()
    preview_rq.action = remove_pb2.REMOVE_ACTION_PREVIEW
    for item in removals:
        op = item.get('operation_type', 'folder-trash')
        if op not in _FOLDER_REMOVE_OPS:
            raise NsfError(
                f"Invalid operation_type '{op}'. Use: {', '.join(_FOLDER_REMOVE_OPS)}")
        folder_uid = resolve_nsf_folder_uid(vault, item['folder_uid']) or item['folder_uid']
        fr = remove_pb2.FolderRemoval()
        fr.folder_uid = utils.base64_url_decode(folder_uid)
        fr.operation_type = _FOLDER_REMOVE_OPS[op]
        preview_rq.folders.append(fr)

    preview_rs = vault.keeper_auth.execute_auth_rest(
        'vault/folders/v3/remove_folder',
        preview_rq,
        response_type=remove_pb2.RemoveResponse)
    assert preview_rs is not None

    preview_items: List[NsfRemovePreviewItem] = []
    for res in preview_rs.results:
        preview_items.append(NsfRemovePreviewItem(
            item_uid=utils.base64_url_encode(res.item_uid),
            status=remove_pb2.RemoveStatus.Name(res.status),
            impact=_parse_remove_impact(res.impact if res.HasField('impact') else None),
            error=_parse_remove_error(res.error if res.HasField('error') else None),
        ))

    token_expires = preview_rs.token_expires_at or None
    if dry_run or not preview_rs.confirmation_token:
        return NsfRemoveResult(
            preview_results=preview_items,
            confirmed=False,
            confirmation_token_expires_at=token_expires,
        )

    confirm_rq = remove_pb2.RemoveFolderRequest()
    confirm_rq.action = remove_pb2.REMOVE_ACTION_CONFIRM
    confirm_rq.confirmation_token = preview_rs.confirmation_token
    confirm_rq.folders.extend(preview_rq.folders)
    vault.keeper_auth.execute_auth_rest(
        'vault/folders/v3/remove_folder',
        confirm_rq,
        response_type=remove_pb2.RemoveResponse)
    _request_sync(vault, request_sync)
    return NsfRemoveResult(
        preview_results=preview_items,
        confirmed=True,
        confirmation_token_expires_at=token_expires,
    )


def build_nsf_record_removals(
        vault: VaultOnline,
        record_identifiers: Iterable[str],
        *,
        operation_type: str = 'owner-trash',
        folder_uid: Optional[str] = None) -> List[Dict[str, str]]:
    """Resolve record UIDs and folder context for remove_nsf_records."""
    resolved_folder: Optional[str] = None
    if folder_uid:
        resolved_folder = resolve_nsf_folder_uid(vault, folder_uid) or folder_uid
        if not is_nsf_folder(vault, resolved_folder):
            raise NsfError(f'NSF folder not found: {folder_uid}')

    removals: List[Dict[str, str]] = []
    for identifier in record_identifiers:
        record_uid = resolve_nsf_record_uid(vault, identifier)
        if not record_uid:
            raise NsfError(f"NSF record not found: {identifier}")
        ctx_folder = resolved_folder
        if not ctx_folder:
            folders = find_nsf_folders_for_record(vault, record_uid)
            if not folders and operation_type != 'owner-trash':
                raise NsfError(
                    f"No folder context for record '{identifier}'. "
                    f"Use folder_uid or operation owner-trash.")
            ctx_folder = folders[0] if folders else None
        entry: Dict[str, str] = {
            'record_uid': record_uid,
            'operation_type': operation_type,
        }
        if ctx_folder:
            entry['folder_uid'] = ctx_folder
        removals.append(entry)
    return removals
