"""NSF folder-record linking and shortcut management."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Dict, List, Optional, Set

from .. import utils
from ..errors import KeeperApiError
from ..proto import folder_pb2
from . import nsf_common
from .nsf_management import (
    NsfError,
    _get_folder_key,
    _get_record_key,
    _nsf_view,
    _request_sync,
    is_nsf_folder,
    resolve_nsf_folder_uid,
    resolve_nsf_record_uid,
)
from .vault_online import VaultOnline


@dataclass
class NsfFolderRecordResult:
    folder_uid: str
    record_uid: str
    success: bool
    status: str = ''
    message: str = ''


@dataclass(frozen=True)
class NsfShortcutRow:
    record_uid: str
    title: str
    folder_uids: List[str]


def _record_key_type(vault: VaultOnline, record_uid: str) -> Optional[int]:
    for rk in _nsf_view(vault).storage.record_keys.get_links_by_subject(record_uid):
        if rk.record_key_type:
            return rk.record_key_type
    return None


def _build_record_metadata(
        vault: VaultOnline,
        folder_uid: str,
        record_uid: str,
        *,
        expiration_timestamp: Optional[int] = None) -> folder_pb2.RecordMetadata:
    folder_key = _get_folder_key(vault, folder_uid)
    record_key = _get_record_key(vault, record_uid)
    rkt = _record_key_type(vault, record_uid)
    enc_rk, enc_rkt = nsf_common.encrypt_record_key_for_folder(record_key, folder_key, rkt)
    rm = folder_pb2.RecordMetadata()
    rm.recordUid = utils.base64_url_decode(record_uid)
    rm.encryptedRecordKey = enc_rk
    rm.encryptedRecordKeyType = enc_rkt
    if expiration_timestamp is not None:
        rm.tlaProperties.expiration = expiration_timestamp
    return rm


def _build_removal_metadata(record_uid: str) -> folder_pb2.RecordMetadata:
    rm = folder_pb2.RecordMetadata()
    rm.recordUid = utils.base64_url_decode(record_uid)
    rm.encryptedRecordKey = b''
    rm.encryptedRecordKeyType = folder_pb2.no_key
    return rm


def _folder_record_update(
        vault: VaultOnline,
        folder_uid: str,
        *,
        add_records: Optional[List[folder_pb2.RecordMetadata]] = None,
        update_records: Optional[List[folder_pb2.RecordMetadata]] = None,
        remove_records: Optional[List[folder_pb2.RecordMetadata]] = None) -> folder_pb2.FolderRecordUpdateResponse:
    rq = folder_pb2.FolderRecordUpdateRequest()
    rq.folderUid = utils.base64_url_decode(folder_uid)
    if add_records:
        rq.addRecords.extend(add_records)
    if update_records:
        rq.updateRecords.extend(update_records)
    if remove_records:
        rq.removeRecords.extend(remove_records)
    response = vault.keeper_auth.execute_auth_rest(
        'vault/folders/v3/record_update',
        rq,
        response_type=folder_pb2.FolderRecordUpdateResponse)
    assert response is not None
    return response


def _parse_folder_record_result(
        response: folder_pb2.FolderRecordUpdateResponse,
        folder_uid: str,
        record_uid: str,
        default_message: str) -> NsfFolderRecordResult:
    if response.folderRecordUpdateResult:
        row = response.folderRecordUpdateResult[0]
        status_name = folder_pb2.FolderModifyStatus.Name(row.status)
        return NsfFolderRecordResult(
            folder_uid=folder_uid,
            record_uid=record_uid,
            success=row.status == folder_pb2.SUCCESS,
            status=status_name,
            message=row.message,
        )
    return NsfFolderRecordResult(
        folder_uid=folder_uid,
        record_uid=record_uid,
        success=True,
        status='SUCCESS',
        message=default_message,
    )


def link_nsf_record_to_folder(
        vault: VaultOnline,
        record_identifier: str,
        folder_identifier: str,
        *,
        request_sync: bool = True) -> NsfFolderRecordResult:
    """Link a record into an NSF folder."""
    record_uid = resolve_nsf_record_uid(vault, record_identifier)
    if not record_uid:
        raise NsfError(f'NSF record not found: {record_identifier}')
    folder_uid = resolve_nsf_folder_uid(vault, folder_identifier) or folder_identifier
    if not is_nsf_folder(vault, folder_uid):
        raise NsfError(f'NSF folder not found: {folder_identifier}')

    rm = _build_record_metadata(vault, folder_uid, record_uid)
    response = _folder_record_update(vault, folder_uid, add_records=[rm])
    result = _parse_folder_record_result(
        response, folder_uid, record_uid, 'Record linked to folder successfully')
    if not result.success:
        raise KeeperApiError(result.status, result.message)
    _request_sync(vault, request_sync)
    return result


def unlink_nsf_record_from_folder(
        vault: VaultOnline,
        record_uid: str,
        folder_uid: str,
        *,
        request_sync: bool = True) -> NsfFolderRecordResult:
    """Remove a record link from an NSF folder."""
    resolved_folder = resolve_nsf_folder_uid(vault, folder_uid) or folder_uid
    resolved_record = resolve_nsf_record_uid(vault, record_uid) or record_uid
    rm = _build_removal_metadata(resolved_record)
    response = _folder_record_update(vault, resolved_folder, remove_records=[rm])
    result = _parse_folder_record_result(
        response, resolved_folder, resolved_record, 'Record unlinked from folder')
    if not result.success:
        raise KeeperApiError(result.status, result.message)
    _request_sync(vault, request_sync)
    return result


def get_nsf_shortcut_map(vault: VaultOnline) -> Dict[str, Set[str]]:
    """Return ``{record_uid: {folder_uids}}`` for records in 2+ NSF folders."""
    records: Dict[str, Set[str]] = {}
    for folder in _nsf_view(vault).folders():
        for record_uid in folder.record_uids:
            records.setdefault(record_uid, set()).add(folder.folder_uid)
    return {uid: folders for uid, folders in records.items() if len(folders) > 1}


def list_nsf_shortcuts(
        vault: VaultOnline,
        *,
        target: Optional[str] = None) -> List[NsfShortcutRow]:
    """List NSF records linked to multiple folders."""
    shortcuts = get_nsf_shortcut_map(vault)
    if not shortcuts:
        return []

    if target:
        record_uid = resolve_nsf_record_uid(vault, target)
        if record_uid:
            if record_uid not in shortcuts:
                raise NsfError(f'Record {target} does not have shortcuts')
            uids = {record_uid}
        else:
            folder_uid = resolve_nsf_folder_uid(vault, target)
            if folder_uid:
                uids = {r for r, folders in shortcuts.items() if folder_uid in folders}
            else:
                raise NsfError(f'Target "{target}" is not a known record or folder')
    else:
        uids = set(shortcuts.keys())

    rows: List[NsfShortcutRow] = []
    view = _nsf_view(vault)
    for record_uid in sorted(uids):
        entry = view.get_record(record_uid)
        title = record_uid
        if entry and entry.decrypted_data:
            try:
                payload = json.loads(entry.decrypted_data)
                if isinstance(payload, dict) and payload.get('title'):
                    title = str(payload['title'])
            except json.JSONDecodeError:
                pass
        rows.append(NsfShortcutRow(
            record_uid=record_uid,
            title=title,
            folder_uids=sorted(shortcuts[record_uid]),
        ))
    return rows


def keep_nsf_shortcut_in_folder(
        vault: VaultOnline,
        record_identifier: str,
        keep_folder_identifier: str,
        *,
        request_sync: bool = True) -> List[NsfFolderRecordResult]:
    """Keep a shortcut record in one folder; unlink from all others."""
    record_uid = resolve_nsf_record_uid(vault, record_identifier)
    if not record_uid:
        raise NsfError(f'NSF record not found: {record_identifier}')
    keep_folder = resolve_nsf_folder_uid(vault, keep_folder_identifier) or keep_folder_identifier
    if not is_nsf_folder(vault, keep_folder):
        raise NsfError(f'NSF folder not found: {keep_folder_identifier}')

    shortcuts = get_nsf_shortcut_map(vault)
    if record_uid not in shortcuts:
        raise NsfError(f'Record "{record_identifier}" is not linked to multiple folders')
    if keep_folder not in shortcuts[record_uid]:
        raise NsfError(f'Record is not in folder {keep_folder_identifier}')

    results: List[NsfFolderRecordResult] = []
    for folder_uid in shortcuts[record_uid]:
        if folder_uid == keep_folder:
            continue
        results.append(unlink_nsf_record_from_folder(
            vault, record_uid, folder_uid, request_sync=False))
    _request_sync(vault, request_sync)
    return results
