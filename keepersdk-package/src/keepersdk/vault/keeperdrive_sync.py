from __future__ import annotations

import dataclasses
import json
from typing import Any, Dict, List, Mapping, Optional, TYPE_CHECKING, Tuple, Union

from .. import utils
from . import keeperdrive_storage_types as kd
from .keeperdrive_vault_storage import IKeeperDriveStorage
from ..proto import SyncDown_pb2, folder_pb2, breachwatch_pb2, record_pb2

if TYPE_CHECKING:
    from .keeperdrive_data import KeeperDriveRebuildTask

CHUNK_RECORD_ROTATION = 'recordRotationData'
CHUNK_RAW_DAG = 'rawDagData'

_PROTO_ENUM_TYPES = (
    folder_pb2.FolderUsageType,
    folder_pb2.FolderKeyEncryptionType,
    folder_pb2.SetBooleanValue,
    folder_pb2.EncryptedKeyType,
    folder_pb2.AccessType,
    folder_pb2.AccessRoleType,
    breachwatch_pb2.BreachWatchInfoType,
    record_pb2.RecordKeyType,
)


def _coerce_int(value: Any, default: int = 0) -> int:
    if value is None or value == '':
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.lstrip('-').isdigit():
            return int(stripped)
        for enum_type in _PROTO_ENUM_TYPES:
            try:
                return int(enum_type.Value(stripped))
            except (ValueError, AttributeError):
                pass
            if stripped in enum_type.keys():
                return int(enum_type.Value(stripped))
        return default
    return default


def _wire_b64(data: bytes) -> str:
    return utils.base64_url_encode(data) if data else ''


def _uid_b64(uid: bytes) -> str:
    return utils.base64_url_encode(uid) if uid else ''


def _proto_submessage_set(msg: Any) -> bool:
    return bool(msg and list(msg.ListFields()))


def _j(value: Any) -> str:
    if value is None:
        return ''
    if isinstance(value, str):
        return value
    if hasattr(value, 'DESCRIPTOR'):
        try:
            from google.protobuf.json_format import MessageToDict
            return json.dumps(
                MessageToDict(value, preserving_proto_field_name=False, use_integers_for_enums=True),
                separators=(',', ':'))
        except (TypeError, ValueError):
            return ''
    return json.dumps(value, separators=(',', ':'))


def _folder_uid(item: Union[str, Mapping[str, Any]]) -> str:
    if isinstance(item, str):
        return item
    return str(item.get('folderUid') or item.get('folder_uid') or '')


def _access_uid(x: Mapping[str, Any], *, proto_actor: bool = False) -> str:
    if proto_actor:
        return str(x.get('actorUid') or x.get('accessTypeUid') or '')
    return str(x.get('actorUid') or x.get('accessTypeUid') or '')


def extract_keeper_drive_data(sync_payload: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    raw = sync_payload.get('keeperDriveData')
    if isinstance(raw, dict):
        return raw
    return None


def try_apply_keeper_drive_from_sync_down_proto(
        response: SyncDown_pb2.SyncDownResponse,
        drive_storage: IKeeperDriveStorage,
        task: Optional['KeeperDriveRebuildTask'] = None) -> bool:
    if not response.HasField('keeperDriveData'):
        return False
    kd_msg = response.keeperDriveData
    if not list(kd_msg.ListFields()):
        return False
    apply_keeper_drive_proto_message(kd_msg, drive_storage, task)
    return True


def try_apply_keeper_drive_from_sync_down_json(
        auth: Any,
        drive_storage: IKeeperDriveStorage,
        continuation_token: bytes,
        task: Optional['KeeperDriveRebuildTask'] = None) -> bool:
    logger = utils.get_logger()
    try:
        rq: Dict[str, Any] = {'continuationToken': utils.base64_url_encode(continuation_token)}
        rs = auth.execute_router_json('vault/sync_down', rq)
    except Exception as e:
        logger.debug('Keeper Drive JSON sync_down skipped: %s', e)
        return False
    if not isinstance(rs, dict):
        return False
    inner = extract_keeper_drive_data(rs)
    if inner is None:
        return False
    apply_keeper_drive_data_dict(drive_storage, inner, task)
    return True


def apply_keeper_drive_from_full_sync_json(
        drive_storage: IKeeperDriveStorage,
        sync_payload: Mapping[str, Any],
        task: Optional['KeeperDriveRebuildTask'] = None) -> None:
    inner = extract_keeper_drive_data(sync_payload)
    if inner is not None:
        apply_keeper_drive_data_dict(drive_storage, inner, task)


def apply_keeper_drive_proto_message(
        kd_msg: SyncDown_pb2.KeeperDriveData,
        drive_storage: IKeeperDriveStorage,
        task: Optional['KeeperDriveRebuildTask'] = None) -> None:
    _process_removed_folders_proto(kd_msg, drive_storage, task)
    _process_removed_folder_records_proto(kd_msg, drive_storage, task)
    _process_removed_record_links_proto(kd_msg, drive_storage, task)
    _store_folders_proto(kd_msg, drive_storage, task)
    _store_folder_keys_proto(kd_msg, drive_storage)
    _store_record_data_proto(kd_msg, drive_storage, task)
    _store_folder_records_proto(kd_msg, drive_storage, task)
    _store_records_proto(kd_msg, drive_storage, task)
    _process_revoked_folder_accesses_proto(kd_msg, drive_storage, task)
    _store_folder_accesses_proto(kd_msg, drive_storage)
    _process_revoked_record_accesses_proto(kd_msg, drive_storage, task)
    _store_record_accesses_proto(kd_msg, drive_storage, task)
    _store_record_links_proto(kd_msg, drive_storage, task)
    _store_folder_sharing_states_proto(kd_msg, drive_storage)
    _store_record_sharing_states_proto(kd_msg, drive_storage)
    _store_optional_extras_proto(kd_msg, drive_storage, task)


def apply_keeper_drive_data_dict(
        drive_storage: IKeeperDriveStorage,
        keeper_drive_data: Mapping[str, Any],
        task: Optional['KeeperDriveRebuildTask'] = None) -> None:
    _process_removed_folders_dict(keeper_drive_data, drive_storage, task)
    _process_removed_folder_records_dict(keeper_drive_data, drive_storage, task)
    _process_removed_record_links_dict(keeper_drive_data, drive_storage, task)
    _store_folders_dict(keeper_drive_data, drive_storage, task)
    _store_folder_keys_dict(keeper_drive_data, drive_storage)
    _store_record_data_dict(keeper_drive_data, drive_storage, task)
    _store_folder_records_dict(keeper_drive_data, drive_storage, task)
    _store_records_dict(keeper_drive_data, drive_storage, task)
    _process_revoked_folder_accesses_dict(keeper_drive_data, drive_storage, task)
    _store_folder_accesses_dict(keeper_drive_data, drive_storage)
    _process_revoked_record_accesses_dict(keeper_drive_data, drive_storage, task)
    _store_record_accesses_dict(keeper_drive_data, drive_storage, task)
    _store_record_links_dict(keeper_drive_data, drive_storage, task)
    _store_folder_sharing_states_dict(keeper_drive_data, drive_storage)
    _store_record_sharing_states_dict(keeper_drive_data, drive_storage)
    _store_optional_extras_dict(keeper_drive_data, drive_storage, task)


def _process_removed_folders_proto(
        kd_msg: SyncDown_pb2.KeeperDriveData,
        storage: IKeeperDriveStorage,
        task: Optional['KeeperDriveRebuildTask']) -> None:
    removed = [_uid_b64(x.folder_uid) for x in kd_msg.removedFolders if x.folder_uid]
    if not removed:
        return
    storage.folder_keys.delete_links_by_subjects(removed)
    storage.folder_records.delete_links_by_subjects(removed)
    storage.folders.delete_uids(removed)
    if task:
        task.add_folders(removed)


def _process_removed_folder_records_proto(
        kd_msg: SyncDown_pb2.KeeperDriveData,
        storage: IKeeperDriveStorage,
        task: Optional['KeeperDriveRebuildTask']) -> None:
    links: List[Tuple[str, str]] = []
    key_links: List[Tuple[str, str]] = []
    for x in kd_msg.removedFolderRecords:
        fu, ru = _uid_b64(x.folderUid), _uid_b64(x.recordUid)
        if fu and ru:
            links.append((fu, ru))
            key_links.append((ru, fu))
    if links:
        storage.folder_records.delete_links(links)
    if key_links:
        storage.record_keys.delete_links(key_links)
    if task and links:
        task.add_records((ru for _, ru in links))


def _process_removed_record_links_proto(
        kd_msg: SyncDown_pb2.KeeperDriveData,
        storage: IKeeperDriveStorage,
        task: Optional['KeeperDriveRebuildTask']) -> None:
    for x in kd_msg.removedRecordLinks:
        parent_uid, child_uid = _uid_b64(x.parentRecordUid), _uid_b64(x.childRecordUid)
        storage.record_links.delete_links([(parent_uid, child_uid)])
        if task and child_uid:
            task.add_record(child_uid)


def _process_revoked_folder_accesses_proto(
        kd_msg: SyncDown_pb2.KeeperDriveData,
        storage: IKeeperDriveStorage,
        task: Optional['KeeperDriveRebuildTask']) -> None:
    links = [(_uid_b64(x.folderUid), _uid_b64(x.actorUid)) for x in kd_msg.revokedFolderAccesses]
    if links:
        storage.folder_accesses.delete_links(links)
        if task:
            task.add_folders((fu for fu, _ in links if fu))


def _process_revoked_record_accesses_proto(
        kd_msg: SyncDown_pb2.KeeperDriveData,
        storage: IKeeperDriveStorage,
        task: Optional['KeeperDriveRebuildTask']) -> None:
    links = [(_uid_b64(x.recordUid), _uid_b64(x.actorUid)) for x in kd_msg.revokedRecordAccesses]
    if links:
        storage.record_accesses.delete_links(links)
        if task:
            task.add_records((ru for ru, _ in links if ru))


def _store_folders_proto(
        kd_msg: SyncDown_pb2.KeeperDriveData,
        storage: IKeeperDriveStorage,
        task: Optional['KeeperDriveRebuildTask']) -> None:
    folders = [_proto_folder(x) for x in kd_msg.folders]
    if folders:
        storage.folders.put_entities(folders)
        if task:
            task.add_folders((f.folder_uid for f in folders))


def _store_folder_keys_proto(kd_msg: SyncDown_pb2.KeeperDriveData, storage: IKeeperDriveStorage) -> None:
    keys = [_proto_folder_key(x) for x in kd_msg.folderKeys]
    if keys:
        storage.folder_keys.put_links(keys)


def _store_record_data_proto(
        kd_msg: SyncDown_pb2.KeeperDriveData,
        storage: IKeeperDriveStorage,
        task: Optional['KeeperDriveRebuildTask']) -> None:
    updated: List[kd.KDRecord] = []
    for rd in kd_msg.recordData:
        record_uid = _uid_b64(rd.recordUid)
        existing = storage.records.get_entity(record_uid)
        if existing is None:
            continue
        row = dataclasses.replace(existing, data=_wire_b64(rd.data))
        updated.append(row)
        if task:
            task.add_record(record_uid)
    if updated:
        storage.records.put_entities(updated)


def _store_folder_records_proto(
        kd_msg: SyncDown_pb2.KeeperDriveData,
        storage: IKeeperDriveStorage,
        task: Optional['KeeperDriveRebuildTask']) -> None:
    folder_records: List[kd.KDFolderRecord] = []
    record_keys: List[kd.KDRecordKey] = []
    for fr in kd_msg.folderRecords:
        folder_uid = _uid_b64(fr.folderUid)
        md = fr.recordMetadata
        if md is None or not list(md.ListFields()):
            continue
        record_uid = _uid_b64(md.recordUid)
        folder_records.append(kd.KDFolderRecord(folder_uid=folder_uid, record_uid=record_uid))
        if md.encryptedRecordKey:
            record_keys.append(kd.KDRecordKey(
                record_uid=record_uid,
                folder_uid=folder_uid,
                record_key=_wire_b64(md.encryptedRecordKey),
                record_key_type=int(md.encryptedRecordKeyType),
                folder_key_encryption_type=int(fr.folderKeyEncryptionType),
            ))
    if folder_records:
        storage.folder_records.put_links(folder_records)
        if task:
            task.add_records((r.record_uid for r in folder_records))
    if record_keys:
        storage.record_keys.put_links(record_keys)


def _store_records_proto(
        kd_msg: SyncDown_pb2.KeeperDriveData,
        storage: IKeeperDriveStorage,
        task: Optional['KeeperDriveRebuildTask']) -> None:
    rows: List[kd.KDRecord] = []
    for dr in kd_msg.records:
        record_uid = _uid_b64(dr.recordUid)
        existing = storage.records.get_entity(record_uid)
        rows.append(kd.KDRecord(
            record_uid=record_uid,
            revision=dr.revision,
            version=dr.version,
            shared=dr.shared,
            client_modified_time=dr.clientModifiedTime,
            file_size=dr.fileSize,
            thumbnail_size=dr.thumbnailSize,
            data=existing.data if existing else '',
        ))
    if rows:
        storage.records.put_entities(rows)
        if task:
            task.add_records((r.record_uid for r in rows))


def _store_folder_accesses_proto(kd_msg: SyncDown_pb2.KeeperDriveData, storage: IKeeperDriveStorage) -> None:
    rows = [_proto_folder_access(x) for x in kd_msg.folderAccesses]
    if rows:
        storage.folder_accesses.put_links(rows)


def _store_record_accesses_proto(
        kd_msg: SyncDown_pb2.KeeperDriveData,
        storage: IKeeperDriveStorage,
        task: Optional['KeeperDriveRebuildTask']) -> None:
    rows = [_proto_record_access(x) for x in kd_msg.recordAccesses]
    if rows:
        storage.record_accesses.put_links(rows)
        if task:
            task.add_records((r.record_uid for r in rows))


def _store_record_links_proto(
        kd_msg: SyncDown_pb2.KeeperDriveData,
        storage: IKeeperDriveStorage,
        task: Optional['KeeperDriveRebuildTask']) -> None:
    rows = [_proto_record_link(x) for x in kd_msg.recordLinks]
    if rows:
        storage.record_links.put_links(rows)
        if task:
            task.add_records((r.child_record_uid for r in rows))


def _store_folder_sharing_states_proto(kd_msg: SyncDown_pb2.KeeperDriveData, storage: IKeeperDriveStorage) -> None:
    rows = [kd.KDFolderSharingState(
        folder_uid=_uid_b64(x.folderUid),
        shared=x.shared,
        count=x.count,
    ) for x in kd_msg.folderSharingState]
    if rows:
        storage.folder_sharing_states.put_entities(rows)


def _store_record_sharing_states_proto(kd_msg: SyncDown_pb2.KeeperDriveData, storage: IKeeperDriveStorage) -> None:
    rows = [kd.KDRecordSharingState(
        record_uid=_uid_b64(x.recordUid),
        is_directly_shared=x.isDirectlyShared,
        is_indirectly_shared=x.isIndirectlyShared,
        is_shared=x.isShared,
    ) for x in kd_msg.recordSharingStates]
    if rows:
        storage.record_sharing_states.put_entities(rows)


def _store_optional_extras_proto(
        kd_msg: SyncDown_pb2.KeeperDriveData,
        storage: IKeeperDriveStorage,
        task: Optional['KeeperDriveRebuildTask']) -> None:
    nsd = [_proto_non_shared(x) for x in kd_msg.nonSharedData]
    if nsd:
        storage.non_shared_data.put_entities(nsd)
        if task:
            task.add_records((r.record_uid for r in nsd))
    bw = [_proto_bw_record(x) for x in kd_msg.breachWatchRecords]
    if bw:
        storage.breach_watch_records.put_entities(bw)
        if task:
            task.add_records((r.record_uid for r in bw))
    ss = [_proto_security_score(x) for x in kd_msg.securityScoreData]
    if ss:
        storage.security_score_data.put_entities(ss)
        if task:
            task.add_records((r.record_uid for r in ss))
    bws = [_proto_bw_security(x) for x in kd_msg.breachWatchSecurityData]
    if bws:
        storage.breach_watch_security_data.put_entities(bws)
        if task:
            task.add_records((r.record_uid for r in bws))
    chunk_payload: Dict[str, Any] = {
        CHUNK_RECORD_ROTATION: list(kd_msg.recordRotationData),
        CHUNK_RAW_DAG: list(kd_msg.rawDagData),
    }
    _replace_json_lists(storage, chunk_payload)


def _process_removed_folders_dict(
        d: Mapping[str, Any],
        storage: IKeeperDriveStorage,
        task: Optional['KeeperDriveRebuildTask']) -> None:
    removed = [_folder_uid(y) for y in (d.get('removedFolders') or []) if _folder_uid(y)]
    if not removed:
        return
    storage.folder_keys.delete_links_by_subjects(removed)
    storage.folder_records.delete_links_by_subjects(removed)
    storage.folders.delete_uids(removed)
    if task:
        task.add_folders(removed)


def _process_removed_folder_records_dict(
        d: Mapping[str, Any],
        storage: IKeeperDriveStorage,
        task: Optional['KeeperDriveRebuildTask']) -> None:
    links: List[Tuple[str, str]] = []
    key_links: List[Tuple[str, str]] = []
    for x in d.get('removedFolderRecords') or []:
        if not isinstance(x, dict):
            continue
        fu = str(x.get('folderUid', ''))
        ru = str(x.get('recordUid', ''))
        if fu and ru:
            links.append((fu, ru))
            key_links.append((ru, fu))
    if links:
        storage.folder_records.delete_links(links)
    if key_links:
        storage.record_keys.delete_links(key_links)
    if task and links:
        task.add_records((ru for _, ru in links))


def _process_removed_record_links_dict(
        d: Mapping[str, Any],
        storage: IKeeperDriveStorage,
        task: Optional['KeeperDriveRebuildTask']) -> None:
    for x in d.get('removedRecordLinks') or []:
        if not isinstance(x, dict):
            continue
        child_uid = str(x.get('childRecordUid', ''))
        storage.record_links.delete_links([(
            str(x.get('parentRecordUid', '')),
            child_uid,
        )])
        if task and child_uid:
            task.add_record(child_uid)


def _process_revoked_folder_accesses_dict(
        d: Mapping[str, Any],
        storage: IKeeperDriveStorage,
        task: Optional['KeeperDriveRebuildTask']) -> None:
    links: List[Tuple[str, str]] = []
    for x in d.get('revokedFolderAccesses') or []:
        if not isinstance(x, dict):
            continue
        fu = str(x.get('folderUid', ''))
        au = _access_uid(x)
        if fu and au:
            links.append((fu, au))
    if links:
        storage.folder_accesses.delete_links(links)
        if task:
            task.add_folders((fu for fu, _ in links))


def _process_revoked_record_accesses_dict(
        d: Mapping[str, Any],
        storage: IKeeperDriveStorage,
        task: Optional['KeeperDriveRebuildTask']) -> None:
    links: List[Tuple[str, str]] = []
    for x in d.get('revokedRecordAccesses') or []:
        if not isinstance(x, dict):
            continue
        ru = str(x.get('recordUid', ''))
        au = _access_uid(x)
        if ru and au:
            links.append((ru, au))
    if links:
        storage.record_accesses.delete_links(links)
        if task:
            task.add_records((ru for ru, _ in links))


def _store_folders_dict(
        d: Mapping[str, Any],
        storage: IKeeperDriveStorage,
        task: Optional['KeeperDriveRebuildTask']) -> None:
    folders = [_dict_to_folder(x) for x in d.get('folders') or [] if isinstance(x, dict)]
    if folders:
        storage.folders.put_entities(folders)
        if task:
            task.add_folders((f.folder_uid for f in folders))


def _store_folder_keys_dict(d: Mapping[str, Any], storage: IKeeperDriveStorage) -> None:
    keys = [_dict_to_folder_key(x) for x in d.get('folderKeys') or [] if isinstance(x, dict)]
    if keys:
        storage.folder_keys.put_links(keys)


def _store_record_data_dict(
        d: Mapping[str, Any],
        storage: IKeeperDriveStorage,
        task: Optional['KeeperDriveRebuildTask']) -> None:
    updated: List[kd.KDRecord] = []
    for x in d.get('recordData') or []:
        if not isinstance(x, dict):
            continue
        record_uid = str(x.get('recordUid', ''))
        existing = storage.records.get_entity(record_uid)
        if existing is None:
            continue
        updated.append(dataclasses.replace(existing, data=str(x.get('data', ''))))
        if task:
            task.add_record(record_uid)
    if updated:
        storage.records.put_entities(updated)


def _store_folder_records_dict(
        d: Mapping[str, Any],
        storage: IKeeperDriveStorage,
        task: Optional['KeeperDriveRebuildTask']) -> None:
    folder_records: List[kd.KDFolderRecord] = []
    record_keys: List[kd.KDRecordKey] = []
    for x in d.get('folderRecords') or []:
        if not isinstance(x, dict):
            continue
        folder_uid = str(x.get('folderUid', ''))
        md = x.get('recordMetadata') or {}
        record_uid = str(md.get('recordUid', ''))
        if not folder_uid or not record_uid:
            continue
        folder_records.append(kd.KDFolderRecord(folder_uid=folder_uid, record_uid=record_uid))
        enc_key = str(md.get('encryptedRecordKey', ''))
        if enc_key:
            record_keys.append(kd.KDRecordKey(
                record_uid=record_uid,
                folder_uid=folder_uid,
                record_key=enc_key,
                record_key_type=_coerce_int(md.get('encryptedRecordKeyType'), 0),
                folder_key_encryption_type=_coerce_int(x.get('folderKeyEncryptionType'), 0),
            ))
    if folder_records:
        storage.folder_records.put_links(folder_records)
        if task:
            task.add_records((r.record_uid for r in folder_records))
    if record_keys:
        storage.record_keys.put_links(record_keys)


def _store_records_dict(
        d: Mapping[str, Any],
        storage: IKeeperDriveStorage,
        task: Optional['KeeperDriveRebuildTask']) -> None:
    rows: List[kd.KDRecord] = []
    for x in d.get('records') or []:
        if not isinstance(x, dict):
            continue
        record_uid = str(x.get('recordUid', ''))
        existing = storage.records.get_entity(record_uid)
        rows.append(kd.KDRecord(
            record_uid=record_uid,
            revision=_coerce_int(x.get('revision'), 0),
            version=_coerce_int(x.get('version'), 0),
            shared=bool(x.get('shared')),
            client_modified_time=_coerce_int(x.get('clientModifiedTime'), 0),
            file_size=_coerce_int(x.get('fileSize'), 0),
            thumbnail_size=_coerce_int(x.get('thumbnailSize'), 0),
            data=existing.data if existing else '',
        ))
    if rows:
        storage.records.put_entities(rows)
        if task:
            task.add_records((r.record_uid for r in rows))


def _store_folder_accesses_dict(d: Mapping[str, Any], storage: IKeeperDriveStorage) -> None:
    rows = [_dict_to_folder_access(x) for x in d.get('folderAccesses') or [] if isinstance(x, dict)]
    if rows:
        storage.folder_accesses.put_links(rows)


def _store_record_accesses_dict(d: Mapping[str, Any], storage: IKeeperDriveStorage) -> None:
    rows = [_dict_to_record_access(x) for x in d.get('recordAccesses') or [] if isinstance(x, dict)]
    if rows:
        storage.record_accesses.put_links(rows)


def _store_record_links_dict(
        d: Mapping[str, Any],
        storage: IKeeperDriveStorage,
        task: Optional['KeeperDriveRebuildTask']) -> None:
    rows = [_dict_to_record_link(x) for x in d.get('recordLinks') or [] if isinstance(x, dict)]
    if rows:
        storage.record_links.put_links(rows)
        if task:
            task.add_records((r.child_record_uid for r in rows))


def _store_folder_sharing_states_dict(d: Mapping[str, Any], storage: IKeeperDriveStorage) -> None:
    rows: List[kd.KDFolderSharingState] = []
    for x in d.get('folderSharingState') or []:
        if not isinstance(x, dict):
            continue
        rows.append(kd.KDFolderSharingState(
            folder_uid=str(x.get('folderUid', '')),
            shared=bool(x.get('shared')),
            count=_coerce_int(x.get('count'), 0),
        ))
    if rows:
        storage.folder_sharing_states.put_entities(rows)


def _store_record_sharing_states_dict(d: Mapping[str, Any], storage: IKeeperDriveStorage) -> None:
    rows: List[kd.KDRecordSharingState] = []
    for x in d.get('recordSharingStates') or []:
        if not isinstance(x, dict):
            continue
        rows.append(kd.KDRecordSharingState(
            record_uid=str(x.get('recordUid', '')),
            is_directly_shared=bool(x.get('isDirectlyShared')),
            is_indirectly_shared=bool(x.get('isIndirectlyShared')),
            is_shared=bool(x.get('isShared')),
        ))
    if rows:
        storage.record_sharing_states.put_entities(rows)


def _store_optional_extras_dict(
        d: Mapping[str, Any],
        storage: IKeeperDriveStorage,
        task: Optional['KeeperDriveRebuildTask']) -> None:
    nsd = [_dict_to_non_shared(x) for x in d.get('nonSharedData') or [] if isinstance(x, dict)]
    if nsd:
        storage.non_shared_data.put_entities(nsd)
        if task:
            task.add_records((r.record_uid for r in nsd))
    bw = [_dict_to_bw_record(x) for x in d.get('breachWatchRecords') or [] if isinstance(x, dict)]
    if bw:
        storage.breach_watch_records.put_entities(bw)
        if task:
            task.add_records((r.record_uid for r in bw))
    ss = [_dict_to_security_score(x) for x in d.get('securityScoreData') or [] if isinstance(x, dict)]
    if ss:
        storage.security_score_data.put_entities(ss)
        if task:
            task.add_records((r.record_uid for r in ss))
    bws = [_dict_to_bw_security(x) for x in d.get('breachWatchSecurityData') or [] if isinstance(x, dict)]
    if bws:
        storage.breach_watch_security_data.put_entities(bws)
        if task:
            task.add_records((r.record_uid for r in bws))
    chunk_payload: Dict[str, Any] = {
        CHUNK_RECORD_ROTATION: d.get('recordRotationData'),
        CHUNK_RAW_DAG: d.get('rawDagData'),
    }
    _replace_json_lists(storage, chunk_payload)


def _replace_json_lists(storage: IKeeperDriveStorage, d: Mapping[str, Any]) -> None:
    _replace_chunk_group(storage, CHUNK_RECORD_ROTATION, d.get(CHUNK_RECORD_ROTATION))
    _replace_chunk_group(storage, CHUNK_RAW_DAG, d.get(CHUNK_RAW_DAG))


def _replace_chunk_group(storage: IKeeperDriveStorage, group: str, items: Any) -> None:
    storage.list_chunks.delete_links_by_subjects([group])
    if not isinstance(items, list) or not items:
        return
    links: List[kd.KDListChunk] = []
    for i, it in enumerate(items):
        links.append(kd.KDListChunk(chunk_group=group, chunk_key=f'{i:010d}', payload_json=_j(it)))
    storage.list_chunks.put_links(links)


def _proto_folder(fd: folder_pb2.FolderData) -> kd.KDFolder:
    oi = fd.ownerInfo
    return kd.KDFolder(
        folder_uid=_uid_b64(fd.folderUid),
        parent_uid=_uid_b64(fd.parentUid),
        data=_wire_b64(fd.data),
        folder_type=int(fd.type),
        inherit_user_permissions=int(fd.inheritUserPermissions),
        folder_key=_wire_b64(fd.folderKey),
        owner_account_uid=_uid_b64(oi.accountUid) if _proto_submessage_set(oi) else '',
        owner_username=oi.username if _proto_submessage_set(oi) else '',
        date_created=fd.dateCreated,
        last_modified=fd.lastModified,
    )


def _proto_folder_key(fk: folder_pb2.FolderKey) -> kd.KDFolderKey:
    return kd.KDFolderKey(
        folder_uid=_uid_b64(fk.folderUid),
        parent_uid=_uid_b64(fk.parentUid),
        folder_key=_wire_b64(fk.folderKey),
        encrypted_by=int(fk.encryptedBy),
    )


def _proto_folder_access(fa: folder_pb2.FolderAccessData) -> kd.KDFolderAccess:
    enc, kt = '', 0
    fk = fa.folderKey
    if _proto_submessage_set(fk):
        enc = _wire_b64(fk.encryptedKey)
        kt = int(fk.encryptedKeyType)
    return kd.KDFolderAccess(
        folder_uid=_uid_b64(fa.folderUid),
        access_type_uid=_uid_b64(fa.accessTypeUid),
        access_type=int(fa.accessType),
        access_role_type=int(fa.accessRoleType),
        folder_key_encrypted=enc,
        folder_key_type=kt,
        inherited=fa.inherited,
        hidden=fa.hidden,
        denied_access=fa.deniedAccess,
        permissions_json=_j(fa.permissions) if _proto_submessage_set(fa.permissions) else '',
        tla_properties_json='',
        date_created=fa.dateCreated,
        last_modified=fa.lastModified,
    )


def _proto_non_shared(nsd: SyncDown_pb2.NonSharedData) -> kd.KDNonSharedData:
    return kd.KDNonSharedData(
        record_uid=_uid_b64(nsd.recordUid),
        data=_wire_b64(nsd.data),
    )


def _proto_record_access(ra: folder_pb2.RecordAccessData) -> kd.KDRecordAccess:
    return kd.KDRecordAccess(
        record_uid=_uid_b64(ra.recordUid),
        access_type_uid=_uid_b64(ra.accessTypeUid),
        access_type=int(ra.accessType),
        access_role_type=int(ra.accessRoleType),
        owner=ra.owner,
        inherited=ra.inherited,
        hidden=ra.hidden,
        denied_access=ra.deniedAccess,
        can_view_title=ra.can_view_title,
        can_edit=ra.can_edit,
        can_view=ra.can_view,
        can_list_access=ra.can_list_access,
        can_update_access=ra.can_update_access,
        can_delete=ra.can_delete,
        can_change_ownership=ra.can_change_ownership,
        can_request_access=ra.can_request_access,
        can_approve_access=ra.can_approve_access,
        date_created=ra.dateCreated,
        last_modified=ra.lastModified,
        tla_properties_json='',
    )


def _proto_record_link(rl: SyncDown_pb2.RecordLink) -> kd.KDRecordLink:
    return kd.KDRecordLink(
        parent_record_uid=_uid_b64(rl.parentRecordUid),
        child_record_uid=_uid_b64(rl.childRecordUid),
        record_key=_wire_b64(rl.recordKey),
        revision=rl.revision,
    )


def _proto_bw_record(bwr: SyncDown_pb2.BreachWatchRecord) -> kd.KDBreachWatchRecord:
    return kd.KDBreachWatchRecord(
        record_uid=_uid_b64(bwr.recordUid),
        data=_wire_b64(bwr.data),
        type=int(bwr.type),
        scanned_by=bwr.scannedBy,
        revision=bwr.revision,
        scanned_by_account_uid=_uid_b64(bwr.scannedByAccountUid),
    )


def _proto_security_score(ss: SyncDown_pb2.SecurityScoreData) -> kd.KDSecurityScoreData:
    return kd.KDSecurityScoreData(
        record_uid=_uid_b64(ss.recordUid),
        data=_wire_b64(ss.data),
        revision=ss.revision,
    )


def _proto_bw_security(bws: SyncDown_pb2.BreachWatchSecurityData) -> kd.KDBreachWatchSecurityData:
    return kd.KDBreachWatchSecurityData(
        record_uid=_uid_b64(bws.recordUid),
        revision=bws.revision,
        removed=bws.removed,
    )


def _dict_to_folder(x: Dict[str, Any]) -> kd.KDFolder:
    oi = x.get('ownerInfo') or {}
    return kd.KDFolder(
        folder_uid=str(x.get('folderUid', '')),
        parent_uid=str(x.get('parentUid', '')),
        data=str(x.get('data', '')),
        folder_type=_coerce_int(x.get('type'), 0),
        inherit_user_permissions=_coerce_int(x.get('inheritUserPermissions'), 0),
        folder_key=str(x.get('folderKey', '')),
        owner_account_uid=str(oi.get('accountUid', '')),
        owner_username=str(oi.get('username', '')),
        date_created=_coerce_int(x.get('dateCreated'), 0),
        last_modified=_coerce_int(x.get('lastModified'), 0),
    )


def _dict_to_folder_key(x: Dict[str, Any]) -> kd.KDFolderKey:
    return kd.KDFolderKey(
        folder_uid=str(x.get('folderUid', '')),
        parent_uid=str(x.get('parentUid', '')),
        folder_key=str(x.get('folderKey', '')),
        encrypted_by=_coerce_int(x.get('encryptedBy'), 0),
    )


def _dict_to_folder_access(x: Dict[str, Any]) -> kd.KDFolderAccess:
    fk = x.get('folderKey')
    enc, kt = '', 0
    if isinstance(fk, dict):
        enc = str(fk.get('encryptedKey', ''))
        kt = _coerce_int(fk.get('encryptedKeyType'), 0)
    elif fk is not None and fk != '':
        enc = str(fk)
    return kd.KDFolderAccess(
        folder_uid=str(x.get('folderUid', '')),
        access_type_uid=str(x.get('accessTypeUid', '')),
        access_type=_coerce_int(x.get('accessType'), 0),
        access_role_type=_coerce_int(x.get('accessRoleType'), 0),
        folder_key_encrypted=enc,
        folder_key_type=kt,
        inherited=bool(x.get('inherited')),
        hidden=bool(x.get('hidden')),
        denied_access=bool(x.get('deniedAccess')),
        permissions_json=_j(x.get('permissions')),
        tla_properties_json=_j(x.get('tlaProperties')),
        date_created=_coerce_int(x.get('dateCreated'), 0),
        last_modified=_coerce_int(x.get('lastModified'), 0),
    )


def _dict_to_non_shared(x: Dict[str, Any]) -> kd.KDNonSharedData:
    return kd.KDNonSharedData(
        record_uid=str(x.get('recordUid', '')),
        data=str(x.get('data', '')),
    )


def _dict_to_record_access(x: Dict[str, Any]) -> kd.KDRecordAccess:
    return kd.KDRecordAccess(
        record_uid=str(x.get('recordUid', '')),
        access_type_uid=str(x.get('accessTypeUid', '')),
        access_type=_coerce_int(x.get('accessType'), 0),
        access_role_type=_coerce_int(x.get('accessRoleType'), 0),
        owner=bool(x.get('owner')),
        inherited=bool(x.get('inherited')),
        hidden=bool(x.get('hidden')),
        denied_access=bool(x.get('deniedAccess')),
        can_view_title=bool(x.get('canViewTitle')),
        can_edit=bool(x.get('canEdit')),
        can_view=bool(x.get('canView')),
        can_list_access=bool(x.get('canListAccess')),
        can_update_access=bool(x.get('canUpdateAccess')),
        can_delete=bool(x.get('canDelete')),
        can_change_ownership=bool(x.get('canChangeOwnership')),
        can_request_access=bool(x.get('canRequestAccess')),
        can_approve_access=bool(x.get('canApproveAccess')),
        date_created=_coerce_int(x.get('dateCreated'), 0),
        last_modified=_coerce_int(x.get('lastModified'), 0),
        tla_properties_json=_j(x.get('tlaProperties')),
    )


def _dict_to_record_link(x: Dict[str, Any]) -> kd.KDRecordLink:
    return kd.KDRecordLink(
        parent_record_uid=str(x.get('parentRecordUid', '')),
        child_record_uid=str(x.get('childRecordUid', '')),
        record_key=str(x.get('recordKey', '')),
        revision=_coerce_int(x.get('revision'), 0),
    )


def _dict_to_bw_record(x: Dict[str, Any]) -> kd.KDBreachWatchRecord:
    return kd.KDBreachWatchRecord(
        record_uid=str(x.get('recordUid', '')),
        data=str(x.get('data', '')),
        type=_coerce_int(x.get('type'), 0),
        scanned_by=str(x.get('scannedBy', '')),
        revision=_coerce_int(x.get('revision'), 0),
        scanned_by_account_uid=str(x.get('scannedByAccountUid', '')),
    )


def _dict_to_security_score(x: Dict[str, Any]) -> kd.KDSecurityScoreData:
    return kd.KDSecurityScoreData(
        record_uid=str(x.get('recordUid', '')),
        data=str(x.get('data', '')),
        revision=_coerce_int(x.get('revision'), 0),
    )


def _dict_to_bw_security(x: Dict[str, Any]) -> kd.KDBreachWatchSecurityData:
    return kd.KDBreachWatchSecurityData(
        record_uid=str(x.get('recordUid', '')),
        revision=_coerce_int(x.get('revision'), 0),
        removed=bool(x.get('removed')),
    )


def load_list_chunks(storage: IKeeperDriveStorage, group: str) -> List[Any]:
    """Decode ``KDListChunk`` rows for ``group`` back into Python values."""
    out: List[Any] = []
    for link in storage.list_chunks.get_links_by_subject(group):
        if not isinstance(link, kd.KDListChunk) or not link.payload_json:
            continue
        try:
            out.append(json.loads(link.payload_json))
        except json.JSONDecodeError:
            out.append(link.payload_json)
    return out
