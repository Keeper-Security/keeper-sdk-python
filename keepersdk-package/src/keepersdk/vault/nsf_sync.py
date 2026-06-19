from __future__ import annotations

import dataclasses
import json
from typing import Any, Dict, List, Mapping, Optional, TYPE_CHECKING, Tuple, Union

from .. import utils
from . import nsf_storage_types as nsf
from .nsf_vault_storage import INSFStorage
from ..proto import SyncDown_pb2, folder_pb2, breachwatch_pb2, record_pb2

if TYPE_CHECKING:
    from .nsf_data import NSFRebuildTask

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


def try_apply_nsf_from_sync_down_proto(
        response: SyncDown_pb2.SyncDownResponse,
        nsf_storage: INSFStorage,
        task: Optional['NSFRebuildTask'] = None) -> bool:
    if not response.HasField('keeperDriveData'):
        return False
    nsf_msg = response.keeperDriveData
    if not list(nsf_msg.ListFields()):
        return False
    apply_nsf_proto_message(nsf_msg, nsf_storage, task)
    return True


def apply_nsf_proto_message(
        nsf_msg: SyncDown_pb2.KeeperDriveData,
        nsf_storage: INSFStorage,
        task: Optional['NSFRebuildTask'] = None) -> None:
    _process_removed_folders_proto(nsf_msg, nsf_storage, task)
    _process_removed_folder_records_proto(nsf_msg, nsf_storage, task)
    _process_removed_record_links_proto(nsf_msg, nsf_storage, task)
    _store_folders_proto(nsf_msg, nsf_storage, task)
    _store_folder_keys_proto(nsf_msg, nsf_storage)
    _store_records_proto(nsf_msg, nsf_storage, task)
    _store_record_data_proto(nsf_msg, nsf_storage, task)
    _store_folder_records_proto(nsf_msg, nsf_storage, task)
    _process_revoked_folder_accesses_proto(nsf_msg, nsf_storage, task)
    _store_folder_accesses_proto(nsf_msg, nsf_storage)
    _process_revoked_record_accesses_proto(nsf_msg, nsf_storage, task)
    _store_record_accesses_proto(nsf_msg, nsf_storage, task)
    _store_record_links_proto(nsf_msg, nsf_storage, task)
    _store_folder_sharing_states_proto(nsf_msg, nsf_storage)
    _store_record_sharing_states_proto(nsf_msg, nsf_storage)
    _store_optional_extras_proto(nsf_msg, nsf_storage, task)


def _process_removed_folders_proto(
        nsf_msg: SyncDown_pb2.KeeperDriveData,
        storage: INSFStorage,
        task: Optional['NSFRebuildTask']) -> None:
    removed = [_uid_b64(x.folder_uid) for x in nsf_msg.removedFolders if x.folder_uid]
    if not removed:
        return
    storage.folder_keys.delete_links_by_subjects(removed)
    storage.folder_records.delete_links_by_subjects(removed)
    storage.folders.delete_uids(removed)
    if task:
        task.add_folders(removed)


def _process_removed_folder_records_proto(
        nsf_msg: SyncDown_pb2.KeeperDriveData,
        storage: INSFStorage,
        task: Optional['NSFRebuildTask']) -> None:
    links: List[Tuple[str, str]] = []
    key_links: List[Tuple[str, str]] = []
    for x in nsf_msg.removedFolderRecords:
        fu, ru = _uid_b64(x.folder_uid), _uid_b64(x.record_uid)
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
        nsf_msg: SyncDown_pb2.KeeperDriveData,
        storage: INSFStorage,
        task: Optional['NSFRebuildTask']) -> None:
    for x in nsf_msg.removedRecordLinks:
        parent_uid, child_uid = _uid_b64(x.parentRecordUid), _uid_b64(x.childRecordUid)
        storage.record_links.delete_links([(parent_uid, child_uid)])
        if task and child_uid:
            task.add_record(child_uid)


def _process_revoked_folder_accesses_proto(
        nsf_msg: SyncDown_pb2.KeeperDriveData,
        storage: INSFStorage,
        task: Optional['NSFRebuildTask']) -> None:
    links = [(_uid_b64(x.folderUid), _uid_b64(x.actorUid)) for x in nsf_msg.revokedFolderAccesses]
    if links:
        storage.folder_accesses.delete_links(links)
        if task:
            task.add_folders((fu for fu, _ in links if fu))


def _process_revoked_record_accesses_proto(
        nsf_msg: SyncDown_pb2.KeeperDriveData,
        storage: INSFStorage,
        task: Optional['NSFRebuildTask']) -> None:
    links = [(_uid_b64(x.recordUid), _uid_b64(x.actorUid)) for x in nsf_msg.revokedRecordAccesses]
    if links:
        storage.record_accesses.delete_links(links)
        if task:
            task.add_records((ru for ru, _ in links if ru))


def _store_folders_proto(
        nsf_msg: SyncDown_pb2.KeeperDriveData,
        storage: INSFStorage,
        task: Optional['NSFRebuildTask']) -> None:
    folders = [_proto_folder(x) for x in nsf_msg.folders]
    if folders:
        storage.folders.put_entities(folders)
        if task:
            task.add_folders((f.folder_uid for f in folders))


def _store_folder_keys_proto(nsf_msg: SyncDown_pb2.KeeperDriveData, storage: INSFStorage) -> None:
    keys = [_proto_folder_key(x) for x in nsf_msg.folderKeys]
    if keys:
        storage.folder_keys.put_links(keys)


def _store_record_data_proto(
        nsf_msg: SyncDown_pb2.KeeperDriveData,
        storage: INSFStorage,
        task: Optional['NSFRebuildTask']) -> None:
    updated: List[nsf.NSFRecord] = []
    for rd in nsf_msg.recordData:
        record_uid = _uid_b64(rd.recordUid)
        if not record_uid:
            continue
        existing = storage.records.get_entity(record_uid)
        if existing is None:
            existing = nsf.NSFRecord(record_uid=record_uid)
        row = dataclasses.replace(existing, data=_wire_b64(rd.data))
        updated.append(row)
        if task:
            task.add_record(record_uid)
    if updated:
        storage.records.put_entities(updated)


def _store_folder_records_proto(
        nsf_msg: SyncDown_pb2.KeeperDriveData,
        storage: INSFStorage,
        task: Optional['NSFRebuildTask']) -> None:
    folder_records: List[nsf.NSFFolderRecord] = []
    record_keys: List[nsf.NSFRecordKey] = []
    for fr in nsf_msg.folderRecords:
        folder_uid = _uid_b64(fr.folderUid)
        md = fr.recordMetadata
        if md is None or not list(md.ListFields()):
            continue
        record_uid = _uid_b64(md.recordUid)
        folder_records.append(nsf.NSFFolderRecord(folder_uid=folder_uid, record_uid=record_uid))
        if md.encryptedRecordKey:
            record_keys.append(nsf.NSFRecordKey(
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
        nsf_msg: SyncDown_pb2.KeeperDriveData,
        storage: INSFStorage,
        task: Optional['NSFRebuildTask']) -> None:
    rows: List[nsf.NSFRecord] = []
    for dr in nsf_msg.records:
        record_uid = _uid_b64(dr.recordUid)
        existing = storage.records.get_entity(record_uid)
        rows.append(nsf.NSFRecord(
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


def _store_folder_accesses_proto(nsf_msg: SyncDown_pb2.KeeperDriveData, storage: INSFStorage) -> None:
    rows = [_proto_folder_access(x) for x in nsf_msg.folderAccesses]
    if rows:
        storage.folder_accesses.put_links(rows)


def _store_record_accesses_proto(
        nsf_msg: SyncDown_pb2.KeeperDriveData,
        storage: INSFStorage,
        task: Optional['NSFRebuildTask']) -> None:
    rows = [_proto_record_access(x) for x in nsf_msg.recordAccesses]
    if rows:
        storage.record_accesses.put_links(rows)
        if task:
            task.add_records((r.record_uid for r in rows))


def _store_record_links_proto(
        nsf_msg: SyncDown_pb2.KeeperDriveData,
        storage: INSFStorage,
        task: Optional['NSFRebuildTask']) -> None:
    rows = [_proto_record_link(x) for x in nsf_msg.recordLinks]
    if rows:
        storage.record_links.put_links(rows)
        if task:
            task.add_records((r.child_record_uid for r in rows))


def _store_folder_sharing_states_proto(nsf_msg: SyncDown_pb2.KeeperDriveData, storage: INSFStorage) -> None:
    rows = [nsf.NSFFolderSharingState(
        folder_uid=_uid_b64(x.folderUid),
        shared=x.shared,
        count=x.count,
    ) for x in nsf_msg.folderSharingState]
    if rows:
        storage.folder_sharing_states.put_entities(rows)


def _store_record_sharing_states_proto(nsf_msg: SyncDown_pb2.KeeperDriveData, storage: INSFStorage) -> None:
    rows = [nsf.NSFRecordSharingState(
        record_uid=_uid_b64(x.recordUid),
        is_directly_shared=x.isDirectlyShared,
        is_indirectly_shared=x.isIndirectlyShared,
        is_shared=x.isShared,
    ) for x in nsf_msg.recordSharingStates]
    if rows:
        storage.record_sharing_states.put_entities(rows)


def _store_optional_extras_proto(
        nsf_msg: SyncDown_pb2.KeeperDriveData,
        storage: INSFStorage,
        task: Optional['NSFRebuildTask']) -> None:
    nsd = [_proto_non_shared(x) for x in nsf_msg.nonSharedData]
    if nsd:
        storage.non_shared_data.put_entities(nsd)
        if task:
            task.add_records((r.record_uid for r in nsd))
    bw = [_proto_bw_record(x) for x in nsf_msg.breachWatchRecords]
    if bw:
        storage.breach_watch_records.put_entities(bw)
        if task:
            task.add_records((r.record_uid for r in bw))
    ss = [_proto_security_score(x) for x in nsf_msg.securityScoreData]
    if ss:
        storage.security_score_data.put_entities(ss)
        if task:
            task.add_records((r.record_uid for r in ss))
    bws = [_proto_bw_security(x) for x in nsf_msg.breachWatchSecurityData]
    if bws:
        storage.breach_watch_security_data.put_entities(bws)
        if task:
            task.add_records((r.record_uid for r in bws))
    chunk_payload: Dict[str, Any] = {
        CHUNK_RECORD_ROTATION: list(nsf_msg.recordRotationData),
        CHUNK_RAW_DAG: list(nsf_msg.rawDagData),
    }
    _replace_json_lists(storage, chunk_payload)


def _replace_json_lists(storage: INSFStorage, d: Mapping[str, Any]) -> None:
    _replace_chunk_group(storage, CHUNK_RECORD_ROTATION, d.get(CHUNK_RECORD_ROTATION))
    _replace_chunk_group(storage, CHUNK_RAW_DAG, d.get(CHUNK_RAW_DAG))


def _replace_chunk_group(storage: INSFStorage, group: str, items: Any) -> None:
    storage.list_chunks.delete_links_by_subjects([group])
    if not isinstance(items, list) or not items:
        return
    links: List[nsf.NSFListChunk] = []
    for i, it in enumerate(items):
        links.append(nsf.NSFListChunk(chunk_group=group, chunk_key=f'{i:010d}', payload_json=_j(it)))
    storage.list_chunks.put_links(links)


def _proto_folder(fd: folder_pb2.FolderData) -> nsf.NSFFolder:
    oi = fd.ownerInfo
    return nsf.NSFFolder(
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


def _proto_folder_key(fk: folder_pb2.FolderKey) -> nsf.NSFFolderKey:
    return nsf.NSFFolderKey(
        folder_uid=_uid_b64(fk.folderUid),
        parent_uid=_uid_b64(fk.parentUid),
        folder_key=_wire_b64(fk.folderKey),
        encrypted_by=int(fk.encryptedBy),
    )


def _proto_folder_access(fa: folder_pb2.FolderAccessData) -> nsf.NSFFolderAccess:
    enc, kt = '', 0
    fk = fa.folderKey
    if _proto_submessage_set(fk):
        enc = _wire_b64(fk.encryptedKey)
        kt = int(fk.encryptedKeyType)
    return nsf.NSFFolderAccess(
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


def _proto_non_shared(nsd: SyncDown_pb2.NonSharedData) -> nsf.NSFNonSharedData:
    return nsf.NSFNonSharedData(
        record_uid=_uid_b64(nsd.recordUid),
        data=_wire_b64(nsd.data),
    )


def _proto_record_access(ra: folder_pb2.RecordAccessData) -> nsf.NSFRecordAccess:
    return nsf.NSFRecordAccess(
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


def _proto_record_link(rl: SyncDown_pb2.RecordLink) -> nsf.NSFRecordLink:
    return nsf.NSFRecordLink(
        parent_record_uid=_uid_b64(rl.parentRecordUid),
        child_record_uid=_uid_b64(rl.childRecordUid),
        record_key=_wire_b64(rl.recordKey),
        revision=rl.revision,
    )


def _proto_bw_record(bwr: SyncDown_pb2.BreachWatchRecord) -> nsf.NSFBreachWatchRecord:
    return nsf.NSFBreachWatchRecord(
        record_uid=_uid_b64(bwr.recordUid),
        data=_wire_b64(bwr.data),
        type=int(bwr.type),
        scanned_by=bwr.scannedBy,
        revision=bwr.revision,
        scanned_by_account_uid=_uid_b64(bwr.scannedByAccountUid),
    )


def _proto_security_score(ss: SyncDown_pb2.SecurityScoreData) -> nsf.NSFSecurityScoreData:
    return nsf.NSFSecurityScoreData(
        record_uid=_uid_b64(ss.recordUid),
        data=_wire_b64(ss.data),
        revision=ss.revision,
    )


def _proto_bw_security(bws: SyncDown_pb2.BreachWatchSecurityData) -> nsf.NSFBreachWatchSecurityData:
    return nsf.NSFBreachWatchSecurityData(
        record_uid=_uid_b64(bws.recordUid),
        revision=bws.revision,
        removed=bws.removed,
    )


def load_list_chunks(storage: INSFStorage, group: str) -> List[Any]:
    """Decode ``NSFListChunk`` rows for ``group`` back into Python values."""
    out: List[Any] = []
    for link in storage.list_chunks.get_links_by_subject(group):
        if not isinstance(link, nsf.NSFListChunk) or not link.payload_json:
            continue
        try:
            out.append(json.loads(link.payload_json))
        except json.JSONDecodeError:
            out.append(link.payload_json)
    return out
