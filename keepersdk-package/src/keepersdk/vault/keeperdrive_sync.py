from __future__ import annotations

import json
from typing import Any, Dict, List, Mapping, Optional, TYPE_CHECKING, Union

from .. import utils
from . import keeperdrive_storage_types as kd
from .keeperdrive_vault_storage import IKeeperDriveStorage
from ..proto import SyncDown_pb2, folder_pb2, breachwatch_pb2, record_pb2

if TYPE_CHECKING:
    from .keeperdrive_data import KeeperDriveRebuildTask

CHUNK_RECORD_SHARING_STATES = 'recordSharingStates'
CHUNK_RECORD_ROTATION = 'recordRotationData'
CHUNK_FOLDER_SHARING_STATE = 'folderSharingState'
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


def _record_uid(item: Mapping[str, Any]) -> str:
    return str(item.get('recordUid') or item.get('record_uid') or '')


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
    for x in kd_msg.removedRecordLinks:
        parent_uid, child_uid = _uid_b64(x.parentRecordUid), _uid_b64(x.childRecordUid)
        drive_storage.record_links.delete_links([(parent_uid, child_uid)])
        if task:
            task.add_record(child_uid)

    removed_folders = [_uid_b64(x.folder_uid) for x in kd_msg.removedFolders if x.folder_uid]
    if removed_folders:
        for fu in removed_folders:
            drive_storage.folder_keys.delete_links_by_subjects([fu])
            drive_storage.folder_accesses.delete_links_by_subjects([fu])
            drive_storage.folder_records.delete_links_by_subjects([fu])
        drive_storage.folders.delete_uids(removed_folders)
        if task:
            task.add_folders(removed_folders)

    for x in kd_msg.removedFolderRecords:
        fu, ru = _uid_b64(x.folderUid), _uid_b64(x.recordUid)
        if fu and ru:
            drive_storage.folder_records.delete_links([(fu, ru)])
            if task:
                task.add_record(ru)

    for x in kd_msg.revokedFolderAccesses:
        fu, au = _uid_b64(x.folderUid), _uid_b64(x.actorUid)
        drive_storage.folder_accesses.delete_links([(fu, au)])
        if task and fu:
            task.add_folder(fu)

    for x in kd_msg.revokedRecordAccesses:
        ru, au = _uid_b64(x.recordUid), _uid_b64(x.actorUid)
        drive_storage.record_accesses.delete_links([(ru, au)])
        if task and ru:
            task.add_record(ru)

    folders = [_proto_folder(x) for x in kd_msg.folders]
    if folders:
        drive_storage.folders.put_entities(folders)
        if task:
            task.add_folders((f.folder_uid for f in folders))

    fkeys = [_proto_folder_key(x) for x in kd_msg.folderKeys]
    if fkeys:
        drive_storage.folder_keys.put_links(fkeys)

    facc = [_proto_folder_access(x) for x in kd_msg.folderAccesses]
    if facc:
        drive_storage.folder_accesses.put_links(facc)

    rdata = [_proto_record_data(x) for x in kd_msg.recordData]
    if rdata:
        drive_storage.record_data.put_entities(rdata)
        if task:
            task.add_records((r.record_uid for r in rdata))

    nsd = [_proto_non_shared(x) for x in kd_msg.nonSharedData]
    if nsd:
        drive_storage.non_shared_data.put_entities(nsd)
        if task:
            task.add_records((r.record_uid for r in nsd))

    racc = [_proto_record_access(x) for x in kd_msg.recordAccesses]
    if racc:
        drive_storage.record_accesses.put_links(racc)
        if task:
            task.add_records((r.record_uid for r in racc))

    rlinks = [_proto_record_link(x) for x in kd_msg.recordLinks]
    if rlinks:
        drive_storage.record_links.put_links(rlinks)
        if task:
            task.add_records((r.child_record_uid for r in rlinks))

    bw = [_proto_bw_record(x) for x in kd_msg.breachWatchRecords]
    if bw:
        drive_storage.breach_watch_records.put_entities(bw)
        if task:
            task.add_records((r.record_uid for r in bw))

    ss = [_proto_security_score(x) for x in kd_msg.securityScoreData]
    if ss:
        drive_storage.security_score_data.put_entities(ss)
        if task:
            task.add_records((r.record_uid for r in ss))

    bws = [_proto_bw_security(x) for x in kd_msg.breachWatchSecurityData]
    if bws:
        drive_storage.breach_watch_security_data.put_entities(bws)
        if task:
            task.add_records((r.record_uid for r in bws))

    fr = [_proto_folder_record(x) for x in kd_msg.folderRecords]
    if fr:
        drive_storage.folder_records.put_links(fr)
        if task:
            task.add_records((r.record_uid for r in fr))

    summ = [_proto_record_summary(x) for x in kd_msg.records]
    if summ:
        drive_storage.record_summaries.put_entities(summ)
        if task:
            task.add_records((r.record_uid for r in summ))

    chunk_payload: Dict[str, Any] = {
        'recordSharingStates': list(kd_msg.recordSharingStates),
        'recordRotationData': list(kd_msg.recordRotationData),
        'folderSharingState': list(kd_msg.folderSharingState),
        'rawDagData': list(kd_msg.rawDagData),
    }
    _replace_json_lists(drive_storage, chunk_payload)


def apply_keeper_drive_data_dict(
        drive_storage: IKeeperDriveStorage,
        keeper_drive_data: Mapping[str, Any],
        task: Optional['KeeperDriveRebuildTask'] = None) -> None:
    _apply_revocations_and_removals(drive_storage, keeper_drive_data, task)
    _apply_upserts(drive_storage, keeper_drive_data, task)
    _replace_json_lists(drive_storage, keeper_drive_data)


def _apply_revocations_and_removals(
        storage: IKeeperDriveStorage,
        d: Mapping[str, Any],
        task: Optional['KeeperDriveRebuildTask'] = None) -> None:
    for x in d.get('revokedFolderAccesses') or []:
        if not isinstance(x, dict):
            continue
        fu, au = str(x.get('folderUid', '')), str(x.get('accessTypeUid', ''))
        storage.folder_accesses.delete_links([(fu, au)])
        if task and fu:
            task.add_folder(fu)

    for x in d.get('revokedRecordAccesses') or []:
        if not isinstance(x, dict):
            continue
        ru, au = str(x.get('recordUid', '')), str(x.get('accessTypeUid', ''))
        storage.record_accesses.delete_links([(ru, au)])
        if task and ru:
            task.add_record(ru)

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

    removed_folders = [_folder_uid(y) for y in (d.get('removedFolders') or []) if _folder_uid(y)]
    if removed_folders:
        for fu in removed_folders:
            storage.folder_keys.delete_links_by_subjects([fu])
            storage.folder_accesses.delete_links_by_subjects([fu])
            storage.folder_records.delete_links_by_subjects([fu])
        storage.folders.delete_uids(removed_folders)
        if task:
            task.add_folders(removed_folders)

    for x in d.get('removedFolderRecords') or []:
        if not isinstance(x, dict):
            continue
        fu, ru = str(x.get('folderUid', '')), str(x.get('recordUid', ''))
        if fu and ru:
            storage.folder_records.delete_links([(fu, ru)])
            if task:
                task.add_record(ru)


def _apply_upserts(
        storage: IKeeperDriveStorage,
        d: Mapping[str, Any],
        task: Optional['KeeperDriveRebuildTask'] = None) -> None:
    folders = [_dict_to_folder(x) for x in d.get('folders') or [] if isinstance(x, dict)]
    if folders:
        storage.folders.put_entities(folders)
        if task:
            task.add_folders((f.folder_uid for f in folders))

    fkeys = [_dict_to_folder_key(x) for x in d.get('folderKeys') or [] if isinstance(x, dict)]
    if fkeys:
        storage.folder_keys.put_links(fkeys)

    facc = [_dict_to_folder_access(x) for x in d.get('folderAccesses') or [] if isinstance(x, dict)]
    if facc:
        storage.folder_accesses.put_links(facc)

    rdata = [_dict_to_record_data(x) for x in d.get('recordData') or [] if isinstance(x, dict)]
    if rdata:
        storage.record_data.put_entities(rdata)
        if task:
            task.add_records((r.record_uid for r in rdata))

    nsd = [_dict_to_non_shared(x) for x in d.get('nonSharedData') or [] if isinstance(x, dict)]
    if nsd:
        storage.non_shared_data.put_entities(nsd)
        if task:
            task.add_records((r.record_uid for r in nsd))

    racc = [_dict_to_record_access(x) for x in d.get('recordAccesses') or [] if isinstance(x, dict)]
    if racc:
        storage.record_accesses.put_links(racc)
        if task:
            task.add_records((r.record_uid for r in racc))

    rlinks = [_dict_to_record_link(x) for x in d.get('recordLinks') or [] if isinstance(x, dict)]
    if rlinks:
        storage.record_links.put_links(rlinks)
        if task:
            task.add_records((r.child_record_uid for r in rlinks))

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

    fr = [_dict_to_folder_record(x) for x in d.get('folderRecords') or [] if isinstance(x, dict)]
    if fr:
        storage.folder_records.put_links(fr)
        if task:
            task.add_records((r.record_uid for r in fr))

    summ = [_dict_to_record_summary(x) for x in d.get('records') or [] if isinstance(x, dict)]
    if summ:
        storage.record_summaries.put_entities(summ)
        if task:
            task.add_records((r.record_uid for r in summ))


def _replace_json_lists(storage: IKeeperDriveStorage, d: Mapping[str, Any]) -> None:
    _replace_chunk_group(storage, CHUNK_RECORD_SHARING_STATES, d.get('recordSharingStates'))
    _replace_chunk_group(storage, CHUNK_RECORD_ROTATION, d.get('recordRotationData'))
    _replace_chunk_group(storage, CHUNK_FOLDER_SHARING_STATE, d.get('folderSharingState'))
    _replace_chunk_group(storage, CHUNK_RAW_DAG, d.get('rawDagData'))


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


def _proto_record_data(rd: folder_pb2.RecordData) -> kd.KDRecordData:
    u = rd.user
    return kd.KDRecordData(
        record_uid=_uid_b64(rd.recordUid),
        account_uid=_uid_b64(u.accountUid) if u else '',
        username=u.username if u else '',
        data=_wire_b64(rd.data),
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


def _proto_folder_record(fr: folder_pb2.FolderRecord) -> kd.KDFolderRecord:
    md = fr.recordMetadata
    return kd.KDFolderRecord(
        folder_uid=_uid_b64(fr.folderUid),
        record_uid=_uid_b64(md.recordUid) if md else '',
        encrypted_record_key=_wire_b64(md.encryptedRecordKey) if md else '',
        encrypted_record_key_type=int(md.encryptedRecordKeyType) if md else 0,
        folder_key_encryption_type=int(fr.folderKeyEncryptionType),
        tla_properties_json='',
    )


def _proto_record_summary(rec: SyncDown_pb2.DriveRecord) -> kd.KDRecordSummary:
    return kd.KDRecordSummary(
        record_uid=_uid_b64(rec.recordUid),
        revision=rec.revision,
        version=rec.version,
        shared=rec.shared,
        client_modified_time=rec.clientModifiedTime,
        file_size=rec.fileSize,
        thumbnail_size=rec.thumbnailSize,
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


def _dict_to_record_data(x: Dict[str, Any]) -> kd.KDRecordData:
    u = x.get('user') or {}
    return kd.KDRecordData(
        record_uid=str(x.get('recordUid', '')),
        account_uid=str(u.get('accountUid', '')),
        username=str(u.get('username', '')),
        data=str(x.get('data', '')),
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


def _dict_to_folder_record(x: Dict[str, Any]) -> kd.KDFolderRecord:
    md = x.get('recordMetadata') or {}
    return kd.KDFolderRecord(
        folder_uid=str(x.get('folderUid', '')),
        record_uid=str(md.get('recordUid', '')),
        encrypted_record_key=str(md.get('encryptedRecordKey', '')),
        encrypted_record_key_type=_coerce_int(md.get('encryptedRecordKeyType'), 0),
        folder_key_encryption_type=_coerce_int(x.get('folderKeyEncryptionType'), 0),
        tla_properties_json=_j(md.get('tlaProperties')),
    )


def _dict_to_record_summary(x: Dict[str, Any]) -> kd.KDRecordSummary:
    return kd.KDRecordSummary(
        record_uid=str(x.get('recordUid', '')),
        revision=_coerce_int(x.get('revision'), 0),
        version=_coerce_int(x.get('version'), 0),
        shared=bool(x.get('shared')),
        client_modified_time=_coerce_int(x.get('clientModifiedTime'), 0),
        file_size=_coerce_int(x.get('fileSize'), 0),
        thumbnail_size=_coerce_int(x.get('thumbnailSize'), 0),
    )


def load_list_chunks(storage: IKeeperDriveStorage, group: str) -> List[Any]:
    """Decode ``KDListChunk`` rows for ``group`` back into Python values (JSON objects or scalars)."""
    out: List[Any] = []
    for link in storage.list_chunks.get_links_by_subject(group):
        if not isinstance(link, kd.KDListChunk) or not link.payload_json:
            continue
        try:
            out.append(json.loads(link.payload_json))
        except json.JSONDecodeError:
            out.append(link.payload_json)
    return out
