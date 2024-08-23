import json
from typing import Optional, Iterable, Union, Callable, List, Set, Dict

from . import vault_extensions, vault_online, vault_utils, vault_types
from .vault_record import PasswordRecord, TypedRecord
from .. import utils, crypto
from ..errors import KeeperApiError
from ..proto import record_pb2, client_pb2


def add_record_to_folder(vault: vault_online.VaultOnline, record: Union[PasswordRecord, TypedRecord],
                         folder_uid: Optional[str]=None) -> str:
    if not record.record_uid:
        record.record_uid = utils.generate_uid()

    record_key = utils.generate_aes_key()

    vault_data = vault.vault_data

    folder = vault_data.get_folder(folder_uid) if folder_uid else None
    folder_key: Optional[bytes] = None
    if folder and folder.folder_type in {'shared_folder', 'shared_folder_folder'}:
        assert folder.folder_scope_uid is not None
        folder_key = vault_data.get_shared_folder_key(folder.folder_scope_uid)

    adp = vault.audit_data_plugin()
    caep = vault.client_audit_event_plugin()

    data_key = vault.keeper_auth.auth_context.data_key
    if isinstance(record, PasswordRecord):
        rq_v2 = {
            'command': 'record_add',
            'record_uid': record.record_uid,
            'record_key': utils.base64_url_encode(crypto.encrypt_aes_v1(record_key, data_key)),
            'record_type': 'password',
            'folder_type': folder.folder_type if folder else 'user_folder',
            'how_long_ago': 0,
        }
        if folder:
            rq_v2['folder_uid'] = folder.folder_uid
        if folder_key:
            rq_v2['folder_key'] = utils.base64_url_encode(crypto.encrypt_aes_v1(record_key, folder_key))
        data, extra, file_ids = vault_extensions.extract_password_record(record)
        rq_v2['data'] = utils.base64_url_encode(crypto.encrypt_aes_v1(json.dumps(data).encode(), record_key))
        rq_v2['extra'] = utils.base64_url_encode(crypto.encrypt_aes_v1(json.dumps(extra).encode(), record_key))
        if isinstance(file_ids, list) and len(file_ids) > 0:
            rq_v2['file_ids'] = file_ids

        vault.keeper_auth.execute_auth_command(rq_v2)
        if adp:
            adp.schedule_audit_data((record.record_uid,))

    elif isinstance(record, TypedRecord):
        add_record = record_pb2.RecordAdd()
        add_record.record_uid = utils.base64_url_decode(record.record_uid)
        add_record.record_key = crypto.encrypt_aes_v2(record_key, vault.keeper_auth.auth_context.data_key)
        add_record.client_modified_time = utils.current_milli_time()
        add_record.folder_type = record_pb2.user_folder
        if folder:
            add_record.folder_uid = utils.base64_url_decode(folder.folder_uid)
            if folder.folder_type == 'shared_folder':
                add_record.folder_type = record_pb2.shared_folder
            elif folder.folder_type == 'shared_folder_folder':
                add_record.folder_type = record_pb2.shared_folder_folder
            if folder_key:
                add_record.folder_key = crypto.encrypt_aes_v2(record_key, folder_key)

        data = vault_extensions.extract_typed_record_data(record, vault_data.get_record_type_by_name(record.record_type))
        json_data = vault_extensions.get_padded_json_bytes(data)
        add_record.data = crypto.encrypt_aes_v2(json_data, record_key)

        refs = vault_extensions.extract_typed_record_refs(record)
        for ref in refs:
            ref_record_key: Optional[bytes] = None
            if record.linked_keys:
                ref_record_key = record.linked_keys.get(ref)
            if not ref_record_key:
                ref_record_key = vault.vault_data.get_record_key(ref)

            if ref_record_key:
                link = record_pb2.RecordLink()
                link.record_uid = utils.base64_url_decode(ref)
                link.record_key = crypto.encrypt_aes_v2(ref_record_key, record_key)
                add_record.record_links.append(link)

        if vault.keeper_auth.auth_context.enterprise_ec_public_key:
            audit_data = vault_extensions.extract_audit_data(record)
            if audit_data:
                add_record.audit.version = 0
                add_record.audit.data = crypto.encrypt_ec(
                    json.dumps(audit_data).encode('utf-8'), vault.keeper_auth.auth_context.enterprise_ec_public_key)

        rq_v3 = record_pb2.RecordsAddRequest()
        rq_v3.client_time = utils.current_milli_time()
        rq_v3.records.append(add_record)
        rs_v3 = vault.keeper_auth.execute_auth_rest(
            'vault/records_add', rq_v3, response_type=record_pb2.RecordsModifyResponse)
        assert rs_v3 is not None
        record_rs = next((x for x in rs_v3.records if utils.base64_url_encode(x.record_uid) == record.record_uid), None)
        if record_rs:
            if record_rs.status != record_pb2.RS_SUCCESS:
                status = record_pb2.RecordModifyResult.Name(record_rs.status)   # type: ignore
                raise KeeperApiError(status, record_rs.message)
    else:
        raise ValueError('Unsupported Keeper record')

    if caep:
        ids = vault_extensions.extract_record_attachment_ids(record)
        if len(ids) > 0:
            for attachment_id in ids:
                caep.schedule_audit_event(
                    'file_attachment_uploaded', record_uid=record.record_uid, attachment_id=attachment_id)

    record_password = record.extract_password()
    if record_password:
        bwp = vault.breach_watch_plugin()
        bw_status: Optional[int] = None
        if bwp:
            bw_password = bwp.scan_and_store_record_status(record.record_uid, record_key, record_password)
            if bw_password:
                bw_status = bw_password.status
                if bw_password.status == client_pb2.WEAK:
                    utils.get_logger().info('High-Risk password detected. Record UID: %s', record.record_uid)
                    if caep:
                        caep.schedule_audit_event('bw_record_high_risk')

        sap = vault.security_audit_plugin()
        if sap:
            score = utils.password_score(record_password)
            url = record.extract_url()
            sap.schedule_security_data(record.record_uid, score, url, bw_status)

    vault.sync_requested = True
    vault.run_pending_jobs()

    return record.record_uid


def update_record(vault: vault_online.VaultOnline, record: Union[PasswordRecord, TypedRecord]) -> None:
    record_info = vault.vault_data.get_record(record.record_uid)
    if not record_info:
        raise Exception(f'Record Update: {record.record_uid}: record cannot be found.')
    record_key = vault.vault_data.get_record_key(record.record_uid)
    if not record_key:
        raise Exception(f'Record Update: {record.record_uid}: record key cannot be resolved.')

    existing_record = vault.vault_data.load_record(record.record_uid)
    if isinstance(record, PasswordRecord) and isinstance(existing_record, PasswordRecord):
        status = vault_extensions.compare_records(record, existing_record)
    elif isinstance(record, TypedRecord) and isinstance(existing_record, TypedRecord):
        status = vault_extensions.compare_records(record, existing_record)
    else:
        raise Exception(f'Record {record.record_uid}: Invalid record type.')

    adp = vault.audit_data_plugin()
    caep = vault.client_audit_event_plugin()

    if isinstance(record, PasswordRecord) and isinstance(existing_record, PasswordRecord):
        data, extra, file_ids = vault_extensions.extract_password_record(record)
        record_object = {
            'record_uid': record.record_uid,
            'version': 2,
            'revision': record_info.revision,
            'client_modified_time': utils.current_milli_time(),
            'data': utils.base64_url_encode(crypto.encrypt_aes_v1(json.dumps(data).encode(), record_key)),
            'extra': utils.base64_url_encode(crypto.encrypt_aes_v1(json.dumps(extra).encode(), record_key))}
        if file_ids:
            record_object['udata'] = { 'file_ids': file_ids }
        vault_extensions.resolve_record_access_path(vault.vault_data.storage, record_object, for_edit=True)
        rqu_v2 = {
            'command': 'record_update',
            'client_time': utils.current_milli_time(),
            'update_records': [record_object]
        }
        rsu_v2 = vault.keeper_auth.execute_auth_command(rqu_v2)
        update_status = next(
            (x for x in rsu_v2.get('update_records', []) if x.get('record_uid') == record.record_uid), None)
        if update_status:
            record_status = update_status.get('status', 'success')
            if record_status != 'success':
                raise KeeperApiError(record_status, update_status.get('message', ''))

        if adp and bool(status & (vault_extensions.RecordChangeStatus.Title | vault_extensions.RecordChangeStatus.URL)):
            adp.schedule_audit_data((record.record_uid,))

    elif isinstance(record, TypedRecord) and isinstance(existing_record, TypedRecord):
        record_uid_bytes = utils.base64_url_decode(record.record_uid)
        ur = record_pb2.RecordUpdate()
        ur.record_uid = record_uid_bytes
        ur.client_modified_time = utils.current_milli_time()
        ur.revision = record_info.revision

        data = vault_extensions.extract_typed_record_data(record, vault.vault_data.get_record_type_by_name(record.record_type))
        ur.data = crypto.encrypt_aes_v2(vault_extensions.get_padded_json_bytes(data), record_key)

        existing_refs = vault_extensions.extract_typed_record_refs(existing_record)
        refs = vault_extensions.extract_typed_record_refs(record)
        for ref_record_uid in refs.difference(existing_refs):
            ref_record_key = None
            if record.linked_keys and ref_record_uid in record.linked_keys:
                ref_record_key = record.linked_keys[ref_record_uid]
            if not ref_record_key:
                ref_record_key = vault.vault_data.get_record_key(ref_record_uid)
            if ref_record_key:
                link = record_pb2.RecordLink()
                link.record_uid = utils.base64_url_decode(ref_record_uid)
                link.record_key = crypto.encrypt_aes_v2(ref_record_key, record_key)
                ur.record_links_add.append(link)
        for ref in existing_refs.difference(refs):
            ur.record_links_remove.append(utils.base64_url_decode(ref))

        if vault.keeper_auth.auth_context.enterprise_ec_public_key:
            if bool(status & (vault_extensions.RecordChangeStatus.Title | vault_extensions.RecordChangeStatus.URL |
                              vault_extensions.RecordChangeStatus.RecordType)):
                audit_data = vault_extensions.extract_audit_data(record)
                if audit_data:
                    ur.audit.version = 0
                    ur.audit.data = crypto.encrypt_ec(
                        json.dumps(audit_data).encode('utf-8'), vault.keeper_auth.auth_context.enterprise_ec_public_key)

        rqu_v3 = record_pb2.RecordsUpdateRequest()
        rqu_v3.client_time = utils.current_milli_time()
        rqu_v3.records.append(ur)

        rsu_v3 = vault.keeper_auth.execute_auth_rest(
            'vault/records_update', rqu_v3, response_type=record_pb2.RecordsModifyResponse)
        assert rsu_v3 is not None
        rs_status = next((x for x in rsu_v3.records if record_uid_bytes == x.record_uid), None)
        if rs_status and rs_status.status != record_pb2.RecordModifyResult.RS_SUCCESS:
            code = record_pb2.RecordModifyResult.Name(rs_status.status)      # type: ignore
            raise KeeperApiError(code, rs_status.message)
    else:
        raise ValueError('Unsupported Keeper record')

    if caep:
        prev_atta_ids = vault_extensions.extract_record_attachment_ids(existing_record)
        new_atta_refs = vault_extensions.extract_record_attachment_ids(record)
        for file_id in new_atta_refs.difference(prev_atta_ids):
            caep.schedule_audit_event(
                'file_attachment_uploaded', record_uid=record.record_uid, attachment_id=file_id)
        for file_id in prev_atta_ids.difference(new_atta_refs):
            caep.schedule_audit_event(
                'file_attachment_deleted', record_uid=record.record_uid, attachment_id=file_id)

    if bool(status & vault_extensions.RecordChangeStatus.Password):
        if caep:
            caep.schedule_audit_event('record_password_change', record_uid=record.record_uid)

        sap = vault.security_audit_plugin()
        record_password = record.extract_password()
        if record_password:
            bwp = vault.breach_watch_plugin()
            bw_status: Optional[int] = None
            if bwp:
                bw_password = bwp.scan_and_store_record_status(record.record_uid, record_key, record_password)
                if bw_password:
                    bw_status = bw_password.status
                    if bw_password.status == client_pb2.WEAK:
                        utils.get_logger().info('High-Risk password detected. Record UID: %s', record.record_uid)
                        if caep:
                            caep.schedule_audit_event('bw_record_high_risk')

            if sap:
                score = utils.password_score(record_password)
                url = record.extract_url()
                sap.schedule_security_data(record.record_uid, score, url, bw_status)
        else:
            if sap:
                sap.schedule_security_data_delete(record.record_uid)

    vault.sync_requested = True
    vault.run_pending_jobs()


def delete_vault_objects(vault: vault_online.VaultOnline,
                         vault_objects: Iterable[Union[str, vault_types.RecordPath]],
                         confirm: Optional[Callable[[str], bool]]=None) -> None:
    objects: List[dict] = []
    for to_delete in vault_objects:
        if not to_delete:
            raise ValueError('Delete by UID: Cannot be empty')
        if isinstance(to_delete, str):
            folder = vault.vault_data.get_folder(to_delete)
            if folder:
                obj = {
                    'object_uid': folder.folder_uid,
                    'object_type': folder.folder_type,
                    'delete_resolution': 'unlink',
                    'from_type': folder.folder_type,
                }
                if folder.parent_uid:
                    obj['from_uid'] = folder.parent_uid
                elif folder.folder_type == 'shared_folder_folder':
                    assert folder.folder_scope_uid is not None
                    obj['from_uid'] = folder.folder_scope_uid
                objects.append(obj)
            else:
                record = vault.vault_data.get_record(to_delete)
                # TODO resolve folder
                if record:
                    obj = {
                        'object_uid': record.record_uid,
                        'object_type': 'record',
                        'delete_resolution': 'unlink',
                        'from_type': 'user_folder',
                    }
                    objects.append(obj)
        elif isinstance(to_delete, vault_types.RecordPath):
            if not to_delete.record_uid:
                raise ValueError('record UID cannot be empy')

            folder = None
            if to_delete.folder_uid:
                folder = vault.vault_data.get_folder(to_delete.folder_uid)
                if not folder:
                    raise ValueError(f'Folder \"{to_delete.folder_uid}\" not found')
            record = vault.vault_data.get_record(to_delete.record_uid)
            if not record:
                raise ValueError(f'Record \"{to_delete.record_uid}\" not found')
            obj = {
                'object_uid': record.record_uid,
                'object_type': 'record',
                'delete_resolution': 'unlink',
            }
            if folder:
                obj['from_uid'] = folder.folder_uid
                obj['from_type'] = 'user_folder' if folder.folder_type == 'user_folder' else 'shared_folder_folder'
            else:
                obj['from_type'] = 'user_folder'
            objects.append(obj)
    if objects:
        rq = {
            'command': 'pre_delete',
            'objects': objects
        }
        rs = vault.keeper_auth.execute_auth_command(rq)
        response = rs['pre_delete_response']
        delete_token = response['pre_delete_token']
        if confirm:
            would_delete = response.get('would_delete')
            if isinstance(would_delete, dict):
                summary = would_delete.get('deletion_summary')
                if isinstance(summary, list):
                    message = '\n'.join(summary)
                    answer = confirm(message)
                    if not answer:
                        return
        rq = {
            'command': 'delete',
            'pre_delete_token': delete_token
        }
        vault.keeper_auth.execute_auth_command(rq)
    vault.sync_requested = True


def move_vault_objects(vault: vault_online.VaultOnline,
                       src_objects: Iterable[Union[str, vault_types.RecordPath]],
                       dst_folder_uid: str='',
                       *,
                       is_link: bool = False,
                       can_edit: Optional[bool] = None,
                       can_share: Optional[bool] = None,
                       on_warning: Optional[Callable[[str], None]] = None) -> None:

    logger = utils.get_logger()
    dst_folder = vault.vault_data.get_folder(dst_folder_uid) if dst_folder_uid else vault.vault_data.root_folder
    if not dst_folder:
        raise ValueError(f'Destination folder \"{dst_folder_uid}\" not found')
    dst_encryption_key: Optional[bytes] = None
    if dst_folder.folder_type == 'user_folder':
        dst_scope_uid = ''
        dst_encryption_key = vault.keeper_auth.auth_context.data_key
    else:
        dst_scope_uid = dst_folder.folder_scope_uid or ''
        dst_encryption_key = vault.vault_data.get_shared_folder_key(dst_scope_uid)
    if dst_encryption_key is None:
        raise ValueError(f'Destination shared folder key \"{dst_scope_uid}\" not found')

    dst_records: Set[str] = set(dst_folder.records)

    record_to_move: Dict[str, Set[str]] = {}
    records_to_delete: Dict[str, Set[str]] = {}
    record_uid_to_move: Set[str] = set()
    folder_uid_to_move: Set[str] = set()

    def notify_on_error(message: str) -> None:
        logger.debug(message)
        if callable(on_warning):
            on_warning(message)
            return
        raise ValueError(message)

    def notify_on_warning(message: str) -> None:
        logger.debug(message)
        if callable(on_warning):
            on_warning(message)

    for src in src_objects:
        if isinstance(src, vault_types.RecordPath):
            src_folder_uid = src.folder_uid
            src_folder = vault.vault_data.get_folder(src_folder_uid) if src_folder_uid else vault.vault_data.root_folder
            if not src_folder:
                notify_on_error(f'Source folder \"{src_folder_uid}\" not found')
                continue

            src_record_uid = src.record_uid
            if src_record_uid not in src_folder.records:
                notify_on_error(f'Source record \"{src_record_uid}\" not found in the folder \"{src_folder_uid}\"')
                continue

            if src_record_uid in dst_records:
                notify_on_warning(f'Destination folder already contains record \"{src_record_uid}\".')
                if not is_link:
                    if src_folder_uid not in records_to_delete:
                        records_to_delete[src_folder_uid] = set()
                    records_to_delete[src_folder_uid].add(src_record_uid)
            else:
                if src_folder_uid not in record_to_move:
                    record_to_move[src_folder_uid] = set()
                record_to_move[src_folder_uid].add(src_record_uid)
        else:
            folder = vault.vault_data.get_folder(src)
            if folder:
                if folder.folder_uid == dst_folder_uid:
                    notify_on_warning('Source and destination folders are the same.')
                else:
                    folder_uid_to_move.add(folder.folder_uid)
            else:
                record = vault.vault_data.get_record(src)
                if record:
                    record_uid_to_move.add(record.record_uid)
                else:
                    notify_on_error(f'UID \"{src}\" cannot be detected as a record or a folder')

    record_uid: str
    if len(record_uid_to_move) > 0:
        for record_uid in record_uid_to_move:
            folders = vault_utils.get_folders_for_record(vault.vault_data, record_uid)
            if record_uid in dst_folder.subfolders:
                notify_on_warning(f'Destination folder already contains record \"{record_uid}\".')
            else:
                selected_folder_uid: Optional[str] = None
                for f in folders:
                    if f.folder_type == 'user_folder':
                        scope_uid = ''
                    else:
                        scope_uid = f.folder_scope_uid or ''
                    if scope_uid == dst_scope_uid:
                        selected_folder_uid = f.folder_uid
                        break
                if selected_folder_uid is None:
                    selected_folder_uid = next((x for x in record_uid_to_move))
                folders = [x for x in folders if x.folder_uid != selected_folder_uid]

                if selected_folder_uid not in record_to_move:
                    record_to_move[selected_folder_uid] = set()
                record_to_move[selected_folder_uid].add(record_uid)

            if not is_link:
                for f in folders:
                    if f.folder_uid != dst_folder_uid:
                        if f.folder_uid not in records_to_delete:
                            records_to_delete[f.folder_uid] = set()
                        records_to_delete[f.folder_uid].add(record_uid)
    del record_uid_to_move

    move_object_max = 1000
    # move records first
    while len(record_to_move) > 0:
        move: List[dict] = []
        rq = {
            'command': 'move',
            'link': is_link,
            'to_type': dst_folder.folder_type,
        }
        if dst_folder.folder_uid:
            rq['to_uid'] = dst_folder.folder_uid

        transition_keys: Dict[str, str] = {}
        is_full = False
        while len(record_to_move) > 0 and not is_full:
            folder_uid, records = next((x for x in record_to_move.items()))
            all_records = list(records)
            if len(move) + len(records) < move_object_max:
                del record_to_move[folder_uid]
            else:
                is_full = True
                to_copy = move_object_max - len(move)
                record_to_move[folder_uid] = set(all_records[to_copy:])
                all_records = all_records[:to_copy]

            folder = vault.vault_data.get_folder(folder_uid) if folder_uid else vault.vault_data.root_folder
            assert folder is not None
            if folder.folder_type == 'user_folder':
                src_scope_uid = ''
            else:
                src_scope_uid = folder.folder_scope_uid or ''

            for record_uid in all_records:
                record = vault.vault_data.get_record(record_uid)
                if not record:
                    notify_on_error(f'Cannot get record \"{record_uid}\".')
                    continue

                if src_scope_uid != dst_scope_uid:
                    if record.record_uid not in transition_keys:
                        record_key = vault.vault_data.get_record_key(record.record_uid)
                        if record_key:
                            if record.version >= 3:
                                key = crypto.encrypt_aes_v2(record_key, dst_encryption_key)
                            else:
                                key = crypto.encrypt_aes_v1(record_key, dst_encryption_key)
                            transition_keys[record.record_uid] = utils.base64_url_encode(key)
                mo = {
                    'uid': record.record_uid,
                    'type': 'record',
                    'cascade': False,
                    'from_type': folder.folder_type
                }
                if folder.folder_uid:
                    mo['from_uid'] = folder.folder_uid
                if folder.folder_type != 'user_folder':
                    if isinstance(can_edit, bool):
                        mo['can_edit'] = can_edit
                if isinstance(can_share, bool):
                    mo['can_reshare'] = can_share
                move.append(mo)

        if len(move) > 0:
            rq['move'] = move
            if len(transition_keys) > 0:
                rq['transition_keys'] = [{'uid': uid, 'key': key} for uid, key in transition_keys.items()]
            vault.keeper_auth.execute_auth_command(rq)

    if len(records_to_delete) > 0:
        delete_vault_objects(vault, records_to_delete, lambda x: True)
    del records_to_delete

    vault.sync_down()

    # move folders
    if len(folder_uid_to_move) > 0:
        transition_keys = {}
        move = []
        rq = {
            'command': 'move',
            'link': is_link,
            'to_type': dst_folder.folder_type,
        }
        if dst_folder.folder_uid:
            rq['to_uid'] = dst_folder.folder_uid

        for folder_uid in folder_uid_to_move:
            folder = vault.vault_data.get_folder(folder_uid)
            assert folder is not None
            if folder.folder_type == 'user_folder':
                src_scope_uid = ''
            else:
                src_scope_uid = folder.folder_scope_uid or ''
            if src_scope_uid != dst_scope_uid:
                def prepare_transition_keys(f: vault_types.Folder):
                    assert dst_encryption_key is not None
                    t_folder_key = crypto.encrypt_aes_v1(f.folder_key, dst_encryption_key)
                    transition_keys[f.folder_uid] = utils.base64_url_encode(t_folder_key)
                    if f.records:
                        for record_uid in f.records:
                            if record_uid not in transition_keys:
                                record = vault.vault_data.get_record(record_uid)
                                if record:
                                    record_key = vault.vault_data.get_record_key(record_uid)
                                    if record_key:
                                        if record.version >= 3:
                                            t_record_key = crypto.encrypt_aes_v2(record_key, dst_encryption_key)
                                        else:
                                            t_record_key = crypto.encrypt_aes_v1(record_key, dst_encryption_key)
                                        transition_keys[f.folder_uid] = utils.base64_url_encode(t_record_key)
                vault_utils.traverse_folder_tree(vault.vault_data, folder, prepare_transition_keys)
            parent_folder = vault.vault_data.get_folder(folder.parent_uid) if folder.parent_uid else vault.vault_data.root_folder
            assert parent_folder is not None
            mo = {
                'uid': folder_uid,
                'type': folder.folder_type,
                'cascade': True,
                'from_type': parent_folder.folder_type
            }
            if parent_folder.folder_uid:
                mo['from_uid'] = parent_folder.folder_uid
            move.append(mo)

        if len(move) > 0:
            rq['move'] = move
            if len(transition_keys) > 0:
                rq['transition_keys'] = [{'uid': uid, 'key': key} for uid, key in transition_keys.items()]

            vault.keeper_auth.execute_auth_command(rq)
            vault.sync_requested = True
