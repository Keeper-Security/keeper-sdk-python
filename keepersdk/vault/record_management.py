#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#
import enum
import json
from typing import Optional, Iterable, Union, Callable, List, Set

from . import vault_extensions, record_facades, vault_online
from .vault_record import PasswordRecord, TypedRecord, TypedField
from .vault_types import RecordPath
from .. import utils, crypto
from ..errors import KeeperApiError
from ..proto import record_pb2


def add_record_to_folder(vault, record, folder_uid=None):
    # type: (vault_online.VaultOnline, Union[PasswordRecord, TypedRecord], Optional[str]) -> str
    if not record.record_uid:
        record.record_uid = utils.generate_uid()

    record_key = utils.generate_aes_key()

    folder = vault.get_folder(folder_uid) if folder_uid else None
    folder_key = None  # type: Optional[bytes]
    if folder and folder.folder_type in {'shared_folder', 'shared_folder_folder'}:
        assert folder.folder_scope_uid is not None
        folder_key = vault.get_shared_folder_key(folder.folder_scope_uid)

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
        data = vault_extensions.extract_password_record_data(record)
        rq_v2['data'] = utils.base64_url_encode(crypto.encrypt_aes_v1(json.dumps(data).encode(), record_key))
        extra = vault_extensions.extract_password_record_extras(record)
        rq_v2['extra'] = utils.base64_url_encode(crypto.encrypt_aes_v1(json.dumps(extra).encode(), record_key))
        if record.attachments:
            file_ids = []
            for atta in record.attachments:
                file_ids.append(atta.id)
                if atta.thumbnails:
                    for thumb in atta.thumbnails:
                        file_ids.append(thumb.id)
            rq_v2['file_ids'] = file_ids

        rs_v2 = vault.keeper_auth.execute_auth_command(rq_v2)
        if 'revision' in rs_v2:
            vault.schedule_audit_data(record, rs_v2['revision'])
        if record.attachments:
            for atta in record.attachments:
                vault.schedule_audit_event(
                    'file_attachment_uploaded', record_uid=record.record_uid, attachment_id=atta.id)

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

        data = vault_extensions.extract_typed_record_data(record, vault.get_record_type_by_name(record.record_type))
        json_data = vault_extensions.get_padded_json_bytes(data)
        add_record.data = crypto.encrypt_aes_v2(json_data, record_key)

        refs = vault_extensions.extract_typed_record_refs(record)
        for ref in refs:
            ref_record_key = None     # type: Optional[bytes]
            if record.linked_keys:
                ref_record_key = record.linked_keys.get(ref)
            if not ref_record_key:
                ref_record_key = vault.get_record_key(ref)

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
            if record_rs.status == record_pb2.RS_SUCCESS:
                file_facade = record_facades.FileRefRecordFacade()
                file_facade.record = record
                if isinstance(file_facade.file_ref, list):
                    for file_uid in file_facade.file_ref:
                        vault.schedule_audit_event(
                            'file_attachment_uploaded', record_uid=record.record_uid, attachment_id=file_uid)
            else:
                raise KeeperApiError(record_rs.status, record_rs.message)

    else:
        raise ValueError('Unsupported Keeper record')

    vault.sync_requested = True
    vault.run_pending_jobs()

    return record.record_uid


class RecordChangeStatus(enum.Flag):
    Title = enum.auto()
    RecordType = enum.auto()
    Username = enum.auto()
    Password = enum.auto()
    URL = enum.auto()


def compare_records(record1, record2):
    # type: (Union[PasswordRecord, TypedRecord], Union[PasswordRecord, TypedRecord]) -> RecordChangeStatus
    status = RecordChangeStatus(0)

    if record1.title != record2.title:
        status = status | RecordChangeStatus.Title
    if isinstance(record1, PasswordRecord) and isinstance(record2, PasswordRecord):
        if record1.login != record2.login:
            status = status | RecordChangeStatus.Username
        if record1.password != record2.password:
            status = status | RecordChangeStatus.Password
        if record1.link != record2.link:
            status = status | RecordChangeStatus.URL
    elif isinstance(record1, TypedRecord) and isinstance(record2, TypedRecord):
        if record1.record_type != record2.record_type:
            status = status | RecordChangeStatus.RecordType

        r_login = record1.get_typed_field('login') or record1.get_typed_field('email')
        e_login = record2.get_typed_field('login') or record2.get_typed_field('email')
        if r_login or e_login:
            if r_login and e_login:
                if r_login.get_external_value() or '' != e_login.get_external_value() or '':
                    status = status | RecordChangeStatus.Username
            else:
                status = status | RecordChangeStatus.Username

        r_password = record1.get_typed_field('password')
        e_password = record2.get_typed_field('password')
        if r_password or e_password:
            if r_password and e_password:
                if r_password.get_external_value() or '' != e_password.get_external_value() or '':
                    status = status | RecordChangeStatus.Password
            else:
                status = status | RecordChangeStatus.Password

        r_url = record1.get_typed_field('url')
        e_url = record2.get_typed_field('url')
        if r_url or e_url:
            if r_url and e_url:
                if r_url.get_external_value() or '' != e_url.get_external_value() or '':
                    status = status | RecordChangeStatus.URL
            else:
                status = status | RecordChangeStatus.URL

    return status


def update_record(vault, record, skip_extra=False):
    # type: (vault_online.VaultOnline, Union[PasswordRecord, TypedRecord], bool) -> None
    record_key = vault.get_record_key(record.record_uid)
    if not record_key:
        raise Exception(f'Record Update: {record.record_uid}: record key cannot be resolved.')

    storage_record = vault.storage.records.get_entity(record.record_uid)
    if not storage_record:
        raise Exception(f'Record Update: {record.record_uid} not found.')

    existing_record = vault_extensions.load_keeper_record(storage_record, record_key)
    if isinstance(record, PasswordRecord) and isinstance(existing_record, PasswordRecord):
        status = compare_records(record, existing_record)
    elif isinstance(record, TypedRecord) and isinstance(existing_record, TypedRecord):
        status = compare_records(record, existing_record)
    else:
        raise Exception(f'Record {record.record_uid}: Invalid record type.')

    if isinstance(record, PasswordRecord) and isinstance(existing_record, PasswordRecord):
        record_object = {
            'record_uid': record.record_uid,
            'version': 2,
            'revision': storage_record.revision,
            'client_modified_time': utils.current_milli_time(),
        }
        vault_extensions.resolve_record_access_path(vault.storage, record_object, for_edit=True)

        data = vault_extensions.extract_password_record_data(record)
        record_object['data'] = utils.base64_url_encode(
            crypto.encrypt_aes_v1(json.dumps(data).encode(), record_key))

        if not skip_extra:
            try:
                if storage_record.extra:
                    json_str = crypto.decrypt_aes_v1(storage_record.extra, record_key).decode()
                    existing_extra = json.loads(json_str)
                else:
                    existing_extra = {}
            except Exception as e:
                existing_extra = {}
                utils.get_logger().warning('Decrypt record %s extra error: %s', record.record_uid, e)

            extra = vault_extensions.extract_password_record_extras(record, existing_extra)
            record_object['extra'] = utils.base64_url_encode(
                crypto.encrypt_aes_v1(json.dumps(extra).encode(), record_key))

            if storage_record.udata:
                udata = json.loads(storage_record.udata)
            else:
                udata = {}

            file_ids = []    # type: List[str]
            udata['file_ids'] = file_ids
            if record.attachments:
                for atta in record.attachments:
                    file_ids.append(atta.id)
                    if atta.thumbnails:
                        for thumb in atta.thumbnails:
                            file_ids.append(thumb.id)
            record_object['udata'] = udata

        rqu_v2 = {
            "command": "record_update",
            "client_time": utils.current_milli_time(),
            'update_records': [record_object]
        }
        rsu_v2 = vault.keeper_auth.execute_auth_command(rqu_v2)
        update_status = next(
            (x for x in rsu_v2.get('update_records', []) if x.get('record_uid') == record.record_uid), None)
        if update_status:
            record_status = update_status.get('status', 'success')
            if record_status != 'success':
                raise KeeperApiError(record_status, update_status.get('message', ''))

        if bool(status & (RecordChangeStatus.Title | RecordChangeStatus.URL)):
            revision = rsu_v2.get('revision') or 0
            vault.schedule_audit_data(record, revision)
        prev_file_refs = set((x.id for x in existing_record.attachments or []))
        new_file_refs = set((x.id for x in record.attachments or []))
        for file_id in new_file_refs.difference(prev_file_refs):
            vault.schedule_audit_event(
                'file_attachment_uploaded', record_uid=record.record_uid, attachment_id=file_id)
        for file_id in prev_file_refs.difference(new_file_refs):
            vault.schedule_audit_event(
                'file_attachment_deleted', record_uid=record.record_uid, attachment_id=file_id)

    elif isinstance(record, TypedRecord) and isinstance(existing_record, TypedRecord):
        record_uid_bytes = utils.base64_url_decode(record.record_uid)
        ur = record_pb2.RecordUpdate()
        ur.record_uid = record_uid_bytes
        ur.client_modified_time = utils.current_milli_time()
        ur.revision = storage_record.revision

        data = vault_extensions.extract_typed_record_data(record, vault.get_record_type_by_name(record.record_type))
        json_data = vault_extensions.get_padded_json_bytes(data)
        ur.data = crypto.encrypt_aes_v2(json_data, record_key)

        existing_refs = vault_extensions.extract_typed_record_refs(existing_record)
        refs = vault_extensions.extract_typed_record_refs(record)
        for ref_record_uid in refs.difference(existing_refs):
            ref_record_key = None
            if record.linked_keys and ref_record_uid in record.linked_keys:
                ref_record_key = record.linked_keys[ref_record_uid]
            if not ref_record_key:
                ref_record_key = vault.get_record_key(ref_record_uid)
            if ref_record_key:
                link = record_pb2.RecordLink()
                link.record_uid = utils.base64_url_decode(ref_record_uid)
                link.record_key = crypto.encrypt_aes_v2(ref_record_key, record_key)
                ur.record_links_add.append(link)
        for ref in existing_refs.difference(refs):
            ur.record_links_remove.append(utils.base64_url_decode(ref))

        if vault.keeper_auth.auth_context.enterprise_ec_public_key:
            if bool(status & (RecordChangeStatus.Title | RecordChangeStatus.URL | RecordChangeStatus.RecordType)):
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
            raise KeeperApiError(rs_status.status, rs_status.message)

        prev_refs = set()   # type: Set[str]
        new_refs = set()    # type: Set[str]
        file_refs = existing_record.get_typed_field('fileRef')
        if isinstance(file_refs, TypedField) and isinstance(file_refs.value, list):
            for uid in file_refs.value:
                prev_refs.add(uid)
        file_refs = record.get_typed_field('fileRef')
        if isinstance(file_refs, TypedField) and isinstance(file_refs.value, list):
            for uid in file_refs.value:
                new_refs.add(uid)
        for file_id in new_refs.difference(prev_refs):
            vault.schedule_audit_event(
                'file_attachment_uploaded', record_uid=record.record_uid, attachment_id=file_id)
        for file_id in prev_refs.difference(new_refs):
            vault.schedule_audit_event(
                'file_attachment_deleted', record_uid=record.record_uid, attachment_id=file_id)
    else:
        raise ValueError('Unsupported Keeper record')

    vault.sync_requested = True
    if bool(status & RecordChangeStatus.Password):
        vault.schedule_audit_event('record_password_change', record_uid=record.record_uid)

    vault.run_pending_jobs()


def delete_vault_objects(vault, vault_objects, confirm=None):
    # type: (vault_online.VaultOnline, Iterable[Union[str, RecordPath]], Optional[Callable[[str], bool]]) -> None
    shared_folders = set()
    objects = []             # type: List[dict]
    for to_delete in vault_objects:
        if not to_delete:
            raise ValueError('Delete by UID: Cannot be empty')
        if isinstance(to_delete, str):
            folder = vault.get_folder(to_delete)
            if folder:
                if folder.folder_type == 'shared_folder':
                    shared_folders.add(to_delete)
                else:
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
                continue
            record = vault.get_record(to_delete)
            # TODO resolve folder
            if record:
                obj = {
                    'object_uid': record.record_uid,
                    'object_type': 'record',
                    'delete_resolution': 'unlink',
                    'from_type': 'user_folder',
                }
                objects.append(obj)
                continue

        elif isinstance(to_delete, RecordPath):
            if not to_delete.record_uid:
                raise ValueError('Cannot be empy')

            folder = None
            if to_delete.folder_uid:
                folder = vault.get_folder(to_delete.folder_uid)
                if not folder:
                    raise ValueError(f'Folder \"{to_delete.folder_uid}\" not found')
            record = vault.get_record(to_delete.record_uid)
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

    if shared_folders:
        if confirm:
            message = f'Your request will result in the deletion of:\n{len(shared_folders)} Shared Folder(s)'
            answer = confirm(message)
            if not answer:
                return
        rqs = [{
            'command': 'shared_folder_update',
            'operation': 'delete',
            'shared_folder_uid': x
        } for x in shared_folders]

        vault.keeper_auth.execute_batch(rqs)

    vault.sync_requested = True
