import dataclasses
import datetime
import itertools
import re
from typing import Optional, List, Any, Union, Dict, Set, Tuple

import attrs

from . import import_data
from .. import utils, errors, crypto
from ..authentication import keeper_auth
from ..enterprise import enterprise_types
from ..proto import folder_pb2
from ..vault import vault_online, batch_operations, vault_utils, vault_record, vault_types, record_types, \
    typed_field_utils, attachment, storage_types, vault_data


def _as_password_record(record: import_data.Record) -> vault_record.PasswordRecord:
    pr = vault_record.PasswordRecord()
    if record.uid:
        pr.record_uid = str(record.uid)
    pr.title = record.title
    pr.login = record.login or ''
    pr.password = record.password or ''
    pr.link = record.login_url or ''
    pr.notes = record.notes or ''
    if isinstance(record.fields, list):
        if not isinstance(pr.custom, list):
            pr.custom = []
        for rf in record.fields:
            if not rf.value:
                continue
            if rf.label == import_data.TWO_FACTOR_CODE or rf.type == import_data.FIELD_TYPE_ONE_TIME_CODE:
                if pr.totp is None:
                    if not rf.value.startswith('otpauth://'):
                       pr.totp = f'otpauth://totp/?secret={rf.value}'
                    continue
            name = rf.label or rf.type or utils.generate_uid()
            value = rf.value if isinstance(rf.value, str) else str(rf.value)
            pr.custom.append(vault_record.CustomField.create_field(name, value))

    return pr


def _as_typed_record(record: import_data.Record, *,
                     rti: Optional[vault_types.RecordType] = None
                     ) -> vault_record.TypedRecord:
    tr = vault_record.TypedRecord()
    if record.uid:
        tr.record_uid = str(record.uid)
    tr.title = record.title
    tr.record_type = record.type or (rti.name if rti else 'login') or 'login'
    tr.notes = record.notes or ''
    if isinstance(record.fields, list):
        old_totp = next((x for x in record.fields if x.label == import_data.TWO_FACTOR_CODE), None)
        if old_totp:
            old_totp.type = import_data.FIELD_TYPE_ONE_TIME_CODE
            old_totp.label = ''
    all_fields = {(x.external_name() or '').lower(): x for x in record.fields}

    tmp_label = utils.generate_uid()
    for x in zip(('login', 'password', 'url'), (record.login, record.password, record.login_url)):
        if isinstance(x[1], str) and len(x[1]) > 0:
            fld = import_data.RecordField.create(x[0], None, x[1])
            key = (fld.external_name() or '').lower()
            if key in all_fields:
                fld1 = all_fields.pop(key)
                fld1.label = tmp_label
                all_fields[(fld1.external_name() or '').lower()] = fld1
            all_fields[key] = fld

    fields: List[Any] = (rti.fields if rti else record.schema) or []
    for field in fields:
        if isinstance(field, vault_types.RecordTypeField):
            typed_field = vault_record.TypedField.create_schema_field(field)
        elif isinstance(field, import_data.RecordSchemaField):
            typed_field = vault_record.TypedField.create_field(field.ref, field.label, required=field.required or False)
        else:
            continue
        f_key = (typed_field.external_name() or '').lower()
        if f_key in all_fields:
            record_field = all_fields.pop(f_key)
            value = adjust_typed_field(typed_field.type, record_field.value)
            if isinstance(value, list):
                typed_field.value.extend(value)
            else:
                typed_field.value.append(value)
        tr.fields.append(typed_field)

    for import_field in all_fields.values():
        field_label = import_field.label
        if field_label == tmp_label:
            field_label = ''
        typed_field = vault_record.TypedField.create_field(import_field.type or 'text', field_label)
        value = adjust_typed_field(typed_field.type, import_field.value)
        if isinstance(value, list):
            typed_field.value.extend(value)
        else:
            typed_field.value.append(value)
        tr.custom.append(typed_field)

    return tr

def adjust_field_label(record: import_data.Record, field_type: str, field_label: str, rti: vault_types.RecordType) -> str:
    """
    Overwrites the field label according to record type schema. Selects a field label from record type schema
    checking if it is not already present in the record. The field will go to `fields` section when imported.
    :param record: imported record
    :param field_type: field type
    :param field_label: field label
    :param rti: record type information
    :return: field label
    """
    if not isinstance(rti, vault_types.RecordType):
        return field_label
    if field_type == 'text':
        return field_label

    fields = [x for x in rti.fields if x.type == field_type]
    if len(fields) > 0:
        existing_fields = {x.external_name() for x in record.fields if x.type == field_type}
        for field in fields:
            if field.external_name() not in existing_fields:
                return field.label

    return field_label


def adjust_typed_field(field_type: str, field_value: Any) -> Any:
    if field_value is None:
        return None
    if not field_type:
        return field_value

    ft: Optional[record_types.FieldType]
    if field_type in record_types.RecordFields:
        ft = record_types.FieldTypes.get(record_types.RecordFields[field_type].type)
    else:
        ft = record_types.FieldTypes.get(field_type)
    if ft is None:
        return field_value

    if not isinstance(field_value, list):
        field_value = [field_value]

    adjusted_values = []
    for value in field_value:
        if isinstance(value, str) and len(value) == 0:
            continue

        if ft.name == 'multiple' and isinstance(value, str):
            value = value.replace('\\n', '\n')
        if ft.name in ('otp', 'oneTimeCode') and isinstance(value, str):
            if not value.startswith('otpauth://'):
                value = f'otpauth://totp/?secret={value}'

        if isinstance(value, type(ft.value)):
            adjusted_values.append(value)
            continue

        if isinstance(ft.value, str):
            value = str(value)

        elif isinstance(ft.value, int):
            if isinstance(value, str):
                try:
                    if value.isnumeric():
                        value = int(value)
                    else:
                        if len(value) <= 10:
                            dt = datetime.datetime.strptime(value, '%Y-%m-%d')
                        else:
                            dt = datetime.datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ')
                        value = int(dt.timestamp() * 1000)
                except Exception:
                    pass
            elif isinstance(value, float):
                value = int(value)
            elif isinstance(value, datetime.date):
                dt = datetime.datetime.combine(value, datetime.datetime.min.time())
                value = int(dt.timestamp() * 1000)
            elif isinstance(value, datetime.datetime):
                value = int(value.timestamp() * 1000)

        elif isinstance(ft.value, bool):
            if isinstance(value, str):
                lv = value.lower()
                if lv in ('1', 'y', 'yes', 't', 'true'):
                    value = True
                elif lv in ('0', 'n', 'no', 'f', 'false'):
                    value = False
            elif isinstance(value, (int, float)):
                i_value = int(value)
                value = i_value != 0

        elif isinstance(ft.value, dict):
            if isinstance(value, str):
                if ft.name == 'name':
                    value = typed_field_utils.TypedFieldMixin.import_name_field(value)
                elif ft.name == 'address':
                    value = typed_field_utils.TypedFieldMixin.import_address_field(value)
                elif ft.name == 'host':
                    value = typed_field_utils.TypedFieldMixin.import_host_field(value)
                elif ft.name == 'phone':
                    value = typed_field_utils.TypedFieldMixin.import_phone_field(value)
                elif ft.name == 'paymentCard':
                    value = typed_field_utils.TypedFieldMixin.import_card_field(value)
                elif ft.name == 'bankAccount':
                    value = typed_field_utils.TypedFieldMixin.import_account_field(value)
                elif ft.name == 'securityQuestion':
                    values = []
                    for qa in value.split(';'):
                        qa = qa.strip()
                        qav = typed_field_utils.TypedFieldMixin.import_q_and_a_field(qa)
                        if qav:
                            values.append(qav)
                    value = values
                elif ft.name == 'privateKey':
                    value = typed_field_utils.TypedFieldMixin.import_ssh_key_field(value)
                elif ft.name == 'schedule':
                    value = typed_field_utils.TypedFieldMixin.import_schedule_field(value)

        if isinstance(value, list):
            adjusted_values.extend(value)
        else:
            adjusted_values.append(value)

    if len(adjusted_values) == 1:
        return adjusted_values[0]
    elif len(adjusted_values) > 1:
        return adjusted_values
    else:
        return None

@dataclasses.dataclass
class _RecordPermission:
    record_uid: str
    can_edit: Optional[bool] = None
    can_share: Optional[bool] = None

def _prepare_move_requests(vault: vault_online.VaultOnline, links: Dict[str, List[_RecordPermission]]) -> List[Dict[str, Any]]:
    rqs: List[Dict[str, Any]] = []
    for folder_uid, record_links in links.items():
        dst_folder = vault.vault_data.get_folder(folder_uid) if folder_uid else vault.vault_data.root_folder
        if not dst_folder:
            continue
        move: List[Any] = []
        transition_keys: List[Any] = []
        req = {
            'command': 'move',
            'to_type': dst_folder.folder_type,
            'link': True,
            'move': move,
            'transition_keys': transition_keys
        }
        if dst_folder.folder_uid:
            req['to_uid'] = dst_folder.folder_uid

        for record_link in record_links:
            r = vault.vault_data.get_record(record_link.record_uid)
            if not r:
                continue
            src_folders = vault_utils.get_folders_for_record(vault.vault_data, r.record_uid)
            if len(src_folders) == 0:
                continue
            src_folder_uids = {x.folder_uid for x in src_folders}
            if folder_uid in src_folder_uids:
                continue
            src_folder = next((x for x in src_folders if (x.folder_scope_uid or '') == (dst_folder.folder_scope_uid or '')), None)
            if src_folder is None:
                src_folder = src_folders[0]
            mo = {
                'type': 'record',
                'uid': r.record_uid,
                'from_type': src_folder.folder_type,
                'cascade': True
            }
            if src_folder.folder_uid:
                mo['from_uid'] = src_folder.folder_uid
            move.append(mo)

            if (src_folder.folder_scope_uid or '') != (dst_folder.folder_scope_uid or ''):
                record_key = vault.vault_data.get_record_key(r.record_uid)
                if not record_key:
                    continue
                if dst_folder.folder_scope_uid:
                    if isinstance(record_link.can_edit, bool):
                        mo['can_edit'] = record_link.can_edit
                    if isinstance(record_link.can_share, bool):
                        mo['can_reshare'] = record_link.can_share
                    encryption_key = vault.vault_data.get_shared_folder_key(dst_folder.folder_scope_uid)
                else:
                    encryption_key = vault.keeper_auth.auth_context.data_key
                if isinstance(encryption_key, bytes):
                    if r.version >= 3:
                        transition_key = crypto.encrypt_aes_v2(record_key, encryption_key)
                    else:
                        transition_key = crypto.encrypt_aes_v1(record_key, encryption_key)
                    transition_keys.append({
                        'uid': r.record_uid,
                        'key': utils.base64_url_encode(transition_key)
                    })
        if len(move) > 0:
            rqs.append(req)
    return rqs


def _prepare_record_permission_requests(vault: vault_online.VaultOnline,
                                        links: Dict[str, List[_RecordPermission]]
                                        ) -> List[folder_pb2.SharedFolderUpdateV3Request]:
    permission_rqs: List[folder_pb2.SharedFolderUpdateV3Request] = []
    for folder_uid, record_links in links.items():
        folder = vault.vault_data.get_folder(folder_uid)
        if folder is None:
            continue
        if folder.folder_type == 'user_folder' or not folder.folder_scope_uid:
            continue
        shared_folder = vault.vault_data.load_shared_folder(folder.folder_scope_uid)
        if not shared_folder:
            continue
        permission_links = [x for x in record_links if isinstance(x.can_edit, bool) or isinstance(x.can_share, bool)]
        if len(permission_links) == 0:
            continue

        sfu_rq = folder_pb2.SharedFolderUpdateV3Request()
        sfu_rq.sharedFolderUid = utils.base64_url_decode(shared_folder.shared_folder_uid)
        sfu_rq.forceUpdate = True
        rl = {x.record_uid: (x.can_edit, x.can_share) for x in shared_folder.record_permissions}
        for link in permission_links:
            if link.record_uid in rl:
                continue
            can_edit, can_share = rl[link.record_uid]
            sfur = folder_pb2.SharedFolderUpdateRecord()
            sfur.recordUid = utils.base64_url_decode(link.record_uid)
            sfur.sharedFolderUid = sfu_rq.sharedFolderUid
            if isinstance(link.can_edit, bool) and link.can_edit != can_edit:
                sfur.canEdit = folder_pb2.SetBooleanValue.BOOLEAN_TRUE if can_edit else folder_pb2.SetBooleanValue.BOOLEAN_FALSE
            if isinstance(link.can_share, bool) and link.can_share != can_share:
                sfur.canShare = folder_pb2.SetBooleanValue.BOOLEAN_TRUE if can_share else folder_pb2.SetBooleanValue.BOOLEAN_FALSE
            if sfur.canShare != folder_pb2.SetBooleanValue.BOOLEAN_NO_CHANGE or sfur.canEdit != folder_pb2.SetBooleanValue.BOOLEAN_NO_CHANGE:
                sfu_rq.sharedFolderUpdateRecord.append(sfur)
        if len(sfu_rq.sharedFolderUpdateRecord) > 0:
            permission_rqs.append(sfu_rq)

    return permission_rqs


def do_import_vault(vault: vault_online.VaultOnline,
                    data_source: import_data.BaseImporter,
                    *,
                    import_logger: Optional[import_data.IImportLogger]=None,
                    filter_folder: Optional[str]=None,
                    **kwargs
                    ) -> None:

    if 'restrict_import' in vault.keeper_auth.auth_context.enforcements:
        if vault.keeper_auth.auth_context.enforcements.get('restrict_import') is True:
            raise errors.KeeperError('"import" is restricted by Keeper Administrator')

    vault.sync_down()
    if isinstance(import_logger, batch_operations.BatchLogger):
        batch_logger = import_logger
    else:
        batch_logger = batch_operations.BatchLogger()
    batch = batch_operations.BatchVaultOperations(vault, batch_operations.RecordMatch.AllFields, logger=batch_logger)

    shared_folders: List[import_data.SharedFolder] = []
    records: List[import_data.Record] = []

    folder_prefix = ''
    if filter_folder and not data_source.support_folder_filter():
        fs_count = sum((1 for x in filter_folder if x == '/'))
        bs_count = sum((1 for x in filter_folder if x == '\\'))

        if bs_count == 0 and fs_count == 0:
            folders = [filter_folder]
        elif fs_count >= bs_count:
            fn = filter_folder.replace('//', '\x00')
            folders = [y for y in (x.strip().replace('\x00', '/') for x in fn.split('/')) if y]
        else:
            fn = filter_folder.replace('\\\\', '\x00')
            folders = [y for y in (x.strip().replace('\x00', '\\') for x in fn.split('\\')) if y]

        folder_prefix = import_data.PathDelimiter.join((x.replace(import_data.PathDelimiter, 2*import_data.PathDelimiter) for x in folders))
        folder_prefix = folder_prefix.casefold()

    for x in data_source.vault_import(filter_folder=filter_folder, **kwargs):
        if isinstance(x, import_data.Record):
            if not x.title:
                if import_logger:
                    import_logger.failed_record('<empty>', 'Record title cannot be empty')
                continue

            match = True
            if filter_folder and x.folders:
                match = False
                for fol in x.folders:
                    if fol.get_folder_path().casefold().startswith(folder_prefix):
                        match = True
                        break
            if match:
                records.append(x)
        elif isinstance(x, import_data.SharedFolder):
            if not x.path:
                continue

            match = True
            if filter_folder and x.path:
                match = x.path.casefold().startswith(folder_prefix)

            if match:
                shared_folders.append(x)

    for sf in shared_folders:
        if sf.path:
            options = batch_operations.SharedFolderOptions(
                can_edit=sf.can_edit, can_share=sf.can_share, manage_users=sf.manage_users, manage_records=sf.manage_records)

            folder_path = vault_utils.parse_folder_path(sf.path, path_delimiter=import_data.PathDelimiter)
            _ = batch.create_folder_path(folder_path, shared_folder_options=options)

    record_links: Dict[str, List[_RecordPermission]] = {}
    record_map: List[Tuple[Union[vault_record.PasswordRecord, vault_record.TypedRecord], import_data.Record]] = []

    for r in records:
        keeper_record: Union[vault_record.PasswordRecord, vault_record.TypedRecord]
        if r.type:
            record_type = vault.vault_data.get_record_type_by_name(r.type)
            keeper_record = _as_typed_record(r, rti=record_type)
        else:
            keeper_record = _as_password_record(r)

        folder_node: Optional[batch_operations.FolderNode] = None
        if isinstance(r.folders, list) and len(r.folders) > 0:
            import_folder: import_data.Folder = r.folders[0]
            folder_path = vault_utils.parse_folder_path(import_folder.get_folder_path(), path_delimiter=import_data.PathDelimiter)
            folder_node = batch.create_folder_path(folder_path)

        kr = batch.add_record(keeper_record, folder_node)
        if not kr:
            continue
        keeper_record = kr
        record_map.append((keeper_record, r))

        if isinstance(r.folders, list) and len(r.folders) > 0:
            for import_folder in r.folders:
                f_path = import_folder.get_folder_path()
                folder_node = batch.get_folder_by_path(f_path)
                if folder_node:
                    record_uids = record_links.get(folder_node.folder_uid)
                    if record_uids is None:
                        record_uids = list()
                        record_links[folder_node.folder_uid] = record_uids
                    record_uids.append(_RecordPermission(record_uid=keeper_record.record_uid,
                                                         can_edit=import_folder.can_edit,
                                                         can_share=import_folder.can_share))
    if import_logger:
        for name, message in batch_logger.record_failure.items():
            import_logger.failed_record(name, message)

        for keeper_record, import_record in record_map:
            if keeper_record.record_uid in batch_logger.record_added:
                import_logger.added_record(import_record, False, keeper_record)
            elif keeper_record.record_uid in batch_logger.record_updated:
                import_logger.added_record(import_record, True, keeper_record)

        if not import_logger.confirm_import():
            return

    if len(record_map) > 0:
        uid_lookup = {import_record.uid: keeper_record.record_uid for keeper_record, import_record in record_map if import_record.uid}
        for keeper_record, import_record in record_map:
            if isinstance(keeper_record, vault_record.TypedRecord) and isinstance(import_record.references, list) and len(import_record.references) > 0:
                reference: import_data.RecordReferences
                for reference in import_record.references:
                    if isinstance(reference.uids, list) and len(reference.uids) > 0:
                        field_type = f'{reference.type}Ref'
                        if field_type not in record_types.FieldTypes:
                            field_type = 'recordRef'
                        typed_field: Optional[vault_record.TypedField] = None
                        if reference.label:
                            typed_field = keeper_record.get_typed_field(field_type, reference.label)
                        if typed_field is None:
                            typed_field = keeper_record.get_typed_field(field_type)
                        if typed_field is None:
                            typed_field = vault_record.TypedField.create_field(field_type, reference.label)
                            keeper_record.custom.append(typed_field)
                        ref_values = set()
                        if isinstance(typed_field.value, list):
                            ref_values.update(typed_field.value)
                        for uid in reference.uids:
                            record_uid = uid_lookup.get(uid)
                            if record_uid:
                                ref_values.add(record_uid)
                        typed_field.value = list(ref_values)
    batch.apply_changes()

    vault.sync_down()
    move_rqs = _prepare_move_requests(vault, record_links)
    if len(move_rqs) > 0:
        try:
            move_rss = vault.keeper_auth.execute_batch(move_rqs)
            for move_rq in move_rss:
                if move_rq.get('result') != 'success':
                    result_code = move_rq.get('result_code')
                    error_message = move_rq.get('message')
                    if error_message:
                        error_message = f'{result_code}: {error_message}'
                    else:
                        error_message = f'Result code: {result_code}'
                    utils.get_logger().warning(error_message)
        except Exception as e:
            utils.get_logger().warning(f'Create Record Links Error: {e}')
        vault.sync_down()

    permission_rqs = _prepare_record_permission_requests(vault, record_links)
    if len(permission_rqs) > 0:
        while len(permission_rqs) > 0:
            chunk = permission_rqs[:900]
            permission_rqs = permission_rqs[900:]
            sfurs_rq = folder_pb2.SharedFolderUpdateV3RequestV2()
            sfurs_rq.sharedFoldersUpdateV3.extend(chunk)
            try:
                _ = vault.keeper_auth.execute_auth_rest(
                    'vault/shared_folder_update_v3', sfurs_rq,
                    response_type = folder_pb2.SharedFolderUpdateV3ResponseV2,
                    payload_version = 1)
            except Exception as e:
                utils.get_logger().warning(f'Adjust Record Permissions Errors: {e}')
        vault.sync_down()

    caep = vault.client_audit_event_plugin()
    attachment_records = [(kr.record_uid, ir) for kr, ir in record_map if isinstance(ir.attachments, list) and len(ir.attachments)]
    if len(attachment_records) > 0:
        batch.reset(record_match=batch_operations.RecordMatch.Nothing)
        for record_uid, import_record in attachment_records:
            record = vault.vault_data.load_record(record_uid)
            if not isinstance(record, (vault_record.PasswordRecord, vault_record.TypedRecord)):
                continue
            if not import_record.attachments:
                continue
            existing_file_names: Set[str] = set()
            if isinstance(record, vault_record.TypedRecord):
                file_ref = record.get_typed_field('fileRef')
                if isinstance(file_ref, vault_record.TypedField) and isinstance(file_ref.value, list):
                    for file_uid in file_ref.value:
                        file_info = vault.vault_data.get_record(file_uid)
                        if file_info:
                            existing_file_names.add(file_info.title)

            elif isinstance(record, vault_record.PasswordRecord) and isinstance(record.attachments, list):
                atta: vault_record.AttachmentFile
                for atta in record.attachments:
                    if atta.title:
                        existing_file_names.add(atta.title)
                    if atta.name:
                        existing_file_names.add(atta.name)
            else:
                continue

            tasks = [import_data.AttachmentUploadTask(x) for x in import_record.attachments if x.name not in existing_file_names]
            if len(tasks) > 0:
                attachment.upload_attachments(vault, record, tasks)
                batch.update_record(record)
        batch.apply_changes()

    if caep:
        caep.schedule_audit_event('imported_records', file_format=data_source.description())


def to_import_shared_folder(vault: vault_data.VaultData,
                            shared_folder: vault_types.SharedFolder) -> import_data.SharedFolder:
    sf = import_data.SharedFolder()
    sf.uid = shared_folder.shared_folder_uid
    sf.path = vault_utils.get_folder_path(vault, shared_folder.shared_folder_uid)
    sf.manage_users = shared_folder. default_manage_users
    sf.manage_records = shared_folder.default_manage_records
    sf.can_edit = shared_folder.default_can_edit
    sf.can_share = shared_folder.default_can_share
    sf.permissions = []
    for permission in shared_folder.user_permissions:
        perm = import_data.Permission()
        if permission.user_type == storage_types.SharedFolderUserType.Team:
            perm.uid = permission.user_uid
            perm.name = permission.name
        else:
            perm.name = permission.name
        perm.manage_users = permission.manage_users
        perm.manage_records = permission.manage_records
        sf.permissions.append(perm)
    return sf


def to_import_record(record: vault_record.KeeperRecord) -> Optional[import_data.Record]:
    rec = import_data.Record()
    rec.uid = record.record_uid
    rec.title = record.title
    rec.last_modified = record.client_time_modified
    if isinstance(record, vault_record.PasswordRecord):
        rec.notes = record.notes
        rec.login = record.login
        rec.password = record.password
        rec.login_url = record.link
        if record.totp:
            rf = import_data.RecordField()
            rf.type = import_data.FIELD_TYPE_ONE_TIME_CODE
            rf.value = record.totp
            rec.fields.append(rf)
        if isinstance(record.custom, list) and len(record.custom) > 0:
            for cf in record.custom:
                rf = import_data.RecordField()
                rf.label = cf.name
                rf.value = cf.value
                rec.fields.append(rf)
    elif isinstance(record, vault_record.TypedRecord):
        rec.notes = record.notes
        rec.type = record.record_type
        if rec.type not in import_data.STANDARD_RECORD_TYPES:
            schema_fields = []
            for field in record.fields:
                schema_field = import_data.RecordSchemaField()
                schema_field.ref = field.type
                schema_field.label = field.label or ''
                schema_fields.append(schema_field)
        for field in itertools.chain(record.fields, record.custom):
            if not field.value:
                continue
            if field.type == 'login' and not rec.login:
                rec.login = field.get_default_value(str)
            elif field.type == 'password' and not rec.password:
                rec.password = field.get_default_value(str)
            elif field.type == 'url' and not field.label and not rec.login_url:
                rec.login_url = field.get_default_value(str)
            elif field.type.endswith('Ref'):
                ref_type = field.type[:-3]
                if ref_type == 'file':
                    continue
                if isinstance(field.value, list) and len(field.value) > 0:
                    references = import_data.RecordReferences()
                    references.type = ref_type
                    references.label = field.label
                    references.uids = list(field.value)
                    if rec.references is None:
                        rec.references = []
                    rec.references.append(references)
            else:
                rf = import_data.RecordField()
                rf.type = field.type
                rf.label = field.label
                rf.value = field.get_external_value()
                if rec.fields is None:
                    rec.fields = []
                rec.fields.append(rf)
    else:
        return None

    return rec


def prepare_folder_permission(vault: vault_online.VaultOnline,
                              folders: List[import_data.SharedFolder],
                              full_sync: bool) -> List[folder_pb2.SharedFolderUpdateV3Request]:
    logger = utils.get_logger()
    shared_folder_lookup = {}
    available_teams = list(vault_utils.load_available_teams(vault.keeper_auth))

    for shared_folder_info in vault.vault_data.shared_folders():
        path = vault_utils.get_folder_path(vault.vault_data, shared_folder_info.shared_folder_uid)
        if path:
            shared_folder_lookup[path.strip()] = shared_folder_info.shared_folder_uid

    email_pattern = re.compile(utils.EMAIL_PATTERN)
    emails_to_add: Set[str] = set()
    teams_to_add: Set[str] = set()
    for fol in folders:
        if not fol.path:
            continue
        shared_folder_uid = shared_folder_lookup.get(fol.path)
        if not shared_folder_uid:
            logger.debug('Cannot resolve shared folder UID by path: %s', fol.path)
            continue
        shared_folder = vault.vault_data.load_shared_folder(shared_folder_uid)
        if not shared_folder:
            logger.debug('Cannot resolve shared folder by UID: %s', shared_folder_uid)
            continue
        shared_folder_key = vault.vault_data.get_shared_folder_key(shared_folder_uid)
        if not shared_folder_key:
            logger.debug('Shared folder \"%s\" does not have a key', shared_folder_uid)
            continue

        logger.debug('Verify permissions for shared folder \"%s\"', fol.path)

        if fol.permissions:
            for perm in fol.permissions:
                if perm.uid:
                    permission = next((x for x in shared_folder.user_permissions if x.user_uid == perm.uid), None)
                    if permission is not None:
                        continue
                    team = next((x for x in available_teams if x.team_uid == perm.uid), None)
                    if team is not None:
                        teams_to_add.add(team.team_uid)
                        continue
                    user = vault.vault_data.get_user_email(perm.uid)
                    if user:
                        emails_to_add.add(user.username)
                        continue

                if perm.name:
                    lower_name = perm.name.casefold()
                    permission = next((x for x in shared_folder.user_permissions if x.name and x.name.casefold() == lower_name), None)
                    if permission is not None:
                        continue

                    match = email_pattern.match(perm.name)
                    if match:
                        if perm.name == vault.keeper_auth.auth_context.username:
                            continue
                        emails_to_add.add(perm.name.lower())
                        continue
                    else:
                        team = next((x for x in available_teams if x.name.casefold() == lower_name), None)
                        if team is not None:
                            teams_to_add.add(team.team_uid)
                            continue

    if len(emails_to_add) > 0:
        logger.debug('Loading public keys for %d user(s)', len(emails_to_add))
        vault.keeper_auth.load_user_public_keys(emails_to_add, send_invites = False)

    if len(teams_to_add) > 0:
        logger.debug('Resolving team UIDs for %d team(s)', len(teams_to_add))
        vault.keeper_auth.load_team_keys(teams_to_add)

    folder_permissions: List[folder_pb2.SharedFolderUpdateV3Request] = []
    current_user = vault.keeper_auth.auth_context.username
    for fol in folders:
        if not fol.path:
            continue
        shared_folder_uid = shared_folder_lookup.get(fol.path)
        if not shared_folder_uid:
            continue
        shared_folder = vault.vault_data.load_shared_folder(shared_folder_uid)
        if not shared_folder:
            continue
        shared_folder_key = vault.vault_data.get_shared_folder_key(shared_folder_uid)
        if not shared_folder_key:
            continue

        existing_teams = set((x.user_uid for x in shared_folder.user_permissions if x.user_type == vault_types.SharedFolderUserType.Team))
        existing_users = set((x.name for x in shared_folder.user_permissions if x.name and x.user_type == vault_types.SharedFolderUserType.User))
        if current_user in existing_users:
            existing_users.remove(current_user)
        keep_teams = set()
        keep_users = set()

        if fol.permissions:
            add_users: List[folder_pb2.SharedFolderUpdateUser] = []
            add_teams: List[folder_pb2.SharedFolderUpdateTeam] = []
            update_users: List[folder_pb2.SharedFolderUpdateUser] = []
            update_teams: List[folder_pb2.SharedFolderUpdateTeam] = []
            remove_users: List[str] = []
            remove_teams: List[str] = []
            for perm in fol.permissions:
                team_uid = None
                username = None
                try:
                    if perm.uid and any(True for x in available_teams if x.team_uid == perm.uid):
                        team_uid = perm.uid
                    elif perm.name:
                        name = perm.name.casefold()
                        team_uid = next((x.team_uid for x in available_teams if x.name.casefold() == name), None)
                        if team_uid is None:
                            username = name

                    if team_uid:
                        folder_team = next((
                            x for x in shared_folder.user_permissions if x.user_type == storage_types.SharedFolderUserType.Team and x.user_uid == team_uid), None)

                        if folder_team:
                            manage_users = folder_team.manage_users
                            manage_records = folder_team.manage_records
                            keep_teams.add(team_uid)
                            if manage_users != (perm.manage_users or manage_users) or manage_records != (perm.manage_records or manage_records):
                                sft = folder_pb2.SharedFolderUpdateTeam()
                                sft.teamUid = utils.base64_url_decode(team_uid)
                                sft.manageUsers = perm.manage_users or manage_users
                                sft.manageRecords = perm.manage_records or manage_records
                                update_teams.append(sft)
                        else:
                            sft = folder_pb2.SharedFolderUpdateTeam()
                            sft.teamUid = utils.base64_url_decode(team_uid)
                            sft.manageUsers = perm.manage_users or shared_folder.default_manage_users
                            sft.manageRecords = perm.manage_records or shared_folder.default_manage_records
                            keep_teams.add(team_uid)
                            team_key = vault.vault_data.get_team_key(team_uid)
                            if team_key:
                                sft.typedSharedFolderKey.encryptedKey = crypto.encrypt_aes_v1(shared_folder_key, team_key)
                                sft.typedSharedFolderKey.encryptedKeyType = folder_pb2.EncryptedKeyType.encrypted_by_data_key
                            else:
                                team_keys = vault.keeper_auth.get_team_keys(team_uid)
                                if not team_keys:
                                    continue
                                if team_keys.aes:
                                    sft.typedSharedFolderKey.encryptedKey = crypto.encrypt_aes_v1(shared_folder_key, team_keys.aes)
                                    sft.typedSharedFolderKey.encryptedKeyType = folder_pb2.EncryptedKeyType.encrypted_by_data_key
                                elif team_keys.rsa:
                                    rsa_key = crypto.load_rsa_public_key(team_keys.rsa)
                                    sft.typedSharedFolderKey.encryptedKey = crypto.encrypt_rsa(shared_folder_key, rsa_key)
                                    sft.typedSharedFolderKey.encryptedKeyType = folder_pb2.EncryptedKeyType.encrypted_by_public_key
                                elif team_keys.ec:
                                    ec_key = crypto.load_ec_public_key(team_keys.ec)
                                    sft.typedSharedFolderKey.encryptedKey = crypto.encrypt_ec(shared_folder_key, ec_key)
                                    sft.typedSharedFolderKey.encryptedKeyType = folder_pb2.EncryptedKeyType.encrypted_by_public_key_ecc
                                else:
                                    continue
                            add_teams.append(sft)
                        continue

                    if username:
                        folder_user = next((x for x in shared_folder.user_permissions
                                            if x.user_type == storage_types.SharedFolderUserType.User and x.name and x.name.lower() == username), None)

                        sfu = folder_pb2.SharedFolderUpdateUser()
                        sfu.username = username
                        sfu.manageUsers = folder_pb2.BOOLEAN_TRUE \
                            if perm.manage_users else folder_pb2.BOOLEAN_FALSE
                        sfu.manageRecords = folder_pb2.BOOLEAN_TRUE \
                            if perm.manage_records else folder_pb2.BOOLEAN_FALSE

                        if folder_user:
                            keep_users.add(username)
                            manage_users = folder_user.manage_users
                            manage_records = folder_user.manage_records
                            if manage_users != perm.manage_users or manage_records != perm.manage_records:
                                update_users.append(sfu)
                        else:
                            user_keys = vault.keeper_auth.get_user_keys(username)
                            if not user_keys:
                                continue
                            keep_users.add(username)
                            if user_keys.rsa:
                                rsa_key = crypto.load_rsa_public_key(user_keys.rsa)
                                sfu.typedSharedFolderKey.encryptedKey = crypto.encrypt_rsa(shared_folder_key, rsa_key)
                                sfu.typedSharedFolderKey.encryptedKeyType = folder_pb2.EncryptedKeyType.encrypted_by_public_key
                            elif user_keys.ec:
                                ec_key = crypto.load_ec_public_key(user_keys.ec)
                                sfu.typedSharedFolderKey.encryptedKey = crypto.encrypt_ec(shared_folder_key, ec_key)
                                sfu.typedSharedFolderKey.encryptedKeyType = folder_pb2.EncryptedKeyType.encrypted_by_public_key_ecc
                            else:
                                continue
                            add_users.append(sfu)
                except Exception as e:
                    utils.get_logger().debug('Shared folder key encrypt error: %s', e)
                    continue

            update_defaults = False
            if full_sync:
                for prop in ('manage_users', 'manage_records', 'can_edit', 'can_share'):
                    if hasattr(fol, prop) and hasattr(shared_folder, f'default_{prop}'):
                        b1 = getattr(fol, prop) is True
                        b2 = getattr(shared_folder, f'default_{prop}') is True
                        if b2 != b1:
                            update_defaults = True
                            break

                if len(keep_teams) > 0 or len(keep_users) > 0:
                    remove_users.extend(x for x in existing_users.difference(keep_users))
                    remove_teams.extend(x for x in existing_teams.difference(keep_teams))
            else:
                update_users.clear()
                update_teams.clear()

            request_v3 = folder_pb2.SharedFolderUpdateV3Request()
            request_v3.sharedFolderUid = utils.base64_url_decode(shared_folder_uid)
            request_v3.forceUpdate = True

            # request_v3.fromTeamUid = ...
            if update_defaults:
                if isinstance(fol.manage_records, bool):
                    request_v3.defaultManageRecords = \
                        folder_pb2.BOOLEAN_TRUE if fol.manage_records else folder_pb2.BOOLEAN_FALSE
                if isinstance(fol.manage_users, bool):
                    request_v3.defaultManageUsers = \
                        folder_pb2.BOOLEAN_TRUE if fol.manage_users else folder_pb2.BOOLEAN_FALSE
                if isinstance(fol.can_edit, bool):
                    request_v3.defaultCanEdit = \
                        folder_pb2.BOOLEAN_TRUE if fol.can_edit else folder_pb2.BOOLEAN_FALSE
                if isinstance(fol.can_share, bool):
                    request_v3.defaultCanShare = \
                        folder_pb2.BOOLEAN_TRUE if fol.can_share else folder_pb2.BOOLEAN_FALSE

            if len(add_users) > 0:
                request_v3.sharedFolderAddUser.extend(add_users)
            if len(add_teams) > 0:
                request_v3.sharedFolderAddTeam.extend(add_teams)
            if len(update_users) > 0:
                request_v3.sharedFolderUpdateUser.extend(update_users)
            if len(update_teams) > 0:
                request_v3.sharedFolderUpdateTeam.extend(update_teams)
            if len(remove_users) > 0:
                request_v3.sharedFolderRemoveUser.extend(remove_users)
            if len(remove_teams) > 0:
                request_v3.sharedFolderRemoveTeam.extend((utils.base64_url_decode(x) for x in remove_teams))

            if (request_v3.sharedFolderAddUser or request_v3.sharedFolderAddTeam or
                    request_v3.sharedFolderUpdateUser or request_v3.sharedFolderUpdateTeam or
                    request_v3.sharedFolderRemoveUser or request_v3.sharedFolderRemoveTeam or update_defaults):
                folder_permissions.append(request_v3)

    return folder_permissions


@attrs.define
class UserPermissionSummary:
    teams_added: int = 0
    teams_updated: int = 0
    teams_removed: int = 0
    users_added: int = 0
    users_updated: int = 0
    users_removed: int = 0


def import_user_permissions(vault: vault_online.VaultOnline,
                            shared_folders: List[import_data.SharedFolder],
                            full_sync=False) -> UserPermissionSummary:
    summary = UserPermissionSummary()
    if not shared_folders:
        return summary

    folders = [x for x in shared_folders if isinstance(x, import_data.SharedFolder) and x.permissions]
    if not folders:
        return summary

    folder_lookup: Dict[str, Tuple[str, vault_types.FolderTypes]] = {}
    for fol in vault.vault_data.folders():
        f_key = '{0}|{1}'.format((fol.name or '').casefold().strip(), fol.parent_uid or '')
        folder_lookup[f_key] = fol.folder_uid, fol.folder_type

    for sh_fol in folders:
        if not sh_fol.path:
            continue
        comps = list(vault_utils.parse_folder_path(sh_fol.path, path_delimiter=import_data.PathDelimiter))
        parent_uid = ''
        for i in range(len(comps)):
            is_last = False
            if i == len(comps) - 1:
                is_last = True
            comp = comps[i]
            if not comp:
                continue
            f_key = '{0}|{1}'.format(comp.casefold(), parent_uid)
            if f_key in folder_lookup:
                parent_uid, fol_type = folder_lookup[f_key]
                if is_last and fol_type == 'shared_folder':
                    sh_fol.uid = parent_uid
            else:
                break

    existing_shared_folders = {x.shared_folder_uid for x in vault.vault_data.shared_folders()}
    folders = [x for x in folders if x.uid and x.uid in existing_shared_folders]
    if folders:
        permissions = prepare_folder_permission(vault, folders, full_sync)
        if permissions:
            while len(permissions) > 0:
                chunk = permissions[:999]
                permissions = permissions[999:]
                rqs = folder_pb2.SharedFolderUpdateV3RequestV2()
                for rq in chunk:
                    if isinstance(rq, folder_pb2.SharedFolderUpdateV3Request):
                        rqs.sharedFoldersUpdateV3.append(rq)
                try:
                    rss = vault.keeper_auth.execute_auth_rest(
                        'vault/shared_folder_update_v3', rqs, payload_version=1,
                        response_type=folder_pb2.SharedFolderUpdateV3ResponseV2)
                    assert rss is not None
                    for rs in rss.sharedFoldersUpdateV3Response:
                        if rs.status == 'success':
                            if len(rs.sharedFolderAddUserStatus) > 0:
                                summary.users_added += len([x for x in rs.sharedFolderAddUserStatus if x.status == 'success'])
                            if len(rs.sharedFolderAddTeamStatus) > 0:
                                summary.teams_added += len([x for x in rs.sharedFolderAddTeamStatus if x.status == 'success'])
                            if len(rs.sharedFolderUpdateUserStatus) > 0:
                                summary.users_updated += len([x for x in rs.sharedFolderUpdateUserStatus if x.status == 'success'])
                            if len(rs.sharedFolderUpdateTeamStatus) > 0:
                                summary.teams_updated += len([x for x in rs.sharedFolderUpdateTeamStatus if x.status == 'success'])
                            if len(rs.sharedFolderRemoveUserStatus) > 0:
                                summary.users_removed += len([x for x in rs.sharedFolderRemoveUserStatus if x.status == 'success'])
                            if len(rs.sharedFolderRemoveTeamStatus) > 0:
                                summary.teams_removed += len([x for x in rs.sharedFolderRemoveTeamStatus if x.status == 'success'])
                        else:
                            shared_folder_uid = utils.base64_url_encode(rs.sharedFolderUid)
                            utils.get_logger().warning('Shared Folder "%s" update error: %s', shared_folder_uid, rs.status)
                except Exception as e:
                    utils.get_logger().warning('Shared Folders update error: %s', e)

    return summary


@attrs.define
class TeamMembershipSummary:
    users_added: int = 0
    users_removed: int = 0
    users_failed: List[str] = attrs.field(factory=list)


def import_teams(enterprise_data: enterprise_types.IEnterpriseData,
                 auth: keeper_auth.KeeperAuth,
                 teams: List[import_data.Team],
                 full_sync: bool=False) -> TeamMembershipSummary:
    summary = TeamMembershipSummary()
    team_lookup: Dict[str, Union[str, List[str]]] = {}
    team_uid: Optional[str]

    for t in enterprise_data.teams.get_all_entities():
        team_uid = t.team_uid
        team_name = t.name
        if team_uid and team_name:
            team_name = team_name.lower()
            if team_name in team_lookup:
                tn = team_lookup[team_name]
                if not isinstance(tn, list):
                    tn = [tn]
                    team_lookup[team_name] = tn
                tn.append(team_uid)
            else:
                team_lookup[team_name] = team_uid

    user_lookup: Dict[str, int] = {}
    for u in enterprise_data.users.get_all_entities():
        if u.status == 'active' and u.lock == 0:
            user_lookup[u.username.lower()] = u.enterprise_user_id

    users_to_add: List[Tuple[str, str]]= []
    users_to_remove: List[Tuple[str, int]] = []
    for team in teams:
        team_uid = None
        if team.uid and isinstance(team.uid, str):
            for v in team_lookup.values():
                if isinstance(v, str):
                    if v == team.uid:
                        team_uid = team.uid
                        break
                elif isinstance(v, list):
                    if team.uid in v:
                        team_uid = team.uid
                        break

        if not team_uid:
            if isinstance(team.name, str):
                name = team.name.lower()
                if name in team_lookup:
                    v = team_lookup[name]
                    if isinstance(v, str):
                        team_uid = v
                    elif isinstance(v, list):
                        summary.users_failed.append(f'There are more than one teams with name \"{team.name}\".')

        if team_uid and isinstance(team.members, list):
            current_members = set((x.enterprise_user_id for x in enterprise_data.team_users.get_all_links() if x.team_uid == team_uid))
            keep_members = set()
            for email in team.members:
                if isinstance(email, str):
                    email = email.lower()
                    if email in user_lookup:
                        user_id = user_lookup[email]
                        keep_members.add(user_id)
                        if user_id not in current_members:
                            users_to_add.append((email, team_uid))
            if full_sync and len(keep_members) > 0:
                users_to_remove.extend(((team_uid, x) for x in current_members.difference(keep_members)))

    rqs = []
    if len(users_to_add) > 0:
        emails = set((x[0] for x in users_to_add))
        auth.load_user_public_keys(emails, send_invites=False)
        team_uids = set((x[1] for x in users_to_add))
        auth.load_team_keys(team_uids)

        for email, team_uid in users_to_add:
            team_keys = auth.get_team_keys(team_uid)
            user_keys = auth.get_user_keys(email)
            if team_keys and user_keys:
                if team_keys.aes and user_keys.rsa:
                    try:
                        rsa_key = crypto.load_rsa_public_key(user_keys.rsa)
                        team_key = team_keys.aes

                        rqs.append({
                            'command': 'team_enterprise_user_add',
                            'team_uid': team_uid,
                            'enterprise_user_id': user_lookup[email],
                            'user_type': 0,
                            'team_key': utils.base64_url_encode(crypto.encrypt_rsa(team_key, rsa_key)),
                            'team_key_type': 'encrypted_by_public_key'
                        })
                    except Exception as e:
                        summary.users_failed.append(f'Add user {email} to team {team_uid} error: {e}')

    if len(users_to_remove) > 0:
        rqs.extend(({
            'command': 'team_enterprise_user_remove',
            'team_uid': team_uid,
            'enterprise_user_id': user_id,
        } for team_uid, user_id in users_to_remove))
    if rqs:
        rs = auth.execute_batch(rqs)
        if rs:
            for q, s in zip(rqs, rs):
                command = q.get('command') or ''
                if s.get('result') == 'success':
                    if command == 'team_enterprise_user_add':
                        summary.users_added += 1
                    elif command == 'team_enterprise_user_remove':
                        summary.users_removed += 1
                else:
                    tuid = q.get('team_uid') or ''
                    summary.users_failed.append(f'{command}: Team UID={tuid} failed: {s.get("message")}')
    return summary
