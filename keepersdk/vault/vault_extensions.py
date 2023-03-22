#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper SDK
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import datetime
import itertools
import json
import math
from typing import Optional, Dict, Union, Set, Any, Iterable

from . import record_types
from .vault_record import KeeperRecord, PasswordRecord, TypedRecord, TypedField, FileRecord, ApplicationRecord
from .vault_types import RecordType
from .. import utils, crypto


def resolve_record_access_path(storage, path, for_edit=False, for_share=False):
    # type: (vault_storage.IVaultStorage, dict, bool, bool) -> bool
    record_uid = path.get('record_uid')
    if not path:
        return False

    for rmd in storage.record_keys.get_links_for_subject(record_uid):
        if for_edit and not rmd.can_edit:
            continue
        if for_share and not rmd.can_share:
            continue
        if rmd.shared_folder_uid == storage.personal_scope_uid:
            return True
        for sfmd in storage.shared_folder_keys.get_links_for_subject(rmd.shared_folder_uid):
            shared_folder = storage.shared_folders.get_entity(sfmd.shared_folder_uid)
            if not shared_folder:
                continue
            if sfmd.team_uid == storage.personal_scope_uid:
                path['shared_folder_uid'] = sfmd.shared_folder_uid
                return True
            team = storage.teams.get_entity(sfmd.team_uid)
            if not team:
                continue
            if for_edit and team.restrict_edit:
                continue
            if for_share and team.restrict_share:
                continue
            path['shared_folder_uid'] = sfmd.shared_folder_uid
            path['team_uid'] = sfmd.team_uid
            return True

    return False


def extract_password_record_data(record):  # type: (PasswordRecord) -> dict
    if isinstance(record, PasswordRecord):
        return {
            'title': record.title,
            'secret1': record.login,
            'secret2': record.password,
            'link': record.link,
            'notes': record.notes,
            'custom': [{
                'name': x.name or '',
                'value': x.value or '',
                'type': x.type or 'text',
            } for x in record.custom]
        }
    else:
        raise Exception(f'extract_password_record_data: Invalid object type')


def extract_password_record_extras(record, existing_extra=None):
    # type: (PasswordRecord, Optional[dict]) -> dict
    if isinstance(record, PasswordRecord):
        extra = existing_extra if isinstance(existing_extra, dict) else {}

        if 'fields' not in extra:
            extra['fields'] = []

        extra['files'] = []
        if record.attachments:
            for atta in record.attachments:
                extra_file = {
                    'id': atta.id,
                    'key': atta.key,
                    'name': atta.name,
                    'size': atta.size,
                    'type': atta.mime_type,
                    'title': atta.title,
                    'lastModified': atta.last_modified,
                    'thumbs': [{'id': x.id, 'type': x.type, 'size': x.size} for x in atta.thumbnails or []]
                }
                extra['files'].append(extra_file)
        totp_field = next((x for x in extra['fields'] if x.get('field_type') == 'totp'), None)
        if record.totp:
            if not totp_field:
                totp_field = {
                    'id': utils.base64_url_encode(crypto.get_random_bytes(8)),
                    'field_type': 'totp',
                    'field_title': ''
                }
                extra['fields'].append(totp_field)
            totp_field['data'] = totp_field
        else:
            if totp_field:
                extra['fields'] = [x for x in extra['fields'] if x.get('field_type') == 'totp']
        return extra
    else:
        raise Exception(f'extract_password_record_extra: Invalid record type')


def extract_typed_field(field):     # type: (TypedField) -> dict
    field_values = []
    field_type = None    # type: Optional[record_types.FieldType]
    multiple = record_types.Multiple.Optional

    if field.type in record_types.RecordFieldIds:
        field_id = record_types.RecordFieldIds[field.type]
        multiple = record_types.RecordFieldIds[field.type].multiple
        if field_id.type in record_types.FieldTypes:
            field_type = record_types.FieldTypes[field_id.type]
    elif field.type in record_types.FieldTypes:
        field_type = record_types.FieldTypes[field.type]

    if field.value:
        values = field.value
        if isinstance(values, (str, int, dict)):
            values = [values]
        if isinstance(values, list):
            for value in values:
                if not value:
                    continue
                if field_type:
                    if not isinstance(value, type(field_type.value)):
                        continue
                    if isinstance(value, dict):
                        for key in field_type.value:
                            if key not in value:
                                value[key] = ''
                field_values.append(value)
                if field_type and multiple != record_types.Multiple.Always:
                    break
    result = {
        'type': field.type or 'text',
        'label': field.label or '',
        'value': field_values
    }
    if field.required:
        result['required'] = True
    return result


def extract_typed_record_data(record, schema):     # type: (TypedRecord, Optional[RecordType]) -> dict
    data = {
        'type': (schema.name if schema else record.record_type) or 'login',
        'title': record.title or '',
        'notes': record.notes or '',
        'fields': [],
        'custom': [],
    }
    if schema:
        fields = {f'{(x.type or "text").lower()}:{(x.label or "").lower()}': i for i, x in enumerate(schema.fields)}
        data['fields'].extend(itertools.repeat(None, len(schema.fields)))
        for field in itertools.chain(record.fields, record.custom):
            key = f'{(field.type or "text")}:{(field.label or "").lower()}'
            if key in fields:
                index = fields.pop(key)
                data['fields'][index] = extract_typed_field(field)
            else:
                data['custom'].append(extract_typed_field(field))
        nones = [i for i, x in data['fields'] if x is None]
        for index in nones:
            field = schema.fields[index]
            data['fields'][index] = {
                'type': field.type or 'text',
                'label': field.label or '',
                'value': []
            }
    else:
        for field in record.fields:
            data['fields'].append(extract_typed_field(field))
        for field in record.custom:
            data['custom'].append(extract_typed_field(field))
    return data


def extract_file_record_data(record):    # type: (FileRecord) -> dict
    return {
        'title': record.title or '',
        'type': record.mime_type,
        'size': record.size,
        'name': record.file_name,
        'lastModified': utils.current_milli_time()
    }


def extract_audit_data(record):      # type: (Union[KeeperRecord, TypedRecord]) -> Optional[dict]
    url = ''
    if isinstance(record, PasswordRecord):
        url = record.link
    elif isinstance(record, TypedRecord):
        url_field = record.get_typed_field('url')
        if url_field:
            url = url_field.get_default_value(str)
    else:
        return

    title = record.title or ''
    if url:
        url = utils.url_strip(url)
    else:
        url = ''
    if len(title) + len(url) > 900:
        if len(title) > 900:
            title = title[:900]
        if len(url) > 0:
            url = url[:900]
    audit_data = {
        'title': title
    }
    if isinstance(record, TypedRecord):
        audit_data['record_type'] = record.record_type

    if url:
        audit_data['url'] = utils.url_strip(url)
    return audit_data


def extract_typed_record_refs(record):  # type: (TypedRecord) -> Set[str]
    refs = set()
    for field in itertools.chain(record.fields, record.custom):
        if field.type in {'fileRef', 'addressRef', 'cardRef'}:
            if isinstance(field.value, list):
                for ref in field.value:
                    if isinstance(ref, str):
                        refs.add(ref)
    return refs


def get_padded_json_bytes(data):    # type: (dict) -> bytes
    data_str = json.dumps(data)
    padding = int(math.ceil(max(384, len(data_str)) / 16) * 16)
    if padding:
        data_str = data_str.ljust(padding)
    return data_str.encode('utf-8')


def get_record_description(record):   # type: (KeeperRecord) -> Optional[str]
    comps = []

    if isinstance(record, PasswordRecord):
        comps.extend((record.login or '', record.link or ''))
        return ' @ '.join((str(x) for x in comps if x))

    if isinstance(record, TypedRecord):
        field = next((x for x in record.fields if x.type == 'login'), None)
        if field:
            value = field.get_default_value()
            if value:
                comps.append(field.get_default_value() or '')
                field = next((x for x in record.fields if x.type == 'url'), None)
                if field:
                    comps.append(field.get_default_value())
                else:
                    field = next((x for x in record.fields if x.type == 'host'), None)
                    if field:
                        host = field.get_default_value()
                        if isinstance(host, dict):
                            address = host.get('hostName')
                            if address:
                                port = host.get('port')
                                if port:
                                    address = f'{address}:{port}'
                                comps.append(address)
                return ' @ '.join((str(x) for x in comps if x))

        field = next((x for x in record.fields if x.type == 'paymentCard'), None)
        if field:
            value = field.get_default_value()
            if isinstance(value, dict):
                number = value.get('cardNumber') or ''
                if isinstance(number, str):
                    if len(number) > 4:
                        number = '*' + number[-4:]
                        comps.append(number)

                field = next((x for x in record.fields if x.type == 'text' and x.label == 'cardholderName'), None)
                if field:
                    name = field.get_default_value()
                    if name and isinstance(name, str):
                        comps.append(name.upper())
                return ' / '.join((str(x) for x in comps if x))

        field = next((x for x in record.fields if x.type == 'bankAccount'), None)
        if field:
            value = field.get_default_value()
            if isinstance(value, dict):
                routing = value.get('routingNumber') or ''
                if routing:
                    routing = '*' + routing[-3:]
                account = value.get('accountNumber') or ''
                if account:
                    account = '*' + account[-3:]
                if routing or account:
                    if routing and account:
                        return f'{routing} / {account}'
                    else:
                        return routing if routing else account

        field = next((x for x in record.fields if x.type == 'keyPair'), None)
        if field:
            value = field.get_default_value()
            if isinstance(value, dict):
                if value.get('privateKey'):
                    comps.append('<Private Key>')
                if value.get('publicKey'):
                    comps.append('<Public Key>')
            return ' / '.join((str(x) for x in comps if x))

        field = next((x for x in record.fields if x.type == 'address'), None)
        if field:
            value = field.get_default_value()
            if isinstance(value, dict):
                comps.extend((
                    f'{value.get("street1", "")} {value.get("street2", "")}'.strip(),
                    f'{value.get("city", "")}',
                    f'{value.get("state", "")} {value.get("zip", "")}'.strip(),
                    f'{value.get("country", "")}'))
            return ', '.join((str(x) for x in comps if x))

        field = next((x for x in record.fields if x.type == 'name'), None)
        if field:
            value = field.get_default_value()
            if isinstance(value, dict):
                comps.extend((value.get('first', ''), value.get('middle', ''), value.get('last', '')))
                return ' '.join((str(x) for x in comps if x))

    if isinstance(record, FileRecord):
        comps.extend((record.file_name, utils.size_to_str(record.size)))
        return ': '.join((str(x) for x in comps if x))

    if isinstance(record, ApplicationRecord):
        return ''


def load_keeper_record(record, record_key):
    # type: (storage_types.StorageRecord, bytes) -> Optional[KeeperRecord]
    if record.version in {0, 1, 2}:
        data_bytes = crypto.decrypt_aes_v1(record.data, record_key)
        data_dict = json.loads(data_bytes.decode())
    elif record.version in {3, 4, 5}:
        data_bytes = crypto.decrypt_aes_v2(record.data, record_key)
        data_dict = json.loads(data_bytes.decode())
    else:
        return None

    extra_dict = None   # type: Optional[Dict[str, Any]]
    if record.extra:
        extra_bytes = crypto.decrypt_aes_v1(record.extra, record_key)
        extra_dict = json.loads(extra_bytes.decode())

    udata_dict = None   # type: Optional[Dict[str, Any]]
    if record.udata:
        try:
            udata_dict = json.loads(record.udata)
        except:
            pass

    if record.version in {0, 1, 2}:
        k_record = PasswordRecord()
    elif record.version == 3:
        k_record = TypedRecord()
    elif record.version == 4:
        k_record = FileRecord()
        if udata_dict:
            k_record.storage_size = udata_dict.get('file_size')
    elif record.version == 5:
        k_record = ApplicationRecord()
    else:
        return

    k_record.record_uid = record.record_uid
    k_record.client_time_modified = record.client_modified_time

    k_record.load_record_data(data_dict, extra_dict)

    return k_record


RECORD_FIELD_ID_TO_SKIP = {'password', 'pinCode', 'oneTimeCode', 'keyPair', 'licenseNumber'}
FIELD_TYPE_TO_SKIP = {'secret', 'otp', 'privateKey'}
FIELD_TYPE_ENTIRE = {'email'}


def get_record_words(record):   # type: (KeeperRecord) -> Iterable[str]
    if isinstance(record, KeeperRecord):
        for record_field, field_label, values in record.enumerate_fields():
            if field_label:
                for t in utils.tokenize_searchable_text(field_label.lower()):
                    yield t
            if not values:
                continue
            if record_field in record_types.RecordFieldIds:
                if record_field in RECORD_FIELD_ID_TO_SKIP:
                    continue
                else:
                    record_field = record_types.RecordFieldIds[record_field]
            if record_field in record_types.FieldTypes:
                if record_field in FIELD_TYPE_TO_SKIP:
                    continue
            if not isinstance(values, (tuple, list)):
                values = (values,)
            for value in values:
                if isinstance(value, str):
                    if record_field in FIELD_TYPE_ENTIRE:
                        yield value.lower()
                    else:
                        for t in utils.tokenize_searchable_text(value.lower()):
                            yield t
                elif isinstance(value, int):
                    if record_field == 'date' and value > 0:
                        dt = datetime.datetime.fromtimestamp(value)
                        yield str(dt.year)
                        yield dt.strftime("%B")
                elif isinstance(value, dict):
                    for key in value:
                        v = value[key]
                        if isinstance(v, str):
                            if record_field == 'phone' and key == 'number':
                                v = ''.join((x for x in v if x.isdigit()))
                                if v:
                                    yield v
                            else:
                                for t in utils.tokenize_searchable_text(v.lower()):
                                    yield t


def adjust_typed_record(record, record_type):   # type: (TypedRecord, RecordType) -> bool
    if not isinstance(record, TypedRecord):
        return False
    if not isinstance(record_type, RecordType):
        return False

    new_fields = []
    old_fields = list(record.fields)
    custom = list(record.custom)
    should_rebuild = False
    for schema_field in record_type.fields:
        if not schema_field.type:
            return False
        schema_label = schema_field.label
        required = schema_field.required
        ignore_label = schema_field.type in record_types.RecordFieldIds
        field = next((x for x in old_fields if x.type == schema_field.type and
                      (ignore_label or (x.label or '') == schema_label)), None)
        if field:
            new_fields.append(field)
            old_fields.remove(field)
            if field.label != schema_label:
                field.label = schema_label
                should_rebuild = True
            continue

        field = next((x for x in custom if x.type == schema_field.type and
                      (ignore_label or (x.label or '') == schema_label)), None)
        if field:
            field.required = required
            new_fields.append(field)
            custom.remove(field)
            should_rebuild = True
            continue

        field = TypedField.create_schema_field(schema_field)
        new_fields.append(field)
        should_rebuild = True

    if len(old_fields) > 0:
        custom.extend(old_fields)
        should_rebuild = True

    if record.record_type != record_type.name:
        record.record_type = record_type.name
        should_rebuild = True

    if not should_rebuild:
        should_rebuild = any(x for x in custom if not x.value)

    if should_rebuild:
        record.fields.clear()
        record.fields.extend(new_fields)
        record.custom.clear()
        record.custom.extend((x for x in custom if x.value))

    return should_rebuild
