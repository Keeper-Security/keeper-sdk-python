import datetime
import enum
import itertools
import json
import math
from typing import Optional, Dict, Union, Set, Any, Iterable, List, Tuple

from . import record_types, vault_storage, storage_types, vault_record, vault_types
from .. import utils, crypto


def resolve_record_access_path(storage: vault_storage.IVaultStorage, path: Dict[str, Any],
                               for_edit: bool=False, for_share: bool=False) -> bool:
    record_uid = path.get('record_uid')
    if not record_uid:
        return False

    for rmd in storage.record_keys.get_links_by_subject(record_uid):
        if for_edit and not rmd.can_edit:
            continue
        if for_share and not rmd.can_share:
            continue
        if rmd.encrypter_uid == storage.personal_scope_uid:
            return True
        for sfmd in storage.shared_folder_keys.get_links_by_subject(rmd.encrypter_uid):
            shared_folder = storage.shared_folders.get_entity(sfmd.shared_folder_uid)
            if not shared_folder:
                continue
            if sfmd.encrypter_uid == storage.personal_scope_uid:
                path['shared_folder_uid'] = sfmd.shared_folder_uid
                return True
            team = storage.teams.get_entity(sfmd.encrypter_uid)
            if not team:
                continue
            if for_edit and team.restrict_edit:
                continue
            if for_share and team.restrict_share:
                continue
            path['shared_folder_uid'] = sfmd.shared_folder_uid
            path['team_uid'] = sfmd.encrypter_uid
            return True

    return False


def extract_password_record(record: vault_record.PasswordRecord) -> Tuple[dict, dict, Optional[List[str]]]:
    if not isinstance(record, vault_record.PasswordRecord):
        raise Exception('extract_password_record: Invalid object type')

    data = {
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

    extra: Dict[str, Any] = record.unparsed_extra or {}
    file_ids: Optional[List[str]] = None

    if 'files' not in extra:
        extra['files'] = []
    if record.attachments:
        file_ids = []
        for atta in record.attachments:
            file_ids.append(atta.id)
            file_ids.extend((x.id for x in atta.thumbnails if x.id))
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

    fields = extra.get('fields')
    if not isinstance(fields, list):
        fields = list()
        extra['fields'] = fields
    totp_field = next((x for x in fields if x.get('field_type') == 'totp'), None)
    if record.totp:
        if totp_field is None:
            totp_field = {
                'id': utils.base64_url_encode(crypto.get_random_bytes(8)),
                'field_type': 'totp',
                'field_title': ''
            }
            fields.append(totp_field)
        totp_field['data'] = record.totp
    else:
        if totp_field:
            fields.remove(totp_field)

    return data, extra, file_ids


def extract_typed_field(field: vault_record.TypedField) -> Dict[str, Any]:
    field_values = []
    field_type: Optional[record_types.FieldType] = None
    multiple = record_types.Multiple.Never

    if field.type in record_types.RecordFields:
        field_id = record_types.RecordFields[field.type]
        multiple = record_types.RecordFields[field.type].multiple
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
                if value is None:
                    continue
                if field_type:
                    if not isinstance(value, type(field_type.value)):
                        continue
                    if isinstance(value, dict) and isinstance(field_type.value, dict):
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


def extract_typed_record_data(record: vault_record.TypedRecord, schema: Optional[vault_types.RecordType]) -> Dict[str, Any]:
    data: Dict[str, Any] = {
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
            key = f'{(field.type or "text").lower()}:{(field.label or "").lower()}'
            if key in fields:
                index = fields.pop(key)
                data['fields'][index] = extract_typed_field(field)
            else:
                data['custom'].append(extract_typed_field(field))
        nones = [i for i in range(len(data['fields'])) if data['fields'][i] is None]
        for index in nones:
            rt_field = schema.fields[index]
            data['fields'][index] = {
                'type': rt_field.type or 'text',
                'label': rt_field.label or '',
                'value': []
            }
    else:
        for field in record.fields:
            data['fields'].append(extract_typed_field(field))
        for field in record.custom:
            data['custom'].append(extract_typed_field(field))
    return data


def extract_file_record_data(record: vault_record.FileRecord) -> Dict[str, Any]:
    return {
        'title': record.title or '',
        'type': record.mime_type,
        'size': record.size,
        'name': record.file_name,
        'lastModified': utils.current_milli_time()
    }


def extract_record_attachment_ids(record: vault_record.KeeperRecord) -> Set[str]:
    attachment_ids: Set[str] = set()
    if isinstance(record, vault_record.TypedRecord):
        file_ref = record.get_typed_field('fileRef')
        if isinstance(file_ref, vault_record.TypedField) and isinstance(file_ref.value, list):
            attachment_ids.union(file_ref.value)
    elif isinstance(record, vault_record.PasswordRecord) and isinstance(record.attachments, list):
        attachment_ids.union((x.id for x in record.attachments))
    elif isinstance(record, vault_record.FileRecord):
        attachment_ids.add(record.record_uid)

    return attachment_ids


def extract_audit_data(record: Union[vault_record.KeeperRecord, vault_record.TypedRecord]) -> Optional[Dict[str, Any]]:
    url = record.extract_url()
    title = record.title
    if isinstance(record, vault_record.PasswordRecord):
        record_type = ''
    elif isinstance(record, vault_record.TypedRecord):
        record_type = record.record_type
    else:
        return None

    if title is None:
        title = ''
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
    if record_type:
        audit_data['record_type'] = record_type
    if url:
        audit_data['url'] = utils.url_strip(url)
    return audit_data


def extract_typed_record_refs(record: vault_record.TypedRecord) -> Set[str]:
    refs = set()
    for field in itertools.chain(record.fields, record.custom):
        if field.type in {'fileRef', 'addressRef', 'cardRef'}:
            if isinstance(field.value, list):
                for ref in field.value:
                    if isinstance(ref, str):
                        refs.add(ref)
    return refs


def get_padded_json_bytes(data: Dict[str, Any]) -> bytes:
    data_str = json.dumps(data)
    padding = int(math.ceil(max(384, len(data_str)) / 16) * 16)
    if padding:
        data_str = data_str.ljust(padding)
    return data_str.encode('utf-8')


def get_record_description(record: vault_record.KeeperRecord) -> str:
    comps: List[str] = []

    if isinstance(record, vault_record.PasswordRecord):
        comps.extend((record.login or '', record.link or ''))
        return ' @ '.join((str(x) for x in comps if x))

    if isinstance(record, vault_record.TypedRecord):
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

    if isinstance(record, vault_record.FileRecord):
        comps.extend((record.file_name, utils.size_to_str(record.size)))
        return ': '.join((str(x) for x in comps if x))

    return ''


def load_keeper_record_type(store_record_type: storage_types.StorageRecordType) -> vault_types.RecordType:
    record_type = vault_types.RecordType()
    record_type.id = store_record_type.id
    record_type.scope = store_record_type.scope
    content = json.loads(store_record_type.content)
    record_type.name = content.get('$id', '')
    record_type.description = content.get('description', '')
    fields = content.get('fields')
    if isinstance(fields, list):
        rfs: List[vault_types.RecordTypeField] = []
        for field in fields:
            record_field = vault_types.RecordTypeField()
            record_field.type = field.get('$ref', '')
            record_field.label = field.get('label', '')
            record_field.required = field.get('required', False)
            rfs.append(record_field)

        record_type.fields = rfs
    return record_type


RECORD_FIELD_ID_TO_SKIP = {'password', 'pinCode', 'oneTimeCode', 'keyPair', 'licenseNumber'}
FIELD_TYPE_TO_SKIP = {'secret', 'otp', 'privateKey'}
FIELD_TYPE_ENTIRE = {'email'}


def get_record_words(record: vault_record.KeeperRecord) -> Iterable[str]:
    if isinstance(record, vault_record.KeeperRecord):
        for record_field, field_label, values in record.enumerate_fields():
            if field_label:
                for t in utils.tokenize_searchable_text(field_label.lower()):
                    yield t
            if not values:
                continue
            if record_field in record_types.RecordFields:
                if record_field in RECORD_FIELD_ID_TO_SKIP:
                    continue
                else:
                    record_field = record_types.RecordFields[record_field].type
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
                        dt = datetime.datetime.fromtimestamp(value / 1000)
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


def adjust_typed_record(record: vault_record.TypedRecord, record_type: vault_types.RecordType) -> bool:
    if not isinstance(record, vault_record.TypedRecord):
        return False
    if not isinstance(record_type, vault_types.RecordType):
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
        ignore_label = schema_field.type in record_types.RecordFields
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

        field = vault_record.TypedField.create_schema_field(schema_field)
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

class RecordChangeStatus(enum.Flag):
    Title = enum.auto()
    RecordType = enum.auto()
    Username = enum.auto()
    Password = enum.auto()
    URL = enum.auto()

def compare_records(record1: Union[vault_record.PasswordRecord, vault_record.TypedRecord],
                    record2: Union[vault_record.PasswordRecord, vault_record.TypedRecord]) -> RecordChangeStatus:
    status = RecordChangeStatus(0)

    if record1.title != record2.title:
        status = status | RecordChangeStatus.Title
    if isinstance(record1, vault_record.PasswordRecord) and isinstance(record2, vault_record.PasswordRecord):
        if record1.login != record2.login:
            status = status | RecordChangeStatus.Username
        if record1.password != record2.password:
            status = status | RecordChangeStatus.Password
        if record1.link != record2.link:
            status = status | RecordChangeStatus.URL
    elif isinstance(record1, vault_record.TypedRecord) and isinstance(record2, vault_record.TypedRecord):
        if record1.record_type != record2.record_type:
            status = status | RecordChangeStatus.RecordType

        r_login = record1.get_typed_field('login') or record1.get_typed_field('email')
        e_login = record2.get_typed_field('login') or record2.get_typed_field('email')
        if r_login or e_login:
            if r_login and e_login:
                if (r_login.get_external_value() or '') != (e_login.get_external_value() or ''):
                    status = status | RecordChangeStatus.Username
            else:
                status = status | RecordChangeStatus.Username

        r_password = record1.get_typed_field('password')
        e_password = record2.get_typed_field('password')
        if r_password or e_password:
            if r_password and e_password:
                if (r_password.get_external_value() or '') != (e_password.get_external_value() or ''):
                    status = status | RecordChangeStatus.Password
            else:
                status = status | RecordChangeStatus.Password

        r_url = record1.get_typed_field('url')
        e_url = record2.get_typed_field('url')
        if r_url or e_url:
            if r_url and e_url:
                if (r_url.get_external_value() or '') != (e_url.get_external_value() or ''):
                    status = status | RecordChangeStatus.URL
            else:
                status = status | RecordChangeStatus.URL

    return status
