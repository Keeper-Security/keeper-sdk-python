import json

from . import vault_online, storage_types, record_types, vault_types
from ..proto import record_pb2

def get_record_type_example(vault: vault_online.VaultOnline, record_type_name: str) -> str:
    STR_VALUE = 'text'

    result = ''
    rte = {}
    record_type = vault.vault_data.get_record_type_by_name(record_type_name)
    if record_type:
        record_type_fields = record_type.fields
        rte = {
            'type': record_type_name,
            'title': STR_VALUE,
            'notes': STR_VALUE,
            'fields': [],
            'custom': []
        }

        fields = record_type.fields or []
        fields = [x.label for x in fields]
        for fname in fields:
            ft = get_field_type(fname)
            if not ft:
                ft = {
                    'id': fname,
                    'type': 'text',
                    'valueType': 'string',
                    'value': '',
                    'sample': 'unknown type'
                }

            required = next((x.required for x in record_type_fields if x.label == fname), None)
            label = next((x.label for x in record_type_fields if x.label == fname), None)

            val = {
                'type': fname,
                'value': [ft.get('value')],
                'required': required,
                'label': label
            }

            if fname not in ('fileRef', 'addressRef', 'cardRef'):
                if fname == 'phone' and 'sample' in ft and 'region' in ft['sample']:
                    ft['sample']['region'] = 'US'

            rte['fields'].append(val)
    else:
        raise ValueError(f'No record type found with name {record_type_name}. Use "record-type-info" to list all record types')

    result = json.dumps(rte, indent=2) if rte else ''
    return result


def get_record_types(vault:vault_online.VaultOnline) -> list[vault_types.RecordType]:
        records = []  # (recordTypeId, name, scope)
        record_types = vault.vault_data.get_record_types()

        if record_types:
            for record_type in record_types:
                name = record_type.name
                scope = get_record_type_scope(record_type.scope)
                records.append((record_type.id, name, scope))

        return records


def get_field_type(id):
    ftypes = [
        {**vars(record_types.RecordFields[rkey]), **vars(record_types.FieldTypes[fkey])}
        for rkey in record_types.RecordFields
        for fkey in record_types.FieldTypes
        if record_types.RecordFields[rkey].type == record_types.FieldTypes[fkey].name
    ]
    ids = [ft for ft in ftypes if id and (id == ft.get('name'))]
    result = ids[0] if ids else {}
    if result:
        # Determine value based on whether the id matches a FieldType or RecordField
        field_type_obj = next((ft for ft in record_types.FieldTypes.values() if ft.name == id), None)
        record_field_obj = next((rf for rf in record_types.RecordFields.values() if rf.name == id), None)

        if field_type_obj:
            value = getattr(field_type_obj, 'value', None)
        elif record_field_obj:
            value = getattr(record_field_obj, 'type', None)
        else:
            value = None

        result = {
            'id': result.get('$id') or result.get('name') or '',
            'type': result.get('type') or result.get('name') or '',
            'value': value,
        }
    return result


def isEnterpriseRecordType(record_type_id: int) -> bool:
    num_rts_per_scope = 1_000_000
    enterprise_scope = record_pb2.RT_ENTERPRISE
    min_id = num_rts_per_scope * enterprise_scope
    max_id = min_id + num_rts_per_scope
    is_enterprise_rt = min_id < record_type_id <= max_id
    real_type_id = record_type_id % num_rts_per_scope

    return is_enterprise_rt, real_type_id


def get_field_definitions(field: record_types.FieldType):
    recordfield_names = {rf.name for rf in record_types.RecordFields.values()}
    lookup = field.name if field.name in recordfield_names else ""
    multiple = (
        record_types.RecordFields[field.name].multiple.name
        if lookup else "Optional"
    )
    row = [
        field.name,
        lookup,
        multiple,
        field.description
    ]
    return row


scope_map = {
    storage_types.RecordTypeScope.Standard: 'Standard',
    storage_types.RecordTypeScope.User: 'User',
    storage_types.RecordTypeScope.Enterprise: 'Enterprise'
}


def get_record_type_scope(scope: storage_types.RecordTypeScope) -> str:
    return scope_map.get(scope, str(scope))


def validate_record_type_file(file_path: str) -> list:
    if not file_path:
        raise ValueError('File path is required.')

    if not file_path.endswith('.json'):
        raise ValueError('Record type file must be a JSON file.')

    try:
        with open(file_path, 'r') as f:
            json_obj = json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f'Invalid JSON in record type file: {e}')
    except FileNotFoundError:
        raise ValueError(f'Record type file not found: {file_path}')
    
    if not isinstance(json_obj, dict):
        raise ValueError('Invalid custom record types file')

    record_types_list = json_obj.get('record_types')

    if not isinstance(record_types_list, list):
        raise ValueError('Invalid custom record types list')
    
    return record_types_list