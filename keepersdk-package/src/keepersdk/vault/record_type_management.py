import json
import tabulate

from typing import List, Dict, Optional

from . import vault_online, record_types, record_type_utils, storage_types
from ..proto import record_pb2

def create_custom_record_type(vault: vault_online.VaultOnline, title: str, fields: List[Dict[str, str]], description: str, categories: List[str] = None):
    is_enterprise_admin = vault.keeper_auth.auth_context.is_enterprise_admin
    if not is_enterprise_admin:
        raise ValueError('This command is restricted to Keeper Enterprise administrators.')

    if not fields:
        raise ValueError('At least one field must be specified.')

    field_definitions = []
    for field in fields:
        field_name = field.get("$ref")
        if not field_name:
            raise ValueError("Each field must contain a '$ref' key.")
        if field_name not in record_types.FieldTypes and field_name not in record_types.RecordFields:
            raise ValueError(f"Field '{field_name}' is not a valid RecordField.")
        field_definitions.append({"$ref": field_name})

    record_type_data = {
        "$id": title,
        "description": description,
        "categories": categories if categories else [],
        "fields": field_definitions
    }

    request_payload = record_pb2.RecordType()
    request_payload.content = json.dumps(record_type_data)
    request_payload.scope = record_pb2.RecordTypeScope.RT_ENTERPRISE

    response = vault.keeper_auth.execute_auth_rest('vault/record_type_add', request_payload, response_type=record_pb2.RecordTypeModifyResponse)

    return response


def edit_custom_record_types(vault: vault_online.VaultOnline, record_type_id: int, title: str, fields: List[Dict[str, str]], description: str, categories: List[str] = None):
    is_enterprise_admin = vault.keeper_auth.auth_context.is_enterprise_admin
    if not is_enterprise_admin:
        raise ValueError('This command is restricted to Keeper Enterprise administrators.')

    if not fields:
        raise ValueError('At least one field must be specified.')

    is_enterprise_rt, real_type_id = record_type_utils.isEnterpriseRecordType(record_type_id)

    if not is_enterprise_rt:
        raise ValueError('Only custom record types can be modified.')

    field_definitions = []
    for field in fields:
        field_name = field.get("$ref")
        if not field_name:
            raise ValueError("Each field must contain a '$ref' key.")
        if field_name not in record_types.FieldTypes and field_name not in record_types.RecordFields:
            raise ValueError(f"Field '{field_name}' is not a valid RecordField.")
        field_definitions.append({"$ref": field_name})

    record_type_data = {
        "$id": title,
        "description": description,
        "categories": categories if categories else [],
        "fields": field_definitions
    }

    request_payload = record_pb2.RecordType()
    request_payload.content = json.dumps(record_type_data)
    request_payload.scope = record_pb2.RT_ENTERPRISE
    request_payload.recordTypeId = real_type_id

    response = vault.keeper_auth.execute_auth_rest('vault/record_type_update', request_payload, response_type=record_pb2.RecordTypeModifyResponse)

    return response


def delete_custom_record_types(vault: vault_online.VaultOnline, record_type_id: int):
    is_enterprise_admin = vault.keeper_auth.auth_context.is_enterprise_admin
    if not is_enterprise_admin:
        raise ValueError('This command is restricted to Keeper Enterprise administrators.')
    
    is_enterprise_rt, real_type_id = record_type_utils.isEnterpriseRecordType(record_type_id)

    if not is_enterprise_rt:
        raise ValueError('Only custom record types can be removed.')

    request_payload = record_pb2.RecordType()
    request_payload.scope = record_pb2.RT_ENTERPRISE
    request_payload.recordTypeId = real_type_id

    response = vault.keeper_auth.execute_auth_rest('vault/record_type_delete', request_payload, response_type=record_pb2.RecordTypeModifyResponse)

    return response


def record_type_info(
    vault: vault_online.VaultOnline,
    field_name: Optional[str] = None,
    record_type_name: Optional[str] = None,
    example: Optional[bool] = None,
):
    #field types
    if field_name is not None:
        # List all field types
        if field_name.strip() == '' or field_name.strip() == '*':
            rows = []
            recordfield_names = {rf.name for rf in record_types.RecordFields.values()}
            for ft in record_types.FieldTypes.values():
                lookup = ft.name if ft.name in recordfield_names else ""
                multiple = (
                    record_types.RecordFields[ft.name].multiple.name
                    if lookup else "Optional"
                )
                rows.append([
                    ft.name,
                    lookup,
                    multiple,
                    ft.description
                ])
            headers = ('Field Type ID', 'Lookup', 'Multiple', 'Description')
            return tabulate.tabulate(rows, headers=headers, tablefmt='simple')
        # Fetch a specific field type
        else:
            ft = record_types.FieldTypes.get(field_name)
            recordfield_names = {rf.name for rf in record_types.RecordFields.values()}
            if not ft:
                raise ValueError(f"Field type '{field_name}' is not a valid RecordField.")
            lookup = ft.name if ft.name in recordfield_names else ""
            multiple = (
                record_types.RecordFields[field_name].multiple.name
                if lookup else "Optional"
            )
            row = [
                ft.name,
                lookup,
                multiple,
                ft.description
            ]
            headers = ('Field Type ID', 'Lookup', 'Multiple', 'Description')
            return tabulate.tabulate([row], headers=headers, tablefmt='simple')

    # Handle record type example
    if record_type_name and record_type_name != '*' and record_type_name != '' and example:
        record_type_example = record_type_utils.get_record_type_example(vault, record_type_name)
        return record_type_example

    # Record Types
    if record_type_name and record_type_name != '*' and record_type_name != '':
        record_type = vault.vault_data.get_record_type_by_name(record_type_name)
        if not record_type:
            return f"Record type '{record_type_name}' not found."

        rows = []
        fields = record_type.fields
        scope_int = record_type.scope
        scope = (
            "Standard" if scope_int == storage_types.RecordTypeScope.Standard else
            "User" if scope_int == storage_types.RecordTypeScope.User else
            "Enterprise" if scope_int == storage_types.RecordTypeScope.Enterprise else
            str(scope_int)
        )
        rows.append([
            record_type.id,
            record_type.name,
            scope,
            fields[0].label if hasattr(fields[0], 'label') else str(fields[0])
        ])
        for field in fields[1:]:
            rows.append(['', '', '', field.label if hasattr(field, 'label') else str(field)])

        headers = ('id', 'name', 'scope', 'fields')
        return tabulate.tabulate(rows, headers=headers, tablefmt='simple')
    else:
        records = record_type_utils.get_record_types(vault)
        if not records:
            return "No record types found."

        rows = []
        for rtid, name, scope in records:
            rows.append([rtid, name, scope])

        headers = ('Record Type ID', 'Record Type Name', 'Record Type Scope')
        return tabulate.tabulate(rows, headers=headers, tablefmt='simple')
