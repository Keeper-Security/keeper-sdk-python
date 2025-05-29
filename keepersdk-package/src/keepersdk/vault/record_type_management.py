import json

from typing import List, Dict

from . import vault_online, record_types
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

    num_rts_per_scope = 1000000
    enterprise_scope = record_pb2.RT_ENTERPRISE
    min_id = num_rts_per_scope * enterprise_scope
    max_id = min_id + num_rts_per_scope
    is_enterprise_rt = min_id < record_type_id <= max_id
    real_type_id = record_type_id % num_rts_per_scope

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
    request_payload.scope = enterprise_scope
    request_payload.recordTypeId = real_type_id

    response = vault.keeper_auth.execute_auth_rest('vault/record_type_update', request_payload, response_type=record_pb2.RecordTypeModifyResponse)

    return response


def delete_custom_record_types(vault: vault_online.VaultOnline, record_type_id: int):
    is_enterprise_admin = vault.keeper_auth.auth_context.is_enterprise_admin
    if not is_enterprise_admin:
        raise ValueError('This command is restricted to Keeper Enterprise administrators.')

    num_rts_per_scope = 1_000_000
    enterprise_scope = record_pb2.RT_ENTERPRISE
    min_id = num_rts_per_scope * enterprise_scope
    max_id = min_id + num_rts_per_scope
    is_enterprise_rt = min_id < record_type_id <= max_id
    real_type_id = record_type_id % num_rts_per_scope

    if not is_enterprise_rt:
        raise ValueError('Only custom record types can be removed.')

    request_payload = record_pb2.RecordType()
    request_payload.scope = enterprise_scope
    request_payload.recordTypeId = real_type_id

    response = vault.keeper_auth.execute_auth_rest('vault/record_type_delete', request_payload, response_type=record_pb2.RecordTypeModifyResponse)

    return response

