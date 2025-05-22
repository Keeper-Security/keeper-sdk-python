import json

from typing import List, Dict

from . import vault_online, record_types
from ..proto import record_pb2


def create_custom_record_type(vault: vault_online.VaultOnline, title: str, fields: List[Dict[str, str]], description: str) -> str:
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
        if field_name not in record_types.FieldTypes:
            raise ValueError(f"Field '{field_name}' is not a valid RecordField.")
        field_definitions.append({"$ref": field_name})

    record_type_data = {
        "$id": title,
        "description": description,
        "categories": ["note"],
        "fields": field_definitions
    }

    request_payload = record_pb2.RecordType()
    request_payload.content = json.dumps(record_type_data)
    request_payload.scope = record_pb2.RecordTypeScope.RT_ENTERPRISE

    response = vault.keeper_auth.execute_auth_rest('vault/record_type_add', request_payload, response_type=record_pb2.RecordTypeModifyResponse)

    return f"Custom record type '{title}' created successfully with fields: {[f['$ref'] for f in field_definitions]} and recordTypeId: {response.recordTypeId}"