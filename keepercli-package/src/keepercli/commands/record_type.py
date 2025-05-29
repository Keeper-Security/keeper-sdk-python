import argparse
import json
import logging

from keepersdk.vault import record_type_management

from . import base
from ..params import KeeperParams
from .. import api

logger = api.get_logger()

class RecordTypeAddCommand(base.ArgparseCommand):
    parser = argparse.ArgumentParser(
        prog='record-type-add',
        description='Create a custom record type.'
    )
    parser.add_argument(
        '--data',
        dest='data',
        action='store',
        required=True,
        help='Record type definition in JSON format. Or use "filepath:" to read from JSON file.'
    )

    def __init__(self):
        super().__init__(RecordTypeAddCommand.parser)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        if not context.vault:
            raise ValueError("Vault is not initialized.")

        data = kwargs.get('data')
        record_type = None

        if data and data.strip().startswith('filepath:'):
            filepath = data.split('filepath:')[1].strip()
            try:
                with open(filepath, 'r') as file:
                    data = file.read()
            except FileNotFoundError:
                raise ValueError(f"File not found: {filepath}")
        if not data:
            raise ValueError("Cannot add record type without definition. Option --data is required.")

        try:
            record_type = json.loads(data)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON format in --data: {e}")

        title = record_type.get('$id')
        fields = record_type.get('fields')
        description = record_type.get('description', '')
        categories = record_type.get('categories', [])

        if not title:
            raise ValueError("Record type must have a '$id' field.")
        if not fields or not isinstance(fields, list):
            raise ValueError("Record type must include a list of 'fields'.")

        # Implicit fields - always present on any record, no need to be specified in the template: title, custom, notes
        implicit_field_names = [x for x in record_implicit_fields]
        implicit_fields = [r for r in record_type if r in implicit_field_names]
        if implicit_fields:
            error = {'error: Implicit fields not allowed in record type definition: ' + str(implicit_fields)}
            raise ValueError(error)

        rt_attributes = ('$id', 'categories', 'description', 'fields')
        bada = [r for r in record_type if r not in rt_attributes and r not in implicit_field_names]
        if bada:
            logging.debug(f'Unknown attributes in record type definition: {bada}')

        result = record_type_management.create_custom_record_type(
            context.vault, title, fields, description, categories
        )
        logger.info(f"Custom record type '{title}' created successfully with fields: {[f['$ref'] for f in fields]} and recordTypeId: {result.recordTypeId}")


class RecordTypeEditCommand(base.ArgparseCommand):
    parser = argparse.ArgumentParser(
        prog='record-type-edit',
        description='Update or edit a custom record type.'
    )
    parser.add_argument(
        '--data',
        dest='data',
        required=True,
        help='Record type definition in JSON format. Or use "filepath:" to read from JSON file.'
    )
    parser.add_argument(
        'record_type_id',
        type=int,
        nargs='?',
        help='Record Type ID of record type to be updated.'
    )

    def __init__(self):
        super().__init__(RecordTypeEditCommand.parser)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        if not context.vault:
            raise ValueError("Vault is not initialized.")

        data = kwargs.get('data')
        record_type_id = kwargs.get('record_type_id')

        if not record_type_id:
            raise ValueError("Missing required argument: record_type_id")
        
        record_type = None
        if data and data.strip().startswith('filepath:'):
            filepath = data.split('filepath:')[1].strip()
            try:
                with open(filepath, 'r') as file:
                    data = file.read()
            except FileNotFoundError:
                raise ValueError(f"File not found: {filepath}")
        if not data:
            raise ValueError("Cannot add record type without definition. Option --data is required.")

        try:
            record_type = json.loads(data)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON format in --data: {e}")

        title = record_type.get('$id')
        fields = record_type.get('fields')
        description = record_type.get('description', '')
        categories = record_type.get('categories', [])

        if not title:
            raise ValueError("Record type definition must include a '$id'")
        if not fields or not isinstance(fields, list):
            raise ValueError("Record type definition must include a valid list of 'fields'")

        implicit_field_names = [x for x in record_implicit_fields]
        invalid_fields = [f for f in record_type if f in implicit_field_names]
        if invalid_fields:
            raise ValueError(
                f"Implicit fields should not be included in record type definition: {invalid_fields}"
            )

        allowed_attributes = {'$id', 'categories', 'description', 'fields'}
        unexpected_attrs = [key for key in record_type if key not in allowed_attributes and key not in implicit_field_names]
        if unexpected_attrs:
            logging.debug(f"Unknown attributes in record type definition: {unexpected_attrs}")

        result = record_type_management.edit_custom_record_types(
            context.vault, record_type_id, title, fields, description, categories
        )
        logger.info(f"Custom record type (ID: {record_type_id}) updated successfully with fields: {[f['$ref'] for f in fields]} and recordTypeId: {result.recordTypeId}")



class RecordTypeDeleteCommand(base.ArgparseCommand):
    parser = argparse.ArgumentParser(
        prog='record-type-delete',
        description='Delete a custom record type.'
    )
    parser.add_argument(
        'record_type_id',
        type=int,
        help='Record Type ID of record type to be deleted.'
    )

    def __init__(self):
        super().__init__(RecordTypeDeleteCommand.parser)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        if not context.vault:
            raise ValueError("Vault is not initialized.")

        record_type_id = kwargs.get('record_type_id')
        if not record_type_id:
            raise ValueError("Missing required argument: record_type_id.")

        result = record_type_management.delete_custom_record_types(context.vault, record_type_id)
        logger.info(f"Custom record type deleted successfully with record type id: {result.recordTypeId}")


record_implicit_fields = {
    'title': '',  # string
    'custom': [],  # Array of Field Data objects
    'notes': ''  # string
}