import argparse
import json
import logging

from keepersdk.vault import record_type_management

from . import base
from ..params import KeeperParams
from .. import api

logger = api.get_logger()

class RecordTypeAddCommand(base.ArgparseCommand):

    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='record-type-add',
            description='Add a new custom record type.'
        )
        parser.add_argument(
            '--data',
            dest='data',
            action='store',
            help='Record type definition in JSON format.'
        )
        parser.add_argument(
            '--file',
            action='store',
            dest='file',
            help='File path to read the record type definition from a JSON file.'
        )
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        if not context.vault:
            raise ValueError("Vault is not initialized.")

        data = kwargs.get('data')
        file = kwargs.get('file')

        record_type = load_data(data, file)

        is_valid_data(record_type)

        title = record_type.get('$id')
        fields = record_type.get('fields')
        description = record_type.get('description', '')
        categories = record_type.get('categories', [])

        result = record_type_management.create_custom_record_type(
            context.vault, title, fields, description, categories
        )
        logger.info(f"Custom record type '{title}' created successfully with fields: {[f['$ref'] for f in fields]} and recordTypeId: {result.recordTypeId}")


class RecordTypeEditCommand(base.ArgparseCommand):

    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='record-type-edit',
            description='Update or edit a custom record type.'
        )
        parser.add_argument(
            '--data',
            dest='data',
            action='store',
            help='Record type definition in JSON format.'
        )
        parser.add_argument(
            '--file',
            action='store',
            dest='file',
            help='File path to read the record type definition from a JSON file.'
        )
        parser.add_argument(
            'record_type_id',
            type=int,
            nargs='?',
            help='Record Type ID of record type to be updated.'
        )
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        if not context.vault:
            raise ValueError("Vault is not initialized.")

        data = kwargs.get('data')
        record_type_id = kwargs.get('record_type_id')
        file = kwargs.get('file')

        if not record_type_id:
            raise ValueError("Missing required argument: record_type_id")
        
        record_type = load_data(data, file)

        is_valid_data(record_type)

        title = record_type.get('$id')
        fields = record_type.get('fields')
        description = record_type.get('description', '')
        categories = record_type.get('categories', [])

        result = record_type_management.edit_custom_record_types(
            context.vault, record_type_id, title, fields, description, categories
        )
        logger.info(f"Custom record type (ID: {record_type_id}) updated successfully with fields: {[f['$ref'] for f in fields]} and recordTypeId: {result.recordTypeId}")


class RecordTypeDeleteCommand(base.ArgparseCommand):
    
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='record-type-delete',
            description='Delete a custom record type.'
        )
        parser.add_argument(
            'record_type_id',
            type=int,
            help='Record Type ID of record type to be deleted.'
        )
        super().__init__(parser)

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


def is_valid_data(record_type):
    title = record_type.get('$id')
    fields = record_type.get('fields')

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


def load_data(data, file):
    if file:
        try:
            with open(file, 'r') as f:
                data = f.read()
        except FileNotFoundError:
            raise ValueError(f"File not found: {file}")
    if not data:
        raise ValueError("Cannot add record type without definition. --data or --file is required.")
    
    try:
        return json.loads(data)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON format: {e}")
