import argparse
import json
import logging

from keepersdk.vault import record_type_management, record_types

from . import base, record_type_utils
from ..params import KeeperParams
from .. import api
from ..helpers import report_utils

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
            required=True,
            help='Record type definition in JSON format or "filepath:" to read from JSON file.'
        )
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        if not context.vault:
            raise ValueError("Vault is not initialized.")

        data = kwargs.get('data')

        record_type = load_data(data)

        is_valid_data(record_type)

        title = record_type.get('$id')
        fields = record_type.get('fields')
        description = record_type.get('description', '')
        categories = record_type.get('categories', [])

        result = record_type_management.create_custom_record_type(
            context.vault, title, fields, description, categories
        )
        logger.info(f"Custom record type '{title}' created successfully with fields: {[f['$ref'] for f in fields]} and recordTypeId: {result.recordTypeId}")
        return


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
            required=True,
            help='Record type definition in JSON format or "filepath:" to read from JSON file.'
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

        if not record_type_id:
            raise ValueError("Missing required argument: record_type_id")
        
        record_type = load_data(data)

        is_valid_data(record_type)

        title = record_type.get('$id')
        fields = record_type.get('fields')
        description = record_type.get('description', '')
        categories = record_type.get('categories', [])

        result = record_type_management.edit_custom_record_types(
            context.vault, record_type_id, title, fields, description, categories
        )
        logger.info(f"Custom record type (ID: {record_type_id}) updated successfully with fields: {[f['$ref'] for f in fields]} and recordTypeId: {result.recordTypeId}")
        return


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
        return


class RecordTypeInfoCommand(base.ArgparseCommand):

    def __init__(self):
        self.parser = argparse.ArgumentParser(
            prog='record-type-info',
            description='Get record type info'
        )
        RecordTypeInfoCommand.add_arguments_to_parser(self.parser)
        super().__init__(self.parser)

    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument(
            '-lr',
            '--list-record-type',
            type=str,
            dest='record_name',
            action='store',
            default=None,
            const = '*',
            nargs='?',
            help='list record type by name or use * to list all'
        )
        parser.add_argument(
            '-lf',
            '--list-field',
            type=str,
            dest='field_name',
            action='store',
            default=None,
            help='list field type by name or use * to list all'
        )
        parser.add_argument(
            '-e',
            '--example',
            dest='example',
            action='store_true',
            help='Set to "true" to generate example JSON'
        )

    def execute(self, context: KeeperParams, **kwargs) -> None:
        if not context.vault:
            raise ValueError("Vault is not initialized.")
        
        vault = context.vault
        example = kwargs.get('example', False)
        field_name = kwargs.get('field_name')
        record_type_name = kwargs.get('record_name')

        if field_name is not None:
            headers = ('Field Type ID', 'Lookup', 'Multiple', 'Description')
            show_all_fields = field_name.strip() == '' or field_name.strip() == '*'
            if show_all_fields:
                rows = []
                for ft in record_types.FieldTypes.values():
                    rows.append(record_type_utils.get_field_definitions(ft))
                return report_utils.dump_report_data(rows, headers, column_width='auto', fmt='simple')
            else:
                # Fetch a specific field type
                ft = record_types.FieldTypes.get(field_name)
                if not ft:
                    raise ValueError(f"Field type '{field_name}' is not a valid RecordField.")
                row = record_type_utils.get_field_definitions(ft)
                return report_utils.dump_report_data([row], headers, column_width='auto', fmt='simple')

        if record_type_name and record_type_name != '*' and record_type_name != '' and example:
            record_type_example = record_type_utils.get_record_type_example(vault, record_type_name)
            logger.info(record_type_example)
            return

        # Record Types
        if record_type_name and record_type_name != '*' and record_type_name != '':
            #Fetch a specific record type
            record_type = vault.vault_data.get_record_type_by_name(record_type_name)
            if not record_type:
                raise ValueError(f"Record type '{record_type_name}' not found.")

            rows = []
            fields = record_type.fields
            scope = record_type_utils.get_record_type_scope(record_type.scope)
            rows.append([
                record_type.id,
                record_type.name,
                scope,
                fields[0].label if hasattr(fields[0], 'label') else str(fields[0])
            ])
            for field in fields[1:]:
                rows.append(['', '', '', field.label if hasattr(field, 'label') else str(field)])

            headers = ('id', 'name', 'scope', 'fields')
            return report_utils.dump_report_data(rows, headers, column_width='auto', fmt='simple')
        else:
            #Show all record types
            record_types_list = record_type_utils.get_record_types(vault)
            if not record_types_list:
                raise ValueError("No record types found.")

            rows = []
            for rtid, name, scope in record_types_list:
                rows.append([rtid, name, scope])

            headers = ('Record Type ID', 'Record Type Name', 'Record Type Scope')
            return report_utils.dump_report_data(rows, headers, column_width='auto', fmt='simple')


class LoadRecordTypesCommand(base.ArgparseCommand):

    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='load-record-types',
            description='Loads custom record types from a JSON file.'
        )
        parser.add_argument(
            '--file',
            dest='file',
            action='store',
            required=True,
            help='Path to the JSON file containing the record type definition.'
        )
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        if not context.vault:
            raise ValueError("Vault is not initialized.")

        filepath = kwargs.get('file')
        if not filepath:
            raise ValueError("Missing required argument: --file")
        
        count = 0
        record_types_list = record_type_utils.validate_record_type_file(filepath)

        loaded_record_types = set()
        existing_record_types = record_type_utils.get_record_types(context.vault)
        if existing_record_types:
            for existing_record_type in existing_record_types:
                loaded_record_types.add(existing_record_type[1].lower())

        for record_type in record_types_list:
            record_type_name = record_type.get('record_type_name')
            if not record_type_name:
                logger.error('Record type name is missing in the record type definition.', record_type)
                continue

            record_type_name = record_type_name[:30]
            if record_type_name.lower() in loaded_record_types:
                logger.info(f'Record type "{record_type_name}" already exists. Skipping.')
                continue

            fields = record_type.get('fields')
            if not isinstance(fields, list):
                logger.error('Fields must be a list in the record type definition.', record_type)
                continue

            is_valid = True
            add_fields = []
            for field in fields:
                field_type = field.get('$type')
                if field_type not in record_types.RecordFields:
                    is_valid = False
                    break
                fo = {'$ref': field.get('$type')}
                if field.get('required') is True:
                    fo['required'] = True
                add_fields.append(fo)
            if not is_valid:
                logger.error('Invalid field type in the record type definition.', record_type)
                continue

            if len(add_fields) == 0:
                logger.error('No fields found in the record type definition.', record_type)
                continue

            record_type_management.create_custom_record_type(
                vault=context.vault,
                title=record_type_name,
                fields=add_fields,
                description=record_type.get('description') or '',
                categories=record_type.get('categories') or []
            )
            count += 1

        if count != 0:
            logger.info(f"Custom record types imported successfully. {count} record types were added.")
        else:
            logger.info("No custom record types were imported. Record types already exist in the vault or the file is empty.")
        return


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
    bad_attributes = [r for r in record_type if r not in rt_attributes and r not in implicit_field_names]
    if bad_attributes:
        logging.debug(f'Unknown attributes in record type definition: {bad_attributes}')


def load_data(data):

    if data and data.strip().startswith('filepath:'):
        filepath = data.split('filepath:')[1].strip()
        try:
            with open(filepath, 'r') as file:
                data = file.read()
        except FileNotFoundError:
            raise ValueError(f"File not found: {filepath}")

    if not data:
        raise ValueError("Cannot add record type without definition. --data or --file is required.")
    
    try:
        return json.loads(data)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON format: {e}")
