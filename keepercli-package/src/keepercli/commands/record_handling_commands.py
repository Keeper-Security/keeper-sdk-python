import argparse
import datetime
import json
import re
from typing import Optional, List

from colorama import Fore, Back, Style

from keepersdk.proto import record_pb2
from keepersdk.vault import (record_types, vault_record, vault_online)
from keepersdk import crypto, utils

from . import base
from ..helpers import folder_utils, record_utils, report_utils
from .. import api
from ..params import KeeperParams


logger = api.get_logger()
MAX_VERSION_COUNT = 5
TRUNCATE_LENGTH = 52


class ClipboardCommand(base.ArgparseCommand):
    """Command to copy record data to clipboard or output to various destinations."""
    
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            prog='clipboard-copy', 
            description='Retrieve the password for a specific record.'
        )
        self.add_arguments_to_parser(self.parser)
        super().__init__(self.parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        """Add command line arguments to the parser."""
        parser.add_argument(
            '--username', 
            dest='username', 
            action='store', 
            help='match login name (optional)'
        )
        parser.add_argument(
            '--output', 
            dest='output', 
            choices=['clipboard', 'stdout', 'stdouthidden', 'variable'], 
            default='clipboard', 
            action='store',
            help='password output destination'
        )
        parser.add_argument(
            '--name', 
            dest='name', 
            action='store', 
            help='Variable name if output is set to variable'
        )
        parser.add_argument(
            '-cu', '--copy-uid', 
            dest='copy_uid', 
            action='store_true', 
            help='output uid instead of password'
        )
        parser.add_argument(
            '-l', '--login', 
            dest='login', 
            action='store_true', 
            help='output login name'
        )
        parser.add_argument(
            '-t', '--totp', 
            dest='totp', 
            action='store_true', 
            help='output totp code'
        )
        parser.add_argument(
            '--field', 
            dest='field', 
            action='store', 
            help='output custom field'
        )
        parser.add_argument(
            '-r', '--revision', 
            dest='revision', 
            type=int, 
            action='store',
            help='use a specific record revision'
        )
        parser.add_argument(
            'record', 
            nargs='?', 
            type=str, 
            action='store', 
            help='record path or UID'
        )

    def execute(self, context: KeeperParams, **kwargs):
        """Execute the clipboard copy command."""
        self._validate_vault(context)
        
        record_name = kwargs.get('record', '')
        if not record_name:
            self.get_parser().print_help()
            return

        user_pattern = self._create_user_pattern(kwargs.get('username'))
        record_uid = self._find_record_uid(context, record_name, user_pattern)
        
        if not record_uid:
            raise base.CommandError('Enter name or uid of existing record')

        record = self._load_record_with_revision(context, record_uid, kwargs.get('revision'))
        if not record:
            logger.info(f'Record UID {record_uid} cannot be loaded.')
            return

        copy_item, text = self._extract_record_data(record, kwargs)
        if text:
            self._output_data(copy_item, text, kwargs, context, record_uid)

    def _validate_vault(self, context: KeeperParams):
        """Validate that vault is initialized."""
        if not context.vault:
            raise ValueError('Vault is not initialized. Login to initialize the vault.')

    def _create_user_pattern(self, username: Optional[str]) -> Optional[re.Pattern]:
        """Create regex pattern for username matching."""
        if not username:
            return None
        # Escape special regex characters to prevent ReDoS attacks
        escaped_username = re.escape(username)
        return re.compile(escaped_username, re.IGNORECASE)

    def _find_record_uid(self, context: KeeperParams, record_name: str, user_pattern: Optional[re.Pattern]) -> Optional[str]:
        """Find record UID by name or path."""
        
        if record_name in context.vault.vault_data._records:
            return record_name

        path_result = folder_utils.try_resolve_path(context, record_name)
        if path_result is not None:
            folder, record_name = path_result
            if folder and record_name:
                return self._find_record_in_folder(context, folder, record_name, user_pattern)

        return self._search_records_in_vault(context, record_name, user_pattern)

    def _find_record_in_folder(self, context: KeeperParams, folder, record_name: str, user_pattern: Optional[re.Pattern]) -> Optional[str]:
        """Find record in specific folder."""
        for folder_record_uid in folder.records:
            record = context.vault.vault_data.load_record(folder_record_uid)
            if not isinstance(record, (vault_record.PasswordRecord, vault_record.TypedRecord)):
                continue
            if record.title.lower() == record_name.lower():
                if self._matches_user_pattern(record, user_pattern):
                    return folder_record_uid
        return None

    def _search_records_in_vault(self, context: KeeperParams, record_name: str, user_pattern: Optional[re.Pattern]) -> Optional[str]:
        """Search for records in vault by name."""
        records = []
        for record in context.vault.vault_data.find_records(criteria=record_name):
            if isinstance(record, (vault_record.PasswordRecord, vault_record.TypedRecord)):
                if self._matches_user_pattern(record, user_pattern):
                    records.append(record)

        if len(records) == 0:
            raise base.CommandError('Enter name or uid of existing record')
        elif len(records) > 1:
            records = self._filter_exact_matches(records, record_name)
            if len(records) > 1:
                raise base.CommandError(f'More than one record are found for search criteria: {record_name}')

        if context.vault and 'output' in context.vault.__dict__ and context.vault.output == 'clipboard':
            logger.info('Record Title: %s', records[0].title)
        return records[0].record_uid

    def _filter_exact_matches(self, records: List, record_name: str) -> List:
        """Filter records to exact title matches."""
        try:
            # Escape special regex characters to prevent ReDoS attacks
            escaped_record_name = re.escape(record_name)
            pattern = re.compile(escaped_record_name, re.IGNORECASE).search
            exact_title = [x for x in records if pattern(x.title)]
            if len(exact_title) == 1:
                return exact_title
        except Exception:
            pass
        return records

    def _matches_user_pattern(self, record, user_pattern: Optional[re.Pattern]) -> bool:
        """Check if record matches user pattern."""
        if not user_pattern:
            return True
        
        login = self._get_record_login(record)
        return bool(login and user_pattern.match(login))

    def _get_record_login(self, record) -> str:
        """Extract login from record."""
        if isinstance(record, vault_record.PasswordRecord):
            return record.login
        elif isinstance(record, vault_record.TypedRecord):
            login_field = record.get_typed_field('login')
            if login_field is None:
                login_field = record.get_typed_field('email')
            if login_field:
                return login_field.get_default_value(str)
        return ''

    def _load_record_with_revision(self, context: KeeperParams, record_uid: str, revision: Optional[int]):
        """Load record with optional revision."""
        if revision is not None:
            history = self._load_record_history(context, record_uid)
            if not history:
                logger.info('Record does not have history of edit')
                return None
            
            length = len(history)
            if revision < 0:
                revision = length + revision
            if revision <= 0 or revision >= length:
                logger.info(f'Invalid revision {revision}: valid revisions 1..{length - 1}')
                return None
            
            revision_index = 0 if revision == 0 else length - revision
            return context.vault.vault_data.load_record(history[revision_index])
        else:
            return context.vault.vault_data.load_record(record_uid)

    def _extract_record_data(self, record, kwargs) -> tuple[str, str]:
        """Extract data from record based on command options."""
        if kwargs.get('copy_uid'):
            return 'Record UID', record.record_uid
        elif kwargs.get('login'):
            return 'Login', self._get_record_login(record)
        elif kwargs.get('totp'):
            return self._extract_totp_data(record)
        elif kwargs.get('field'):
            return self._extract_field_data(record, kwargs['field'])
        else:
            return self._extract_password_data(record)

    def _extract_totp_data(self, record) -> tuple[str, str]:
        """Extract TOTP data from record."""
        totp_url = None
        if isinstance(record, vault_record.PasswordRecord):
            totp_url = record.totp
        elif isinstance(record, vault_record.TypedRecord):
            totp_field = record.get_typed_field('oneTimeCode')
            if totp_field is None:
                totp_field = record.get_typed_field('otp')
            if totp_field:
                totp_url = totp_field.get_default_value(str)
        
        if totp_url:
            result = record_utils.get_totp_code(totp_url)
            if result:
                return 'TOTP Code', result[0]
        return 'TOTP Code', ''

    def _extract_field_data(self, record, field_name: str) -> tuple[str, str]:
        """Extract custom field data from record."""
        if field_name == 'notes':
            notes = record.notes if hasattr(record, 'notes') else ''
            return 'Notes', notes
        else:
            return self._extract_custom_field_data(record, field_name)

    def _extract_custom_field_data(self, record, field_name: str) -> tuple[str, str]:
        """Extract custom field data from record."""
        copy_item = f'Custom Field "{field_name}"'
        field_name, field_property = self._parse_field_name(field_name)
        
        if isinstance(record, vault_record.PasswordRecord):
            return copy_item, record.custom.get(field_name, '')
        elif isinstance(record, vault_record.TypedRecord):
            return self._extract_typed_field_data(record, field_name, field_property, copy_item)
        
        return copy_item, ''

    def _parse_field_name(self, field_name: str) -> tuple[str, str]:
        """Parse field name and property."""
        pre, sep, prop = field_name.rpartition(':')
        if sep == ':':
            return pre, prop
        return field_name, ''

    def _extract_typed_field_data(self, record, field_name: str, field_property: str, copy_item: str) -> tuple[str, str]:
        """Extract data from typed field."""
        field_type, sep, field_label = field_name.partition('.')
        rf = record_types.RecordFields.get(field_type)
        ft = record_types.FieldTypes.get(rf.type) if rf else None
        
        if ft is None:
            field_label = field_name
            field_type = 'text'
        
        field = record.get_typed_field(field_type, field_label)
        if not field:
            return copy_item, ''
        
        copy_item = f'Field "{field_name}"'
        
        if ft and field_property and isinstance(ft.value, dict):
            f_value = field.get_default_value(dict)
            if f_value:
                field_property = next(
                    (x for x in ft.value.keys() if x.lower().startswith(field_property.lower())), 
                    None
                )
                if field_property:
                    return copy_item, f_value.get(field_property, '')
                else:
                    return copy_item, json.dumps(f_value, indent=2)
        else:
            return copy_item, '\n'.join(field.get_external_value())

    def _extract_password_data(self, record) -> tuple[str, str]:
        """Extract password data from record."""
        if isinstance(record, vault_record.PasswordRecord):
            return 'Password', record.password
        elif isinstance(record, vault_record.TypedRecord):
            password_field = record.get_typed_field('password')
            if password_field:
                return 'Password', password_field.get_default_value(str)
        return 'Password', ''

    def _output_data(self, copy_item: str, text: str, kwargs: dict, context: KeeperParams, record_uid: str):
        """Output data to specified destination."""
        output_type = kwargs.get('output', 'clipboard')
        
        if output_type == 'clipboard':
            import pyperclip
            pyperclip.copy(text)
            logger.info(f'{copy_item} copied to clipboard')
        elif output_type == 'stdouthidden':
            logger.info(f'{Fore.RED}{Back.RED}{text}{Style.RESET_ALL}')
        elif output_type == 'variable':
            var_name = kwargs.get('name')
            if not var_name:
                raise base.CommandError('"name" parameter is required when "output" is set to "variable"')
            context.environment_variables[var_name] = text
            logger.info(f'{copy_item} is set to variable "{var_name}"')
        else:
            logger.info(text)
        
        # Schedule audit event for password copy
        if copy_item == 'Password' and text:
            context.vault.client_audit_event_plugin().schedule_audit_event('copy_password', record_uid=record_uid)

    def _load_record_history(self, context: KeeperParams, record_uid: str) -> Optional[list]:
        """Load record history from server."""
        if not context.vault:
            raise ValueError('Vault is not initialized. Login to initialize the vault.')
        
        return self._load_record_history_static(context.vault, record_uid)

    @staticmethod
    def _load_record_history_static(vault: vault_online.VaultOnline, record_uid: str) -> Optional[list]:
        """Load record history from server (static method for sharing)."""
        current_rec = vault.vault_data._records[record_uid]
        record_key = current_rec.record_key

        request = {
            'command': 'get_record_history',
            'record_uid': record_uid,
            'client_time': utils.current_milli_time()
        }
        
        try:
            response = vault.keeper_auth.execute_auth_command(request)
        except Exception as e:
            logger.error('Cannot load record history: %s', e)
            return None
        
        history = response['history']
        history.sort(key=lambda x: x.get('revision', 0), reverse=True)
        
        for rec in history:
            rec['record_key_unencrypted'] = record_key
            ClipboardCommand._decrypt_history_record_static(rec, record_key)

        return history

    @staticmethod
    def _decrypt_history_record_static(rec: dict, record_key: bytes):
        """Decrypt history record data (static method for sharing)."""
        if 'data' in rec:
            data = utils.base64_url_decode(rec['data'])
            version = rec.get('version', 0)
            try:
                if version <= 2:
                    rec['data_unencrypted'] = crypto.decrypt_aes_v1(data, record_key)
                else:
                    rec['data_unencrypted'] = crypto.decrypt_aes_v2(data, record_key)
                
                if 'extra' in rec:
                    extra = utils.base64_url_decode(rec['extra'])
                    if version <= 2:
                        rec['extra_unencrypted'] = crypto.decrypt_aes_v1(extra, record_key)
                    else:
                        rec['extra_unencrypted'] = crypto.decrypt_aes_v2(extra, record_key)
            except Exception as e:
                logger.warning('Cannot decrypt record history revision: %s', e)
                rec['data_unencrypted'] = None
                rec['extra_unencrypted'] = None


class RecordHistoryCommand(base.ArgparseCommand):
    """Command to show and manage record modification history."""

    def __init__(self):
        self.parser = argparse.ArgumentParser(
            prog='record-history', 
            parents=[base.report_output_parser],
            description='Show the history of a record modifications.'
        )
        self.add_arguments_to_parser(self.parser)
        super(RecordHistoryCommand, self).__init__(self.parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        """Add command line arguments to the parser."""
        parser.add_argument(
            '-a', '--action', 
            dest='action', 
            choices=['list', 'diff', 'view', 'restore'], 
            action='store',
            help="filter by record history type. (default: 'list'). --revision required with 'restore' action."
        )
        parser.add_argument(
            '-r', '--revision', 
            dest='revision', 
            type=int, 
            action='store',
            help='only show the details for a specific revision.'
        )
        parser.add_argument(
            '-v', '--verbose', 
            dest='verbose', 
            action='store_true', 
            help="verbose output"
        )
        parser.add_argument(
            'record', 
            nargs='?', 
            type=str, 
            action='store', 
            help='record path or UID'
        )

    def execute(self, context: KeeperParams, **kwargs):
        """Execute the record history command."""
        self._validate_vault(context)

        vault = context.vault
        record_name = kwargs.get('record')
        if not record_name:
            self.get_parser().print_help()
            return

        record_uid = self._find_record_uid(context, record_name)
        if not record_uid:
            raise base.CommandError('Record not found: Enter name of existing record')

        history = ClipboardCommand._load_record_history_static(vault, record_uid)
        if not history:
            logger.info('Record does not have history of edit')
            return

        action = kwargs.get('action') or 'list'
        self._execute_action(action, vault, history, kwargs)

    def _validate_vault(self, context: KeeperParams):
        """Validate that vault is initialized."""
        if not context.vault:
            raise ValueError('Vault is not initialized. Login to initialize the vault.')

    def _find_record_uid(self, context: KeeperParams, record_name: str) -> Optional[str]:
        """Find record UID by name or path."""
        
        vault = context.vault
        if record_name in vault.vault_data._records:
            return record_name

        path_result = folder_utils.try_resolve_path(context, record_name)
        if path_result is not None:
            folder, record_name = path_result
            if folder and record_name:
                return self._find_record_in_folder(vault, folder, record_name)

        return None

    def _find_record_in_folder(self, vault: vault_online.VaultOnline, folder, record_name: str) -> Optional[str]:
        """Find record in specific folder."""
        for folder_record_uid in folder.records:
            record = vault.vault_data.load_record(folder_record_uid)
            if record.title.lower() == record_name.lower():
                return folder_record_uid
        return None

    def _execute_action(self, action: str, vault: vault_online.VaultOnline, history: list, kwargs: dict):
        """Execute the specified history action."""
        if action == 'list':
            self._list_history(history, kwargs)
        elif action == 'view':
            self._view_revision(history, kwargs)
        elif action == 'diff':
            self._show_diff(history, kwargs)
        elif action == 'restore':
            self._restore_revision(vault, history, kwargs)

    def _list_history(self, history: list, kwargs: dict):
        """List record history revisions."""
        fmt = kwargs.get('format', '')
        headers = ['version', 'modified_by', 'time_modified']
        if fmt != 'json':
            headers = [report_utils.field_to_title(x) for x in headers]
        
        rows = []
        length = len(history)
        for i, version in enumerate(history):
            dt = None
            if 'client_modified_time' in version:
                dt = datetime.datetime.fromtimestamp(int(version['client_modified_time'] / 1000.0))
            version_label = f'V.{length-i}' if i > 0 else 'Current'
            rows.append([version_label, version.get('user_name', ''), dt])
        
        return report_utils.dump_report_data(rows, headers, fmt=fmt, filename=kwargs.get('output'))

    def _view_revision(self, history: list, kwargs: dict):
        """View a specific revision."""
        revision = kwargs.get('revision') or 0
        length = len(history)
        
        if revision < 0 or revision >= length:
            raise ValueError(f'Invalid revision {revision}: valid revisions 1..{length - 1}')

        index = 0 if revision == 0 else length - revision
        rev = history[index]
        record_data_bytes = rev['data_unencrypted']
        record_data = json.loads(record_data_bytes)

        rows = []
        rows.append(['Title', record_data.get('title')])
        rows.append(['Type', record_data.get('type')])
        fields = record_data.get('fields', [])
        for field in fields:
            label = field.get('label')
            if not label or label == '':
                label = field.get('type')
            value = field.get('value')
            if value:
                if isinstance(value, list):
                    value = '\n'.join(value)
                rows.append([label, value])
        
        modified = datetime.datetime.fromtimestamp(int(rev['client_modified_time'] / 1000.0))
        rows.append(['Modified', modified])
        
        report_utils.dump_report_data(
            rows, 
            headers=['Name', 'Value'],
            title=f'Record Revision V.{revision}', 
            no_header=True, 
            right_align=(0,)
        )

    def _show_diff(self, history: list, kwargs: dict):
        """Show differences between revisions."""
        revision = kwargs.get('revision') or 0
        verbose = kwargs.get('verbose') or False
        length = len(history)
        
        if revision < 0 or revision >= length:
            raise ValueError(f'Invalid revision {revision}: valid revisions 1..{length - 1}')

        index = 0 if revision == 0 else length - revision
        rows = self._generate_diff_rows(history, index, length, verbose)
        
        headers = ('Version', 'Field', 'New Value', 'Old Value')
        report_utils.dump_report_data(rows, headers)

    def _generate_diff_rows(self, history: list, start_index: int, length: int, verbose: bool) -> list:
        """Generate diff rows between revisions."""
        count = MAX_VERSION_COUNT
        current = history[start_index].get('data_unencrypted')
        current = json.loads(current)
        rows = []
        index = start_index
        
        while count >= 0 and current:
            previous = history[index + 1].get('data_unencrypted') if index < (length - 1) else None
            previous = json.loads(previous) if previous else None
            current_fields = self._get_record_fields(current)
            previous_fields = self._get_record_fields(previous) if previous else {}
            
            last_pos = len(rows)
            self._add_field_differences(rows, current_fields, previous_fields)
            
            version_label = 'Current' if index == 0 else f'V.{length - index}'
            if len(rows) > last_pos:
                rows[last_pos][0] = version_label
            else:
                rows.append([version_label, '', '', ''])
            
            count -= 1
            index += 1
            current = previous

        if not verbose:
            self._truncate_long_values(rows)
        
        return rows

    def _get_record_fields(self, record: dict) -> dict:
        """Get record fields as dictionary."""
        return_fields = {}
        return_fields['Title'] = record.get('title')
        for field in record.get('fields', []):
            name = field.get('label')
            if not name or name == '':
                name = field.get('type')
            value = field.get('value')
            if isinstance(value, list):
                value = '\n'.join(value)
            return_fields[name] = value                
        return return_fields

    def _add_field_differences(self, rows: list, current_fields: dict, previous_fields: dict):
        """Add field differences to rows."""
        for name, value in current_fields.items():
            if name in previous_fields:
                pre_value = previous_fields[name]
                if pre_value != value:
                    rows.append(['', name, value, pre_value])
                del previous_fields[name]
            else:
                if value:
                    rows.append(['', name, value, ''])
        
        for name, value in previous_fields.items():
            if value:
                if isinstance(value, list):
                    value = '\n'.join(value)
                rows.append(['', name, '', value])

    def _truncate_long_values(self, rows: list):
        """Truncate long values in diff rows for better readability."""
        for row in rows:
            for index in (2, 3):
                value = row[index]
                if not value:
                    continue
                lines = [x[:TRUNCATE_LENGTH-2]+'...' if len(x) > TRUNCATE_LENGTH else x for x in value.split('\n')]
                if len(lines) > 3:
                    lines = lines[:2]
                    lines.append('...')
                row[index] = '\n'.join(lines)

    def _restore_revision(self, vault: vault_online.VaultOnline, history: list, kwargs: dict):
        """Restore a specific revision."""
        revision = kwargs.get('revision') or 0
        length = len(history)
        
        if revision == 0:
            raise base.CommandError(f'Invalid revision to restore: Revisions: 1-{length - 1}')
        
        if revision < 0 or revision >= length:
            raise ValueError(f'Invalid revision {revision}: valid revisions 1..{length - 1}')

        index = 0 if revision == 0 else length - revision
        rev = history[index]
        record_data_bytes = rev['data_unencrypted']
        record_data = json.loads(record_data_bytes)

        self._execute_restore_request(vault, rev['record_uid'], rev['revision'])
        vault.client_audit_event_plugin().schedule_audit_event('revision_restored', record_uid=rev['record_uid'])
        vault.sync_down()
        logger.info('Record "%s" revision V.%d has been restored', record_data.get('title'), revision)

    def _execute_restore_request(self, vault: vault_online.VaultOnline, record_uid: str, revision: int):
        """Execute the restore request to server."""
        r_uid = utils.base64_url_decode(record_uid)
        roq = record_pb2.RecordRevert()
        roq.record_uid = r_uid
        roq.revert_to_revision = revision

        rq = record_pb2.RecordsRevertRequest()
        rq.records.append(roq)

        rs = vault.keeper_auth.execute_auth_rest(
            'vault/records_revert', 
            rq, 
            response_type=record_pb2.RecordsModifyResponse
        )

        ros = next((x for x in rs.records if x.record_uid == r_uid), None)
        if ros and ros.status != record_pb2.RS_SUCCESS:
            raise base.CommandError(f'Failed to restore record "{record_uid}": {ros.message}')

