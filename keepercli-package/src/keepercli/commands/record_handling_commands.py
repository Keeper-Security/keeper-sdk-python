import argparse
import datetime
import hashlib
import json
import re
from typing import Optional, List
import urllib

from colorama import Fore, Back, Style

from keepersdk.proto import record_pb2
from keepersdk.vault import (record_types, vault_record, vault_online, record_management)
from keepersdk import crypto, utils

from . import base, enterprise_utils
from ..helpers import folder_utils, record_utils, report_utils, share_utils
from .. import api, prompt_utils
from ..params import KeeperParams


logger = api.get_logger()
MAX_VERSION_COUNT = 5
TRUNCATE_LENGTH = 52

# Constants for FindDuplicateCommand
TEAM_USER_TYPE = '(Team User)'
NON_SHARED_LABEL = 'non-shared'
ENTERPRISE_COMPLIANCE_DAYS = 1
URL_DISPLAY_LENGTH = 30
ENTERPRISE_UPDATE_FLOOR_DAYS = 1

# Default field mappings for duplicate detection
DEFAULT_MATCH_FIELDS = ['title', 'login', 'password']
ENTERPRISE_FIELD_KEYS = ['title', 'url', 'record_type']

# Report field names
FIELD_TITLE = 'Title'
FIELD_LOGIN = 'Login'
FIELD_PASSWORD = 'Password'
FIELD_WEBSITE_ADDRESS = 'Website Address'
FIELD_CUSTOM_FIELDS = 'Custom Fields'
FIELD_SHARES = 'Shares'
FIELD_RECORD_UID = 'record_uid'
FIELD_GROUP = 'group'
FIELD_URL = 'url'
FIELD_RECORD_OWNER = 'record_owner'
FIELD_SHARED_TO = 'shared_to'
FIELD_SHARED_FOLDER_UID = 'shared_folder_uid'

# Report titles
ENTERPRISE_DUPLICATE_TITLE = 'Duplicate Search Results (Enterprise Scope):'
VAULT_DUPLICATE_TITLE = 'Duplicates Found:'
NO_DUPLICATES_FOUND = 'No duplicates found.'


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


class FindDuplicateCommand(base.ArgparseCommand):
    """
    Command to find and optionally merge duplicate records in a vault.
    
    This command can identify duplicates based on various field combinations
    (title, login, password, URL, custom fields, shares) and optionally
    consolidate them by removing the duplicate entries.
    """
    
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            prog='find-duplicates',
            description='List duplicated records.',
            parents=[base.report_output_parser]
        )
        self.add_arguments_to_parser(self.parser)
        super().__init__(self.parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('--title', dest='title', action='store_true', help='Match duplicates by title.')
        parser.add_argument('--login', dest='login', action='store_true', help='Match duplicates by login.')
        parser.add_argument('--password', dest='password', action='store_true', help='Match duplicates by password.')
        parser.add_argument('--url', dest='url', action='store_true', help='Match duplicates by URL.')
        parser.add_argument('--shares', action='store_true', help='Match duplicates by share permissions')
        parser.add_argument('--full', dest='full', action='store_true', help='Match duplicates by all fields.')
        merge_help = 'Consolidate duplicate records (matched by all fields, including shares)'
        parser.add_argument('-m', '--merge', action='store_true', help=merge_help)
        ignore_shares_txt = 'ignore share permissions when grouping duplicate records to merge'
        parser.add_argument('--ignore-shares-on-merge', action='store_true', help=ignore_shares_txt)
        force_help = 'Delete duplicates w/o being prompted for confirmation (valid only w/ --merge option)'
        parser.add_argument('-f', '--force', action='store_true', help=force_help)
        dry_run_help = 'Simulate removing duplicates (with this flog, no records are ever removed or modified). ' \
                    'Valid only w/ --merge flag'
        parser.add_argument('-n', '--dry-run', action='store_true', help=dry_run_help)
        parser.add_argument('-q', '--quiet', action='store_true',
                                        help='Suppress screen output, valid only w/ --force flag')
        scope_help = 'The scope of the search (limited to current vault if not specified)'
        parser.add_argument('-s', '--scope', action='store', choices=['vault', 'enterprise'], default='vault',
                                        help=scope_help)
        refresh_help = 'Populate local cache with latest compliance data . Valid only w/ --scope=enterprise option.'
        parser.add_argument('-r', '--refresh-data', action='store_true', help=refresh_help)
    
    def execute(self, context: KeeperParams, **kwargs):
        """Execute the find-duplicates command - main entry point."""
        self._validate_context(context)
        
        scope = kwargs.get('scope', 'vault')
        if scope == 'enterprise':
            raise base.CommandError('Enterprise scope not yet implemented')
        
        return self._process_vault_duplicates(context, kwargs)
    
    def _validate_context(self, context: KeeperParams):
        """Validate that the vault is initialized."""
        if not context.vault:
            raise base.CommandError(self.get_parser().prog, 'Vault is not initialized')
    
    def _process_vault_duplicates(self, context: KeeperParams, kwargs: dict):
        """Process duplicate detection for vault scope."""
        vault = context.vault
        match_fields = self._determine_match_fields(kwargs)
        
        # Build hash groups for duplicate detection
        hashes = self._build_duplicate_hashes(vault, match_fields)
        
        # Log which fields are being used for matching
        fields = self._build_field_list(match_fields)
        logging_fn = self._get_logging_function(kwargs)
        logging_fn('Find duplicated records by: %s', ', '.join(fields))
        
        # Find partitions (groups of duplicates)
        partitions = [rec_uids for rec_uids in hashes.values() if len(rec_uids) > 1]
        
        if not partitions:
            logging_fn(NO_DUPLICATES_FOUND)
            return
        
        # Partition by shares if needed
        partitions = self._apply_share_partitioning(context, partitions, match_fields)
        
        if not partitions:
            logging_fn(NO_DUPLICATES_FOUND)
            return
        
        # Generate and display report
        return self._generate_duplicate_report(context, partitions, match_fields, kwargs)
    
    def _get_logging_function(self, kwargs):
        """Get appropriate logging function based on quiet/dry-run flags."""
        quiet = kwargs.get('quiet', False)
        dry_run = kwargs.get('dry_run', False)
        quiet = quiet and not dry_run
        return logger.info if not quiet else logger.debug
    
    def _build_duplicate_hashes(self, vault, match_fields):
        """Build hash groups to identify duplicate records."""
        hashes = {}
        for record_uid in vault.vault_data._records:
            record = vault.vault_data.load_record(record_uid)
            if not record or not isinstance(record, (vault_record.PasswordRecord, vault_record.TypedRecord)):
                continue
            
            hash_value, non_empty = self._create_record_hash(record, match_fields)
            
            if non_empty > 0:
                rec_uids = hashes.get(hash_value, set())
                rec_uids.add(record_uid)
                hashes[hash_value] = rec_uids
        return hashes
    
    def _apply_share_partitioning(self, context, partitions, match_fields):
        """Apply share-based partitioning if enabled."""
        if not match_fields['by_shares']:
            return partitions
        
        # Get shared records lookup for all record UIDs in partitions
        r_uids = [rec_uid for duplicates in partitions for rec_uid in duplicates]
        shared_records_lookup = share_utils.get_shared_records(context, r_uids, cache_only=True)
        
        return self._partition_by_shares(partitions, shared_records_lookup)
    
    def _partition_by_shares(self, duplicate_sets, shared_recs_lookup):
        """Partition duplicate sets by their share permissions."""
        result = []
        for duplicates in duplicate_sets:
            recs_by_hash = {}
            for rec_uid in duplicates:
                shared_rec = shared_recs_lookup.get(rec_uid)
                permissions = shared_rec.permissions
                
                # Filter out team user and owner permissions
                permissions = self._filter_team_user_permissions(permissions)
                permissions = {k: p for k, p in permissions.items() if p.to_name != shared_rec.owner}
                
                permissions_keys = list(permissions.keys())
                permissions_keys.sort()
                
                # Create hash based on permissions
                to_hash = ';'.join(f'{k}={permissions.get(k).permissions_text}' for k in permissions_keys)
                to_hash = to_hash or NON_SHARED_LABEL
                
                h = hashlib.sha256()
                h.update(to_hash.encode())
                h_val = h.hexdigest()
                
                r_uids = recs_by_hash.get(h_val, set())
                r_uids.add(rec_uid)
                recs_by_hash[h_val] = r_uids
            
            result.extend([r for r in recs_by_hash.values() if len(r) > 1])
        
        return result
    
    def _generate_duplicate_report(self, context, partitions, match_fields, kwargs):
        """Generate and display the duplicate report."""
        vault = context.vault
        out_fmt = kwargs.get('format', 'table')
        out_dst = kwargs.get('output')
        
        # Build headers
        headers = self._build_report_headers(match_fields, out_fmt)
        
        # Build report data
        table, table_raw, to_remove = self._build_report_data(context, vault, partitions, match_fields)
        
        # Handle consolidation or display
        if match_fields['consolidate']:
            return self._consolidate_duplicates(vault, headers, table_raw, to_remove, kwargs)
        else:
            title = VAULT_DUPLICATE_TITLE
            return report_utils.dump_report_data(table, headers, title=title, fmt=out_fmt, filename=out_dst, group_by=0)
    
    def _build_report_headers(self, match_fields, out_fmt):
        """Build report headers based on match fields."""
        headers = [FIELD_GROUP, 'title', 'login']
        if match_fields['by_url']:
            headers.append(FIELD_URL)
        headers.extend(['uid', FIELD_RECORD_OWNER, FIELD_SHARED_TO])
        return [report_utils.field_to_title(h) for h in headers] if out_fmt != 'json' else headers
    
    def _build_report_data(self, context, vault, partitions, match_fields):
        """Build the report data tables."""
        shared_records_lookup = share_utils.get_shared_records(
            context,
            [rec_uid for duplicates in partitions for rec_uid in duplicates],
            cache_only=True
        )
        
        table = []
        table_raw = []
        to_remove = set()
        
        for i, partition in enumerate(partitions):
            for j, record_uid in enumerate(partition):
                row = self._build_report_row(vault, shared_records_lookup, i, record_uid, match_fields)
                table.append(row)
                
                if j != 0:  # Mark for removal (all except first in each partition)
                    to_remove.add(record_uid)
                    table_raw.append(row)
        
        return table, table_raw, to_remove
    
    def _build_report_row(self, vault, shared_records_lookup, group_index, record_uid, match_fields):
        """Build a single row in the report."""
        record = vault.vault_data.load_record(record_uid)
        shared_record = shared_records_lookup[record_uid]
        
        owner = self._get_record_owner(vault, record_uid)
        title, login, url = self._extract_record_info(record, match_fields)
        url = self._format_url(url, match_fields['by_url'])
        shares = self._extract_share_info(shared_record, owner)
        
        return [group_index + 1, title, login] + url + [record_uid, owner, shares]
    
    def _get_record_owner(self, vault, record_uid):
        """Get the owner of a record."""
        record_details = vault.vault_data.get_record(record_uid)
        return record_details.flags.IsOwner
    
    def _extract_share_info(self, shared_record, owner):
        """Extract and format share information."""
        perms = {k: p for k, p in shared_record.permissions.items()}
        keys = list(perms.keys())
        keys.sort()
        perms = [perms.get(k) for k in keys]
        perms = [p for p in perms if TEAM_USER_TYPE not in p.types or len(p.types) > 1]
        return '\n'.join([p.to_name for p in perms if owner != p.to_name])
    
    def _consolidate_duplicates(self, vault, headers, table_raw, to_remove, kwargs):
        """Consolidate (remove) duplicate records."""
        uid_header = report_utils.field_to_title('uid')
        record_uid_index = headers.index(uid_header) if uid_header in headers else None
        
        if not record_uid_index:
            raise base.CommandError(self.get_parser().prog, 'Cannot find record UID for duplicate record')
        
        dup_info = [r for r in table_raw for rec_uid in to_remove if r[record_uid_index] == rec_uid]
        return self._remove_duplicates(vault, dup_info, headers, to_remove, kwargs)
    
    def _remove_duplicates(self, vault, dupe_info, col_headers, dupe_uids, kwargs):
        """Remove duplicate records with confirmation."""
        def confirm_removal(cols):
            prompt_title = f'\nThe following duplicate {"records have" if len(dupe_uids) > 1 else "record has"}' \
                    f' been marked for removal:\n'
            indices = (idx + 1 for idx in range(len(dupe_info)))
            prompt_report = prompt_title + '\n' + report_utils.tabulate(dupe_info, col_headers, showindex=indices)
            prompt_msg = prompt_report + '\n\nDo you wish to proceed?'
            return prompt_utils.user_choice(prompt_msg, 'yn', default='n') in ('y', 'yes')
        
        if kwargs.get('force') or confirm_removal(col_headers):
            record_management.delete_vault_objects(vault, list(dupe_uids))
    
    def _determine_match_fields(self, kwargs):
        """Determine which fields to use for matching duplicates."""
        by_title = kwargs.get('title', False)
        by_login = kwargs.get('login', False)
        by_password = kwargs.get('password', False)
        by_url = kwargs.get('url', False)
        by_custom = kwargs.get('full', False)
        by_shares = kwargs.get('shares', False)
        consolidate = kwargs.get('merge', False)
        
        # If merge or full is specified, match by all fields
        if consolidate or by_custom:
            by_title = True
            by_login = True
            by_password = True
            by_url = True
            by_shares = not kwargs.get('ignore_shares_on_merge') if consolidate else True
        # If no fields specified, use default fields
        elif not any([by_title, by_login, by_password, by_url]):
            by_title = True
            by_login = True
            by_password = True
        
        return {
            'by_title': by_title,
            'by_login': by_login,
            'by_password': by_password,
            'by_url': by_url,
            'by_custom': consolidate or by_custom,
            'by_shares': by_shares,
            'consolidate': consolidate
        }
    
    def _build_field_list(self, match_fields):
        """Build a human-readable list of fields being used for matching."""
        fields = []
        if match_fields['by_title']:
            fields.append(FIELD_TITLE)
        if match_fields['by_login']:
            fields.append(FIELD_LOGIN)
        if match_fields['by_password']:
            fields.append(FIELD_PASSWORD)
        if match_fields['by_url']:
            fields.append(FIELD_WEBSITE_ADDRESS)
        if match_fields['by_custom']:
            fields.append(FIELD_CUSTOM_FIELDS)
        if match_fields['by_shares']:
            fields.append(FIELD_SHARES)
        return fields
    
    def _filter_team_user_permissions(self, permissions):
        """Filter out team user permissions from the permissions dict."""
        filtered_perms = {
            k: p for k, p in permissions.items()
            if TEAM_USER_TYPE not in p.types or len(p.types) > 1
        }
        return filtered_perms
    
    def _create_record_hash(self, record, match_fields):
        """
        Create a hash for a record based on the specified match fields.
        
        Returns:
            tuple: (hash_value, non_empty_count)
                - hash_value: hex digest of the hash
                - non_empty_count: number of non-empty fields processed
        """
        tokens = []
        
        if match_fields['by_title']:
            tokens.append((record.title or '').lower())
        
        if match_fields['by_login']:
            if isinstance(record, vault_record.PasswordRecord):
                tokens.append((record.login or '').lower())
            elif isinstance(record, vault_record.TypedRecord):
                login_field = record.get_typed_field('login')
                if login_field:
                    tokens.append((login_field.get_default_value(str) or '').lower())
        
        if match_fields['by_password']:
            tokens.append(record.extract_password() or '')
        
        if match_fields['by_url']:
            tokens.append(record.extract_url() or '')
        
        hasher = hashlib.sha256()
        non_empty = 0
        
        for token in tokens:
            if token:
                non_empty += 1
            hasher.update(token.encode())
        
        # Process custom fields if needed
        if match_fields['by_custom'] and isinstance(record, vault_record.TypedRecord):
            non_empty += self._hash_custom_fields(record, hasher)
        
        return hasher.hexdigest(), non_empty
    
    def _hash_custom_fields(self, record, hasher):
        """Hash custom fields for typed records."""
        customs = {}
        non_empty = 0
        
        for field in record.custom:
            name = field.label if field.label != '' else field.type
            value = field.value
            
            if not name or not value:
                continue
            
            # Handle different value types
            if isinstance(value, list):
                value = '|'.join(sorted(str(x) for x in value))
            elif isinstance(value, int):
                value = str(value) if value != 0 else None
            elif isinstance(value, dict):
                keys = sorted(value.keys())
                value = ';'.join(f'{k}:{value[k]}' for k in keys if value.get(k))
            elif not isinstance(value, str):
                value = None
            
            if value:
                customs[name] = value
        
        if record.get_typed_field('totp'):
            customs['totp'] = record.get_typed_field('totp').get_default_value(str)
        
        if record.record_type:
            customs['type:'] = record.record_type
        
        for key in sorted(customs.keys()):
            non_empty += 1
            for_hash = f'{key}={customs[key]}'
            hasher.update(for_hash.encode('utf-8'))
        
        return non_empty
    
    def _extract_record_info(self, record, match_fields):
        """Extract basic record information for display."""
        title = record.title or ''
        
        if isinstance(record, vault_record.PasswordRecord):
            url = record.link or ''
            login = record.login or ''
        elif isinstance(record, vault_record.TypedRecord):
            login = record.get_typed_field('login').get_default_value(str) or ''
            url = record.extract_url() or ''
        else:
            login = ''
            url = ''
        
        return title, login, url
    
    def _format_url(self, url, include_in_output):
        """Format URL for display, truncating if necessary."""
        parsed_url = urllib.parse.urlparse(url).hostname
        parsed_url = parsed_url[:URL_DISPLAY_LENGTH] if parsed_url else ''
        return [parsed_url] if include_in_output else []


class RecordPermissionCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='record-permission', description='Modify the permissions of a record')
        RecordPermissionCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('--dry-run', dest='dry_run', action='store_true',
                                            help='Display the permissions changes without committing them')
        parser.add_argument('--force', dest='force', action='store_true',
                                            help='Apply permission changes without any confirmation')
        parser.add_argument('-R', '--recursive', dest='recursive', action='store_true',
                                            help='Apply permission changes to all sub-folders')
        parser.add_argument('--share-record', dest='share_record', action='store_true',
                                            help='Change a records sharing permissions')
        parser.add_argument('--share-folder', dest='share_folder', action='store_true',
                                            help='Change a folders sharing permissions')
        parser.add_argument('-a', '--action', dest='action', action='store', choices=['grant', 'revoke'],
                                            required=True, help='The action being taken')
        parser.add_argument('-s', '--can-share', dest='can_share', action='store_true',
                                            help='Set record permission: can be shared')
        parser.add_argument('-d', '--can-edit', dest='can_edit', action='store_true',
                                            help='Set record permission: can be edited')
        parser.add_argument('folder', nargs='?', type=str, action='store', help='folder path or folder UID')
        parser.error = base.ArgparseCommand.raise_parse_exception
        parser.exit = base.ArgparseCommand.suppress_exit
    
    def execute(self, context: KeeperParams, **kwargs):
        if not context.vault:
            raise base.CommandError('Vault is not initialized')
        vault = context.vault

        folder_name = kwargs['folder'] if 'folder' in kwargs else ''
        folder_uid = None
        if folder_name:
            if folder_name in vault.vault_data._folders:
                folder_uid = folder_name
            else:
                folder, path = folder_utils.try_resolve_path(context, folder_name)
                if len(path) == 0:
                    folder_uid = folder.folder_uid
                else:
                    raise base.CommandError('Folder {0} not found'.format(folder_name))

        if folder_uid:
            folder = vault.vault_data.get_folder(folder_uid)
        else:
            folder = vault.vault_data.root_folder

        share_record = kwargs.get('share_record') or False
        share_folder = kwargs.get('share_folder') or False
        if not share_record and not share_folder:
            share_record = True
            share_folder = True

        flat_subfolders = [folder]
        if kwargs.get('recursive'):
            fols = set()
            fols.add(folder.folder_uid)
            pos = 0
            while pos < len(flat_subfolders):
                subfolder = flat_subfolders[pos]
                if subfolder.subfolders:
                    for f_uid in subfolder.subfolders:
                        if f_uid not in fols:
                            f = vault.vault_data.get_folder(f_uid)
                            if f:
                                flat_subfolders.append(f)
                            fols.add(f_uid)
                pos += 1
            logger.debug('Folder count: %s', len(flat_subfolders))

        should_have = True if kwargs['action'] == 'grant' else False
        change_share = kwargs['can_share'] or False
        change_edit = kwargs['can_edit'] or False

        if not change_share and not change_edit:
            raise base.CommandError('Please choose at least one on the following options: can-edit, can-share')

        if not kwargs.get('force'):
            logger.info('\nRequest to {0} {1}{3}{2} permission(s) in "{4}" folder {5}'
                         .format('GRANT' if should_have else 'REVOKE',
                                 '"Can Edit"' if change_edit else '',
                                 '"Can Share"' if change_share else '',
                                 ' & ' if change_edit and change_share else '',
                                 folder.name,
                                 'recursively' if kwargs.get('recursive') else 'only'))

        uids = set()

        direct_shares_update = []
        direct_shares_skip = []

        # direct shares
        if share_record:
            uids.clear()
            for folder in flat_subfolders:
                folder_uid = folder.uid or ''
                if folder_uid in params.subfolder_record_cache:
                    uids.update(params.subfolder_record_cache[folder_uid])

            if len(uids) > 0:
                shared_records = share_utils.get_record_shares(vault, uids)
                if shared_records:
                    for shared_record in shared_records:
                        if shared_record.user_permissions:
                            for up in shared_record.user_permissions:
                                if up['owner']:  # exclude record owners
                                    continue
                                username = up['username']
                                if username == context.username:  # exclude self
                                    continue
                                if (change_edit and should_have != up['editable']) or \
                                        (change_share and should_have != up['shareable']):
                                    direct_shares_update.append(up)

        shared_folder_update = {} 
        shared_folder_skip = {}

        if share_folder:
            share_admin_in_folders = set()
            for folder in flat_subfolders:
                shared_folder_uid = None
                if folder.folder_type == 'shared_folder':
                    shared_folder_uid = folder.folder_uid
                elif folder.folder_type == 'shared_folder_folder':
                    shared_folder_uid = folder.folder_scope_uid
                if shared_folder_uid:
                    if shared_folder_uid not in share_admin_in_folders and shared_folder_uid in vault.vault_data._shared_folders:
                        share_admin_in_folders.add(shared_folder_uid)
            if len(share_admin_in_folders) > 0:
                rq = record_pb2.AmIShareAdmin()
                for shared_folder_uid in share_admin_in_folders:
                    osa = record_pb2.IsObjectShareAdmin()
                    osa.uid = utils.base64_url_decode(shared_folder_uid)
                    osa.objectType = record_pb2.CHECK_SA_ON_SF
                    rq.isObjectShareAdmin.append(osa)
                share_admin_in_folders.clear()
                try:
                    rs = vault.keeper_auth.execute_auth_rest(rest_endpoint='vault/am_i_share_admin', request=rq, response_type=record_pb2.AmIShareAdmin)
                    for osa in rs.isObjectShareAdmin:
                        if osa.isAdmin:
                            share_admin_in_folders.add(utils.base64_url_encode(osa.uid))
                except:
                    pass

            for folder in flat_subfolders:
                if folder.folder_type not in {'shared_folder', 'shared_folder_folder'}:
                    continue
                uids.clear()
                if folder.folder_uid in params.subfolder_record_cache:
                    uids.update(params.subfolder_record_cache[folder.uid])

                shared_folder_uid = folder.uid
                if type(folder) == SharedFolderFolderNode:
                    shared_folder_uid = folder.shared_folder_uid

                account_uid = context.auth.auth_context.account_uid
                if shared_folder_uid in vault.vault_data._shared_folders:
                    is_share_admin = shared_folder_uid in share_admin_in_folders
                    shared_folder = vault.vault_data.get_shared_folder(shared_folder_uid)
                    team_uid = None
                    has_manage_records_permission = is_share_admin
                    if not has_manage_records_permission:
                        if 'owner_account_uid' in shared_folder:
                            has_manage_records_permission = shared_folder['owner_account_uid'] == account_uid
                    if not has_manage_records_permission:
                        if 'users' in shared_folder:
                            user = next((x for x in shared_folder['users'] if x.get('username') == context.username), None)
                            if user and 'manage_records' in user:
                                has_manage_records_permission = user['manage_records'] is True
                    if not has_manage_records_permission:
                        if 'teams' in shared_folder:
                            for sft in shared_folder.teams:
                                uid = sft
                                if sft.get('manage_records') and uid in context.enterprise_data.teams:
                                    team_uid = uid
                                    has_manage_records_permission = True
                                    break

                    if 'records' in shared_folder:
                        for rp in shared_folder['records']:
                            record_uid = rp['record_uid']
                            if is_share_admin or has_manage_records_permission:
                                container = shared_folder_update
                            else:
                                container = shared_folder_skip

                            if shared_folder_uid not in container:
                                container[shared_folder_uid] = {}
                            record_permissions = container[shared_folder_uid]

                            if record_uid in uids and record_uid not in record_permissions:
                                if (change_edit and should_have != rp['can_edit']) or \
                                        (change_share and should_have != rp['can_share']):
                                    cmd = folder_pb2.SharedFolderUpdateRecord()
                                    cmd.recordUid = utils.base64_url_decode(record_uid)
                                    cmd.sharedFolderUid = utils.base64_url_decode(shared_folder_uid)
                                    if team_uid:
                                        cmd.teamUid = utils.base64_url_decode(team_uid)
                                    cmd.canEdit = (folder_pb2.BOOLEAN_TRUE if should_have else folder_pb2.BOOLEAN_FALSE) if change_edit else folder_pb2.BOOLEAN_NO_CHANGE
                                    cmd.canShare = (folder_pb2.BOOLEAN_TRUE if should_have else folder_pb2.BOOLEAN_FALSE) if change_share else folder_pb2.BOOLEAN_NO_CHANGE
                                    record_permissions[record_uid] = cmd

        if len(shared_folder_update) > 0:
            uids.clear()
            uids.update(shared_folder_update.keys())
            for shared_folder_uid in uids:
                if len(shared_folder_update[shared_folder_uid]) == 0:
                    del shared_folder_update[shared_folder_uid]

        if len(shared_folder_skip) > 0:
            uids.clear()
            uids.update(shared_folder_skip.keys())
            for shared_folder_uid in uids:
                if len(shared_folder_skip[shared_folder_uid]) == 0:
                    del shared_folder_skip[shared_folder_uid]

        if len(direct_shares_skip) > 0:
            if kwargs.get('dry_run'):
                table = []
                for cmd in direct_shares_skip:
                    record_uid = cmd['record_uid']
                    record = params.record_cache[record_uid]
                    record_owners = [x['username'] for x in record['shares']['user_permissions'] if x['owner']]
                    record_owner = record_owners[0] if len(record_owners) > 0 else ''
                    rec = api.get_record(params, record_uid)
                    row = [record_uid, rec.title[:32], record_owner, cmd['to_username']]
                    table.append(row)
                headers = ['Record UID', 'Title', 'Owner', 'Email']
                title = bcolors.FAIL + ' SKIP ' + bcolors.ENDC + 'Direct Record Share permission(s). Not permitted'
                dump_report_data(table, headers, title=title, row_number=True, group_by=0)
                logging.info('')
                logging.info('')

        if len(shared_folder_skip) > 0:
            if kwargs.get('dry_run'):
                table = []
                for shared_folder_uid in shared_folder_skip:
                    shared_folder = api.get_shared_folder(params, shared_folder_uid)
                    uid = shared_folder_uid
                    name = shared_folder.name[:32]
                    for record_uid in shared_folder_skip[shared_folder_uid]:
                        record = api.get_record(params, record_uid)
                        row = [uid, name, record_uid, record.title]
                        uid = ''
                        name = ''
                        table.append(row)
                if len(table) > 0:
                    headers = ['Shared Folder UID', 'Shared Folder Name', 'Record UID', 'Record Title']
                    title = (bcolors.FAIL + ' SKIP ' + bcolors.ENDC +
                             'Shared Folder Record Share permission(s). Not permitted')
                    dump_report_data(table, headers, title=title, row_number=True)
                    logging.info('')
                    logging.info('')

        if len(direct_shares_update) > 0:
            if not kwargs.get('force'):
                table = []
                for cmd in direct_shares_update:
                    record_uid = cmd['record_uid']
                    rec = api.get_record(params, record_uid)
                    row = [record_uid, rec.title[:32], cmd['to_username']]
                    if change_edit:
                        row.append((bcolors.BOLD + '   ' + ('Y' if should_have else 'N') + bcolors.ENDC)
                                   if 'editable' in cmd else '')
                    if change_share:
                        row.append((bcolors.BOLD + '   ' + ('Y' if should_have else 'N') + bcolors.ENDC)
                                   if 'shareable' in cmd else '')
                    table.append(row)

                headers = ['Record UID', 'Title', 'Email']
                if change_edit:
                    headers.append('Can Edit')
                if change_share:
                    headers.append('Can Share')

                title = (bcolors.OKGREEN + ' {0}' + bcolors.ENDC + ' Direct Record Share permission(s)') \
                    .format('GRANT' if should_have else 'REVOKE')
                dump_report_data(table, headers, title=title, row_number=True, group_by=0)
                logging.info('')
                logging.info('')

        if len(shared_folder_update) > 0:
            if not kwargs.get('force'):
                table = []
                for shared_folder_uid in shared_folder_update:
                    commands = shared_folder_update[shared_folder_uid]
                    shared_folder = api.get_shared_folder(params, shared_folder_uid)
                    uid = shared_folder_uid
                    name = shared_folder.name[:32]
                    for record_uid in commands:
                        cmd = commands[record_uid]
                        record = api.get_record(params, record_uid)
                        row = [uid, name, record_uid, record.title[:32]]
                        if change_edit:
                            row.append((bcolors.BOLD + '   ' + ('Y' if should_have else 'N') + bcolors.ENDC)
                                       if cmd.canEdit else '')
                        if change_share:
                            row.append((bcolors.BOLD + '   ' + ('Y' if should_have else 'N') + bcolors.ENDC)
                                       if cmd.canShare else '')
                        table.append(row)
                        uid = ''
                        name = ''

                if len(table) > 0:
                    headers = ['Shared Folder UID', 'Shared Folder Name', 'Record UID', 'Record Title']
                    if change_edit:
                        headers.append('Can Edit')
                    if change_share:
                        headers.append('Can Share')
                    title = (bcolors.OKGREEN + ' {0}' + bcolors.ENDC + ' Shared Folder Record Share permission(s)') \
                        .format('GRANT' if should_have else 'REVOKE')
                    dump_report_data(table, headers, title=title, row_number=True)
                    logging.info('')
                    logging.info('')

        if not kwargs.get('dry_run') and (len(shared_folder_update) > 0 or len(direct_shares_update) > 0):
            print('\n\n' + bcolors.WARNING + bcolors.BOLD + 'ALERT!!!' + bcolors.ENDC)
            answer = base.user_choice("Do you want to proceed with these permission changes?", 'yn', 'n') \
                if not kwargs.get('force') else 'Y'
            if answer.lower() == 'y':
                table = []

                def to_share_record_proto(srd):   # type: (dict) -> record_pb2.SharedRecord
                    srp = record_pb2.SharedRecord()
                    srp.toUsername = srd['to_username']
                    srp.recordUid = utils.base64_url_decode(srd['record_uid'])
                    if 'shared_folder_uid' in srd:
                        srp.sharedFolderUid = utils.base64_url_decode(srd['shared_folder_uid'])
                    if 'team_uid' in srd:
                        srp.teamUid = utils.base64_url_decode(srd['team_uid'])
                    if 'record_key' in srd:
                        srp.recordKey = utils.base64_url_decode(srd['record_key'])
                    if 'use_ecc_key' in srd:
                        srp.useEccKey = srd['use_ecc_key']
                    if 'editable' in srd:
                        srp.editable = srd['editable']
                    if 'shareable' in srd:
                        srp.shareable = srd['shareable']
                    if 'transfer' in srd:
                        srp.shareable = srd['transfer']

                    return srp

                while len(direct_shares_update) > 0:
                    rsu_rq = record_pb2.RecordShareUpdateRequest()
                    rsu_rq.updateSharedRecord.extend((to_share_record_proto(x) for x in direct_shares_update[:900]))
                    direct_shares_update = direct_shares_update[900:]

                    rsu_rs = api.communicate_rest(params, rsu_rq, 'vault/records_share_update',
                                                  rs_type=record_pb2.RecordShareUpdateResponse)
                    for status in rsu_rs.updateSharedRecordStatus:
                        code = status.status.lower()
                        if code != 'success':
                            record_uid = utils.base64_url_encode(status.recordUid)
                            table.append([record_uid, status.username, code, status.message])

                if len(table) > 0:
                    headers = ['Record UID', 'Email', 'Error Code', 'Message']
                    title = (bcolors.WARNING + 'Failed to {0}' + bcolors.ENDC + ' Direct Record Share permission(s)') \
                        .format('GRANT' if should_have else 'REVOKE')
                    dump_report_data(table, headers, title=title, row_number=True)
                    logging.info('')
                    logging.info('')

                table = []
                requests = []
                for shared_folder_uid in shared_folder_update:
                    updates = list(shared_folder_update[shared_folder_uid].values())
                    while len(updates) > 0:
                        batch = updates[:490]
                        updates = updates[490:]
                        rq = folder_pb2.SharedFolderUpdateV3Request()
                        rq.sharedFolderUid = utils.base64_url_decode(shared_folder_uid)
                        rq.forceUpdate = True
                        rq.sharedFolderUpdateRecord.extend(batch)
                        rq.fromTeamUid = batch[0].teamUid
                        requests.append(rq)

                chunks = []         # type: List[Dict[bytes, folder_pb2.SharedFolderUpdateV3Request]]
                current_rq = {}     # type: Dict[bytes, folder_pb2.SharedFolderUpdateV3Request]
                total_elements = 0
                for rq in requests:
                    if rq.sharedFolderUid in current_rq:
                        chunks.append(current_rq)
                        current_rq = {}
                        total_elements = 0
                    if total_elements + len(rq.sharedFolderUpdateRecord) > 500:
                        chunks.append(current_rq)
                        current_rq = {}
                        total_elements = 0

                    current_rq[rq.sharedFolderUid] = rq
                    total_elements += len(rq.sharedFolderUpdateRecord)
                if len(current_rq) > 0:
                    chunks.append(current_rq)

                for chunk in chunks:
                    rqs = folder_pb2.SharedFolderUpdateV3RequestV2()
                    rqs.sharedFoldersUpdateV3.extend(chunk.values())
                    rss = api.communicate_rest(params, rqs, 'vault/shared_folder_update_v3', payload_version=1,
                                               rs_type=folder_pb2.SharedFolderUpdateV3ResponseV2)
                    for rs in rss.sharedFoldersUpdateV3Response:
                        shared_folder_uid = utils.base64_url_encode(rs.sharedFolderUid)
                        for status in rs.sharedFolderUpdateRecordStatus:
                            record_uid = utils.base64_url_encode(status.recordUid)
                            code = status.status
                            if code != 'success':
                                table.append([shared_folder_uid, record_uid, code])

                if len(table) > 0:
                    headers = ['Shared Folder UID', 'Record UID', 'Error Code']
                    title = (
                                bcolors.WARNING + 'Failed to {0}' + bcolors.ENDC +
                                ' Shared Folder Record Share permission(s)').format('GRANT' if should_have else 'REVOKE')
                    dump_report_data(table, headers, title=title)
                    logging.info('')
                    logging.info('')

                params.sync_data = True