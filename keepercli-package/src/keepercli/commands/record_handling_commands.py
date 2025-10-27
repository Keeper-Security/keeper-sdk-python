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
        out_fmt = kwargs.get('format', 'table')
        out_dst = kwargs.get('output')
        if not context.vault:
            raise base.CommandError(self.get_parser().prog, 'Vault is not initialized')
        vault = context.vault
        
        def scan_enterprise_vaults():
            if not context.enterprise_data:
                raise base.CommandError('This feature is available only to enterprise account administrators')

            if not enterprise_utils.is_addon_enabled(context, 'compliance_report'):
                raise base.CommandError('Compliance reports add-on is required to perform this action. '
                    'Please contact your administrator to enable this feature.')
            
            def user_has_privilege(context: KeeperParams) -> bool:
                # Running as MSP admin, user has all available privileges in this context
                licenses = context.enterprise_data.licenses.get_all_entities()
                for license in licenses:
                    if license.msp_permits:
                        return True

                # Not an admin account (user has no admin privileges)
                if not context.enterprise_data:
                    return False

                # Check role-derived privileges
                username = context.auth.auth_context.username
                users =  context.enterprise_data.users.get_all_entities()
                e_user_id = next(iter([u.enterprise_user_id for u in users if u.username == username]))
                role_users = context.enterprise_data.role_users.get_all_links()
                r_ids = [ru.role_id for ru in role_users if ru.enterprise_user_id == e_user_id]
                r_privileges = context.enterprise_data.role_privileges.get_all_links()
                return any(rp for rp in r_privileges if rp.role_id in r_ids and rp._run_compliance_report)

            if not user_has_privilege(context):
                raise base.CommandError('You do not have the required privilege to run a Compliance Report.')
            
            field_keys = ['title', 'url', 'record_type']
            refresh_data = kwargs.get('refresh_data')
            node_id = context.enterprise_data.root_node.node_id
            enterprise_id = node_id >> 32
            now = datetime.datetime.now()
            update_floor_dt = now - datetime.timedelta(days=1)
            update_floor_ts = int(update_floor_dt.timestamp())

            sox_data = enterprise_utils.get_compliance_data(context, node_id, enterprise_id, rebuild=refresh_data,
                                               min_updated=update_floor_ts)
            records = [r for r in sox_data.get_records().values() if not r.in_trash]
            recs_by_hash = {}

            for sd_rec in records:
                h_gen = hashlib.sha256()
                field_vals = [sd_rec.data.get(k) for k in field_keys]
                if not field_vals or not all(field_vals):
                    continue

                token_tuples = zip(field_keys, field_vals)
                for k, v in token_tuples:
                    h_gen.update(f'{k}={v};'.encode())

                hv = h_gen.hexdigest()
                grouped_records = recs_by_hash.get(hv, [])
                grouped_records.append(sd_rec)
                recs_by_hash[hv] = grouped_records

            dupe_groups = [recs for recs in recs_by_hash.values() if len(recs) > 1]
            if not dupe_groups:
                logger.info('No duplicates found.')
                return
            else:
                report_headers = ['group', 'record_uid', 'title', 'url', 'record_type', 'owner', 'shared',
                                  'shared_folder_uid']
                report_headers = report_utils.field_to_title(report_headers) if out_fmt != 'json' else report_headers
                report_data = []
                for i, group in enumerate(dupe_groups):
                    for j, sd_rec in enumerate(group):
                        record_owner = sox_data.get_record_owner(sd_rec.record_uid).email
                        field_vals = [sd_rec.data.get(k) for k in field_keys]
                        sf_uids = sox_data.get_record_sfs(sd_rec.record_uid)
                        sf_uids = '\n'.join(sf_uids)
                        report_row = [i + 1, sd_rec.record_uid, *field_vals, record_owner, sd_rec.shared, sf_uids]
                        report_data.append(report_row)
                report_title = 'Duplicate Search Results (Enterprise Scope):'
                return report_utils.dump_report_data(report_data, report_headers, fmt=out_fmt, filename=out_dst, title=report_title, group_by=0)

        scope = kwargs.get('scope', 'vault')
        if scope == 'enterprise':
            raise base.CommandError('Enterprise scope not yet implemented')
            # return scan_enterprise_vaults()

        quiet = kwargs.get('quiet', False)
        dry_run = kwargs.get('dry_run', False)
        quiet = quiet and not dry_run
        logging_fn = logger.info if not quiet else logger.debug

        def partition_by_shares(duplicate_sets, shared_recs_lookup):
            result = []
            for duplicates in duplicate_sets:
                recs_by_hash = {}
                for rec_uid in duplicates:
                    h = hashlib.sha256()
                    shared_rec = shared_recs_lookup.get(rec_uid)
                    permissions = shared_rec.permissions
                    tu_type = '(Team User)'
                    permissions = {k: p for k, p in permissions.items() if tu_type not in p.types or len(p.types) > 1}
                    permissions = {k: p for k, p in permissions.items() if p.to_name != shared_rec.owner}
                    permissions_keys = list(permissions.keys())
                    permissions_keys.sort()

                    to_hash = ';'.join(f'{k}={permissions.get(k).permissions_text}' for k in permissions_keys)
                    to_hash = to_hash or 'non-shared'
                    h.update(to_hash.encode())
                    h_val = h.hexdigest()
                    r_uids = recs_by_hash.get(h_val, set())
                    r_uids.add(rec_uid)
                    recs_by_hash[h_val] = r_uids
                result.extend([r for r in recs_by_hash.values() if len(r) > 1])
            return result

        def remove_duplicates(dupe_info, col_headers, dupe_uids):
            def confirm_removal(cols):
                prompt_title = f'\nThe following duplicate {"records have" if len(dupe_uids) > 1 else "record has"}' \
                        f' been marked for removal:\n'
                indices = (idx + 1 for idx in range(len(dupe_info)))
                prompt_report = prompt_title + '\n' + report_utils.tabulate(dupe_info, col_headers, showindex=indices)
                prompt_msg = prompt_report + '\n\nDo you wish to proceed?'
                return prompt_utils.user_choice(prompt_msg, 'yn', default='n') in ('y', 'yes')

            if kwargs.get('force') or confirm_removal(col_headers):
                record_management.delete_vault_objects(vault, list(dupe_uids))

        by_title = kwargs.get('title', False)
        by_login = kwargs.get('login', False)
        by_password = kwargs.get('password', False)
        by_url = kwargs.get('url', False)
        by_custom = kwargs.get('full', False)
        by_shares = kwargs.get('shares', False)
        consolidate = kwargs.get('merge', False)

        by_custom = consolidate or by_custom

        if by_custom:
            by_title = True
            by_login = True
            by_password = True
            by_url = True
            by_shares = not kwargs.get('ignore_shares_on_merge') if consolidate else True
        elif not by_title and not by_login and not by_password and not by_url:
            by_title = True
            by_login = True
            by_password = True

        hashes = {}
        for record_uid in vault.vault_data._records:
            record = vault.vault_data.load_record(record_uid)
            if not record or not isinstance(record, (vault_record.PasswordRecord, vault_record.TypedRecord)):
                continue
            tokens = []
            if by_title:
                tokens.append((record.title or '').lower())
            if by_login:
                if isinstance(record, vault_record.PasswordRecord):
                    tokens.append((record.login or '').lower())
                elif isinstance(record, vault_record.TypedRecord):
                    login_field = record.get_typed_field('login')
                    if login_field:
                        tokens.append((login_field.get_default_value(str) or '').lower())
            if by_password:
                tokens.append(record.extract_password() or '')
            if by_url:
                tokens.append(record.extract_url() or '')

            hasher = hashlib.sha256()
            non_empty = 0
            for token in tokens:
                if token:
                    non_empty += 1
                hasher.update(token.encode())

            if by_custom and isinstance(record, vault_record.TypedRecord):
                customs = {}
                for x in record.custom:
                    name = x.label if x.label != '' else x.type   # type: str
                    value = x.value
                    if name and value:
                        if isinstance(value, list):
                            value = [str(x) for x in value]
                            value.sort()
                            value = '|'.join(value)
                        elif isinstance(value, int):
                            if value != 0:
                                value = str(value)
                            else:
                                value = None
                        elif isinstance(value, dict):
                            keys = list(value.keys())
                            keys.sort()
                            value = ';'.join((f'{x}:{value[x]}' for x in keys if value.get(x)))
                        elif not isinstance(value, str):
                            value = None
                        if value:
                            customs[name] = value
                if record.get_typed_field('totp'):
                    customs['totp'] = record.get_typed_field('totp').get_default_value(str)
                if record.record_type:
                    customs['type:'] = record.record_type
                keys = list(customs.keys())
                keys.sort()
                for key in keys:
                    non_empty += 1
                    for_hash = f'{key}={customs[key]}'
                    hasher.update(for_hash.encode('utf-8'))

            if non_empty > 0:
                hash_value = hasher.hexdigest()
                rec_uids = hashes.get(hash_value, set())
                rec_uids.add(record_uid)
                hashes[hash_value] = rec_uids

        fields = []
        if by_title:
            fields.append('Title')
        if by_login:
            fields.append('Login')
        if by_password:
            fields.append('Password')
        if by_url:
            fields.append('Website Address')
        if by_custom:
            fields.append('Custom Fields')
        if by_shares:
            fields.append('Shares')

        logging_fn('Find duplicated records by: %s', ', '.join(fields))
        partitions = [rec_uids for rec_uids in hashes.values() if len(rec_uids) > 1]

        r_uids = [rec_uid for duplicates in partitions for rec_uid in duplicates]
        shared_records_lookup = share_utils.get_shared_records(context, r_uids, cache_only=True)
        if by_shares:
            partitions = partition_by_shares(partitions, shared_records_lookup)
        if partitions:
            headers = ['group', 'title', 'login']
            if by_url:
                headers.append('url')
            headers.extend(['uid', 'record_owner', 'shared_to'])
            headers = [report_utils.field_to_title(h) for h in headers] if out_fmt != 'json' else headers
            table_raw = []
            table = []
            to_remove = set()
            for i, partition in enumerate(partitions):
                for j, record_uid in enumerate(partition):
                    shared_record = shared_records_lookup[record_uid]
                    record = vault.vault_data.load_record(record_uid)
                    record_details = vault.vault_data.get_record(record_uid)
                    owner = record_details.flags.IsOwner
                    title = record.title or ''
                    if isinstance(record, vault_record.PasswordRecord):
                        url = record.link or ''
                        login = record.login or ''
                    elif isinstance(record, vault_record.TypedRecord):
                        login = record.get_typed_field('login').get_default_value(str) or ''
                        url = record.extract_url() or ''
                    url = urllib.parse.urlparse(url).hostname
                    url = url[:30] if url else ''
                    url = [url] if by_url else []
                    team_user_type = '(Team User)'
                    perms = {k: p for k, p in shared_record.permissions.items()}
                    keys = list(perms.keys())
                    keys.sort()
                    perms = [perms.get(k) for k in keys]
                    perms = [p for p in perms if team_user_type not in p.types or len(p.types) > 1]
                    shares = '\n'.join([p.to_name for p in perms if owner != p.to_name])
                    row = [i + 1, title, login] + url + [record_uid, owner, shares]
                    table.append(row)

                    if j != 0:
                        to_remove.add(record_uid)
                        table_raw.append(row)
            if consolidate:
                uid_header = report_utils.field_to_title('uid')
                record_uid_index = headers.index(uid_header) if uid_header in headers else None
                if not record_uid_index:
                    raise base.CommandError(self.get_parser().prog, 'Cannot find record UID for duplicate record')
                dup_info = [r for r in table_raw for rec_uid in to_remove if r[record_uid_index] == rec_uid]
                return remove_duplicates(dup_info, headers, to_remove)
            else:
                title = 'Duplicates Found:'
                return report_utils.dump_report_data(table, headers, title=title, fmt=out_fmt, filename=out_dst, group_by=0)
        else:
            logging_fn('No duplicates found')