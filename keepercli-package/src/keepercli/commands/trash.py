import argparse
import datetime
import fnmatch
import json
import re
from typing import List, Dict, Any, Optional

from . import base
from .. import api, prompt_utils
from ..helpers import report_utils, share_utils
from ..params import KeeperParams

from keepersdk import utils
from keepersdk.proto import record_pb2
from keepersdk.vault import trash_management 
from keepersdk.vault.trash_management import TrashManagement


logger = api.get_logger()
STRING_LENGTH_LIMIT = 100
CHUNK_SIZE_LIMIT = 900
TRUNCATE_SUFFIX = '...'


class TrashCommand(base.GroupCommand):
    """Main command class for trash management operations."""
    
    def __init__(self):
        super().__init__('Trash.')
        self.register_command(TrashListCommand(), 'list')
        self.register_command(TrashGetCommand(), 'get')
        self.register_command(TrashRestoreCommand(), 'restore')
        self.register_command(TrashUnshareCommand(), 'unshare')
        self.register_command(TrashPurgeCommand(), 'purge')
        self.default_verb = 'list'


class TrashListCommand(base.ArgparseCommand):
    """Command to display a list of deleted records in the trash."""
    
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='trash list', description='Displays a list of deleted records.', parents=[base.report_output_parser]
        )
        self.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        """Add command-specific arguments to the parser."""
        parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help="verbose output")
        parser.add_argument('pattern', nargs='?', type=str, action='store', help='search pattern')

    def execute(self, context: KeeperParams, **kwargs):
        """Execute the trash list command."""
        TrashManagement._ensure_deleted_records_loaded(context.vault)
        
        deleted_records = TrashManagement.get_deleted_records()
        orphaned_records = TrashManagement.get_orphaned_records()
        shared_folders = TrashManagement.get_shared_folders()
        
        if self._is_trash_empty(deleted_records, orphaned_records, shared_folders):
            logger.info('Trash is empty')
            return

        pattern = self._normalize_search_pattern(kwargs.get('pattern'))
        if not pattern:
            title_pattern = None
        else:
            title_pattern = self._create_title_pattern(pattern)
        
        headers = ['Folder UID', 'Record UID', 'Name', 'Record Type', 'Deleted At', 'Status']
        record_table = self._build_record_table(deleted_records, orphaned_records, pattern, title_pattern)
        folder_table = self._build_folder_table(shared_folders, kwargs.get('verbose', False))
        
        record_table.sort(key=lambda x: x[2].casefold())
        folder_table.sort(key=lambda x: x[2].casefold())
        all_records = record_table + folder_table

        return report_utils.dump_report_data(
            all_records, headers, 
            fmt=kwargs.get('format'),
            filename=kwargs.get('output'), 
            row_number=True
        )
    
    def _is_trash_empty(self, deleted_records: Dict, orphaned_records: Dict, shared_folders: Dict) -> bool:
        """Check if trash is empty."""
        return (len(deleted_records) == 0 and 
                len(orphaned_records) == 0 and 
                len(shared_folders) == 0)
    
    def _normalize_search_pattern(self, pattern: Optional[str]) -> Optional[str]:
        """Normalize search pattern (convert '*' to None)."""
        if pattern == '*':
            return None
        return pattern
    
    def _create_title_pattern(self, pattern: Optional[str]) -> Optional[re.Pattern]:
        """Safely compile regex pattern with length limits."""
        if len(pattern) > STRING_LENGTH_LIMIT:  # Prevent ReDoS
            logger.warning("Pattern too long, truncated")
            pattern = pattern[:STRING_LENGTH_LIMIT]
        
        try:
            return re.compile(fnmatch.translate(pattern), re.IGNORECASE)
        except re.error as e:
            logger.warning("Invalid pattern: %s", e)
            return None
    
    def _build_record_table(self, deleted_records: Dict, orphaned_records: Dict, 
                           pattern: Optional[str], title_pattern: Optional[re.Pattern]) -> List[List]:
        """Build the record table for deleted and orphaned records."""
        record_table = []
        
        # Process deleted records
        self._add_records_to_table(deleted_records, False, pattern, title_pattern, record_table)
        
        # Process orphaned records
        self._add_records_to_table(orphaned_records, True, pattern, title_pattern, record_table)
        
        return record_table
    
    def _add_records_to_table(self, records: Dict, is_shared: bool, pattern: Optional[str], 
                             title_pattern: Optional[re.Pattern], record_table: List[List]) -> None:
        """Add records to the table if they match the criteria."""
        for record in records.values():
            if self._should_include_record(record, pattern, title_pattern):
                row = self._create_record_row(record, is_shared)
                record_table.append(row)
    
    def _should_include_record(self, record: Dict, pattern: Optional[str], 
                              title_pattern: Optional[re.Pattern]) -> bool:
        """Check if record should be included based on search pattern."""
        if not pattern:
            return True
            
        record_uid = record.get('record_uid')
        if pattern == record_uid:
            return True
            
        if title_pattern:
            record_data_json = record.get('data_unencrypted')
            try:
                record_data = json.loads(record_data_json)
                record_title = record_data.get('title', '')
                return title_pattern.match(record_title) is not None
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                logger.debug("Failed to parse record data: %s", e)
                return False
            
        return False
    
    def _create_record_row(self, record: Dict, is_shared: bool) -> List:
        """Create a table row for a record."""
        record_uid = record.get('record_uid')
        record_data_json = record.get('data_unencrypted')
        
        try:
            record_data = json.loads(record_data_json) if record_data_json else {}
            record_title = record_data.get('title', '')
            record_type = record_data.get('type', '')
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.debug("Failed to parse record data for row creation: %s", e)
            record_title = 'Parse Error'
            record_type = 'Unknown'
        
        if is_shared:
            status = 'Share'
            date_deleted = None
        else:
            status = 'Record'
            date_deleted = self._get_deleted_date(record)
        
        return ['', record_uid, record_title, record_type, date_deleted, status]
    
    def _build_folder_table(self, shared_folders: Dict, verbose: bool) -> List[List]:
        """Build the folder table for shared folders."""
        if not shared_folders:
            return []
            
        folders = shared_folders.get('folders', {})
        records = shared_folders.get('records', {})
        
        if verbose:
            return self._build_verbose_folder_table(folders, records)
        else:
            return self._build_summary_folder_table(folders, records)
    
    def _build_verbose_folder_table(self, folders: Dict, records: Dict) -> List[List]:
        """Build verbose folder table showing individual records."""
        folder_table = []
        
        for record in records.values():
            folder_uid = record.get('folder_uid')
            record_uid = record.get('record_uid')
            record_data_json = record.get('data_unencrypted')
            
            try:
                record_data = json.loads(record_data_json) if record_data_json else {}
                
                if not record_data:
                    continue
                    
                record_title = record_data.get('title', '')
                record_type = record_data.get('type', '')
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                logger.debug("Failed to parse folder record data: %s", e)
                continue
            
            date_deleted = self._get_deleted_date(record)
            
            folder_table.append([
                folder_uid, record_uid, record_title, 
                record_type, date_deleted, 'Folder'
            ])
        
        return folder_table
    
    def _build_summary_folder_table(self, folders: Dict, records: Dict) -> List[List]:
        """Build summary folder table showing folder counts."""
        folder_table = []
        record_counts = self._count_records_per_folder(records)
        
        for folder in folders.values():
            folder_uid = folder.get('folder_uid')
            date_deleted = self._get_deleted_date(folder)
            record_count = record_counts.get(folder_uid, 0)
            
            record_count_text = f'{record_count} record(s)' if record_count > 0 else None
            folder_name = self._get_folder_name(folder, folder_uid)
            
            folder_table.append([
                folder_uid, record_count_text, folder_name, 
                '', date_deleted, 'Folder'
            ])
        
        return folder_table
    
    def _count_records_per_folder(self, records: Dict) -> Dict[str, int]:
        """Count records per folder."""
        record_counts = {}
        for record in records.values():
            folder_uid = record.get('folder_uid')
            record_counts[folder_uid] = record_counts.get(folder_uid, 0) + 1
        return record_counts
    
    def _get_deleted_date(self, item: Dict) -> Optional[datetime.datetime]:
        """Get deleted date from item with validation."""
        date_deleted_timestamp = item.get('date_deleted', 0)
        if date_deleted_timestamp:
            try:
                # Validate timestamp type
                if not isinstance(date_deleted_timestamp, (int, float)):
                    logger.debug("Invalid timestamp type: %s", type(date_deleted_timestamp))
                    return None
                
                # Convert to seconds and validate range
                timestamp_seconds = int(date_deleted_timestamp / 1000)
                
                # Check for reasonable date range (1970-2100)
                if timestamp_seconds < 0 or timestamp_seconds > 4102444800:  # Jan 1, 2100
                    logger.debug("Timestamp out of range: %s", timestamp_seconds)
                    return None
                
                return datetime.datetime.fromtimestamp(timestamp_seconds)
            except (ValueError, OSError, OverflowError) as e:
                logger.debug("Invalid timestamp conversion: %s", e)
                return None
        return None
    
    def _get_folder_name(self, folder: Dict, folder_uid: str) -> str:
        """Get folder name, falling back to UID if parsing fails."""
        try:
            data_bytes = folder.get('data_unencrypted')
            data_json = utils.base64_url_encode(data_bytes)
            data = json.loads(data_json)
            return data.get('name') or folder_uid
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.debug('Load folder data: %s', e)
            return folder_uid
        except Exception as e:
            logger.debug('Load folder data: %s', e)
            return folder_uid


class TrashGetCommand(base.ArgparseCommand):
    """Command to get details of a deleted record."""
    
    def __init__(self):
        parser = argparse.ArgumentParser(prog='trash get', description='Get the details of a deleted record.')
        self.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        """Add command-specific arguments to the parser."""
        parser.add_argument('record', action='store', help='Deleted record UID')
    
    def execute(self, context: KeeperParams, **kwargs):
        """Execute the trash get command."""
        record_uid = kwargs.get('record')
        if not record_uid:
            logger.info('Record UID parameter is required')
            return

        # Validate record UID format and length
        if not isinstance(record_uid, str):
            logger.info('Record UID must be a string')
            return
        
        if len(record_uid) == 0 or len(record_uid) > STRING_LENGTH_LIMIT:
            logger.info('Invalid record UID length')
            return

        try:
            record, is_shared = trash_management.get_trash_record(context.vault, record_uid)
        except Exception as e:
            logger.error('Error retrieving record: %s', e)
            return
        if not record:
            logger.info('%s is not a valid deleted record UID', record_uid)
            return

        record_data = self._parse_record_data(record)
        if not record_data:
            logger.info('Cannot restore record %s', record_uid)
            return

        self._display_record_info(record_data)
        
        if is_shared:
            self._display_share_info(context, record, record_uid)
    
    def _parse_record_data(self, record: Dict) -> Optional[Dict]:
        """Parse record data from JSON with security validation."""
        record_data_json = record.get('data_unencrypted')
        if not record_data_json:
            return None
        
        try:
            return json.loads(record_data_json)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.debug("Failed to parse record data: %s", e)
            return None
    
    def _display_record_info(self, record_data: Dict):
        """Display basic record information."""
        title = record_data.get('title')
        record_type = record_data.get('type')
        
        logger.info('{0:>21s}: {1}'.format('Title', title))
        logger.info('{0:>21s}: {1}'.format('Type', record_type))
        
        self._display_record_fields(record_data.get('fields', {}))
    
    def _display_record_fields(self, fields: List[Dict]):
        """Display record fields."""
        for field in fields:
            field_name = self._get_field_name(field)
            field_value = self._format_field_value(field.get('value'))
            
            if field_value:
                logger.info('{0:>21s}: {1}'.format(field_name, field_value))
    
    def _get_field_name(self, field: Dict) -> str:
        """Get display name for field."""
        label = field.get('label')
        if label and label != '':
            return label
        return field.get('type', '')
    
    def _format_field_value(self, value: Any) -> Optional[str]:
        """Format field value for display."""
        if not value:
            return None
            
        if isinstance(value, list):
            value = '\n'.join(value)
        
        if len(value) > STRING_LENGTH_LIMIT:
            value = value[:STRING_LENGTH_LIMIT-1] + TRUNCATE_SUFFIX
            
        return value
    
    def _display_share_info(self, context: KeeperParams, record: Dict, record_uid: str):
        """Display share information for shared records."""
        if 'shares' not in record:
            self._load_record_shares(context.vault, record, record_uid)

        if 'shares' in record and 'user_permissions' in record['shares']:
            self._display_user_permissions(record['shares']['user_permissions'], context.username)
    
    def _load_record_shares(self, vault, record: Dict, record_uid: str):
        """Load record shares if not already present."""
        record['shares'] = {}
        shares = share_utils.get_record_shares(vault, [record_uid], True)
        
        if isinstance(shares, list):
            record_shares = next(
                (x.get('shares') for x in shares if x.get('record_uid') == record_uid), 
                None
            )
            if isinstance(record_shares, dict):
                record['shares'] = record_shares
    
    def _display_user_permissions(self, user_permissions: List[Dict], current_username: str):
        """Display user permissions in sorted order."""
        sorted_permissions = self._sort_user_permissions(user_permissions)
        
        for index, permission in enumerate(sorted_permissions):
            if permission.get('owner'):
                continue
                
            username = permission['username']
            flags = self._get_permission_flags(permission)
            self_flag = 'self' if username == current_username else ''
            
            header = 'Direct User Shares' if index == 0 else ''
            logger.info('{0:>21s}: {1:<26s} ({2}) {3}'.format(
                header, username, flags, self_flag
            ))
    
    def _sort_user_permissions(self, permissions: List[Dict]) -> List[Dict]:
        """Sort user permissions by priority."""
        return sorted(permissions, key=lambda p: (
            ' 1' if p.get('owner') else
            ' 2' if p.get('editable') else
            ' 3' if p.get('shareable') else
            ''
        ) + p.get('username', ''))
    
    def _get_permission_flags(self, permission: Dict) -> str:
        """Get permission flags as a string."""
        flags = []
        
        if permission.get('editable'):
            flags.append('Can Edit')
        
        if permission.get('shareable'):
            share_flag = 'Can Share'
            if flags:
                share_flag = ' & ' + share_flag
            flags.append(share_flag)
        
        return ' '.join(flags) if flags else 'Read Only'


class TrashRestoreCommand(base.ArgparseCommand):
    """Command to restore deleted records from trash."""
    
    def __init__(self):
        parser = argparse.ArgumentParser(prog='trash restore', description='Restores deleted records.')
        self.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        """Add command-specific arguments to the parser."""
        parser.add_argument('-f', '--force', dest='force', action='store_true',
                                  help='do not prompt for confirmation')
        parser.add_argument('records', nargs='+', type=str, action='store',
                                  help='Record UID or search pattern')
    
    def execute(self, context: KeeperParams, **kwargs):
        """Execute the trash restore command."""
        records = self._validate_records_parameter(kwargs.get('records'))
        if not records:
            logger.info('records parameter is empty.')
            return
        
        confirm_callback = self._create_confirm_callback(kwargs.get('force', False))
        trash_management.restore_trash_records(context.vault, records, confirm_callback)
    
    def _validate_records_parameter(self, records: Any) -> Optional[List[str]]:
        """Validate and normalize records parameter with security checks."""
        if not isinstance(records, (tuple, list)):
            return None
        
        # Check list size to prevent DoS
        if len(records) > 10000:  # Reasonable limit
            logger.info('Too many records specified (max: 10000)')
            return None
        
        validated_records = []
        for i, record in enumerate(records):
            if self._is_valid_record(record, i + 1):
                validated_records.append(record)
        
        return validated_records if validated_records else None
    
    def _is_valid_record(self, record: str, index: int) -> bool:
        """Check if a single record is valid."""
        if not isinstance(record, str):
            logger.info('Record %d must be a string', index)
            return False
        
        # Validate UID format and length
        if len(record) == 0 or len(record) > STRING_LENGTH_LIMIT:
            logger.info('Record %d has invalid length', index)
            return False
        
        return True
    
    def _create_confirm_callback(self, force: bool):
        """Create confirmation callback based on force flag."""
        if force:
            return None
        
        def confirm_callback(question):
            return prompt_utils.user_choice(question, 'yn', default='n')
        return confirm_callback


class TrashPurgeCommand(base.ArgparseCommand):
    """Command to purge all records from trash."""
    
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='trash purge', description='Removes all deleted record from the trash bin.'
        )
        self.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        """Add command-specific arguments to the parser."""
        parser.add_argument(
            '-f', '--force', dest='force', action='store_true', help='do not prompt for confirmation'
        )
    
    def execute(self, context: KeeperParams, **kwargs):
        """Execute the trash purge command."""
        if not kwargs.get('force'):
            if not self._confirm_purge():
                return
        
        trash_management.purge_trash(context.vault)
    
    def _confirm_purge(self) -> bool:
        """Confirm purge operation with user."""
        answer = prompt_utils.user_choice('Do you want to empty your Trash Bin?', 'yn', default='n')
        if answer.lower() == 'y':
            answer = 'yes'
        return answer.lower() == 'yes'


class TrashUnshareCommand(base.ArgparseCommand):
    """Command to remove shares from deleted records."""
    
    def __init__(self):
        parser = argparse.ArgumentParser(prog='trash unshare', description='Remove shares from deleted records.')
        self.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        """Add command-specific arguments to the parser."""
        parser.add_argument(
            '-f', '--force', dest='force', action='store_true', help='do not prompt for confirmation'
        )
        parser.add_argument(
            'records', nargs='+', type=str, action='store', help='Record UID or search pattern. \"*\" for all records'
        )
    
    def execute(self, context: KeeperParams, **kwargs):
        """Execute the trash unshare command."""
        records = self._validate_records_parameter(kwargs.get('records'))
        if not records:
            logger.info('records parameter is empty.')
            return
        
        TrashManagement._ensure_deleted_records_loaded(context.vault)
        orphaned_records = TrashManagement.get_orphaned_records()
        
        if not orphaned_records:
            logger.info('Trash is empty')
            return

        records_to_unshare = self._find_records_to_unshare(records, orphaned_records)
        if not records_to_unshare:
            logger.info('There are no records to unshare')
            return

        if not self._confirm_unshare(kwargs.get('force', False), len(records_to_unshare)):
            return

        self._remove_shares_from_records(context.vault, records_to_unshare)
    
    def _validate_records_parameter(self, records: Any) -> Optional[List[str]]:
        """Validate and normalize records parameter with security checks."""
        if not isinstance(records, (tuple, list)):
            return None
        
        # Check list size to prevent DoS
        if len(records) > 10000:  # Reasonable limit
            logger.info('Too many records specified (max: 10000)')
            return None
        
        validated_records = []
        for i, record in enumerate(records):
            if self._is_valid_record(record, i + 1):
                validated_records.append(record)
        
        return validated_records if validated_records else None
    
    def _is_valid_record(self, record: str, index: int) -> bool:
        """Check if a single record is valid."""
        if len(record) == 0 or len(record) > STRING_LENGTH_LIMIT:
            logger.info('Record %d has invalid length', index)
            return False
        
        return True
    
    def _find_records_to_unshare(self, record_patterns: List[str], orphaned_records: Dict) -> List[str]:
        """Find records to unshare based on patterns."""
        records_to_unshare = set()
        
        for pattern in record_patterns:
            if pattern in orphaned_records:
                records_to_unshare.add(pattern)
            else:
                self._add_matching_records(pattern, orphaned_records, records_to_unshare)
        
        return list(records_to_unshare)
    
    def _add_matching_records(self, pattern: str, orphaned_records: Dict, records_to_unshare: set):
        """Add records matching the pattern to the unshare set."""
        if len(pattern) > STRING_LENGTH_LIMIT:  # Prevent ReDoS
            logger.warning("Record name too long, truncated")
            pattern = pattern[:STRING_LENGTH_LIMIT]
        
        try:
            title_pattern = re.compile(fnmatch.translate(pattern), re.IGNORECASE)
        except re.error as e:
            raise base.CommandError("Invalid record name: %s", e)
        
        for record_uid, record in orphaned_records.items():
            if record_uid in records_to_unshare:
                continue
                
            record_data = self._parse_record_data(record)
            if record_data and title_pattern.match(record_data.get('title', '')):
                records_to_unshare.add(record_uid)
    
    def _parse_record_data(self, record: Dict) -> Optional[Dict]:
        """Parse record data from JSON with security validation."""
        record_data_json = record.get('data_unencrypted')
        if not record_data_json:
            return None
        
        try:
            return json.loads(record_data_json)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.debug("Failed to parse record data: %s", e)
            return None
    
    def _confirm_unshare(self, force: bool, record_count: int) -> bool:
        """Confirm unshare operation with user."""
        if force:
            return True
            
        answer = prompt_utils.user_choice(
            f'Do you want to remove shares from {record_count} record(s)?', 
            'yn', 
            default='n'
        )
        if answer.lower() == 'y':
            answer = 'yes'
        return answer.lower() == 'yes'
    
    def _remove_shares_from_records(self, vault, records_to_unshare: List[str]):
        """Remove shares from the specified records."""
        record_shares = share_utils.get_record_shares(vault, records_to_unshare, True)
        if not record_shares:
            return
            
        remove_share_requests = self._build_remove_share_requests(record_shares)
        if not remove_share_requests:
            return
            
        self._execute_share_removal_requests(vault, remove_share_requests)
    
    def _build_remove_share_requests(self, record_shares: List[Dict]) -> List[record_pb2.SharedRecord]:
        """Build remove share requests from record shares."""
        remove_requests = []
        
        for record_share in record_shares:
            if 'shares' not in record_share:
                continue
                
            shares = record_share['shares']
            if 'user_permissions' not in shares:
                continue
            
            self._process_user_permissions(shares['user_permissions'], record_share['record_uid'], remove_requests)
        
        return remove_requests
    
    def _process_user_permissions(self, user_permissions: List[Dict], record_uid: str, remove_requests: List[record_pb2.SharedRecord]) -> None:
        """Process user permissions and add to remove requests."""
        for user_permission in user_permissions:
            if user_permission.get('owner') is False:
                share_request = record_pb2.SharedRecord()
                share_request.toUsername = user_permission['username']
                share_request.recordUid = utils.base64_url_decode(record_uid)
                remove_requests.append(share_request)
    
    def _execute_share_removal_requests(self, vault, remove_requests: List[record_pb2.SharedRecord]):
        """Execute share removal requests in chunks."""
        while remove_requests:
            chunk = remove_requests[:CHUNK_SIZE_LIMIT]
            remove_requests = remove_requests[CHUNK_SIZE_LIMIT:]
            
            self._process_share_removal_chunk(vault, chunk)
    
    def _process_share_removal_chunk(self, vault, chunk: List[record_pb2.SharedRecord]):
        """Process a chunk of share removal requests."""
        update_request = record_pb2.RecordShareUpdateRequest()
        update_request.removeSharedRecord.extend(chunk)

        response = vault.keeper_auth.execute_auth_rest(
            rest_endpoint='vault/records_share_update',
            request=update_request,
            response_type=record_pb2.RecordShareUpdateResponse
        )

        self._log_share_removal_errors(response)
    
    def _log_share_removal_errors(self, response: record_pb2.RecordShareUpdateResponse):
        """Log any errors from share removal response."""
        for status in response.removeSharedRecordStatus:
            if status.status.lower() != 'success':
                record_uid = utils.base64_url_encode(status.recordUid)
                logger.info('Remove share "%s" from record UID "%s" error: %s',
                           status.username, record_uid, status.message)
