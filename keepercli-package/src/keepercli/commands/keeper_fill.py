"""
KeeperFill command implementation for Keeper Commander CLI.

This module provides commands to manage KeeperFill settings for records,
including listing current settings and updating auto-fill and auto-submit options.
"""

import argparse
import fnmatch
import itertools
import json
import logging
import re
from typing import Union, Optional, List, Iterator

from . import base
from ..helpers import folder_utils, report_utils
from ..params import KeeperParams

from keepersdk import crypto, utils
from keepersdk.vault import vault_record
from keepersdk.proto import record_pb2


logger = logging.getLogger(__name__)


SUPPORTED_RECORD_VERSIONS = (2, 3)
MAX_DISPLAY_LENGTH = 32
TRUNCATE_LENGTH = 30

AUTO_FILL_ALWAYS = 'always'
AUTO_FILL_NEVER = 'never'
SETTING_ON = 'on'
SETTING_OFF = 'off'
SETTING_NONE = 'none'


_keeper_fill_parser = argparse.ArgumentParser(add_help=False)
_keeper_fill_parser.add_argument('-r', '--recursive', dest='recursive', action='store_true',
                                 help='Traverse recursively through subfolders')
_keeper_fill_parser.add_argument('paths', nargs='+', type=str, help='folder or record path or UID')

_keeper_fill_list_parser = argparse.ArgumentParser(
    prog='keeper-fill list', 
    parents=[_keeper_fill_parser, base.report_output_parser]
)
_keeper_fill_list_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', 
                                      help='Do not truncate long names')

_keeper_fill_set_parser = argparse.ArgumentParser(
    prog='keeper-fill set', 
    parents=[_keeper_fill_parser]
)
_keeper_fill_set_parser.add_argument('--auto-fill', dest='auto_fill', action='store', 
                                     choices=['on', 'off', 'none'],
                                     help='Auto Fill setting')
_keeper_fill_set_parser.add_argument('--auto-submit', dest='auto_submit', action='store', 
                                     choices=['on', 'off', 'none'],
                                     help='Auto Submit setting')


class KeeperFillCommand(base.GroupCommand):
    """Main command class for KeeperFill operations."""
    
    def __init__(self):
        super().__init__('KeeperFill settings management.')
        self.register_command(KeeperFillListCommand(), 'list')
        self.register_command(KeeperFillSetCommand(), 'set')
        self.default_verb = 'list'


class _KeeperFillMixin:
    """Mixin class containing shared utility methods for KeeperFill commands."""
    
    @staticmethod
    def _is_supported_record_version(record_info) -> bool:
        """Check if record version supports KeeperFill."""
        return record_info and record_info.version in SUPPORTED_RECORD_VERSIONS
    
    @staticmethod
    def _decrypt_non_shared_data(storage_nsd, data_key: bytes, version: int) -> bytes:
        """Decrypt non-shared data based on record version."""
        if version == 2:
            return crypto.decrypt_aes_v1(storage_nsd.data, data_key)
        return crypto.decrypt_aes_v2(storage_nsd.data, data_key)
    
    @staticmethod
    def _encrypt_non_shared_data(data_bytes: bytes, data_key: bytes, version: int) -> bytes:
        """Encrypt non-shared data based on record version."""
        if version == 2:
            return crypto.encrypt_aes_v1(data_bytes, data_key)
        return crypto.encrypt_aes_v2(data_bytes, data_key)
    
    @staticmethod
    def _normalize_auto_fill_for_display(auto_fill_mode) -> Optional[bool]:
        """Convert auto_fill_mode from storage format to display format."""
        if isinstance(auto_fill_mode, str):
            if auto_fill_mode == AUTO_FILL_ALWAYS:
                return True
            elif auto_fill_mode == AUTO_FILL_NEVER:
                return False
        return None
    
    @staticmethod
    def _normalize_setting_for_comparison(value, is_boolean: bool = False) -> str:
        """Normalize a setting value to 'on', 'off', or 'none' for comparison."""
        if is_boolean:
            if value is True:
                return SETTING_ON
            elif value is False:
                return SETTING_OFF
            return SETTING_NONE
        
        if isinstance(value, str):
            if value == AUTO_FILL_ALWAYS:
                return SETTING_ON
            elif value == AUTO_FILL_NEVER:
                return SETTING_OFF
        return SETTING_NONE
    
    @staticmethod
    def _truncate_text(text: str, max_length: int = MAX_DISPLAY_LENGTH) -> str:
        """Truncate text to maximum length with ellipsis."""
        if len(text) > max_length:
            return text[:TRUNCATE_LENGTH] + '...'
        return text
    
    @staticmethod
    def _format_url_for_display(url, verbose: bool) -> str:
        """Format URL(s) for display, optionally truncating."""
        if not url:
            return ''
        
        if verbose:
            if isinstance(url, str):
                return url
            elif isinstance(url, list) and url:
                return url[0]
            return ''
        
        if isinstance(url, str):
            return _KeeperFillMixin._truncate_text(url)
        elif isinstance(url, list) and url:
            first_url = url[0]
            return _KeeperFillMixin._truncate_text(first_url)
        return ''
    
    @staticmethod
    def _try_resolve_as_record(vault_data, path: str) -> Optional[str]:
        """Try to resolve path as a direct record UID."""
        record_info = vault_data.get_record(path)
        if record_info and _KeeperFillMixin._is_supported_record_version(record_info):
            return path
        return None
    
    @staticmethod
    def _try_resolve_as_folder(context: KeeperParams, path: str):
        """Try to resolve path as a direct folder UID or path."""
        vault_data = context.vault.vault_data
        if path:
            folder = vault_data.get_folder(path)
            if folder:
                return folder, None
        
        folder, pattern = folder_utils.try_resolve_path(context, path)
        return folder, pattern
    
    @staticmethod
    def _get_records_from_folder(vault_data, folder) -> Iterator[str]:
        """Get all supported records from a single folder."""
        for record_uid in folder.records:
            record_info = vault_data.get_record(record_uid)
            if _KeeperFillMixin._is_supported_record_version(record_info):
                yield record_uid
    
    @staticmethod
    def _get_records_matching_pattern(vault_data, folder, pattern: str) -> Iterator[str]:
        """Get records from folder matching a pattern."""
        regex = re.compile(fnmatch.translate(pattern), re.IGNORECASE).match
        
        for record_uid in folder.records:
            record_info = vault_data.get_record(record_uid)
            if _KeeperFillMixin._is_supported_record_version(record_info):
                if regex(record_info.title):
                    yield record_uid
    
    @staticmethod
    def resolve_records(context: KeeperParams, **kwargs) -> Iterator[str]:
        """
        Resolve record UIDs from paths, folders, and patterns.
        
        Args:
            context: Keeper parameters containing vault data
            **kwargs: Command arguments including 'paths' and 'recursive'
            
        Returns:
            Iterator of record UIDs
            
        Raises:
            base.CommandError: If paths parameter is missing or path not found
        """
        vault_data = context.vault.vault_data
        recursive = kwargs.get('recursive', False)
        paths = kwargs.get('paths')
        
        if not paths:
            raise base.CommandError('"paths" parameter is required.')
        
        folders = []
        records = set()
        
        for path in paths:
            record_uid = _KeeperFillMixin._try_resolve_as_record(vault_data, path)
            if record_uid:
                records.add(record_uid)
                continue
            
            try:
                folder, pattern = _KeeperFillMixin._try_resolve_as_folder(context, path)
                if folder is None:
                    raise base.CommandError(f'Folder or record path "{path}" not found')
                
                if not pattern:
                    folders.append(folder)
                else:
                    records.update(_KeeperFillMixin._get_records_matching_pattern(vault_data, folder, pattern))
            except Exception:
                raise base.CommandError(f'Folder or record path "{path}" not found')
        
        for folder in folders:
            if recursive:
                yield from _KeeperFillMixin._get_records_in_folder_tree(vault_data, folder)
            else:
                yield from _KeeperFillMixin._get_records_from_folder(vault_data, folder)
        
        yield from records
    
    @staticmethod
    def _get_records_in_folder_tree(vault_data, folder) -> Iterator[str]:
        """Recursively get all records in a folder tree."""
        visited = set()
        stack = [folder]
        
        while stack:
            current_folder = stack.pop()
            folder_uid = current_folder.folder_uid or ''
            
            if folder_uid in visited:
                continue
            visited.add(folder_uid)
            
            yield from _KeeperFillMixin._get_records_from_folder(vault_data, current_folder)
            
            for subfolder_uid in current_folder.subfolders:
                subfolder = vault_data.get_folder(subfolder_uid)
                if subfolder:
                    stack.append(subfolder)
    
    @staticmethod
    def get_keeper_fill_data(context: KeeperParams, record_uid: str) -> Optional[dict]:
        """
        Extract KeeperFill data from a record's non-shared data.
        
        Args:
            context: Keeper parameters containing vault data
            record_uid: UID of the record
            
        Returns:
            Dictionary containing KeeperFill data or None if not available
        """
        vault_data = context.vault.vault_data
        
        record_info = vault_data.get_record(record_uid)
        if not record_info or record_info.version not in SUPPORTED_RECORD_VERSIONS:
            return None
        
        storage_nsd = vault_data.storage.non_shared_data.get_entity(record_uid)
        if not storage_nsd or not storage_nsd.data:
            return None
        
        data_key = context.vault.keeper_auth.auth_context.data_key
        if not data_key:
            return None
        
        try:
            decrypted_bytes = _KeeperFillMixin._decrypt_non_shared_data(
                storage_nsd,
                data_key,
                record_info.version
            )
            result = json.loads(decrypted_bytes.decode('utf-8'))
            return result
        except Exception as e:
            logger.debug(f'Record {record_uid}: Failed to decrypt non-shared data: {e}')
            return None
    
    @staticmethod
    def get_record_url(record) -> Union[str, List[str], None]:
        """
        Get URL(s) from a record.
        
        Args:
            record: KeeperRecord instance (PasswordRecord or TypedRecord)
            
        Returns:
            URL string, list of URLs, or None if no URLs found
        """
        if isinstance(record, vault_record.PasswordRecord):
            if hasattr(record, 'link') and record.link:
                return record.link
        
        elif isinstance(record, vault_record.TypedRecord):
            url_fields = [
                field for field in itertools.chain(record.fields, record.custom)
                if field.type == 'url' and field.value
            ]
            
            urls = []
            for field in url_fields:
                if isinstance(field.value, list) and field.value:
                    urls.extend(str(v) for v in field.value if v)
                elif field.value:
                    urls.append(str(field.value))
            
            if urls:
                return urls if len(urls) > 1 else urls[0]
        
        return None


class KeeperFillListCommand(base.ArgparseCommand, _KeeperFillMixin):
    """Command to display a list of KeeperFill values for records."""
    
    def __init__(self):
        super().__init__(_keeper_fill_list_parser)
    
    def _build_table_row(self, vault_data, record_uid: str, verbose: bool, context: KeeperParams) -> Optional[list]:
        """Build a table row for a single record."""
        record = vault_data.load_record(record_uid)
        if not record:
            logger.debug(f'Could not load record {record_uid}')
            return None
        
        url = self.get_record_url(record)
        data = self.get_keeper_fill_data(context, record_uid)
        
        auto_fill_mode = self._normalize_auto_fill_for_display(data.get('auto_fill_mode') if data else None)
        ext_auto_submit = data.get('ext_auto_submit') if data else None
        
        if not url and auto_fill_mode is None and ext_auto_submit is None:
            return None
        
        auto_fill_display = 'True' if auto_fill_mode is True else ('False' if auto_fill_mode is False else '-')
        auto_submit_display = 'True' if ext_auto_submit is True else ('False' if ext_auto_submit is False else '-')
        
        title = self._truncate_text(record.title) if not verbose else record.title
        formatted_url = self._format_url_for_display(url, verbose)
        
        return [record_uid, title, formatted_url, auto_fill_display, auto_submit_display]
    
    def execute(self, context: KeeperParams, **kwargs):
        """Execute the KeeperFill list command."""
        vault_data = context.vault.vault_data
        record_uids = list(self.resolve_records(context, **kwargs))
        
        if not record_uids:
            logger.info('No records found in the specified path(s)')
            return
        
        verbose = kwargs.get('verbose', False)
        fmt = kwargs.get('format', 'table')
        if fmt != 'table':
            verbose = True
        
        table = []
        records_with_urls = 0
        records_with_keeper_fill = 0
        
        for record_uid in record_uids:
            row = self._build_table_row(vault_data, record_uid, verbose, context)
            if row:
                table.append(row)
                records_with_urls += 1
                if row[3] != '-' or row[4] != '-':
                    records_with_keeper_fill += 1
        
        if not table:
            return
        
        headers = ['UID', 'Title', 'URL', 'Auto Fill', 'Auto Submit']
        return report_utils.dump_report_data(
            table, 
            headers=headers, 
            row_number=True, 
            sort_by=1, 
            fmt=fmt, 
            filename=kwargs.get('output')
        )


class KeeperFillSetCommand(base.ArgparseCommand, _KeeperFillMixin):
    """Command to set KeeperFill settings for records."""
    
    def __init__(self):
        super().__init__(_keeper_fill_set_parser)
    
    def execute(self, context: KeeperParams, **kwargs):
        """Execute the KeeperFill set command."""
        auto_fill = kwargs.get('auto_fill')
        auto_submit = kwargs.get('auto_submit')
        
        if auto_fill is None and auto_submit is None:
            raise base.CommandError('Nothing to set. Please specify --auto-fill or --auto-submit.')
        
        vault_data = context.vault.vault_data
        data_key = context.vault.keeper_auth.auth_context.data_key
        record_uids = list(self.resolve_records(context, **kwargs))
        
        logger.debug(f'Found {len(record_uids)} records to process')
        logger.debug(f'auto_fill={auto_fill}, auto_submit={auto_submit}')
        
        record_v2_updates = []
        record_v3_updates = []
        
        for record_uid in record_uids:
            record_info = vault_data.get_record(record_uid)
            if not record_info or record_info.version not in SUPPORTED_RECORD_VERSIONS:
                logger.debug(f'Record {record_uid}: Skipping - unsupported version')
                continue
            
            record = vault_data.load_record(record_uid)
            if not record:
                logger.debug(f'Record {record_uid}: Could not load')
                continue
            
            url = self.get_record_url(record)
            if not url:
                logger.debug(f'Record {record_uid} ({record.title}): No URL, skipping')
                continue
            
            data = self.get_keeper_fill_data(context, record_uid) or {}
            
            current_auto_fill = self._normalize_setting_for_comparison(data.get('auto_fill_mode'))
            current_auto_submit = self._normalize_setting_for_comparison(data.get('ext_auto_submit'), is_boolean=True)
            
            logger.debug(f'Record {record_uid} ({record.title}): current_auto_fill={current_auto_fill}, current_auto_submit={current_auto_submit}')
            
            should_save = False
            if auto_fill and auto_fill != current_auto_fill:
                logger.debug(f'Record {record_uid}: Updating auto_fill from {current_auto_fill} to {auto_fill}')
                if auto_fill == SETTING_ON:
                    data['auto_fill_mode'] = AUTO_FILL_ALWAYS
                elif auto_fill == SETTING_OFF:
                    data['auto_fill_mode'] = AUTO_FILL_NEVER
                elif auto_fill == SETTING_NONE:
                    data.pop('auto_fill_mode', None)
                should_save = True
            
            if auto_submit and auto_submit != current_auto_submit:
                logger.debug(f'Record {record_uid}: Updating auto_submit from {current_auto_submit} to {auto_submit}')
                if auto_submit == SETTING_ON:
                    data['ext_auto_submit'] = True
                elif auto_submit == SETTING_OFF:
                    data['ext_auto_submit'] = False
                elif auto_submit == SETTING_NONE:
                    data.pop('ext_auto_submit', None)
                should_save = True
            
            if should_save:
                logger.debug(f'Record {record_uid} ({record.title}): Adding to update queue')
                nsd_json = json.dumps(data).encode('utf-8')
                
                if isinstance(record, vault_record.PasswordRecord):
                    encrypted_nsd = crypto.encrypt_aes_v1(nsd_json, data_key)
                    ur = {
                        'record_uid': record_uid,
                        'revision': record_info.revision,
                        'non_shared_data': utils.base64_url_encode(encrypted_nsd),
                        'version': 2,
                        'client_modified_time': utils.current_milli_time()
                    }
                    record_v2_updates.append(ur)
                    
                elif isinstance(record, vault_record.TypedRecord):
                    ru = record_pb2.RecordUpdate()
                    ru.record_uid = utils.base64_url_decode(record_uid)
                    ru.client_modified_time = utils.current_milli_time()
                    ru.revision = record_info.revision
                    ru.non_shared_data = crypto.encrypt_aes_v2(nsd_json, data_key)
                    record_v3_updates.append(ru)
        
        total_updates = len(record_v3_updates) + len(record_v2_updates)
        
        if total_updates > 0:
            context.sync_data = True
        
        while len(record_v3_updates) > 0:
            chunk = record_v3_updates[:900]
            record_v3_updates = record_v3_updates[900:]
            
            rq = record_pb2.RecordsUpdateRequest()
            rq.records.extend(chunk)
            rq.client_time = utils.current_milli_time()
            
            context.vault.keeper_auth.execute_auth_rest('vault/records_update', rq, 
                                                        response_type=record_pb2.RecordsModifyResponse)
        
        while len(record_v2_updates) > 0:
            chunk = record_v2_updates[:90]
            record_v2_updates = record_v2_updates[90:]
            
            rq = {
                'command': 'record_update',
                'update_records': chunk
            }
            context.vault.keeper_auth.execute_auth_command(rq)
        
        if total_updates > 0:
            logger.info(f'Successfully updated {total_updates} record(s)')
        else:
            logger.info('No records were updated')
