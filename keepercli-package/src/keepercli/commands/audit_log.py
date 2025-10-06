import argparse
import datetime
import hashlib
import json
import sys
from typing import Any, Dict, List, Optional, Union

from keepersdk.vault import vault_record, record_management
from .. import api
from .base import CommandError, ArgparseCommand
from ..params import KeeperParams
from ..prompt_utils import user_choice


logger = api.get_logger()


class RecordOperations:
    """Handles operations on Keeper records for audit log configuration.
    
    This class provides static methods for getting and setting custom fields
    on Keeper records, supporting both PasswordRecord and TypedRecord types.
    """
    
    @staticmethod
    def get_custom_field(record: Union[vault_record.PasswordRecord, 
                                      vault_record.TypedRecord], 
                        field_name: str) -> Optional[str]:
        """Get custom field value from record."""
        if not hasattr(record, 'custom') or not record.custom:
            return None
            
        if isinstance(record, vault_record.PasswordRecord):
            for field in record.custom:
                if field.name == field_name:
                    return field.value
        elif isinstance(record, vault_record.TypedRecord):
            for field in record.custom:
                if field.label == field_name:
                    return field.value[0] if field.value else None
        return None

    @staticmethod
    def set_custom_field(record: Union[vault_record.PasswordRecord, 
                                      vault_record.TypedRecord], 
                        field_name: str, value: str) -> None:
        """Set custom field value in record."""
        if not hasattr(record, 'custom'):
            record.custom = []
            
        if isinstance(record, vault_record.PasswordRecord):
            for field in record.custom:
                if field.name == field_name:
                    field.value = value
                    return
            
            custom_field = vault_record.CustomField()
            custom_field.name = field_name
            custom_field.value = value
            custom_field.type = 'text'
            record.custom.append(custom_field)
            
        elif isinstance(record, vault_record.TypedRecord):
            for field in record.custom:
                if field.label == field_name:
                    field.value = [value]
                    return
            
            typed_field = vault_record.TypedField()
            typed_field.type = 'text'
            typed_field.label = field_name
            typed_field.value = [value]
            record.custom.append(typed_field)


class AuditLogExporter:
    """Base class for audit log export functionality.
    
    This abstract base class defines the interface for audit log exporters.
    Subclasses should implement the specific export format logic.
    """
    
    def __init__(self) -> None:
        self.store_record: bool = False
        self.should_cancel: bool = False
        self.file_handle: Optional[Any] = None

    def get_default_record_title(self) -> str:
        """Get the default title for the audit log record."""
        return 'Audit Log Export'

    def get_chunk_size(self) -> int:
        """Get the chunk size for processing events."""
        return 1000

    def get_properties(self, record: Union[vault_record.PasswordRecord, 
                                          vault_record.TypedRecord], 
                       props: Dict[str, Any]) -> None:
        """Extract properties from record for export context."""
        pass

    def convert_event(self, props: Dict[str, Any], 
                      event: Dict[str, Any]) -> Dict[str, Any]:
        """Convert an audit event to the export format."""
        return event

    def export_events(self, props: Dict[str, Any], 
                      events: List[Dict[str, Any]]) -> None:
        """Export a batch of events."""
        pass

    def finalize_export(self, props: Dict[str, Any]) -> None:
        """Finalize the export process."""
        pass

    def clean_up(self) -> None:
        """Clean up resources."""
        if self.file_handle:
            self.file_handle.close()
            self.file_handle = None


class JsonAuditLogExporter(AuditLogExporter):
    """Handles JSON export of audit log events.
    
    This class exports audit log events to a JSON file format,
    writing events in batches to handle large datasets efficiently.
    """
    
    def __init__(self, filename: str) -> None:
        super().__init__()
        self.filename: str = filename
        self.events: List[Dict[str, Any]] = []
        self.file_handle: Optional[Any] = None
        self.is_first_batch: bool = True

    def get_default_record_title(self) -> str:
        """Get the default title for the audit log record."""
        return 'Audit Log: JSON'

    def _initialize_file(self) -> None:
        """Initialize the JSON file for writing."""
        import os
        if self.file_handle is None:
            try:
                self.file_handle = open(self.filename, 'w', encoding='utf-8')
                self.file_handle.write('[\n')
                logger.info(f'Creating audit log file: '
                      f'{os.path.abspath(self.filename)}')
            except (IOError, OSError) as e:
                raise CommandError(f'Failed to create file {self.filename}: {e}')

    def export_events(self, props: Dict[str, Any], 
                      events: List[Dict[str, Any]]) -> None:
        """Export a batch of events to JSON format."""
        self._initialize_file()
        
        try:
            for i, event in enumerate(events):
                if not self.is_first_batch or i > 0:
                    self.file_handle.write(',\n')
                json.dump(event, self.file_handle, indent=2, 
                          ensure_ascii=False)
                self.is_first_batch = False
            
            self.file_handle.flush()
            self.events.extend(events)
        except (IOError, OSError) as e:
            raise CommandError(f'Failed to write to file {self.filename}: {e}')

    def finalize_export(self, props: Dict[str, Any]) -> None:
        """Finalize the JSON export by closing the array."""
        import os
        if self.file_handle:
            try:
                self.file_handle.write('\n]')
                self.file_handle.close()
                self.file_handle = None
            except (IOError, OSError) as e:
                logger.error('Failed to finalize export: %s', e)
                raise CommandError(f'Failed to finalize export: {e}')
        
        full_path = os.path.abspath(self.filename)
        logger.info(f'Audit log exported to: {full_path}')

    def clean_up(self) -> None:
        """Clean up file resources."""
        if self.file_handle:
            self.file_handle.close()
            self.file_handle = None


class FilterManager:
    """Manages audit log filtering and configuration.
    
    This class handles loading filter settings from Keeper records,
    applying command-line filter overrides, and building API request filters.
    """
    
    def __init__(self, record: Union[vault_record.PasswordRecord, 
                                    vault_record.TypedRecord]) -> None:
        self.record = record
        self.shared_folder_uids: Optional[List[str]] = None
        self.node_ids: Optional[List[int]] = None
        self.days: Optional[int] = None
        self.last_event_time: int = 0

    def load_filters_from_record(self) -> None:
        """Load filter settings from the record."""
        # Load shared folder UIDs
        val = RecordOperations.get_custom_field(
            self.record, 'shared_folder_uids'
        )
        if val:
            try:
                self.shared_folder_uids = [
                    sfuid.strip() for sfuid in val.split(',') 
                    if sfuid.strip()
                ]
            except (ValueError, AttributeError) as e:
                logger.warning('Failed to parse shared folder UIDs: %s', e)
                self.shared_folder_uids = None

        # Load node IDs
        val = RecordOperations.get_custom_field(self.record, 'node_ids')
        if val:
            try:
                self.node_ids = [
                    int(node_id.strip()) for node_id in val.split(',') 
                    if node_id.strip()
                ]
            except (ValueError, AttributeError) as e:
                logger.warning('Failed to parse node IDs: %s', e)
                self.node_ids = None

        # Load last event time
        val = RecordOperations.get_custom_field(self.record, 'last_event_time')
        if val:
            try:
                self.last_event_time = int(val)
            except (ValueError, TypeError) as e:
                logger.warning('Failed to parse last event time: %s', e)
                self.last_event_time = 0

    def apply_command_line_filters(self, shared_folder_uids: Optional[List[str]], 
                                 node_ids: Optional[List[int]], 
                                 days: Optional[int]) -> None:
        """Apply filters from command line arguments."""
        if shared_folder_uids:
            self.shared_folder_uids = shared_folder_uids
        if node_ids:
            self.node_ids = node_ids
        if days:
            if days <= 0:
                raise CommandError('Days must be a positive integer')
            self.days = days
            now_dt = datetime.datetime.now()
            last_event_dt = now_dt - datetime.timedelta(days=int(days))
            self.last_event_time = int(last_event_dt.timestamp())

    def build_request_filter(self, now_ts: int) -> Dict[str, Any]:
        """Build the filter for the audit log request."""
        created_filter = {'max': now_ts}
        rq_filter = {'created': created_filter}
        
        if self.shared_folder_uids:
            rq_filter['shared_folder_uid'] = self.shared_folder_uids
            RecordOperations.set_custom_field(
                self.record, 'shared_folder_uids', 
                ', '.join(self.shared_folder_uids)
            )
        
        if self.node_ids:
            rq_filter['node_id'] = self.node_ids
            node_ids_str = [str(n) for n in self.node_ids]
            RecordOperations.set_custom_field(
                self.record, 'node_ids', ', '.join(node_ids_str)
            )

        return rq_filter

    def save_last_event_time(self, last_event_time: int) -> None:
        """Save the last event time to the record."""
        if last_event_time > 0:
            RecordOperations.set_custom_field(
                self.record, 'last_event_time', str(last_event_time)
            )


class AuditEventFetcher:
    """Handles fetching audit events from the Keeper API.
    
    This class manages the process of fetching audit events from the Keeper API,
    including pagination, filtering, and anonymization of user data.
    """
    
    def __init__(self, context: KeeperParams, filter_manager: FilterManager) -> None:
        self.context = context
        self.filter_manager = filter_manager
        self.ent_user_ids: Dict[str, str] = {}

    def setup_anonymization(self, anonymize: bool) -> None:
        """Setup user ID mapping for anonymization."""
        if anonymize and self.context.enterprise_data:
            self.ent_user_ids = {
                user.username: user.enterprise_user_id 
                for user in self.context.enterprise_data.users.get_all_entities()
            }

    def get_total_events_count(self, now_ts: int) -> int:
        """Get the total number of events to be exported."""
        created_filter_copy = {
            **self.filter_manager.build_request_filter(now_ts)['created'], 
            'min': self.filter_manager.last_event_time
        }
        filter_copy = {
            **self.filter_manager.build_request_filter(now_ts), 
            'created': created_filter_copy
        }
        
        total_events_rq = {
            'command': 'get_audit_event_reports',
            'report_type': 'span',
            'scope': 'enterprise',
            'limit': 1000,
            'order': 'ascending',
            'filter': filter_copy
        }
        
        try:
            total_events_rs = self.context.auth.execute_auth_command(total_events_rq)
            rows = total_events_rs['audit_event_overview_report_rows']
            return rows[0].get('occurrences', 0) if rows else 0
        except (KeyError, IndexError, TypeError):
            logger.info('No events to export')
            return 0

    def anonymize_event(self, event: Dict[str, Any]) -> None:
        """Anonymize user information in an event."""
        uname = (event.get('email') or event.get('username') or '')
        if uname:
            ent_uid = self._resolve_uid(uname)
            event['username'] = ent_uid
            event['email'] = ent_uid
        
        to_uname = event.get('to_username') or ''
        if to_uname:
            event['to_username'] = self._resolve_uid(to_uname)
        
        from_uname = event.get('from_username') or ''
        if from_uname:
            event['from_username'] = self._resolve_uid(from_uname)

    def _resolve_uid(self, username: str) -> str:
        """Resolve username to enterprise user ID or generate deleted user ID."""
        uname = username or ''
        uid = self.ent_user_ids.get(uname)
        if not uid:
            md5 = hashlib.md5(str(uname).encode('utf-8')).hexdigest()
            self.ent_user_ids[uname] = 'DELETED-' + md5
            uid = self.ent_user_ids[uname]
        return uid

    def fetch_events(self, now_ts: int, anonymize: bool = False) -> List[Dict[str, Any]]:
        """Fetch all audit events matching the current filters."""
        events = []
        finished = False
        logged_ids = set()
        last_event_time = self.filter_manager.last_event_time
        
        rq_filter = self.filter_manager.build_request_filter(now_ts)
        rq = {
            'command': 'get_audit_event_reports',
            'report_type': 'raw',
            'scope': 'enterprise',
            'limit': 1000,
            'order': 'ascending',
            'filter': rq_filter
        }

        while not finished:
            finished = True

            if last_event_time > 0:
                rq_filter['created']['min'] = last_event_time

            response = self.context.auth.execute_auth_command(rq)
            if response['result'] == 'success':
                finished = True
                if 'audit_event_overview_report_rows' in response:
                    audit_events = response['audit_event_overview_report_rows']
                    event_count = len(audit_events)
                    
                    if event_count > 0:
                        last_event_time = int(audit_events[-1]['created'])

                    new_events = [
                        e for e in audit_events if e['id'] not in logged_ids
                    ]
                    
                    if anonymize and new_events:
                        for event in new_events:
                            self.anonymize_event(event)
                    
                    for event in new_events:
                        logged_ids.add(event['id'])
                        events.append(event)
                    
                    if event_count < 1000:
                        finished = True
                    else:
                        finished = rq_filter['created']['max'] <= last_event_time

                    if not new_events and not finished:
                        last_event_time += 1

        # Update the filter manager with the last event time
        self.filter_manager.last_event_time = last_event_time
        return events


class AuditLogCommand(ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='audit-log', 
            description='Export and display the enterprise audit log'
        )
        AuditLogCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument(
            '--anonymize', 
            action='store_true',
            help="Anonymizes audit log by replacing email and user name "
                 "with corresponding enterprise user id. If user was removed "
                 "or if user's email was changed then the audit report will "
                 "show that particular entry as deleted user."
        )
        parser.add_argument(
            '--target', 
            choices=['json'],
            help='Target for audit log export'
        )
        parser.add_argument(
            '--record', 
            dest='Record', 
            help='Keeper record name or UID'
        )
        parser.add_argument(
            '--shared-folder-uid', 
            dest='shared_folder_uid', 
            action='append',
            help='Filter: Shared Folder UID(s). Overrides existing setting '
                 'in config record and sets new field value.'
        )
        parser.add_argument(
            '--node-id', 
            dest='node_id', 
            action='append', 
            type=int,
            help='Filter: Node ID(s). Overrides existing setting in config '
                 'record and sets new field value.'
        )
        parser.add_argument(
            '--days', 
            type=int,
            help='Filter: max event age in days. Overrides existing '
                 '"last_event_time" value in config record'
        )
    
    def execute(self, context: KeeperParams, **kwargs):
        """Execute the audit log export command."""
        assert context.auth
        assert context.enterprise_data

        # Validate target
        target = kwargs.get('target')
        if not target:
            raise CommandError('Target is required')
        if target != 'json':
            raise CommandError(f'Target {target} not yet implemented')

        # Get filename and create exporter
        filename = self._get_filename()
        log_export = JsonAuditLogExporter(filename)

        # Find or create record
        record = self._find_or_create_record(context, log_export, kwargs.get('Record'))
        
        # Setup filter manager
        filter_manager = FilterManager(record)
        filter_manager.load_filters_from_record()
        filter_manager.apply_command_line_filters(
            kwargs.get('shared_folder_uid'),
            kwargs.get('node_id'),
            kwargs.get('days')
        )

        # Setup audit event fetcher
        now_ts = int(datetime.datetime.now().timestamp())
        event_fetcher = AuditEventFetcher(context, filter_manager)
        event_fetcher.setup_anonymization(bool(kwargs.get('anonymize')))

        # Get total events count
        total_events = event_fetcher.get_total_events_count(now_ts)
        if total_events == 0:
            return

        # Fetch and export events
        events = event_fetcher.fetch_events(now_ts, bool(kwargs.get('anonymize')))
        self._export_events_in_chunks(log_export, events, total_events)

        # Save last event time and update record
        if filter_manager.last_event_time > 0:
            filter_manager.save_last_event_time(filter_manager.last_event_time)
            record_management.update_record(context.vault, record)
            context.sync_data = True
        
        log_export.clean_up()

    def _get_filename(self) -> str:
        """Get filename from user input."""
        filename = input('JSON File name: ').strip()
        if not filename:
            raise CommandError('Filename is required. Command cancelled.')
        
        if not filename.lower().endswith('.json'):
            filename += '.json'
        
        return filename

    def _find_or_create_record(self, context: KeeperParams, 
                              log_export: JsonAuditLogExporter, 
                              record_name: Optional[str]) -> Union[vault_record.PasswordRecord, 
                                                                  vault_record.TypedRecord]:
        """Find existing record or create new one."""
        if not record_name:
            record_name = log_export.get_default_record_title()

        # Look for existing record
        for record_info in context.vault.vault_data.records():
            rec = context.vault.vault_data.load_record(record_info.record_uid)
            if record_name in [rec.record_uid, rec.title]:
                return rec
        
        # Create new record if not found
        answer = user_choice(
            'Do you want to create a Keeper record to store audit log '
            'settings?', 'yn', 'n'
        )
        if answer.lower() in ('y', 'yes'):
            record_title = input(
                f'Choose the title for audit log record '
                f'[Default: {record_name}]: '
            ) or log_export.get_default_record_title()
            
            record = vault_record.PasswordRecord()
            record.title = record_title
            record_management.add_record_to_folder(context.vault, record)
            record_uid = record.record_uid
            if record_uid:
                context.vault.sync_down()
                return context.vault.vault_data.load_record(record_uid)

        raise CommandError('Record not found')

    def _export_events_in_chunks(self, log_export: JsonAuditLogExporter, 
                                events: List[Dict[str, Any]], 
                                total_events: int) -> None:
        """Export events in chunks with progress indication."""
        props = {'enterprise_name': 'Unknown'}  # Could be enhanced to get from context
        chunk_length = log_export.get_chunk_size()
        num_exported = 0

        while len(events) > 0:
            to_store = events[:chunk_length]
            events = events[chunk_length:]
            log_export.export_events(props, to_store)
            
            if log_export.should_cancel:
                break
                
            num_exported += len(to_store)
            if total_events > 0:
                percent_done = num_exported / total_events * 100
                percent_done = '%.1f' % percent_done
                logger.info(f'Exporting events.... {percent_done}% DONE', 
                      file=sys.stderr, end='\r', flush=True)

        logger.info('')
        logger.info('Exported %d audit event(s)', num_exported)
        
        if num_exported > 0:
            log_export.finalize_export(props)
