import argparse
import datetime
import hashlib
import json
import logging
import sys
from typing import Any, Dict, List, Optional, Union

from keepersdk.vault import vault_record, record_management
from .base import CommandError, ArgparseCommand
from ..params import KeeperParams
from ..prompt_utils import user_choice


class AuditLogBaseExport:
    def __init__(self):
        self.store_record = False
        self.should_cancel = False
        self.file_handle = None

    def default_record_title(self) -> str:
        return 'Audit Log Export'

    def chunk_size(self) -> int:
        return 1000

    def get_properties(self, record: Union[vault_record.PasswordRecord, 
                                          vault_record.TypedRecord], 
                       props: Dict[str, Any]) -> None:
        pass

    def convert_event(self, props: Dict[str, Any], 
                      event: Dict[str, Any]) -> Dict[str, Any]:
        return event

    def export_events(self, props: Dict[str, Any], 
                      events: List[Dict[str, Any]]) -> None:
        pass

    def finalize_export(self, props: Dict[str, Any]) -> None:
        pass

    def clean_up(self) -> None:
        if self.file_handle:
            self.file_handle.close()
            self.file_handle = None

    @staticmethod
    def get_record_custom(record: Union[vault_record.PasswordRecord, 
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
    def set_record_custom(record: Union[vault_record.PasswordRecord, 
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


class AuditLogJsonExport(AuditLogBaseExport):
    def __init__(self):
        super().__init__()
        self.filename = None
        self.events = []
        self.file_handle = None
        self.is_first_batch = True

    def default_record_title(self):
        return 'Audit Log: JSON'

    def export_events(self, props: Dict[str, Any], 
                      events: List[Dict[str, Any]]) -> None:
        import os
        if self.file_handle is None:
            self.file_handle = open(self.filename, 'w', encoding='utf-8')
            self.file_handle.write('[\n')
            print(f'Creating audit log file: '
                  f'{os.path.abspath(self.filename)}')
        
        for i, event in enumerate(events):
            if not self.is_first_batch or i > 0:
                self.file_handle.write(',\n')
            json.dump(event, self.file_handle, indent=2, 
                      ensure_ascii=False)
            self.is_first_batch = False
        
        self.file_handle.flush()
        self.events.extend(events)

    def finalize_export(self, props: Dict[str, Any]) -> None:
        import os
        if self.file_handle:
            self.file_handle.write('\n]')
            self.file_handle.close()
            self.file_handle = None
        
        full_path = os.path.abspath(self.filename)
        print(f'Audit log exported to: {full_path}')
        logging.info('Audit log exported to %s', full_path)

    def clean_up(self) -> None:
        if self.file_handle:
            self.file_handle.close()
            self.file_handle = None
    


class AuditLogCommand(ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='audit-log', 
            description='Export and display the enterprise audit log'
        )
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
        super().__init__(parser)
    
    def execute(self, context: KeeperParams, **kwargs):
        assert context.auth
        assert context.enterprise_data

        target = kwargs.get('target')
        if not target:
            raise CommandError('Target is required')

        if target != 'json':
            raise CommandError(f'Target {target} not yet implemented')

        log_export = AuditLogJsonExport()

        record_name = kwargs.get('Record')
        if not record_name:
            record_name = log_export.default_record_title()

        record = None
        for record_info in context.vault.vault_data.records():
            rec = context.vault.vault_data.load_record(record_info.record_uid)
            if record_name in [rec.record_uid, rec.title]:
                record = rec
                break
        
        if record is None:
            answer = user_choice(
                'Do you want to create a Keeper record to store audit log '
                'settings?', 'yn', 'n'
            )
            if answer.lower() in ('y', 'yes'):
                record_title = input(
                    f'Choose the title for audit log record '
                    f'[Default: {record_name}]: '
                ) or log_export.default_record_title()
                record = vault_record.PasswordRecord()
                record.title = record_title
                record_management.add_record_to_folder(context.vault, record)
                record_uid = record.record_uid
                if record_uid:
                    context.vault.sync_down()
                    record = context.vault.vault_data.load_record(record_uid)

        if record is None:
            raise CommandError('Record not found')

        filename = input('JSON File name: ').strip()
        if not filename:
            raise CommandError('Filename is required. Command cancelled.')
        
        if not filename.lower().endswith('.json'):
            filename += '.json'
        
        log_export.filename = filename

        props = {
            'enterprise_name': (
                context.enterprise_data.enterprise_info.enterprise_name 
                if context.enterprise_data else 'Unknown'
            )
        }
        
        shared_folder_uids = kwargs.get('shared_folder_uid')
        node_ids = kwargs.get('node_id')
        days = kwargs.get('days')
    
        last_event_time = 0
        now_dt = datetime.datetime.now()
        now_ts = int(now_dt.timestamp())
        
        if days:
            last_event_dt = now_dt - datetime.timedelta(days=int(days))
            last_event_time = int(last_event_dt.timestamp())
        else:
            val = AuditLogBaseExport.get_record_custom(record, 'last_event_time')
            if val:
                try:
                    last_event_time = int(val)
                except Exception:
                    last_event_time = 0

        if not shared_folder_uids:
            val = AuditLogBaseExport.get_record_custom(
                record, 'shared_folder_uids'
            )
            if val:
                try:
                    shared_folder_uids = [
                        sfuid.strip() for sfuid in val.split(',') 
                        if sfuid.strip()
                    ]
                except Exception:
                    pass

        if not node_ids:
            val = AuditLogBaseExport.get_record_custom(record, 'node_ids')
            if val:
                try:
                    node_ids = [
                        int(node_id.strip()) for node_id in val.split(',') 
                        if node_id.strip()
                    ]
                except Exception:
                    pass

        anonymize = bool(kwargs.get('anonymize'))
        ent_user_ids = {}
        if anonymize and context.enterprise_data:
            ent_user_ids = {
                user.username: user.enterprise_user_id 
                for user in context.enterprise_data.users.get_all_entities()
            }

        created_filter = {'max': now_ts}
        rq_filter = {'created': created_filter}
        
        if shared_folder_uids:
            rq_filter['shared_folder_uid'] = shared_folder_uids
            AuditLogBaseExport.set_record_custom(
                record, 'shared_folder_uids', ', '.join(shared_folder_uids)
            )
        
        if node_ids:
            rq_filter['node_id'] = node_ids
            node_ids_str = [str(n) for n in node_ids]
            AuditLogBaseExport.set_record_custom(
                record, 'node_ids', ', '.join(node_ids_str)
            )

        created_filter_copy = {**created_filter, 'min': last_event_time}
        filter_copy = {**rq_filter, 'created': created_filter_copy}
        total_events_rq = {
            'command': 'get_audit_event_reports',
            'report_type': 'span',
            'scope': 'enterprise',
            'limit': 1000,
            'order': 'ascending',
            'filter': filter_copy
        }
        
        total_events = 0
        try:
            total_events_rs = context.auth.execute_auth_command(total_events_rq)
            rows = total_events_rs['audit_event_overview_report_rows']
            total_events = rows[0].get('occurrences', 0) if rows else 0
        except (KeyError, IndexError, TypeError):
            logging.info('No events to export')
            return

        events = []
        finished = False
        num_exported = 0
        logged_ids = set()
        chunk_length = log_export.chunk_size()

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
                created_filter['min'] = last_event_time

            response = context.auth.execute_auth_command(rq)
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
                            uname = (event.get('email') or 
                                    event.get('username') or '')
                            if uname:
                                ent_uid = self.resolve_uid(ent_user_ids, uname)
                                event['username'] = ent_uid
                                event['email'] = ent_uid
                            
                            to_uname = event.get('to_username') or ''
                            if to_uname:
                                event['to_username'] = self.resolve_uid(
                                    ent_user_ids, to_uname
                                )
                            
                            from_uname = event.get('from_username') or ''
                            if from_uname:
                                event['from_username'] = self.resolve_uid(
                                    ent_user_ids, from_uname
                                )
                    
                    for event in new_events:
                        logged_ids.add(event['id'])
                        events.append(log_export.convert_event(props, event))
                    
                    if event_count < 1000:
                        finished = True
                    else:
                        finished = created_filter['max'] <= last_event_time

                    if not new_events and not finished:
                        last_event_time += 1

            while len(events) > 0:
                to_store = events[:chunk_length]
                events = events[chunk_length:]
                log_export.export_events(props, to_store)
                if log_export.should_cancel:
                    finished = True
                    break
                num_exported += len(to_store)
                if total_events > 0:
                    percent_done = num_exported / total_events * 100
                    percent_done = '%.1f' % percent_done
                    print(f'Exporting events.... {percent_done}% DONE', 
                          file=sys.stderr, end='\r', flush=True)

        logging.info('')
        logging.info('Exported %d audit event(s)', num_exported)
        
        if num_exported > 0:
            log_export.finalize_export(props)
        
        if last_event_time > 0:
            AuditLogBaseExport.set_record_custom(
                record, 'last_event_time', str(last_event_time)
            )
            record_management.update_record(context.vault, record)
            context.sync_data = True
        
        log_export.clean_up()

    def resolve_uid(self, cache: Dict[str, str], username: str) -> str:
        uname = username or ''
        uid = cache.get(uname)
        if not uid:
            md5 = hashlib.md5(str(uname).encode('utf-8')).hexdigest()
            cache[uname] = 'DELETED-' + md5
            uid = cache.get(uname)
        return uid