"""Enterprise password aging report functionality for Keeper SDK."""

import dataclasses
import datetime
import json
import logging
import os
import traceback
from typing import Optional, List, Dict, Any, Iterable, Tuple

from ..authentication import keeper_auth
from ..proto import enterprise_pb2
from .. import crypto, utils
from . import enterprise_types
from ..vault import vault_online


API_EVENT_SUMMARY_ROW_LIMIT = 1000
DEFAULT_PERIOD_DAYS = 90
SEARCH_HISTORY_YEARS = 5
MAX_PAGINATION_ITERATIONS = 10000  # Safety limit to prevent infinite loops
logger = logging.getLogger(__name__)


@dataclasses.dataclass
class AgingReportEntry:
    """Represents a single record entry in the aging report."""
    record_uid: str
    owner_email: str
    title: str = ''
    last_changed: Optional[datetime.datetime] = None
    record_created: Optional[datetime.datetime] = None
    shared: bool = False
    record_url: str = ''
    shared_folder_uid: Optional[List[str]] = None
    in_trash: bool = False


@dataclasses.dataclass
class AgingReportConfig:
    """Configuration for aging report generation."""
    period_days: int = DEFAULT_PERIOD_DAYS
    cutoff_date: Optional[datetime.datetime] = None
    username: Optional[str] = None
    exclude_deleted: bool = False
    in_shared_folder: bool = False
    rebuild: bool = False
    delete_cache: bool = False
    no_cache: bool = False
    server: str = 'keepersecurity.com'


class AgingReportGenerator:
    """Generates password aging reports for enterprise records.
    
    This class identifies records whose passwords have not been changed
    within a specified period. It fetches data from the compliance API
    and falls back to audit events if needed.
    
    Usage:
        generator = AgingReportGenerator(enterprise_data, auth, config)
        entries = generator.generate_report()
    """
    
    def __init__(
        self,
        enterprise_data: enterprise_types.IEnterpriseData,
        auth: keeper_auth.KeeperAuth,
        config: Optional[AgingReportConfig] = None,
        vault: Optional[vault_online.VaultOnline] = None
    ) -> None:
        self._enterprise_data = enterprise_data
        self._auth = auth
        self._config = config or AgingReportConfig()
        self._vault = vault
        self._email_to_user_id: Optional[Dict[str, int]] = None
        self._user_id_to_email: Optional[Dict[int, str]] = None
        self._records: Dict[str, Dict[str, Any]] = {}
        self._record_shared_folders: Dict[str, List[str]] = {}
    
    @property
    def enterprise_data(self) -> enterprise_types.IEnterpriseData:
        return self._enterprise_data
    
    @property
    def config(self) -> AgingReportConfig:
        return self._config
    
    def get_cache_file_path(self, enterprise_id: int) -> str:
        """Get the path to the local cache database file."""
        home_dir = os.path.expanduser('~')
        cache_dir = os.path.join(home_dir, '.keeper')
        if not os.path.exists(cache_dir):
            os.makedirs(cache_dir)
        return os.path.join(cache_dir, f'aging_cache_{enterprise_id}.db')
    
    def delete_local_cache(self, enterprise_id: int) -> bool:
        """Delete the local database cache file."""
        cache_file = self.get_cache_file_path(enterprise_id)
        if os.path.isfile(cache_file):
            os.remove(cache_file)
            return True
        return False
    
    def _get_cutoff_timestamp(self) -> int:
        """Get the cutoff timestamp based on config."""
        if self._config.cutoff_date:
            return int(self._config.cutoff_date.timestamp())
        else:
            now = datetime.datetime.now()
            cutoff = now - datetime.timedelta(days=self._config.period_days)
            return int(cutoff.timestamp())
    
    def _build_user_lookups(self) -> None:
        """Build lookups between email and enterprise_user_id."""
        if self._email_to_user_id is None:
            self._email_to_user_id = {}
            self._user_id_to_email = {}
            for user in self._enterprise_data.users.get_all_entities():
                email = user.username.lower()
                user_id = user.enterprise_user_id
                self._email_to_user_id[email] = user_id
                self._user_id_to_email[user_id] = email
    
    def _get_target_username(self) -> Optional[str]:
        """Get normalized target username for filtering."""
        if not self._config.username:
            return None
        return self._config.username.lower()
    
    def _get_search_min_timestamp(self) -> int:
        """Get minimum timestamp for historical searches."""
        return int((datetime.datetime.now() - datetime.timedelta(days=365 * SEARCH_HISTORY_YEARS)).timestamp())
    
    def _fetch_paginated_audit_events(
        self,
        event_types: List[str],
        report_type: str = 'raw'
    ) -> Iterable[Dict[str, Any]]:
        """Fetch paginated audit events. Yields individual events."""
        search_min_ts = self._get_search_min_timestamp()
        audit_filter: Dict[str, Any] = {
            'audit_event_type': event_types,
            'created': {'min': search_min_ts}
        }
        
        rq: Dict[str, Any] = {
            'command': 'get_audit_event_reports',
            'scope': 'enterprise',
            'report_type': report_type,
            'filter': audit_filter,
            'limit': API_EVENT_SUMMARY_ROW_LIMIT,
            'order': 'ascending'
        }
        
        if report_type == 'span':
            rq['columns'] = ['record_uid', 'audit_event_type']
            rq['aggregate'] = ['last_created']
            del rq['order']
        
        last_ts = search_min_ts
        iteration_count = 0
        
        while True:
            iteration_count += 1
            if iteration_count > MAX_PAGINATION_ITERATIONS:
                logger.warning(f'Reached maximum pagination iterations ({MAX_PAGINATION_ITERATIONS}). Stopping to prevent infinite loop.')
                break
            
            try:
                rs = self._auth.execute_auth_command(rq)
                events = rs.get('audit_event_overview_report_rows', [])
                
                if not events:
                    break
                
                for event in events:
                    yield event
                    ts_field = 'last_created' if report_type == 'span' else 'created'
                    last_ts = max(last_ts, int(event.get(ts_field, 0)))
                
                if len(events) < API_EVENT_SUMMARY_ROW_LIMIT:
                    break
                
                if report_type == 'span':
                    audit_filter['created']['max'] = last_ts + 1
                else:
                    audit_filter['created'] = {'min': last_ts}
            except Exception as e:
                logger.debug(f'Error fetching audit events: {e}')
                break
    
    def get_record_sfs(self, record_uid: str) -> List[str]:
        """Get list of shared folder UIDs where the record exists."""
        return self._record_shared_folders.get(record_uid, [])
    
    def _get_ec_private_key(self) -> Optional[bytes]:
        """Get the enterprise EC private key for decryption."""
        return self._enterprise_data.enterprise_info.ec_private_key
    
    def _decrypt_record_data(self, encrypted_data: bytes) -> Dict[str, Any]:
        """Decrypt record data using EC private key."""
        if not encrypted_data:
            return {}
        
        ec_key = self._get_ec_private_key()
        if ec_key is None:
            return {}
        
        try:
            data_json = crypto.decrypt_ec(encrypted_data, ec_key)
            return json.loads(data_json.decode('utf-8'))
        except Exception as e:
            logger.debug(f'Failed to decrypt record data: {e}')
            return {}
    
    def _fetch_compliance_data(self, user_ids: Optional[List[int]] = None) -> None:
        """Fetch record data from compliance API."""
        if user_ids is None:
            user_ids = [u.enterprise_user_id for u in self._enterprise_data.users.get_all_entities()]
        
        if not user_ids:
            logger.warning('No enterprise users found')
            return
        
        rq = enterprise_pb2.PreliminaryComplianceDataRequest()
        rq.includeNonShared = True
        rq.includeTotalMatchingRecordsInFirstResponse = True
        for uid in user_ids:
            rq.enterpriseUserIds.append(uid)
        
        has_more = True
        continuation_token = None
        
        while has_more:
            if continuation_token:
                rq.continuationToken = continuation_token
            
            try:
                rs = self._auth.execute_auth_rest(
                    'enterprise/get_preliminary_compliance_data',
                    rq,
                    response_type=enterprise_pb2.PreliminaryComplianceDataResponse
                )
                
                for user_data in rs.auditUserData:
                    user_id = user_data.enterpriseUserId
                    owner_email = self._user_id_to_email.get(user_id, '')
                    
                    for record in user_data.auditUserRecords:
                        record_uid = utils.base64_url_encode(record.recordUid)
                        record_data = self._decrypt_record_data(record.encryptedData)
                        
                        self._records[record_uid] = {
                            'record_uid': record_uid,
                            'owner_email': owner_email,
                            'owner_user_id': user_id,
                            'title': record_data.get('title', ''),
                            'shared': record.shared,
                            'created_ts': 0,
                            'pw_changed_ts': 0,
                            'in_trash': record_data.get('in_trash', False)
                        }
                
                has_more = rs.hasMore and rs.continuationToken
                if has_more:
                    continuation_token = rs.continuationToken
                    
            except Exception as e:
                logger.warning(f'Error fetching compliance data: {e}')
                logger.debug(traceback.format_exc())
                break
        
        logger.debug(f'Fetched {len(self._records)} records from compliance API')
    
    def _update_timestamps_from_audit_events(self) -> None:
        """Update records with timestamps from audit events using span reports."""
        created_lookup: Dict[str, int] = {}
        folder_add_lookup: Dict[str, int] = {}
        pw_change_lookup: Dict[str, int] = {}
        
        event_types = ['record_add', 'record_password_change', 'folder_add_record']
        for event in self._fetch_paginated_audit_events(event_types, report_type='span'):
            record_uid = event.get('record_uid', '')
            if not record_uid or record_uid not in self._records:
                continue
            
            event_type = event.get('audit_event_type', '')
            event_ts = int(event.get('last_created', 0))
            
            if event_type == 'record_add':
                created_lookup.setdefault(record_uid, event_ts)
            elif event_type == 'folder_add_record':
                folder_add_lookup[record_uid] = event_ts
            elif event_type == 'record_password_change':
                if event_ts > pw_change_lookup.get(record_uid, 0):
                    pw_change_lookup[record_uid] = event_ts
        
        for record_uid, ts in folder_add_lookup.items():
            created_lookup.setdefault(record_uid, ts)
        
        if self._config.in_shared_folder:
            self._fetch_shared_folder_mappings()
        
        if self._config.exclude_deleted:
            self._fetch_deleted_records()
        
        for record_uid, ts in created_lookup.items():
            if record_uid in self._records:
                rec = self._records[record_uid]
                if rec['created_ts'] == 0 or ts < rec['created_ts']:
                    rec['created_ts'] = ts
        
        for record_uid, ts in pw_change_lookup.items():
            if record_uid in self._records:
                self._records[record_uid]['pw_changed_ts'] = ts
    
    def _fetch_deleted_records(self) -> None:
        """Fetch deleted records from audit events for --exclude-deleted filtering."""
        for event in self._fetch_paginated_audit_events(['record_delete']):
            record_uid = event.get('record_uid', '')
            if record_uid and record_uid in self._records:
                self._records[record_uid]['in_trash'] = True
    
    def _fetch_shared_folder_mappings(self) -> None:
        """Fetch shared folder mappings for --in-shared-folder filtering."""
        for event in self._fetch_paginated_audit_events(['folder_add_record']):
            record_uid = event.get('record_uid', '')
            shared_folder_uid = event.get('shared_folder_uid', '')
            
            if record_uid and shared_folder_uid:
                if record_uid not in self._record_shared_folders:
                    self._record_shared_folders[record_uid] = []
                if shared_folder_uid not in self._record_shared_folders[record_uid]:
                    self._record_shared_folders[record_uid].append(shared_folder_uid)
    
    def _fetch_records_from_audit_events(self) -> None:
        """Fallback: Fetch records from audit events if compliance API fails."""
        for event in self._fetch_paginated_audit_events(['record_add', 'folder_add_record']):
            record_uid = event.get('record_uid', '')
            if not record_uid:
                continue
            
            event_ts = int(event.get('created', 0))
            username = event.get('username', '')
            event_type = event.get('audit_event_type', '')
            shared_folder_uid = event.get('shared_folder_uid', '')
            
            if record_uid not in self._records:
                self._records[record_uid] = {
                    'record_uid': record_uid,
                    'owner_email': username,
                    'owner_user_id': 0,
                    'title': '',
                    'shared': bool(shared_folder_uid),
                    'created_ts': event_ts if event_type == 'record_add' else 0,
                    'pw_changed_ts': 0,
                    'in_trash': False
                }
            else:
                rec = self._records[record_uid]
                if event_type == 'record_add' and event_ts > 0:
                    if rec['created_ts'] == 0 or event_ts < rec['created_ts']:
                        rec['created_ts'] = event_ts
                    if username:
                        rec['owner_email'] = username
                if shared_folder_uid:
                    rec['shared'] = True
                if rec['created_ts'] == 0 and event_ts > 0:
                    rec['created_ts'] = event_ts
        
        logger.debug(f'Fetched {len(self._records)} records from audit events')
    
    def _get_record_title_from_vault(self, record_uid: str) -> str:
        """Try to get record title from vault."""
        if self._vault is None:
            return ''
        try:
            vault_data = self._vault.vault_data
            if vault_data:
                record = vault_data.get_record(record_uid)
                if record:
                    return record.title or ''
        except Exception:
            pass
        return ''
    
    def _enrich_titles_from_vault(self) -> None:
        """Enrich records missing titles from vault data."""
        if self._vault is None:
            return
        for record_uid, data in self._records.items():
            if not data.get('title'):
                title = self._get_record_title_from_vault(record_uid)
                if title:
                    data['title'] = title
    
    def generate_report(self) -> List[AgingReportEntry]:
        """Generate the password aging report."""
        cutoff_ts = self._get_cutoff_timestamp()
        target_username = self._get_target_username()
        
        self._build_user_lookups()
        
        if target_username and target_username not in self._email_to_user_id:
            return []
        
        user_ids = None
        if target_username:
            user_id = self._email_to_user_id.get(target_username)
            if user_id:
                user_ids = [user_id]
        
        self._fetch_compliance_data(user_ids)
        
        if not self._records:
            self._fetch_records_from_audit_events()
        
        self._update_timestamps_from_audit_events()
        self._enrich_titles_from_vault()
        
        report_entries: List[AgingReportEntry] = []
        
        for record_uid, data in self._records.items():
            owner_email = data.get('owner_email', '')
            
            if target_username and owner_email.lower() != target_username:
                continue
            
            if self._config.exclude_deleted and data.get('in_trash'):
                continue
            
            record_sfs = self.get_record_sfs(record_uid)
            if self._config.in_shared_folder and not record_sfs:
                continue
            
            created_ts = data.get('created_ts', 0)
            pw_changed_ts = data.get('pw_changed_ts', 0)
            
            if (created_ts and created_ts >= cutoff_ts) or (pw_changed_ts and pw_changed_ts >= cutoff_ts):
                continue
            
            ts = pw_changed_ts or created_ts
            change_dt = datetime.datetime.fromtimestamp(ts) if ts else None
            created_dt = datetime.datetime.fromtimestamp(created_ts) if created_ts else None
            
            entry = AgingReportEntry(
                record_uid=record_uid,
                owner_email=owner_email,
                title=data.get('title', ''),
                last_changed=change_dt,
                record_created=created_dt,
                shared=data.get('shared', False),
                record_url=f'https://{self._config.server}/vault/#detail/{record_uid}',
                shared_folder_uid=record_sfs or None,
                in_trash=data.get('in_trash', False)
            )
            report_entries.append(entry)
        
        report_entries.sort(key=self._sort_key)
        return report_entries
    
    @staticmethod
    def _sort_key(entry: AgingReportEntry) -> Tuple[int, float]:
        """Sort key for report entries by date."""
        if entry.last_changed:
            return (0, entry.last_changed.timestamp())
        if entry.record_created:
            return (1, entry.record_created.timestamp())
        return (2, 0)
    
    def cleanup(self, enterprise_id: int) -> None:
        """Clean up cache if no_cache option is set."""
        if self._config.no_cache:
            self.delete_local_cache(enterprise_id)
    
    def generate_report_rows(self, include_shared_folder: bool = False) -> Iterable[List[Any]]:
        """Generate report rows for tabular output."""
        for entry in self.generate_report():
            row = [entry.owner_email, entry.title, entry.last_changed, entry.shared, entry.record_url]
            if include_shared_folder:
                row.append(entry.shared_folder_uid or '')
            yield row
    
    @staticmethod
    def get_headers(include_shared_folder: bool = False) -> List[str]:
        """Get column headers for the report."""
        headers = ['owner', 'title', 'password_changed', 'shared', 'record_url']
        if include_shared_folder:
            headers.append('shared_folder_uid')
        return headers


def parse_period(period_str: str) -> Optional[int]:
    """Parse period string (e.g., '3m', '10d', '1y') to days.
    
    Args:
        period_str: Period string with format '<number><unit>' where unit is:
            - 'd' for days
            - 'm' for months (30 days)
            - 'y' for years (365 days)
    
    Returns:
        Number of days, or None if parsing fails.
    """
    if not period_str or len(period_str.strip()) < 2:
        return None
    
    period_str = period_str.strip().lower()
    unit = period_str[-1]
    
    try:
        value = abs(int(period_str[:-1]))
    except ValueError:
        return None
    
    multipliers = {'d': 1, 'm': 30, 'y': 365}
    multiplier = multipliers.get(unit)
    if multiplier is None:
        return None
    
    return value * multiplier


def parse_date(date_str: str) -> Optional[datetime.datetime]:
    """Parse date string in various formats."""
    formats = ['%Y-%m-%d', '%Y.%m.%d', '%Y/%m/%d', '%m-%d-%Y', '%m.%d.%Y', '%m/%d/%Y']
    for fmt in formats:
        try:
            return datetime.datetime.strptime(date_str, fmt)
        except ValueError:
            continue
    return None


def generate_aging_report(
    enterprise_data: enterprise_types.IEnterpriseData,
    auth: keeper_auth.KeeperAuth,
    period_days: int = DEFAULT_PERIOD_DAYS,
    cutoff_date: Optional[datetime.datetime] = None,
    username: Optional[str] = None,
    exclude_deleted: bool = False,
    in_shared_folder: bool = False,
    rebuild: bool = False,
    server: str = 'keepersecurity.com'
) -> List[AgingReportEntry]:
    """Convenience function to generate an aging report."""
    config = AgingReportConfig(
        period_days=period_days,
        cutoff_date=cutoff_date,
        username=username,
        exclude_deleted=exclude_deleted,
        in_shared_folder=in_shared_folder,
        rebuild=rebuild,
        server=server
    )
    return AgingReportGenerator(enterprise_data, auth, config).generate_report()
