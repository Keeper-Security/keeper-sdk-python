"""Enterprise password aging report functionality for Keeper SDK.

Uses the same approach as the old aging-report command (Untitled-1 lines 1806-2032):
1. Get record data (title, owner, shared) from compliance API (like sox_data)
2. Get timestamps from audit events using span reports for efficiency
"""

import dataclasses
import datetime
import json
import logging
import os
from typing import Optional, List, Dict, Any, Iterable, Tuple

from ..authentication import keeper_auth
from ..proto import enterprise_pb2
from .. import crypto, utils
from . import enterprise_types


API_EVENT_SUMMARY_ROW_LIMIT = 1000
DEFAULT_PERIOD_DAYS = 90  # Default: 3 months
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
    shared_folder_uid: Optional[str] = None
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
    
    Uses the same approach as the old code (Untitled-1 lines 1868-1932):
    1. Get record data from compliance API (title, owner, shared)
    2. Get timestamps from audit events using span reports
    """
    
    def __init__(
        self,
        enterprise_data: enterprise_types.IEnterpriseData,
        auth: keeper_auth.KeeperAuth,
        config: Optional[AgingReportConfig] = None,
        vault: Optional[Any] = None
    ) -> None:
        self._enterprise_data = enterprise_data
        self._auth = auth
        self._config = config or AgingReportConfig()
        self._vault = vault
        self._email_to_user_id: Optional[Dict[str, int]] = None
        self._user_id_to_email: Optional[Dict[int, str]] = None
        
        # Record data storage (similar to sox_data)
        self._records: Dict[str, Dict[str, Any]] = {}
    
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
    
    def _get_tree_key(self) -> bytes:
        """Get the enterprise tree key for decryption."""
        return self._enterprise_data.enterprise_info.tree_key
    
    def _decrypt_record_data(self, encrypted_data: bytes) -> Dict[str, Any]:
        """Decrypt record data using tree key.
        
        Similar to old code's sox_data decryption.
        """
        try:
            tree_key = self._get_tree_key()
            if not tree_key or not encrypted_data:
                return {}
            
            # Try AES-GCM v2 first (12 byte nonce), then v1
            try:
                decrypted = crypto.decrypt_aes_v2(encrypted_data, tree_key)
            except Exception:
                try:
                    decrypted = crypto.decrypt_aes_v1(encrypted_data, tree_key)
                except Exception:
                    return {}
            
            return json.loads(decrypted.decode('utf-8'))
        except Exception:
            return {}
    
    def _fetch_compliance_data(self, user_ids: Optional[List[int]] = None) -> None:
        """Fetch record data from compliance API.
        
        Calls enterprise/get_preliminary_compliance_data to get all records
        with their encrypted data (title, etc.), similar to old code's
        get_prelim_data/get_compliance_data (Untitled-1 line 1868-1872).
        """
        # If no specific user_ids provided, get ALL enterprise users
        # (old code line 1893: user_uids = None means get all)
        if user_ids is None:
            user_ids = []
            for user in self._enterprise_data.users.get_all_entities():
                user_ids.append(user.enterprise_user_id)
        
        if not user_ids:
            logger.warning('No enterprise users found')
            return
        
        logger.debug(f'Fetching compliance data for {len(user_ids)} user(s)')
        
        rq = enterprise_pb2.PreliminaryComplianceDataRequest()
        rq.includeNonShared = True
        rq.includeTotalMatchingRecordsInFirstResponse = True
        
        # Always provide user IDs explicitly
        for uid in user_ids:
            rq.enterpriseUserIds.append(uid)
        
        has_more = True
        continuation_token = None
        total_records = 0
        
        while has_more:
            if continuation_token:
                rq.continuationToken = continuation_token
            
            try:
                rs = self._auth.execute_auth_rest(
                    'enterprise/get_preliminary_compliance_data',
                    rq,
                    rs_type=enterprise_pb2.PreliminaryComplianceDataResponse
                )
                
                # Process user records
                for user_data in rs.auditUserData:
                    user_id = user_data.enterpriseUserId
                    owner_email = self._user_id_to_email.get(user_id, '')
                    
                    for record in user_data.auditUserRecords:
                        record_uid = utils.base64_url_encode(record.recordUid)
                        
                        # Decrypt record data to get title
                        record_data = self._decrypt_record_data(record.encryptedData)
                        title = record_data.get('title', '')
                        
                        self._records[record_uid] = {
                            'record_uid': record_uid,
                            'owner_email': owner_email,
                            'owner_user_id': user_id,
                            'title': title,
                            'shared': record.shared,
                            'created_ts': 0,
                            'pw_changed_ts': 0,
                            'in_trash': record_data.get('in_trash', False)
                        }
                        total_records += 1
                
                has_more = rs.hasMore
                if has_more and rs.continuationToken:
                    continuation_token = rs.continuationToken
                else:
                    has_more = False
                    
            except Exception as e:
                logger.warning(f'Error fetching compliance data: {e}')
                import traceback
                logger.debug(traceback.format_exc())
                has_more = False
        
        logger.debug(f'Fetched {total_records} records from compliance API')
    
    def _update_timestamps_from_audit_events(self) -> None:
        """Update records with timestamps from audit events.
        
        Uses span reports with aggregation for efficiency
        (old code lines 1962-2012).
        """
        # Search from 5 years back
        search_min_ts = int((datetime.datetime.now() - datetime.timedelta(days=365 * 5)).timestamp())
        
        filter_period: Dict[str, Any] = {'min': search_min_ts}
        audit_filter: Dict[str, Any] = {
            'audit_event_type': ['record_add', 'record_password_change', 'folder_add_record'],
            'created': filter_period
        }
        
        limit = API_EVENT_SUMMARY_ROW_LIMIT
        
        # Use span report with aggregation - efficient (old code lines 1965-1972)
        rq = {
            'command': 'get_audit_event_reports',
            'scope': 'enterprise',
            'report_type': 'span',
            'columns': ['record_uid', 'audit_event_type'],
            'aggregate': ['last_created'],
            'filter': audit_filter,
            'limit': limit
        }
        
        # Track timestamps
        created_lookup: Dict[str, int] = {}
        folder_add_lookup: Dict[str, int] = {}
        pw_change_lookup: Dict[str, int] = {}
        
        done = False
        
        while not done:
            try:
                rs = self._auth.execute_auth_command(rq)
                events = rs.get('audit_event_overview_report_rows', [])
                done = len(events) < limit
                
                if not done and events:
                    # Pagination using max filter (old code line 2001)
                    filter_period['max'] = int(events[-1].get('last_created', 0)) + 1
                
                for event in events:
                    record_uid = event.get('record_uid', '')
                    if not record_uid:
                        continue
                    
                    # Only process records we know about from compliance data
                    if record_uid not in self._records:
                        continue
                    
                    event_type = event.get('audit_event_type', '')
                    event_ts = int(event.get('last_created', 0))
                    
                    if event_type == 'record_add':
                        created_lookup.setdefault(record_uid, event_ts)
                    elif event_type == 'folder_add_record':
                        folder_add_lookup[record_uid] = event_ts
                    elif event_type == 'record_password_change':
                        existing = pw_change_lookup.get(record_uid, 0)
                        if event_ts > existing:
                            pw_change_lookup[record_uid] = event_ts
                            
            except Exception:
                break
        
        # Apply folder_add as fallback for created (old code lines 2006-2007)
        for record_uid, ts in folder_add_lookup.items():
            created_lookup.setdefault(record_uid, ts)
        
        # Update records with timestamps
        for record_uid, ts in created_lookup.items():
            if record_uid in self._records:
                rec = self._records[record_uid]
                if rec['created_ts'] == 0 or ts < rec['created_ts']:
                    rec['created_ts'] = ts
        
        for record_uid, ts in pw_change_lookup.items():
            if record_uid in self._records:
                self._records[record_uid]['pw_changed_ts'] = ts
    
    def _fetch_records_from_audit_events(self) -> None:
        """Fallback: Fetch records from audit events if compliance API fails.
        
        Uses raw audit events to get record info (owner, timestamps).
        Titles may be missing with this approach.
        """
        logger.debug('Fetching records from audit events as fallback')
        
        # Search from 5 years back
        search_min_ts = int((datetime.datetime.now() - datetime.timedelta(days=365 * 5)).timestamp())
        
        limit = API_EVENT_SUMMARY_ROW_LIMIT
        
        # Query both record_add and folder_add_record
        audit_filter: Dict[str, Any] = {
            'audit_event_type': ['record_add', 'folder_add_record'],
            'created': {'min': search_min_ts}
        }
        
        rq = {
            'command': 'get_audit_event_reports',
            'scope': 'enterprise',
            'report_type': 'raw',
            'filter': audit_filter,
            'limit': limit,
            'order': 'ascending'
        }
        
        done = False
        last_ts = search_min_ts
        
        while not done:
            try:
                rs = self._auth.execute_auth_command(rq)
                events = rs.get('audit_event_overview_report_rows', [])
                
                if len(events) < limit:
                    done = True
                
                for event in events:
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
                            'title': '',  # Title not available from audit events
                            'shared': bool(shared_folder_uid),
                            'created_ts': event_ts if event_type == 'record_add' else 0,
                            'pw_changed_ts': 0,
                            'in_trash': False
                        }
                    else:
                        rec = self._records[record_uid]
                        if event_type == 'record_add':
                            if event_ts > 0 and (rec['created_ts'] == 0 or event_ts < rec['created_ts']):
                                rec['created_ts'] = event_ts
                                if username:
                                    rec['owner_email'] = username
                        if shared_folder_uid:
                            rec['shared'] = True
                        if rec['created_ts'] == 0 and event_ts > 0:
                            rec['created_ts'] = event_ts
                    
                    last_ts = max(last_ts, event_ts)
                
                # Pagination
                if not done and events:
                    audit_filter['created'] = {'min': last_ts}
                    
            except Exception as e:
                logger.debug(f'Error fetching audit events: {e}')
                done = True
        
        logger.debug(f'Fetched {len(self._records)} records from audit events')
    
    def _get_record_title_from_vault(self, record_uid: str) -> str:
        """Try to get record title from vault as fallback."""
        if self._vault is None:
            return ''
        try:
            vault_data = getattr(self._vault, 'vault_data', None)
            if vault_data is None:
                return ''
            record = vault_data.get_record(record_uid)
            if record and hasattr(record, 'title'):
                return record.title or ''
        except Exception:
            pass
        return ''
    
    def _enrich_titles_from_vault(self) -> None:
        """Enrich records with titles from vault for records missing titles."""
        if self._vault is None:
            return
        
        for record_uid, data in self._records.items():
            if not data.get('title'):
                title = self._get_record_title_from_vault(record_uid)
                if title:
                    data['title'] = title
    
    def generate_report(self) -> List[AgingReportEntry]:
        """Generate the password aging report.
        
        Similar to old code (Untitled-1 lines 1893-1923).
        """
        cutoff_ts = self._get_cutoff_timestamp()
        target_username = self._get_target_username()
        
        # Build user lookups
        self._build_user_lookups()
        
        # Validate username if provided
        if target_username and target_username not in self._email_to_user_id:
            return []
        
        # Get user IDs to query (filter by username if specified)
        user_ids = None
        if target_username:
            user_id = self._email_to_user_id.get(target_username)
            if user_id:
                user_ids = [user_id]
        
        # Step 1: Try to fetch record data from compliance API
        self._fetch_compliance_data(user_ids)
        
        # If compliance API returned no records, fallback to audit events
        if not self._records:
            logger.debug('No records from compliance API, falling back to audit events')
            self._fetch_records_from_audit_events()
        
        # Step 2: Update timestamps from audit events
        self._update_timestamps_from_audit_events()
        
        # Step 3: Try to enrich titles from vault as fallback
        self._enrich_titles_from_vault()
        
        logger.debug(f'Total records after processing: {len(self._records)}')
        
        report_entries: List[AgingReportEntry] = []
        
        for record_uid, data in self._records.items():
            owner_email = data.get('owner_email', '')
            
            # Filter by username if specified (should already be filtered, but double-check)
            if target_username and owner_email.lower() != target_username:
                continue
            
            # Exclude deleted records if specified (old code line 1910)
            if self._config.exclude_deleted and data.get('in_trash'):
                continue
            
            created_ts = data.get('created_ts', 0)
            pw_changed_ts = data.get('pw_changed_ts', 0)
            
            # Effective timestamp for filtering (old code lines 1906-1909)
            created_after_date = created_ts and (created_ts >= cutoff_ts)
            pw_changed_after_date = pw_changed_ts and (pw_changed_ts >= cutoff_ts)
            
            # Skip if created or password changed after cutoff
            if created_after_date or pw_changed_after_date:
                continue
            
            # Build datetime objects (old code line 1917)
            ts = pw_changed_ts or created_ts
            change_dt = datetime.datetime.fromtimestamp(ts) if ts else None
            
            created_dt = None
            if created_ts:
                created_dt = datetime.datetime.fromtimestamp(created_ts)
            
            # Record URL (old code line 1918)
            record_url = f'https://{self._config.server}/vault/#detail/{record_uid}'
            
            entry = AgingReportEntry(
                record_uid=record_uid,
                owner_email=owner_email,
                title=data.get('title', ''),
                last_changed=change_dt,
                record_created=created_dt,
                shared=data.get('shared', False),
                record_url=record_url,
                shared_folder_uid=None,
                in_trash=data.get('in_trash', False)
            )
            
            report_entries.append(entry)
        
        # Sort by last_changed date (old code lines 1926-1930)
        def sort_key(x: AgingReportEntry) -> Tuple[int, float]:
            if x.last_changed:
                return (0, x.last_changed.timestamp())
            elif x.record_created:
                return (1, x.record_created.timestamp())
            return (2, 0)
        
        report_entries.sort(key=sort_key)
        
        return report_entries
    
    def cleanup(self, enterprise_id: int) -> None:
        """Clean up cache if no_cache option is set."""
        if self._config.no_cache:
            self.delete_local_cache(enterprise_id)
    
    def generate_report_rows(self, include_shared_folder: bool = False) -> Iterable[List[Any]]:
        """Generate report rows suitable for tabular output.
        
        Returns datetime objects for date columns (old code line 1917),
        letting dump_report_data handle formatting.
        """
        for entry in self.generate_report():
            # Row format matches old code line 1919
            row = [
                entry.owner_email,
                entry.title,
                entry.last_changed,  # datetime object
                entry.shared,
                entry.record_url
            ]
            
            # Only add shared_folder_uid if requested (old code lines 1920-1922)
            if include_shared_folder:
                row.append(entry.shared_folder_uid or '')
            
            yield row
    
    @staticmethod
    def get_headers(include_shared_folder: bool = False) -> List[str]:
        """Get column headers for the report.
        
        Returns lowercase headers (old code line 1896).
        """
        headers = ['owner', 'title', 'password_changed', 'shared', 'record_url']
        if include_shared_folder:
            headers.append('shared_folder_uid')
        return headers


def parse_period(period_str: str) -> Optional[int]:
    """Parse period string (e.g., '3m', '10d', '1y') to days.
    
    Same logic as old code (Untitled-1 lines 1813-1835).
    """
    if not period_str:
        return None
    
    period_str = period_str.strip().lower()
    if len(period_str) < 2:
        return None
    
    unit = period_str[-1]
    try:
        value = abs(int(period_str[:-1]))
    except ValueError:
        return None
    
    if unit == 'd':
        return value
    elif unit == 'm':
        return value * 30
    elif unit == 'y':
        return value * 365
    else:
        return None


def parse_date(date_str: str) -> Optional[datetime.datetime]:
    """Parse date string in various formats.
    
    Same formats as old code (Untitled-1 lines 1837-1846).
    """
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
