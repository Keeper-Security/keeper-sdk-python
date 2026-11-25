"""Enterprise compliance report functionality for Keeper SDK."""

import datetime
import json
import logging
import fnmatch
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Iterable, Set, Tuple, Callable

from ..authentication import keeper_auth
from ..proto import enterprise_pb2
from .. import crypto, errors, utils
from . import enterprise_types
from ..plugins.sox import storage_types as st


API_EVENT_SUMMARY_ROW_LIMIT = 1000
MAX_RECORDS_PER_REQUEST = 1000
MAX_USERS_PER_REQUEST = 5000

# Report type constants
REPORT_TYPE_DEFAULT = 'default'
REPORT_TYPE_TEAM = 'team'
REPORT_TYPE_RECORD_ACCESS = 'record_access'
REPORT_TYPE_SUMMARY = 'summary'
REPORT_TYPE_SHARED_FOLDER = 'shared_folder'
REPORT_TYPE_HISTORY = 'history'
REPORT_TYPE_VAULT = 'vault'
REPORT_TYPE_EXTERNAL_SHARES = 'external_shares'

logger = logging.getLogger(__name__)


PERMISSION_OWNER = 1
PERMISSION_MASK = 2
PERMISSION_EDIT = 4
PERMISSION_SHARE = 8
PERMISSION_SHARE_ADMIN = 16


def permissions_to_string(permission_bits: int) -> str:
    """Convert permission bits to human-readable string."""
    permission_masks = {
        PERMISSION_OWNER: 'owner',
        PERMISSION_MASK: 'mask', 
        PERMISSION_EDIT: 'edit',
        PERMISSION_SHARE: 'share',
        PERMISSION_SHARE_ADMIN: 'share_admin'
    }
    
    permissions = [perm for mask, perm in permission_masks.items() if (permission_bits & mask)]
    if not permissions:
        permissions.append('read-only')
    
    return ','.join(permissions)


@dataclass
class ComplianceReportEntry:
    """Represents a single record entry in the compliance report."""
    record_uid: str
    title: str = ''
    record_type: str = ''
    username: str = ''
    permissions: str = ''
    url: str = ''
    in_trash: bool = False
    shared: bool = False
    shared_folder_uid: Optional[List[str]] = None
    created: Optional[datetime.datetime] = None
    last_pw_change: Optional[datetime.datetime] = None
    last_modified: Optional[datetime.datetime] = None
    last_rotation: Optional[datetime.datetime] = None


@dataclass
class TeamReportEntry:
    """Represents a team's access to shared folders."""
    team_name: str
    team_uid: str
    shared_folder_name: str
    shared_folder_uid: str
    permissions: str
    records: int = 0
    team_users: Optional[List[str]] = None


@dataclass
class RecordAccessReportEntry:
    """Represents record access history for a user."""
    vault_owner: str
    record_uid: str
    record_title: str = ''
    record_type: str = ''
    record_url: str = ''
    has_attachments: Optional[bool] = None
    in_trash: bool = False
    record_owner: str = ''
    ip_address: str = ''
    device: str = ''
    last_access: Optional[datetime.datetime] = None
    created: Optional[datetime.datetime] = None
    last_pw_change: Optional[datetime.datetime] = None
    last_modified: Optional[datetime.datetime] = None
    last_rotation: Optional[datetime.datetime] = None


@dataclass
class SummaryReportEntry:
    """Represents summary statistics for a user."""
    email: str
    total_items: int = 0
    total_owned: int = 0
    active_owned: int = 0
    deleted_owned: int = 0


@dataclass
class SharedFolderReportEntry:
    """Represents shared folder access details."""
    shared_folder_uid: str
    team_uid: Optional[List[str]] = None
    team_name: Optional[List[str]] = None
    record_uid: Optional[List[str]] = None
    record_title: Optional[List[str]] = None
    email: Optional[List[str]] = None


@dataclass
class ComplianceReportConfig:
    """Configuration for compliance report generation."""
    username: Optional[List[str]] = None
    job_title: Optional[List[str]] = None
    team: Optional[List[str]] = None
    record: Optional[List[str]] = None
    url: Optional[List[str]] = None
    shared: bool = False
    deleted_items: bool = False
    active_items: bool = False
    show_team_users: bool = False
    report_type: str = 'history'
    aging: bool = False
    node_id: Optional[int] = None
    rebuild: bool = False
    no_rebuild: bool = False
    no_cache: bool = False
    cache_max_age_days: int = 1
    external_share_type: str = 'all'
    resolve_teams: bool = False

    def __post_init__(self) -> None:
        """Validate options before a report starts fetching data."""
        if self.rebuild and self.no_rebuild:
            raise ValueError("rebuild and no_rebuild cannot both be enabled")
        if self.cache_max_age_days < 0:
            raise ValueError("cache_max_age_days cannot be negative")
        if self.report_type not in (REPORT_TYPE_HISTORY, REPORT_TYPE_VAULT):
            raise ValueError(f"Unsupported report type: {self.report_type}")
        if self.external_share_type not in ('all', 'direct', 'shared-folder'):
            raise ValueError(f"Unsupported external share type: {self.external_share_type}")


@dataclass
class RecordInfo:
    """Internal representation of record data."""
    record_uid: str = ''
    record_uid_bytes: bytes = b''
    encrypted_data: bytes = b''  # API's EC-encrypted data for cache storage
    owner_email: str = ''
    owner_user_id: int = 0
    title: str = ''
    record_type: str = ''
    url: str = ''
    shared: bool = False
    in_trash: bool = False
    has_attachments: bool = False
    shared_folder_uid: Optional[str] = None


@dataclass
class SharedFolderInfo:
    """Internal representation of shared folder data."""
    folder_uid: str = ''
    records: Dict[str, int] = field(default_factory=dict)
    users: Set[int] = field(default_factory=set)
    teams: Set[str] = field(default_factory=set)


class ComplianceReportGenerator:
    """Generates compliance reports for enterprise records and users.
    
    This class provides various compliance reporting capabilities including:
    - Default compliance report with record permissions
    - Team access to shared folders report
    - Record access history by user
    - Summary statistics by user
    - Shared folder access details
    """
    
    def __init__(
        self,
        enterprise_data: enterprise_types.IEnterpriseData,
        auth: keeper_auth.KeeperAuth,
        config: Optional[ComplianceReportConfig] = None,
        vault_storage: Optional[Any] = None,
        compliance_storage: Optional[Any] = None,
        progress_callback: Optional[Callable[[str], None]] = None,
        vault_data: Optional[Any] = None
    ) -> None:
        """``vault_data`` (a ``VaultData``) supplies decrypted shared folder names, if given."""
        self._enterprise_data = enterprise_data
        self._auth = auth
        self._config = config or ComplianceReportConfig()
        self._vault_storage = vault_storage
        self._vault_data = vault_data
        self._progress_callback = progress_callback
        self._compliance_storage = compliance_storage
        self._user_teams: Optional[Dict[int, Set[str]]] = None
        self._records: Dict[str, RecordInfo] = {}
        self._record_shared_folders: Dict[str, List[str]] = {}
        self._shared_folders: Dict[str, SharedFolderInfo] = {}
        self._email_to_user_id: Optional[Dict[str, int]] = None
        self._user_id_to_email: Optional[Dict[int, str]] = None
        self._record_permissions: Dict[Tuple[str, int], int] = {}
        self._team_members: Dict[str, Set[int]] = {}
        self._team_uid_to_name: Dict[str, str] = {}
        self._team_name_to_uid: Dict[str, str] = {}
        self._team_filter_user_ids: Optional[Set[int]] = None
    
    @property
    def enterprise_data(self) -> enterprise_types.IEnterpriseData:
        return self._enterprise_data
    
    @property
    def config(self) -> ComplianceReportConfig:
        return self._config
    
    def get_preliminary_records(self) -> Dict[str, RecordInfo]:
        """Build user lookups and fetch preliminary compliance data."""
        self._build_user_lookups()
        self._fetch_preliminary_compliance_data()
        return dict(self._records)
    
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
    
    def _build_user_teams_lookup(self) -> Dict[int, Set[str]]:
        """Build lookup of users to their teams."""
        if self._user_teams is not None:
            return self._user_teams
        
        self._user_teams = defaultdict(set)
        self._team_uid_to_name = {}
        self._team_name_to_uid = {}

        for team in self._enterprise_data.teams.get_all_entities():
            self._team_uid_to_name[team.team_uid] = team.name
            self._team_name_to_uid[team.name.lower()] = team.team_uid
        
        for team_user in self._enterprise_data.team_users.get_all_links():
            self._user_teams[team_user.enterprise_user_id].add(team_user.team_uid)
            if team_user.team_uid not in self._team_members:
                self._team_members[team_user.team_uid] = set()
            self._team_members[team_user.team_uid].add(team_user.enterprise_user_id)
        
        return self._user_teams
    
    def _get_team_filter_user_ids(self) -> Optional[Set[int]]:
        """Get user IDs that match the team filter."""
        if not self._config.team:
            return None
        
        if self._team_filter_user_ids is not None:
            return self._team_filter_user_ids
        
        self._build_user_teams_lookup()
        self._team_filter_user_ids = set()
        
        for team_ref in self._config.team:
            if team_ref in self._team_members:
                self._team_filter_user_ids.update(self._team_members[team_ref])
            elif team_ref.lower() in self._team_name_to_uid:
                team_uid = self._team_name_to_uid[team_ref.lower()]
                if team_uid in self._team_members:
                    self._team_filter_user_ids.update(self._team_members[team_uid])
            else:
                logger.warning(f'Team not found: {team_ref}')
        
        return self._team_filter_user_ids
    
    def _is_prelim_cache_fresh(self) -> bool:
        """Check if preliminary data cache is still valid."""
        if not self._compliance_storage:
            return False
        if self._config.rebuild:
            return False
        if self._config.no_rebuild:
            return self._compliance_storage.last_prelim_data_update > 0
        
        max_age = datetime.timedelta(days=self._config.cache_max_age_days)
        min_ts = int((datetime.datetime.now() - max_age).timestamp())
        return self._compliance_storage.last_prelim_data_update >= min_ts
    
    def _is_compliance_cache_fresh(self) -> bool:
        """Check if full compliance data cache is still valid."""
        if not self._compliance_storage:
            return False
        if self._config.rebuild:
            return False
        if self._config.no_rebuild:
            return self._compliance_storage.last_compliance_data_update > 0
        
        max_age = datetime.timedelta(days=self._config.cache_max_age_days)
        min_ts = int((datetime.datetime.now() - max_age).timestamp())
        return self._compliance_storage.last_compliance_data_update >= min_ts
    
    def _load_prelim_from_cache(self) -> bool:
        """Load preliminary data from SQLite cache."""
        if not self._compliance_storage:
            return False
        
        try:
            records = list(self._compliance_storage.records.get_all_entities())
            if not records:
                return False
            
            for entity in records:
                record_data = self._decrypt_record_data(entity.encrypted_data)
                self._records[entity.record_uid] = RecordInfo(
                    record_uid=entity.record_uid,
                    record_uid_bytes=entity.record_uid_bytes,
                    encrypted_data=entity.encrypted_data,
                    title=record_data.get('title', ''),
                    record_type=record_data.get('record_type', ''),
                    url=record_data.get('url', ''),
                    shared=entity.shared,
                    in_trash=entity.in_trash,
                    has_attachments=entity.has_attachments
                )
            
            links = list(self._compliance_storage.user_record_links.get_all_links())
            for link in links:
                if link.record_uid in self._records:
                    self._records[link.record_uid].owner_user_id = link.user_uid
                    self._records[link.record_uid].owner_email = self._user_id_to_email.get(link.user_uid, '')
                    self._update_permissions_lookup(
                        link.record_uid,
                        link.user_uid,
                        PERMISSION_OWNER | PERMISSION_EDIT | PERMISSION_SHARE | PERMISSION_SHARE_ADMIN
                    )
            
            if self._progress_callback:
                self._progress_callback('Loaded from cache.')
            return True
        except Exception as e:
            logger.debug(f'Error loading from cache: {e}')
            return False
    
    def _load_compliance_from_cache(self) -> bool:
        """Load full compliance data from SQLite cache."""
        if not self._compliance_storage:
            return False
        
        try:
            perms = self._compliance_storage.record_permissions.get_all_links()
            for link in perms:
                self._update_permissions_lookup(link.record_uid, link.user_uid, link.permissions)
            
            sf_records = self._compliance_storage.sf_record_links.get_all_links()
            for link in sf_records:
                if link.folder_uid not in self._shared_folders:
                    self._shared_folders[link.folder_uid] = SharedFolderInfo(folder_uid=link.folder_uid)
                self._shared_folders[link.folder_uid].records[link.record_uid] = link.permissions
                
                if link.record_uid not in self._record_shared_folders:
                    self._record_shared_folders[link.record_uid] = []
                if link.folder_uid not in self._record_shared_folders[link.record_uid]:
                    self._record_shared_folders[link.record_uid].append(link.folder_uid)
                
                if link.record_uid in self._records:
                    self._records[link.record_uid].shared = True
            
            sf_users = self._compliance_storage.sf_user_links.get_all_links()
            for link in sf_users:
                if link.folder_uid in self._shared_folders:
                    self._shared_folders[link.folder_uid].users.add(link.user_uid)
            
            sf_teams = self._compliance_storage.sf_team_links.get_all_links()
            for link in sf_teams:
                if link.folder_uid in self._shared_folders:
                    self._shared_folders[link.folder_uid].teams.add(link.team_uid)
            
            team_users = self._compliance_storage.team_user_links.get_all_links()
            for link in team_users:
                if link.team_uid not in self._team_members:
                    self._team_members[link.team_uid] = set()
                self._team_members[link.team_uid].add(link.user_uid)
            
            return True
        except Exception as e:
            logger.debug(f'Error loading compliance from cache: {e}')
            return False
    
    def _save_prelim_to_cache(self) -> None:
        """Save preliminary data to SQLite cache."""
        if not self._compliance_storage:
            return
        
        try:
            from ..plugins.sox import storage_types as st
            
            self._compliance_storage.clear_non_aging_data()
            
            records = []
            links = []
            for record_uid, info in self._records.items():
                entity = st.StorageRecord()
                entity.record_uid = record_uid
                entity.record_uid_bytes = info.record_uid_bytes
                entity.encrypted_data = info.encrypted_data
                entity.shared = info.shared
                entity.in_trash = info.in_trash
                entity.has_attachments = info.has_attachments
                records.append(entity)
                
                if info.owner_user_id:
                    link = st.StorageUserRecordLink()
                    link.record_uid = record_uid
                    link.user_uid = info.owner_user_id
                    links.append(link)
            
            self._compliance_storage.records.put_entities(records)
            self._compliance_storage.user_record_links.put_links(links)
            self._compliance_storage.set_prelim_data_updated()
        except Exception as e:
            logger.debug(f'Error saving to cache: {e}')
    
    def _save_compliance_to_cache(self) -> None:
        """Save full compliance data to SQLite cache."""
        if not self._compliance_storage:
            return
        
        try:
            perms = []
            for (record_uid, user_id), bits in self._record_permissions.items():
                link = st.StorageRecordPermissions()
                link.record_uid = record_uid
                link.user_uid = user_id
                link.permissions = bits
                perms.append(link)
            self._compliance_storage.record_permissions.put_links(perms)
            
            sf_records = []
            sf_users = []
            sf_teams = []
            for folder_uid, info in self._shared_folders.items():
                for record_uid, perm_bits in info.records.items():
                    link = st.StorageSharedFolderRecordLink()
                    link.folder_uid = folder_uid
                    link.record_uid = record_uid
                    link.permissions = perm_bits
                    sf_records.append(link)
                
                for user_id in info.users:
                    link = st.StorageSharedFolderUserLink()
                    link.folder_uid = folder_uid
                    link.user_uid = user_id
                    sf_users.append(link)
                
                for team_uid in info.teams:
                    link = st.StorageSharedFolderTeamLink()
                    link.folder_uid = folder_uid
                    link.team_uid = team_uid
                    sf_teams.append(link)
            
            self._compliance_storage.sf_record_links.put_links(sf_records)
            self._compliance_storage.sf_user_links.put_links(sf_users)
            self._compliance_storage.sf_team_links.put_links(sf_teams)
            
            team_users = []
            for team_uid, user_ids in self._team_members.items():
                for user_id in user_ids:
                    link = st.StorageTeamUserLink()
                    link.team_uid = team_uid
                    link.user_uid = user_id
                    team_users.append(link)
            self._compliance_storage.team_user_links.put_links(team_users)
            
            records = []
            for record_uid, info in self._records.items():
                entity = self._compliance_storage.records.get_entity(record_uid)
                if entity:
                    entity.in_trash = info.in_trash
                    entity.has_attachments = info.has_attachments
                    entity.shared = info.shared
                    records.append(entity)
            if records:
                self._compliance_storage.records.put_entities(records)
            
            self._compliance_storage.set_compliance_data_updated()
        except Exception as e:
            logger.debug(f'Error saving compliance to cache: {e}')
    
    def _get_ec_private_key(self) -> Optional[Any]:
        """Get the enterprise EC private key for decryption."""
        return self._enterprise_data.enterprise_info.ec_private_key
    
    def _decrypt_record_data(self, encrypted_data: bytes) -> Dict[str, Any]:
        """Decrypt record data using EC private key."""
        if not encrypted_data:
            return {}
        
        ec_key = self._get_ec_private_key()
        if ec_key is None:
            return {}

        # EC compliance metadata is encoded as an uncompressed P-256 point
        # (65 bytes), followed by AES-GCM nonce/ciphertext/tag. Some response
        # rows legitimately have no EC metadata; avoid sending those rows to
        # the EC loader and flooding the CLI with point-format warnings.
        if not isinstance(encrypted_data, (bytes, bytearray)):
            return {}
        if len(encrypted_data) < 93 or encrypted_data[0] != 4:
            return {}
        if isinstance(ec_key, (bytes, bytearray)):
            ec_key = crypto.load_ec_private_key(bytes(ec_key))
        
        try:
            data_json = crypto.decrypt_ec(encrypted_data, ec_key)
            return json.loads(data_json.decode('utf-8'))
        except Exception as e:
            logger.debug(f'Failed to decrypt record data: {e}')
            return {}
    
    def _update_permissions_lookup(
        self,
        record_uid: str,
        user_id: int,
        permission_bits: int
    ) -> None:
        """Update permissions lookup with OR of existing and new bits."""
        lookup_key = (record_uid, user_id)
        existing_bits = self._record_permissions.get(lookup_key, 0)
        self._record_permissions[lookup_key] = existing_bits | permission_bits
    
    def _fetch_preliminary_compliance_data(self, user_ids: Optional[List[int]] = None) -> None:
        """Fetch basic record information from compliance API or cache."""
        if self._is_prelim_cache_fresh():
            if self._progress_callback:
                self._progress_callback('Loading from cache...')
            if self._load_prelim_from_cache():
                return

        if self._config.no_rebuild:
            logger.warning('No usable preliminary compliance cache is available; remote fetch disabled by no_rebuild')
            return
        
        if user_ids is None:
            user_ids = [u.enterprise_user_id for u in self._enterprise_data.users.get_all_entities()]
        
        if not user_ids:
            logger.warning('No enterprise users found')
            return
        
        total_users = len(user_ids)
        total_records = 0
        loaded_records = 0
        users_processed = 0
        processed_user_ids = set()
        
        if self._progress_callback:
            self._progress_callback(f'Loading record information - Users: 0/{total_users}, Records: 0/0')
        
        try:
            for user_offset in range(0, len(user_ids), MAX_USERS_PER_REQUEST):
                user_batch = user_ids[user_offset:user_offset + MAX_USERS_PER_REQUEST]
                continuation_token = None
                seen_tokens = set()
                has_more = True
                first_response = True

                while has_more:
                    rq = enterprise_pb2.PreliminaryComplianceDataRequest()
                    rq.includeNonShared = not self._config.shared
                    rq.includeTotalMatchingRecordsInFirstResponse = first_response
                    rq.enterpriseUserIds.extend(user_batch)
                    if continuation_token:
                        rq.continuationToken = continuation_token

                    rs = self._auth.execute_auth_rest(
                        'enterprise/get_preliminary_compliance_data',
                        rq,
                        response_type=enterprise_pb2.PreliminaryComplianceDataResponse
                    )
                    if rs is None:
                        raise RuntimeError('Preliminary compliance endpoint returned an empty response')

                    if rs.totalMatchingRecords > 0 and total_records == 0:
                        total_records = rs.totalMatchingRecords
                    
                    for user_data in rs.auditUserData:
                        user_id = user_data.enterpriseUserId
                        owner_email = self._user_id_to_email.get(user_id, '')
                        
                        if user_id not in processed_user_ids:
                            processed_user_ids.add(user_id)
                            users_processed = len(processed_user_ids)
                        
                        for record in user_data.auditUserRecords:
                            record_uid = utils.base64_url_encode(record.recordUid)
                            record_data = self._decrypt_record_data(record.encryptedData)
                            
                            shared_folder_uid = record_data.get('shared_folder_uid') or record_data.get('folder_uid')
                            if shared_folder_uid and record.shared:
                                if record_uid not in self._record_shared_folders:
                                    self._record_shared_folders[record_uid] = []
                                if shared_folder_uid not in self._record_shared_folders[record_uid]:
                                    self._record_shared_folders[record_uid].append(shared_folder_uid)
                            
                            existing = self._records.get(record_uid)
                            if existing is None:
                                self._records[record_uid] = RecordInfo(
                                    record_uid=record_uid,
                                    record_uid_bytes=record.recordUid,
                                    encrypted_data=record.encryptedData,
                                    owner_email=owner_email,
                                    owner_user_id=user_id,
                                    title=record_data.get('title', '') or record_data.get('record_title', ''),
                                    record_type=record_data.get('record_type', '') or record_data.get('type', ''),
                                    url=record_data.get('url', ''),
                                    shared=record.shared,
                                    in_trash=record_data.get('in_trash', False),
                                    has_attachments=record_data.get('has_attachments', False),
                                    shared_folder_uid=shared_folder_uid
                                )
                            else:
                                existing.shared = existing.shared or record.shared
                                existing.has_attachments = existing.has_attachments or record_data.get('has_attachments', False)
                            
                            self._update_permissions_lookup(
                                record_uid, 
                                user_id, 
                                PERMISSION_OWNER | PERMISSION_EDIT | PERMISSION_SHARE | PERMISSION_SHARE_ADMIN
                            )
                            loaded_records += 1
                    
                    if self._progress_callback:
                        total_display = total_records if total_records > 0 else loaded_records
                        self._progress_callback(f'Loading record information - Users: {users_processed}/{total_users}, Records: {loaded_records}/{total_display}')

                    if not rs.hasMore:
                        has_more = False
                        continue
                    if not rs.continuationToken:
                        raise RuntimeError('Preliminary compliance response indicated more data without a continuation token')
                    token = bytes(rs.continuationToken)
                    if token in seen_tokens:
                        raise RuntimeError('Preliminary compliance response repeated a continuation token')
                    seen_tokens.add(token)
                    continuation_token = token
                    first_response = False
            
            self._save_prelim_to_cache()
        finally:
            if self._progress_callback:
                self._progress_callback('Preliminary compliance data loaded.')
    
    def _fetch_full_compliance_data(self) -> None:
        """Fetch full compliance data including permissions and shared folders or load from cache."""
        if self._is_compliance_cache_fresh():
            if self._load_compliance_from_cache():
                return

        if self._config.no_rebuild:
            logger.warning('No usable compliance cache is available; remote fetch disabled by no_rebuild')
            return
        
        all_record_bytes = [info.record_uid_bytes for info in self._records.values() if info.record_uid_bytes]
        total_records = len(all_record_bytes)
        
        if total_records == 0:
            return
        
        all_user_ids = [u.enterprise_user_id for u in self._enterprise_data.users.get_all_entities()]
        root_node = getattr(self._enterprise_data, 'root_node', None)
        node_id = self._config.node_id if self._config.node_id is not None else getattr(root_node, 'node_id', 0)
        
        batches = [all_record_bytes[i:i + MAX_RECORDS_PER_REQUEST] for i in range(0, total_records, MAX_RECORDS_PER_REQUEST)]
        total_batches = len(batches)

        # Users the preliminary data listed for each record (their owned records),
        # captured before full data adds shared access to the permissions lookup.
        record_uid_by_bytes = {info.record_uid_bytes: uid for uid, info in self._records.items()}
        record_user_ids: Dict[str, Set[int]] = defaultdict(set)
        for (record_uid, user_id) in self._record_permissions:
            record_user_ids[record_uid].add(user_id)
        
        if self._progress_callback:
            self._progress_callback(f'Loading compliance data - Current Batch: 0/{total_batches}')
        
        try:
            for batch_idx, record_batch in enumerate(batches):
                batch_user_ids: Set[int] = set()
                for record_uid_bytes in record_batch:
                    record_uid = record_uid_by_bytes.get(record_uid_bytes)
                    if record_uid is not None:
                        batch_user_ids.update(record_user_ids.get(record_uid, ()))
                user_ids = list(batch_user_ids or set(all_user_ids))
                for user_offset in range(0, len(user_ids), MAX_USERS_PER_REQUEST):
                    user_batch = user_ids[user_offset:user_offset + MAX_USERS_PER_REQUEST]
                    rq = enterprise_pb2.ComplianceReportRequest()
                    rq.saveReport = False
                    rq.reportName = f'Compliance Report on {datetime.datetime.now()}'

                    report_run = rq.complianceReportRun
                    report_run.users.extend(user_batch)
                    report_run.records.extend(record_batch)
                    caf = report_run.reportCriteriaAndFilter
                    caf.nodeId = node_id
                    caf.criteria.includeNonShared = not self._config.shared

                    try:
                        rs = self._auth.execute_auth_rest(
                            'enterprise/run_compliance_report', rq,
                            response_type=enterprise_pb2.ComplianceReportResponse)
                        if rs is None:
                            raise RuntimeError('Compliance report endpoint returned an empty response')
                        self._process_audit_records(rs.auditRecords)
                        self._process_shared_folder_records(rs.sharedFolderRecords)
                        self._process_user_record_permissions(rs.userRecords)
                        self._process_shared_folder_users(rs.sharedFolderUsers)
                        self._process_shared_folder_teams(rs.sharedFolderTeams)
                        self._process_user_profiles(rs.userProfiles)
                    except Exception as e:
                        error_msg = str(e).lower()
                        if 'access_denied' in error_msg or 'no run compliance reports privilege' in error_msg:
                            self._build_permissions_from_enterprise_data()
                            return
                        raise

                if self._progress_callback:
                    pct = ((batch_idx + 1) / total_batches) * 100
                    self._progress_callback(f'Loading compliance data - Current Batch: {batch_idx + 1}/{total_batches} ({pct:.2f}%)')
            
            self._save_compliance_to_cache()
        finally:
            if self._progress_callback:
                self._progress_callback('')
    
    def _build_permissions_from_enterprise_data(self) -> None:
        """Build permissions from vault data when full compliance API isn't available."""
        if self._vault_storage:
            self._extract_shared_folders_from_vault()
    
    def _extract_shared_folders_from_vault(self) -> None:
        """Extract shared folder relationships from vault storage."""
        try:
            storage = self._vault_storage
            folder_records = storage.folder_records.get_all_links()
            
            for link in folder_records:
                folder = storage.folders.get_entity(link.folder_uid)
                if folder and hasattr(folder, 'shared_folder_uid') and folder.shared_folder_uid:
                    if link.record_uid not in self._record_shared_folders:
                        self._record_shared_folders[link.record_uid] = []
                    if folder.shared_folder_uid not in self._record_shared_folders[link.record_uid]:
                        self._record_shared_folders[link.record_uid].append(folder.shared_folder_uid)
        except Exception as e:
            logger.error(f'Error extracting shared folders from vault: {e}')
    
    def _process_audit_records(self, audit_records) -> None:
        """Process audit records to extract trash and attachment flags."""
        for audit_record in audit_records:
            try:
                record_uid = utils.base64_url_encode(audit_record.recordUid)
                if record_uid not in self._records:
                    continue
                
                self._records[record_uid].in_trash = audit_record.inTrash
                self._records[record_uid].has_attachments = audit_record.hasAttachments
                
                if audit_record.auditData:
                    audit_data = self._decrypt_record_data(audit_record.auditData)
                    if audit_data:
                        record = self._records[record_uid]
                        if not record.title:
                            record.title = audit_data.get('title', '')
                        if not record.record_type:
                            record.record_type = audit_data.get('record_type', '') or audit_data.get('type', '')
                        if not record.url:
                            record.url = audit_data.get('url', '')
            except Exception:
                continue
    
    def _process_shared_folder_records(self, sf_records) -> None:
        """Process shared folder record relationships."""
        for folder in sf_records:
            folder_uid = utils.base64_url_encode(folder.sharedFolderUid)
            
            if folder_uid not in self._shared_folders:
                self._shared_folders[folder_uid] = SharedFolderInfo(folder_uid=folder_uid)
            
            for rp in folder.recordPermissions:
                record_uid = utils.base64_url_encode(rp.recordUid)
                self._shared_folders[folder_uid].records[record_uid] = rp.permissionBits
                
                if record_uid not in self._record_shared_folders:
                    self._record_shared_folders[record_uid] = []
                if folder_uid not in self._record_shared_folders[record_uid]:
                    self._record_shared_folders[record_uid].append(folder_uid)
                
                if record_uid in self._records:
                    self._records[record_uid].shared = True
            
            for sar in folder.shareAdminRecords:
                for idx in sar.recordPermissionIndexes:
                    if idx < len(folder.recordPermissions):
                        rp = folder.recordPermissions[idx]
                        record_uid = utils.base64_url_encode(rp.recordUid)
                        self._update_permissions_lookup(record_uid, sar.enterpriseUserId, PERMISSION_SHARE_ADMIN)
        
        logger.debug(f'Processed {len(sf_records)} shared folder records')
    
    def _process_user_record_permissions(self, user_records) -> None:
        """Process direct user permissions on records."""
        permissions_count = 0
        for ur in user_records:
            user_id = ur.enterpriseUserId
            for rp in ur.recordPermissions:
                record_uid = utils.base64_url_encode(rp.recordUid)
                self._update_permissions_lookup(record_uid, user_id, rp.permissionBits)
                permissions_count += 1
        
        logger.debug(f'Processed {permissions_count} user record permissions from {len(user_records)} users')
    
    def _process_shared_folder_users(self, sf_users) -> None:
        """Process users with direct access to shared folders."""
        for sf_user in sf_users:
            folder_uid = utils.base64_url_encode(sf_user.sharedFolderUid)
            if folder_uid not in self._shared_folders:
                continue
            
            folder_records = self._shared_folders[folder_uid].records
            for user_id in sf_user.enterpriseUserIds:
                self._shared_folders[folder_uid].users.add(user_id)
                for record_uid, perm_bits in folder_records.items():
                    self._update_permissions_lookup(record_uid, user_id, perm_bits)
        
        logger.debug(f'Processed {len(sf_users)} shared folder user links')
    
    def _process_shared_folder_teams(self, sf_teams) -> None:
        """Process teams with access to shared folders."""
        for sf_team in sf_teams:
            folder_uid = utils.base64_url_encode(sf_team.sharedFolderUid)
            if folder_uid not in self._shared_folders:
                continue

            # SharedFolderTeam.teamUids is a repeated protobuf field. Older
            # implementations treated it as a scalar teamUid, which raises
            # AttributeError when the compliance endpoint returns team access.
            for team_uid_bytes in sf_team.teamUids:
                team_uid = utils.base64_url_encode(team_uid_bytes)
                self._shared_folders[folder_uid].teams.add(team_uid)

                folder_records = self._shared_folders[folder_uid].records
                team_members = self._team_members.get(team_uid, set())
                for record_uid, perm_bits in folder_records.items():
                    for user_id in team_members:
                        self._update_permissions_lookup(record_uid, user_id, perm_bits)
        
        logger.debug(f'Processed {len(sf_teams)} shared folder team links')

    def _process_user_profiles(self, user_profiles) -> None:
        """Merge user profiles (e.g. from compliance response) into email lookup for external users."""
        for profile in user_profiles:
            try:
                user_id = profile.enterpriseUserId
                email = getattr(profile, 'email', None) or getattr(profile, 'username', '')
                if user_id and email:
                    self._user_id_to_email[user_id] = email if isinstance(email, str) else email.decode('utf-8')
            except Exception:
                continue

    def _build_permissions_lookup(self) -> Dict[Tuple[str, str], str]:
        """Build final permissions lookup from all sources."""
        permissions_lookup = {}
        
        for (record_uid, user_id), permission_bits in self._record_permissions.items():
            email = self._user_id_to_email.get(user_id, '')
            if email:
                permissions_lookup[(record_uid, email)] = permissions_to_string(permission_bits)
        
        return permissions_lookup
    
    def _get_record_shared_folders(self, record_uid: str) -> List[str]:
        """Get list of shared folder UIDs that contain this record."""
        return self._record_shared_folders.get(record_uid, [])

    def _get_shared_folder_name(self, folder_uid: str) -> str:
        """Return the decrypted shared folder name from vault data, or the UID if unknown.

        Vault storage holds the name encrypted with the shared folder key, so only
        ``VaultData`` (which decrypts it) can supply it.
        """
        if self._vault_data is not None:
            try:
                folder = self._vault_data.get_shared_folder(folder_uid)
                if folder is not None and folder.name:
                    return str(folder.name)
            except Exception:
                logger.debug('Unable to resolve shared folder name for %s', folder_uid, exc_info=True)
        return folder_uid
    
    def generate_default_report(self) -> List[ComplianceReportEntry]:
        """Generate default compliance report with record permissions."""
        self._build_user_lookups()
        self._build_user_teams_lookup()
        self._fetch_preliminary_compliance_data()
        self._fetch_full_compliance_data()
        
        filtered_user_ids = None
        if self._config.node_id:
            filtered_user_ids = {u.enterprise_user_id for u in self._enterprise_data.users.get_all_entities() 
                                if u.node_id == self._config.node_id}
        
        permissions_lookup = self._build_permissions_lookup()
        aging_data = self._fetch_aging_data(list(self._records)) if self._config.aging else {}
        entries = []
        
        for record_uid, record_info in self._records.items():
            users_with_access = {user_id for (r_uid, user_id) in self._record_permissions if r_uid == record_uid}
            
            for user_id in users_with_access:
                if filtered_user_ids is not None and user_id not in filtered_user_ids:
                    continue
                
                email = self._user_id_to_email.get(user_id, '')
                if not email:
                    continue
                
                entry = ComplianceReportEntry(
                    record_uid=record_uid,
                    title=record_info.title,
                    record_type=record_info.record_type,
                    username=email,
                    permissions=permissions_lookup.get((record_uid, email), 'read-only'),
                    url=record_info.url,
                    in_trash=record_info.in_trash,
                    shared=record_info.shared,
                    shared_folder_uid=self._get_record_shared_folders(record_uid) or None,
                    created=aging_data.get(record_uid, {}).get('created'),
                    last_pw_change=aging_data.get(record_uid, {}).get('last_pw_change'),
                    last_modified=aging_data.get(record_uid, {}).get('last_modified'),
                    last_rotation=aging_data.get(record_uid, {}).get('last_rotation')
                )

                if self._should_include_entry(entry):
                    entries.append(entry)
        
        return entries
    
    def _should_include_entry(self, entry: ComplianceReportEntry) -> bool:
        """Check if entry should be included based on config filters."""
        config = self._config
        
        if config.username:
            if not any(p.lower() == entry.username.lower() for p in config.username):
                return False
        
        if config.record:
            if not any(p == entry.record_uid or fnmatch.fnmatch(entry.title.lower(), p.lower())
                       for p in config.record):
                return False
        
        if config.url:
            if not any(p.lower() in entry.url.lower() for p in config.url):
                return False
        
        if config.shared and not entry.shared:
            return False
        
        if config.deleted_items and not entry.in_trash:
            return False
        
        if config.active_items and entry.in_trash:
            return False
        
        if config.team:
            team_user_ids = self._get_team_filter_user_ids()
            if team_user_ids is not None:
                if not team_user_ids:
                    return False
                user_id = self._email_to_user_id.get(entry.username.lower())
                if user_id is None or user_id not in team_user_ids:
                    return False
        
        if config.job_title:
            user_id = self._email_to_user_id.get(entry.username.lower())
            if user_id is not None:
                user = next((u for u in self._enterprise_data.users.get_all_entities() 
                            if u.enterprise_user_id == user_id), None)
                if user is None:
                    return False
                job_title = getattr(user, 'job_title', '') or ''
                if not any(jt.lower() in job_title.lower() for jt in config.job_title):
                    return False
        
        return True
    
    def generate_team_report(self) -> List[TeamReportEntry]:
        """Generate team report showing team access to shared folders."""
        self._build_user_lookups()
        self._build_user_teams_lookup()
        self._fetch_preliminary_compliance_data()
        self._fetch_full_compliance_data()
        
        entries = []
        team_names = {team.team_uid: team.name for team in self._enterprise_data.teams.get_all_entities()}
        requested_team_uids = set()
        if self._config.team:
            self._build_user_teams_lookup()
            requested_team_uids = {
                self._team_name_to_uid.get(team_ref.lower(), team_ref)
                for team_ref in self._config.team
            }
        requested_team_users = self._get_team_filter_user_ids() if self._config.team else set()
        
        for folder_uid, folder_info in self._shared_folders.items():
            folder_teams = folder_info.teams
            folder_records = folder_info.records
            
            for team_uid in folder_teams:
                matches_team = not requested_team_uids or team_uid in requested_team_uids
                matches_user = bool(requested_team_users and folder_info.users & requested_team_users)
                if not matches_team and not (self._config.resolve_teams and matches_user):
                    continue
                team_name = team_names.get(team_uid, team_uid)
                
                team_users = None
                if self._config.show_team_users:
                    team_user_ids = self._team_members.get(team_uid, set())
                    team_users = [self._user_id_to_email.get(uid, '') for uid in team_user_ids]
                
                team_permissions = 0
                for record_uid, perm_bits in folder_records.items():
                    team_permissions |= perm_bits
                
                entry = TeamReportEntry(
                    team_name=team_name,
                    team_uid=team_uid,
                    shared_folder_name=self._get_shared_folder_name(folder_uid),
                    shared_folder_uid=folder_uid,
                    permissions=permissions_to_string(team_permissions),
                    records=len(folder_records),
                    team_users=team_users
                )
                entries.append(entry)
        
        return entries
    
    def generate_record_access_report(self, report_type: str = REPORT_TYPE_HISTORY) -> List[RecordAccessReportEntry]:
        """Generate record access report with usage history."""
        self._build_user_lookups()
        self._fetch_preliminary_compliance_data()
        self._fetch_full_compliance_data()
        
        access_events = self._fetch_record_access_events(report_type)
        record_uids = list(self._records.keys())
        aging_data = self._fetch_aging_data(record_uids)
        
        entries = []

        users_by_record: Dict[str, Set[int]] = defaultdict(set)
        for (r_uid, user_id) in self._record_permissions:
            users_by_record[r_uid].add(user_id)
        if report_type == REPORT_TYPE_HISTORY:
            # Historical access can remain reportable after current vault
            # permissions have changed.
            for (email, r_uid) in access_events:
                event_user_id = self._email_to_user_id.get(email)
                if event_user_id is not None:
                    users_by_record[r_uid].add(event_user_id)

        for record_uid, record_info in self._records.items():
            users_with_access = users_by_record.get(record_uid, set())

            for user_id in users_with_access:
                email = self._user_id_to_email.get(user_id, '')
                if not email:
                    continue
                
                if self._config.username:
                    if not any(pattern.lower() in email.lower() for pattern in self._config.username):
                        continue
                
                if report_type == REPORT_TYPE_VAULT:
                    has_direct_access = (record_uid, user_id) in self._record_permissions
                    if not has_direct_access:
                        continue
                
                access_key = (email, record_uid)
                access_event = access_events.get(access_key, {})
                aging_stats = aging_data.get(record_uid, {})
                
                entry = RecordAccessReportEntry(
                    vault_owner=email,
                    record_uid=record_uid,
                    record_title=record_info.title,
                    record_type=record_info.record_type,
                    record_url=record_info.url,
                    has_attachments=record_info.has_attachments,
                    in_trash=record_info.in_trash,
                    record_owner=record_info.owner_email,
                    ip_address=access_event.get('ip_address', '') or '',
                    device=access_event.get('keeper_version', '') or '',
                    last_access=self._ts_to_datetime(access_event.get('last_created')) if access_event else None,
                    created=aging_stats.get('created'),
                    last_pw_change=aging_stats.get('last_pw_change'),
                    last_modified=aging_stats.get('last_modified'),
                    last_rotation=aging_stats.get('last_rotation')
                )
                entries.append(entry)
        
        return entries
    
    def _fetch_aging_data(self, record_uids: List[str]) -> Dict[str, Dict[str, Optional[datetime.datetime]]]:
        """Fetch and cache record lifecycle dates.

        Audit reports are limited to 1000 record UIDs per request.  The cache
        stores zero values as well as real timestamps so records without a
        matching event are not queried on every report.
        """
        if not record_uids:
            return {}
        
        aging_data = {
            r: {
                'created': None,
                'last_pw_change': None,
                'last_modified': None,
                'last_rotation': None
            } for r in record_uids
        }
        
        now = int(datetime.datetime.now().timestamp())
        cache_cutoff = now - int(datetime.timedelta(days=self._config.cache_max_age_days).total_seconds())
        cached = {}
        stale_uids = set(record_uids)
        reused_cache = False
        if self._compliance_storage is not None:
            try:
                for entity in self._compliance_storage.record_aging.get_all_entities():
                    if entity.record_uid not in aging_data:
                        continue
                    cached[entity.record_uid] = {
                        'created': self._ts_to_datetime(entity.created),
                        'last_pw_change': self._ts_to_datetime(entity.last_pw_change),
                        'last_modified': self._ts_to_datetime(entity.last_modified),
                        'last_rotation': self._ts_to_datetime(entity.last_rotation),
                    }
                if self._compliance_storage.records_dated >= cache_cutoff:
                    aging_data.update(cached)
                    stale_uids -= set(cached)
                    reused_cache = bool(cached)
            except Exception:
                logger.debug('Unable to load record aging cache', exc_info=True)

        if stale_uids:
            stale_uid_list = sorted(stale_uids)
            logger.debug('Fetching aging data for %d records...', len(stale_uids))
            aging_configs = {
                'created': {
                    'event_types': [],
                    'aggregate': 'first_created',
                    'order': 'ascending'
                },
                'last_modified': {
                    'event_types': ['record_update'],
                    'aggregate': 'last_created',
                    'order': 'descending'
                },
                'last_rotation': {
                    'event_types': ['record_rotation_scheduled_ok', 'record_rotation_on_demand_ok'],
                    'aggregate': 'last_created',
                    'order': 'descending'
                },
                'last_pw_change': {
                    'event_types': ['record_password_change'],
                    'aggregate': 'last_created',
                    'order': 'descending'
                }
            }
            
            for stat_name, config in aging_configs.items():
                for offset in range(0, len(stale_uid_list), API_EVENT_SUMMARY_ROW_LIMIT):
                    uid_chunk = stale_uid_list[offset:offset + API_EVENT_SUMMARY_ROW_LIMIT]
                    audit_filter: Dict[str, Any] = {'record_uid': uid_chunk}
                    if config['event_types']:
                        audit_filter['audit_event_type'] = config['event_types']
                    request: Dict[str, Any] = {
                        'command': 'get_audit_event_reports', 'scope': 'enterprise',
                        'report_type': 'span', 'filter': audit_filter,
                        'columns': ['record_uid'], 'aggregate': [config['aggregate']],
                        'order': config['order'], 'limit': API_EVENT_SUMMARY_ROW_LIMIT
                    }
                    response = self._auth.execute_auth_command(request)
                    if not isinstance(response, dict):
                        raise RuntimeError('Audit aging endpoint returned an invalid response')
                    for event in response.get('audit_event_overview_report_rows') or []:
                        uid = event.get('record_uid', '')
                        timestamp = event.get(config['aggregate'], 0)
                        if uid in aging_data and timestamp:
                            aging_data[uid][stat_name] = self._ts_to_datetime(timestamp)

            for uid in stale_uids:
                stats = aging_data[uid]
                if stats['last_modified'] is None:
                    stats['last_modified'] = stats['created']
                if stats['last_pw_change'] is None:
                    stats['last_pw_change'] = stats['created']

            if self._compliance_storage is not None:
                entities = []
                for uid in stale_uids:
                    entity = st.StorageRecordAging(record_uid=uid)
                    for field_name in ('created', 'last_pw_change', 'last_modified', 'last_rotation'):
                        value = aging_data[uid][field_name]
                        setattr(entity, field_name, int(value.timestamp()) if value else 0)
                    entities.append(entity)
                self._compliance_storage.record_aging.put_entities(entities)
                # The date covers the whole aging cache. When cached rows were reused,
                # keep their (older) date so they still expire on schedule.
                if not reused_cache:
                    self._compliance_storage.set_records_dated(now)

        return aging_data
    
    def _ts_to_datetime(self, timestamp: Any) -> Optional[datetime.datetime]:
        """Convert timestamp to datetime."""
        if not timestamp:
            return None
        try:
            ts = int(timestamp)
            if ts > 0:
                return datetime.datetime.fromtimestamp(ts)
        except (ValueError, TypeError, OSError):
            pass
        return None
    
    def _fetch_record_access_events(self, report_type: str = 'history') -> Dict[Tuple[str, str], Dict[str, Any]]:
        """Fetch the latest access event for each report user and record.

        Mirrors Commander: users are queried together through ``execute_batch``.
        A response holds at most 1000 aggregate rows, so each query pages backwards
        in time (``created <= created_max``) until it is complete. The vault report
        filters by the user's records (at most 1000 per query) and stops once every
        record has an event.
        """
        access_events: Dict[Tuple[str, str], Dict[str, Any]] = {}
        email_to_user_id = self._email_to_user_id or {}

        records_by_user: Dict[int, List[str]] = defaultdict(list)
        if report_type == REPORT_TYPE_VAULT:
            for (record_uid, user_id) in self._record_permissions:
                records_by_user[user_id].append(record_uid)

        # One query per user, or per user and record chunk for the vault report.
        queries: Dict[Tuple[str, int], Dict[str, Any]] = {}
        for email, user_id in email_to_user_id.items():
            if report_type == REPORT_TYPE_VAULT:
                record_uids = records_by_user.get(user_id, [])
                for index, offset in enumerate(range(0, len(record_uids), API_EVENT_SUMMARY_ROW_LIMIT)):
                    queries[(email, index)] = {
                        'filter_recs': record_uids[offset:offset + API_EVENT_SUMMARY_ROW_LIMIT],
                        'created_max': None}
            else:
                queries[(email, 0)] = {'filter_recs': None, 'created_max': None}

        while queries:
            keys = list(queries)
            requests = [self._record_access_request(email, **queries[(email, index)]) for email, index in keys]
            responses = self._auth.execute_batch(requests)
            if len(responses) != len(requests):
                raise RuntimeError('Record access batch returned an unexpected number of responses')

            next_queries: Dict[Tuple[str, int], Dict[str, Any]] = {}
            for key, response in zip(keys, responses):
                if not isinstance(response, dict) or response.get('result') != 'success':
                    raise errors.KeeperApiError(
                        (response or {}).get('result_code') or 'audit_report_failed',
                        (response or {}).get('message') or 'Record access report request failed')
                email = key[0]
                query = queries[key]
                events = response.get('audit_event_overview_report_rows') or []
                remaining = set(query['filter_recs'] or ())
                for event in events:
                    uid = event.get('record_uid', '')
                    if not uid:
                        continue
                    remaining.discard(uid)
                    # Pages walk backwards in time: keep the first (latest) event.
                    access_events.setdefault((email, uid), {
                        'record_uid': uid,
                        'ip_address': event.get('ip_address', ''),
                        'keeper_version': event.get('keeper_version', ''),
                        'last_created': event.get('last_created', 0)
                    })

                done = len(events) < API_EVENT_SUMMARY_ROW_LIMIT or (query['filter_recs'] is not None and not remaining)
                if done:
                    continue
                created_max = int(events[-1].get('last_created', 0) or 0)
                if not created_max or (query['created_max'] is not None and created_max >= query['created_max']):
                    logger.warning('Record access events for %s did not page backwards; results may be incomplete', email)
                    continue
                next_queries[key] = {
                    'filter_recs': sorted(remaining) if query['filter_recs'] is not None else None,
                    'created_max': created_max}
            queries = next_queries

        logger.debug(f'Total access events fetched: {len(access_events)}')
        return access_events

    @staticmethod
    def _record_access_request(
            email: str, filter_recs: Optional[List[str]] = None, created_max: Optional[int] = None) -> Dict[str, Any]:
        audit_filter: Dict[str, Any] = {'username': email}
        if filter_recs is not None:
            audit_filter['record_uid'] = filter_recs
        if created_max:
            audit_filter['created'] = {'max': created_max}
        return {
            'command': 'get_audit_event_reports', 'scope': 'enterprise',
            'report_type': 'span', 'filter': audit_filter,
            'columns': ['record_uid', 'ip_address', 'keeper_version'],
            'aggregate': ['last_created'],
            'order': 'descending',
            'limit': API_EVENT_SUMMARY_ROW_LIMIT
        }
    
    def generate_summary_report(self) -> List[SummaryReportEntry]:
        """Generate summary statistics report by user."""
        self._build_user_lookups()
        self._fetch_preliminary_compliance_data()
        self._fetch_full_compliance_data()
        
        filtered_user_ids = None
        if self._config.node_id:
            filtered_user_ids = {u.enterprise_user_id for u in self._enterprise_data.users.get_all_entities() 
                                if u.node_id == self._config.node_id}
        
        user_stats = {}
        for user in self._enterprise_data.users.get_all_entities():
            if filtered_user_ids is not None and user.enterprise_user_id not in filtered_user_ids:
                continue
            
            email = self._user_id_to_email.get(user.enterprise_user_id, '')
            if email:
                user_stats[email] = {
                    'total_items': 0,
                    'total_owned': 0,
                    'active_owned': 0,
                    'deleted_owned': 0
                }
        
        for record_uid, record_info in self._records.items():
            owner_email = record_info.owner_email
            owner_user_id = self._email_to_user_id.get(owner_email.lower(), None) if owner_email else None
            in_trash = record_info.in_trash
            
            if filtered_user_ids is not None and owner_user_id not in filtered_user_ids:
                continue
            
            if owner_email and owner_email in user_stats:
                user_stats[owner_email]['total_owned'] += 1
                if in_trash:
                    user_stats[owner_email]['deleted_owned'] += 1
                else:
                    user_stats[owner_email]['active_owned'] += 1
        
            for (r_uid, user_id), _ in self._record_permissions.items():
                if r_uid == record_uid:
                    if filtered_user_ids is not None and user_id not in filtered_user_ids:
                        continue
                    
                    email = self._user_id_to_email.get(user_id, '')
                    if email and email in user_stats:
                        user_stats[email]['total_items'] += 1
        
        entries = []
        for email, stats in user_stats.items():
            entry = SummaryReportEntry(
                email=email,
                total_items=stats['total_items'],
                total_owned=stats['total_owned'],
                active_owned=stats['active_owned'],
                deleted_owned=stats['deleted_owned']
            )
            entries.append(entry)
        
        return entries
    
    def generate_shared_folder_report(self) -> List[SharedFolderReportEntry]:
        """Generate shared folder access details report."""
        self._build_user_lookups()
        self._build_user_teams_lookup()
        self._fetch_preliminary_compliance_data()
        self._fetch_full_compliance_data()
        
        entries = []
        team_names = {team.team_uid: team.name for team in self._enterprise_data.teams.get_all_entities()}
        
        for folder_uid, folder_info in self._shared_folders.items():
            folder_teams = list(folder_info.teams)
            folder_users = list(folder_info.users)
            folder_records = list(folder_info.records.keys())

            if self._config.team:
                requested = self._get_team_filter_user_ids() or set()
                direct_match = bool(set(folder_teams) & {
                    self._team_name_to_uid.get(ref.lower(), ref) for ref in self._config.team
                })
                user_match = bool(requested & set(folder_users))
                if not direct_match and not (self._config.resolve_teams and user_match):
                    continue
            
            emails = []
            
            if self._config.show_team_users:
                for team_uid in folder_teams:
                    team_members = self._team_members.get(team_uid, set())
                    for user_id in team_members:
                        email = self._user_id_to_email.get(user_id, '')
                        if email:
                            emails.append(f'(TU){email}')
            
            for user_id in folder_users:
                email = self._user_id_to_email.get(user_id, '')
                if email:
                    emails.append(email)
            
            teams_list = [team_names.get(uid, uid) for uid in folder_teams] if folder_teams else None
            
            record_titles = []
            if folder_records:
                for rec_uid in folder_records:
                    record = self._records.get(rec_uid)
                    title = record.title if record else ''
                    record_titles.append(title)
            
            entry = SharedFolderReportEntry(
                shared_folder_uid=folder_uid,
                team_uid=folder_teams if folder_teams else None,
                team_name=teams_list,
                record_uid=folder_records if folder_records else None,
                record_title=record_titles if record_titles else None,
                email=emails if emails else None
            )
            entries.append(entry)

        return entries

    def generate_external_shares_report(self, share_type: Optional[str] = None) -> List[List[Any]]:
        if share_type is None:
            share_type = getattr(self._config, 'external_share_type', 'all') or 'all'
        self._build_user_lookups()
        self._build_user_teams_lookup()
        self._fetch_preliminary_compliance_data()
        self._fetch_full_compliance_data()

        enterprise_user_ids = {u.enterprise_user_id for u in self._enterprise_data.users.get_all_entities()}
        all_user_ids = set()
        for (_, user_id) in self._record_permissions:
            all_user_ids.add(user_id)
        for folder_info in self._shared_folders.values():
            all_user_ids.update(folder_info.users)
        external_user_ids = {uid for uid in all_user_ids if (uid >> 32) == 0 or uid not in enterprise_user_ids}

        permissions_lookup = self._build_permissions_lookup()

        def get_direct_shares():
            rec_shares = {}
            for (record_uid, user_id) in self._record_permissions:
                if user_id not in external_user_ids:
                    continue
                if record_uid not in rec_shares:
                    rec_shares[record_uid] = set()
                rec_shares[record_uid].add(user_id)
            return {uid: uids for uid, uids in rec_shares.items() if self._records.get(uid, None) and self._records[uid].shared}

        def get_sf_shares():
            sf_shares = {}
            for folder_uid, folder_info in self._shared_folders.items():
                ext_in_sf = external_user_ids & folder_info.users
                if ext_in_sf:
                    sf_shares[folder_uid] = ext_in_sf
            return sf_shares

        rows = []
        if share_type in ('direct', 'all'):
            direct_shares = get_direct_shares()
            for record_uid, target_ids in direct_shares.items():
                rec = self._records.get(record_uid)
                name = (rec.title or '') if rec else ''
                for target_id in target_ids:
                    email = self._user_id_to_email.get(target_id, '')
                    perms = permissions_lookup.get((record_uid, email), 'read-only')
                    row = [record_uid, name, 'Direct', email, perms]
                    rows.append(row)

        if share_type in ('shared-folder', 'all'):
            sf_shares = get_sf_shares()
            for folder_uid, target_ids in sf_shares.items():
                for target_id in target_ids:
                    email = self._user_id_to_email.get(target_id, '')
                    row = [folder_uid, '', 'Shared Folder', email, '']
                    rows.append(row)

        return rows

    @staticmethod
    def get_headers(report_type: str, show_team_users: bool = False, aging: bool = False) -> List[str]:
        """Get column headers for the specified report type."""
        if report_type == REPORT_TYPE_DEFAULT:
            headers = ['record_uid', 'title', 'record_type', 'username', 'permissions', 'url', 'in_trash', 'shared_folder_uid']
            if aging:
                headers.extend(['created', 'last_pw_change', 'last_modified', 'last_rotation'])
            return headers
        elif report_type == REPORT_TYPE_TEAM:
            headers = ['team_name', 'team_uid', 'shared_folder_name', 'shared_folder_uid', 'permissions', 'records']
            if show_team_users:
                headers.append('team_users')
            return headers
        elif report_type == REPORT_TYPE_RECORD_ACCESS:
            headers = ['vault_owner', 'record_uid', 'record_title', 'record_type', 'record_url', 'has_attachments', 
                       'in_trash', 'record_owner', 'ip_address', 'device', 'last_access']
            if aging:
                headers.extend(['created', 'last_pw_change', 'last_modified', 'last_rotation'])
            return headers
        elif report_type == REPORT_TYPE_SUMMARY:
            return ['email', 'total_items', 'total_owned', 'active_owned', 'deleted_owned']
        elif report_type == REPORT_TYPE_SHARED_FOLDER:
            return ['shared_folder_uid', 'team_uid', 'team_name', 'record_uid', 'record_title', 'email']
        elif report_type == REPORT_TYPE_EXTERNAL_SHARES:
            return ['uid', 'name', 'type', 'shared_to', 'permissions']
        else:
            return []
    
    def generate_report_rows(
        self,
        report_category: str,
        blank_duplicate_uids: bool = False,
        report_type: str = REPORT_TYPE_HISTORY
    ) -> Iterable[List[Any]]:
        """Generate report rows for the specified report category."""
        if report_category == REPORT_TYPE_DEFAULT:
            entries = self.generate_default_report()
            entries.sort(key=lambda e: e.record_uid)
            
            last_record_uid = ''
            for entry in entries:
                display_uid = entry.record_uid
                if blank_duplicate_uids and entry.record_uid == last_record_uid:
                    display_uid = ''
                last_record_uid = entry.record_uid
                
                row = [
                    display_uid,
                    entry.title,
                    entry.record_type,
                    entry.username,
                    entry.permissions,
                    entry.url,
                    entry.in_trash,
                    entry.shared_folder_uid
                ]
                if self._config.aging:
                    row.extend([entry.created or '', entry.last_pw_change or '',
                                entry.last_modified or '', entry.last_rotation or ''])
                yield row
        
        elif report_category == REPORT_TYPE_TEAM:
            entries = self.generate_team_report()
            for entry in entries:
                row = [
                    entry.team_name,
                    entry.team_uid,
                    entry.shared_folder_name,
                    entry.shared_folder_uid,
                    entry.permissions,
                    entry.records
                ]
                if self._config.show_team_users:
                    row.append(entry.team_users)
                yield row
        
        elif report_category == REPORT_TYPE_RECORD_ACCESS:
            include_aging = self._config.aging
            entries = self.generate_record_access_report(report_type=report_type)
            for entry in entries:
                row = [
                    entry.vault_owner or '',
                    entry.record_uid or '',
                    entry.record_title or '',
                    entry.record_type or '',
                    entry.record_url or '',
                    entry.has_attachments if entry.has_attachments is not None else '',
                    entry.in_trash if entry.in_trash is not None else False,
                    entry.record_owner or '',
                    entry.ip_address or '',
                    entry.device or '',
                    entry.last_access if entry.last_access else ''
                ]
                if include_aging:
                    row.extend([
                        entry.created if entry.created else '',
                        entry.last_pw_change if entry.last_pw_change else '',
                        entry.last_modified if entry.last_modified else '',
                        entry.last_rotation if entry.last_rotation else ''
                    ])
                yield row
        
        elif report_category == REPORT_TYPE_SUMMARY:
            entries = self.generate_summary_report()
            for entry in entries:
                yield [
                    entry.email,
                    entry.total_items,
                    entry.total_owned,
                    entry.active_owned,
                    entry.deleted_owned
                ]
        
        elif report_category == REPORT_TYPE_SHARED_FOLDER:
            entries = self.generate_shared_folder_report()
            for entry in entries:
                yield [
                    entry.shared_folder_uid,
                    entry.team_uid,
                    entry.team_name,
                    entry.record_uid,
                    entry.record_title,
                    entry.email
                ]

        elif report_category == REPORT_TYPE_EXTERNAL_SHARES:
            rows = self.generate_external_shares_report()
            for row in rows:
                yield row


def get_preliminary_compliance_data(
    enterprise_data: enterprise_types.IEnterpriseData,
    auth: keeper_auth.KeeperAuth
) -> Dict[str, RecordInfo]:
    """Convenience function to fetch preliminary compliance data.
    
    Args:
        enterprise_data: Enterprise data interface
        auth: Keeper authentication
        
    Returns:
        Dictionary mapping record UIDs to their basic information
    """
    generator = ComplianceReportGenerator(enterprise_data, auth)
    return generator.get_preliminary_records()
