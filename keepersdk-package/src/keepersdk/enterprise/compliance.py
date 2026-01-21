"""Enterprise compliance report functionality for Keeper SDK."""

import dataclasses
import datetime
import json
import logging
from collections import defaultdict
from typing import Optional, List, Dict, Any, Iterable, Set, Tuple

from ..authentication import keeper_auth
from ..proto import enterprise_pb2
from .. import crypto, utils
from . import enterprise_types


API_EVENT_SUMMARY_ROW_LIMIT = 1000
logger = logging.getLogger(__name__)


# Permission bit masks
PERMISSION_OWNER = 1
PERMISSION_MASK = 2
PERMISSION_EDIT = 4
PERMISSION_SHARE = 8
PERMISSION_SHARE_ADMIN = 16


def permissions_to_string(permission_bits: int) -> str:
    """Convert permission bits to human-readable string.
    
    Args:
        permission_bits: Integer with permission flags
        
    Returns:
        Comma-separated permission string (e.g., "owner,edit,share")
    """
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


@dataclasses.dataclass
class ComplianceReportEntry:
    """Represents a single record entry in the compliance report."""
    record_uid: str
    title: str = ''
    record_type: str = ''
    username: str = ''
    permissions: str = ''
    url: str = ''
    in_trash: bool = False
    shared_folder_uid: Optional[List[str]] = None


@dataclasses.dataclass
class TeamReportEntry:
    """Represents a team's access to shared folders."""
    team_name: str
    team_uid: str
    shared_folder_name: str
    shared_folder_uid: str
    permissions: str
    records: int = 0
    team_users: Optional[List[str]] = None


@dataclasses.dataclass
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


@dataclasses.dataclass
class SummaryReportEntry:
    """Represents summary statistics for a user."""
    email: str
    total_items: int = 0
    total_owned: int = 0
    active_owned: int = 0
    deleted_owned: int = 0


@dataclasses.dataclass
class SharedFolderReportEntry:
    """Represents shared folder access details."""
    shared_folder_uid: str
    team_uid: Optional[List[str]] = None
    team_name: Optional[List[str]] = None
    record_uid: Optional[List[str]] = None
    email: Optional[List[str]] = None


@dataclasses.dataclass
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
    report_type: str = 'history'  # 'history' or 'vault'
    aging: bool = False
    node_id: Optional[int] = None


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
        vault_storage: Optional[Any] = None
    ) -> None:
        self._enterprise_data = enterprise_data
        self._auth = auth
        self._config = config or ComplianceReportConfig()
        self._vault_storage = vault_storage
        self._user_teams: Optional[Dict[int, Set[str]]] = None
        self._records: Dict[str, Dict[str, Any]] = {}
        self._record_shared_folders: Dict[str, List[str]] = {}
        self._shared_folders: Dict[str, Dict[str, Any]] = {}
        self._email_to_user_id: Optional[Dict[str, int]] = None
        self._user_id_to_email: Optional[Dict[int, str]] = None
        self._record_permissions: Dict[Tuple[str, int], int] = {}  # (record_uid, user_id) -> permission_bits
        self._team_members: Dict[str, Set[int]] = {}  # team_uid -> set of user_ids
    
    @property
    def enterprise_data(self) -> enterprise_types.IEnterpriseData:
        return self._enterprise_data
    
    @property
    def config(self) -> ComplianceReportConfig:
        return self._config
    
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
        for team_user in self._enterprise_data.team_users.get_all_links():
            self._user_teams[team_user.enterprise_user_id].add(team_user.team_uid)
            
            # Also build reverse lookup for team members
            if team_user.team_uid not in self._team_members:
                self._team_members[team_user.team_uid] = set()
            self._team_members[team_user.team_uid].add(team_user.enterprise_user_id)
        
        return self._user_teams
    
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
        """Fetch preliminary record data from compliance API.
        
        This gets basic record information (type, URL, title) but not full permissions.
        """
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
                        
                        # Log decrypted data structure for debugging (first record only)
                        if not self._records:
                            logger.debug(f'Sample decrypted record data keys: {list(record_data.keys())}')
                            if record_data:
                                logger.debug(f'Sample record data: title={record_data.get("title")}, '
                                           f'type={record_data.get("record_type")}, '
                                           f'url={record_data.get("url")}, '
                                           f'shared={record.shared}')
                        
                        # Extract shared folder UID if present in decrypted data
                        shared_folder_uid = record_data.get('shared_folder_uid') or record_data.get('folder_uid')
                        if shared_folder_uid and record.shared:
                            # Track record to shared folder relationship
                            if record_uid not in self._record_shared_folders:
                                self._record_shared_folders[record_uid] = []
                            if shared_folder_uid not in self._record_shared_folders[record_uid]:
                                self._record_shared_folders[record_uid].append(shared_folder_uid)
                        
                        # Store record with decrypted data (matching old implementation field names)
                        self._records[record_uid] = {
                            'record_uid': record_uid,
                            'record_uid_bytes': record.recordUid,
                            'owner_email': owner_email,
                            'owner_user_id': user_id,
                            'title': record_data.get('title', ''),
                            'record_type': record_data.get('record_type', ''),  # Fixed: was 'type'
                            'url': record_data.get('url', ''),  # Fixed: was 'login_url'
                            'shared': record.shared,
                            'in_trash': record_data.get('in_trash', False),
                            'has_attachments': record_data.get('has_attachments', False),
                            'shared_folder_uid': shared_folder_uid  # Store folder UID if present
                        }
                        
                        # Owner gets all permissions (matching old implementation)
                        self._update_permissions_lookup(
                            record_uid, 
                            user_id, 
                            PERMISSION_OWNER | PERMISSION_EDIT | PERMISSION_SHARE | PERMISSION_SHARE_ADMIN
                        )
                
                has_more = rs.hasMore and rs.continuationToken
                if has_more:
                    continuation_token = rs.continuationToken
                    
            except Exception as e:
                logger.warning(f'Error fetching preliminary compliance data: {e}')
                break
        
        logger.debug(f'Fetched {len(self._records)} records from preliminary API')
    
    def _fetch_full_compliance_data(self) -> None:
        """Fetch full compliance data including permissions and shared folders.
        
        This API provides:
        - Complete user permissions on records
        - Shared folder relationships
        - Team access to shared folders
        - Share admin permissions
        
        Note: This API requires special compliance privileges. If not available,
        we gracefully continue with limited permission information.
        """
        rq = enterprise_pb2.ComplianceReportRequest()
        
        try:
            logger.debug('Fetching full compliance data from run_compliance_report API...')
            rs = self._auth.execute_auth_rest(
                'enterprise/run_compliance_report',
                rq,
                response_type=enterprise_pb2.ComplianceReportResponse
            )
            
            logger.debug(f'Compliance API returned: {len(rs.sharedFolderRecords)} shared folders, '
                        f'{len(rs.userRecords)} user records, {len(rs.auditTeams)} teams')
            
            # Process shared folder records first
            self._process_shared_folder_records(rs.sharedFolderRecords)
            
            # Process user record permissions
            self._process_user_record_permissions(rs.userRecords)
            
            # Process shared folder users
            self._process_shared_folder_users(rs.sharedFolderUsers)
            
            # Process shared folder teams
            self._process_shared_folder_teams(rs.sharedFolderTeams)
            
            logger.debug(f'Processed full compliance data: {len(self._shared_folders)} shared folders, '
                        f'{len(self._record_permissions)} record permissions')
            
        except Exception as e:
            error_msg = str(e)
            if 'access_denied' in error_msg or 'no run compliance reports privilege' in error_msg:
                logger.info('Full compliance API not available (requires compliance privileges)')
                logger.info('Attempting to use enterprise data for permissions...')
                # Try to extract what we can from enterprise_data
                self._build_permissions_from_enterprise_data()
            else:
                logger.warning(f'Error fetching full compliance data: {e}')
                logger.warning('Continuing with limited permission information')
                import traceback
                logger.debug(traceback.format_exc())
    
    def _build_permissions_from_enterprise_data(self) -> None:
        """Build permissions from enterprise_data when full compliance API isn't available.
        
        This attempts to extract shared folder relationships from vault data if available.
        """
        try:
            # Try to get vault data to extract shared folder relationships
            logger.debug('Attempting to extract shared folder info from vault data...')
            
            if self._vault_storage:
                self._extract_shared_folders_from_vault()
            else:
                logger.debug('Vault storage not provided - shared folder UIDs will be limited')
        except Exception as e:
            logger.debug(f'Error building permissions from enterprise data: {e}')
    
    def _extract_shared_folders_from_vault(self) -> None:
        """Extract shared folder relationships from vault storage.
        
        This is a fallback when run_compliance_report API isn't available.
        Matches the logic from Untitled-5 lines 469-477 (sharedFolderFolderRecords).
        """
        try:
            storage = self._vault_storage
            
            # Get all folder-record links (similar to old code's link processing)
            folder_records = storage.folder_records.get_all_links()
            
            # Build mapping of records to their shared folders
            for link in folder_records:
                record_uid = link.record_uid
                folder_uid = link.folder_uid
                
                # Check if this folder is associated with a shared folder
                folder = storage.folders.get_entity(folder_uid)
                if folder and hasattr(folder, 'shared_folder_uid') and folder.shared_folder_uid:
                    # This record is in a shared folder
                    sf_uid = folder.shared_folder_uid
                    if record_uid not in self._record_shared_folders:
                        self._record_shared_folders[record_uid] = []
                    if sf_uid not in self._record_shared_folders[record_uid]:
                        self._record_shared_folders[record_uid].append(sf_uid)
            
            logger.info(f'Extracted shared folder relationships for {len(self._record_shared_folders)} records from vault')
        except Exception as e:
            logger.debug(f'Error extracting shared folders from vault: {e}')
            import traceback
            logger.debug(traceback.format_exc())
    
    def _process_shared_folder_records(self, sf_records) -> None:
        """Process shared folder record relationships."""
        for folder in sf_records:
            folder_uid = utils.base64_url_encode(folder.sharedFolderUid)
            
            if folder_uid not in self._shared_folders:
                self._shared_folders[folder_uid] = {
                    'folder_uid': folder_uid,
                    'records': {},  # record_uid -> permission_bits
                    'users': set(),
                    'teams': set()
                }
            
            # Store record permissions within this shared folder
            for rp in folder.recordPermissions:
                record_uid = utils.base64_url_encode(rp.recordUid)
                self._shared_folders[folder_uid]['records'][record_uid] = rp.permissionBits
                
                # Track which shared folders contain this record
                if record_uid not in self._record_shared_folders:
                    self._record_shared_folders[record_uid] = []
                if folder_uid not in self._record_shared_folders[record_uid]:
                    self._record_shared_folders[record_uid].append(folder_uid)
            
            # Process share admin records (users with share_admin permission)
            for sar in folder.shareAdminRecords:
                user_id = sar.enterpriseUserId
                # Find which records this share admin has access to
                for idx in sar.recordPermissionIndexes:
                    if idx < len(folder.recordPermissions):
                        rp = folder.recordPermissions[idx]
                        record_uid = utils.base64_url_encode(rp.recordUid)
                        # Share admins get share_admin permission bit (16)
                        self._update_permissions_lookup(record_uid, user_id, PERMISSION_SHARE_ADMIN)
        
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
            user_id = sf_user.enterpriseUserId
            
            if folder_uid in self._shared_folders:
                self._shared_folders[folder_uid]['users'].add(user_id)
                
                # Grant permissions on all records in this folder to this user
                folder_records = self._shared_folders[folder_uid]['records']
                for record_uid, perm_bits in folder_records.items():
                    self._update_permissions_lookup(record_uid, user_id, perm_bits)
        
        logger.debug(f'Processed {len(sf_users)} shared folder user links')
    
    def _process_shared_folder_teams(self, sf_teams) -> None:
        """Process teams with access to shared folders."""
        for sf_team in sf_teams:
            folder_uid = utils.base64_url_encode(sf_team.sharedFolderUid)
            team_uid = utils.base64_url_encode(sf_team.teamUid)
            
            if folder_uid in self._shared_folders:
                self._shared_folders[folder_uid]['teams'].add(team_uid)
                
                # Grant permissions on all records in this folder to all team members
                folder_records = self._shared_folders[folder_uid]['records']
                team_members = self._team_members.get(team_uid, set())
                
                for record_uid, perm_bits in folder_records.items():
                    for user_id in team_members:
                        self._update_permissions_lookup(record_uid, user_id, perm_bits)
        
        logger.debug(f'Processed {len(sf_teams)} shared folder team links')
    
    def _build_permissions_lookup(self) -> Dict[Tuple[str, str], str]:
        """Build final permissions lookup from all sources.
        
        Returns:
            Dict mapping (record_uid, email) to permission string
        """
        permissions_lookup = {}
        
        for (record_uid, user_id), permission_bits in self._record_permissions.items():
            email = self._user_id_to_email.get(user_id, '')
            if email:
                permissions_lookup[(record_uid, email)] = permissions_to_string(permission_bits)
        
        return permissions_lookup
    
    def _get_record_shared_folders(self, record_uid: str) -> List[str]:
        """Get list of shared folder UIDs that contain this record."""
        return self._record_shared_folders.get(record_uid, [])
    
    def generate_default_report(self) -> List[ComplianceReportEntry]:
        """Generate default compliance report with record permissions."""
        self._build_user_lookups()
        self._build_user_teams_lookup()
        
        # Fetch all compliance data
        self._fetch_preliminary_compliance_data()
        self._fetch_full_compliance_data()
        
        # Build final permissions lookup
        permissions_lookup = self._build_permissions_lookup()
        
        # Generate report entries
        entries = []
        for record_uid, record_info in self._records.items():
            # Get all users with access to this record
            users_with_access = set()
            for (r_uid, user_id), _ in self._record_permissions.items():
                if r_uid == record_uid:
                    users_with_access.add(user_id)
            
            # Create entry for each user with access
            for user_id in users_with_access:
                email = self._user_id_to_email.get(user_id, '')
                if not email:
                    continue
                
                permissions = permissions_lookup.get((record_uid, email), 'read-only')
                shared_folders = self._get_record_shared_folders(record_uid)
                
                entry = ComplianceReportEntry(
                    record_uid=record_uid,
                    title=record_info.get('title', ''),
                    record_type=record_info.get('record_type', ''),
                    username=email,
                    permissions=permissions,
                    url=record_info.get('url', ''),
                    in_trash=record_info.get('in_trash', False),
                    shared_folder_uid=shared_folders if shared_folders else None
                )

                # Apply filters
                if self._should_include_entry(entry):
                    entries.append(entry)
        
        logger.info(f'Generated {len(entries)} report entries after filtering')
        return entries
    
    def _should_include_entry(self, entry: ComplianceReportEntry) -> bool:
        """Check if entry should be included based on config filters."""
        config = self._config
        
        # Filter by username
        if config.username:
            match_found = any(pattern.lower() in entry.username.lower() for pattern in config.username)
            if not match_found:
                logger.debug(f'Filtering out {entry.username} - does not match {config.username}')
                return False
            logger.debug(f'Including {entry.username} - matches filter')
        
        # Filter by record UID
        if config.record:
            if not any(pattern in entry.record_uid for pattern in config.record):
                return False
        
        # Filter by URL
        if config.url:
            if not any(pattern.lower() in entry.url.lower() for pattern in config.url):
                return False
        
        # Filter by shared status
        if config.shared and not entry.shared_folder_uid:
            return False
        
        # Filter by trash status
        if config.deleted_items and not entry.in_trash:
            return False
        if config.active_items and entry.in_trash:
            return False
        
        return True
    
    def generate_team_report(self) -> List[TeamReportEntry]:
        """Generate team report showing team access to shared folders."""
        self._build_user_lookups()
        self._build_user_teams_lookup()
        
        # Fetch compliance data
        self._fetch_preliminary_compliance_data()
        self._fetch_full_compliance_data()
        
        entries = []
        
        # Get team names from enterprise data
        team_names = {}
        for team in self._enterprise_data.teams.get_all_entities():
            team_names[team.team_uid] = team.name
        
        # Process each shared folder
        for folder_uid, folder_info in self._shared_folders.items():
            folder_teams = folder_info.get('teams', set())
            folder_records = folder_info.get('records', {})
            
            for team_uid in folder_teams:
                team_name = team_names.get(team_uid, team_uid)
                
                # Get team members if requested
                team_users = None
                if self._config.show_team_users:
                    team_user_ids = self._team_members.get(team_uid, set())
                    team_users = [self._user_id_to_email.get(uid, '') for uid in team_user_ids]
                
                # Aggregate permissions for this team on this folder
                team_permissions = 0
                for record_uid, perm_bits in folder_records.items():
                    team_permissions |= perm_bits
                
                entry = TeamReportEntry(
                    team_name=team_name,
                    team_uid=team_uid,
                    shared_folder_name=folder_uid,  # Would need folder names from vault
                    shared_folder_uid=folder_uid,
                    permissions=permissions_to_string(team_permissions),
                    records=len(folder_records),
                    team_users=team_users
                )
                entries.append(entry)
        
        return entries
    
    def generate_record_access_report(self) -> List[RecordAccessReportEntry]:
        """Generate record access report with usage history."""
        self._build_user_lookups()
        
        # Fetch compliance data
        self._fetch_preliminary_compliance_data()
        self._fetch_full_compliance_data()
        
        # This would require audit log data for access times
        # For now, return basic record information
        entries = []
        
        for record_uid, record_info in self._records.items():
            entry = RecordAccessReportEntry(
                vault_owner=record_info.get('owner_email', ''),
                record_uid=record_uid,
                record_title=record_info.get('title', ''),
                record_type=record_info.get('record_type', ''),
                record_url=record_info.get('url', ''),
                has_attachments=record_info.get('has_attachments'),
                in_trash=record_info.get('in_trash', False),
                record_owner=record_info.get('owner_email', '')
            )
            entries.append(entry)
        
        return entries
    
    def generate_summary_report(self) -> List[SummaryReportEntry]:
        """Generate summary statistics report by user."""
        self._build_user_lookups()
        
        # Fetch compliance data
        self._fetch_preliminary_compliance_data()
        
        # Build statistics per user
        user_stats = defaultdict(lambda: {
            'total_items': 0,
            'total_owned': 0,
            'active_owned': 0,
            'deleted_owned': 0
        })
        
        for record_uid, record_info in self._records.items():
            owner_email = record_info.get('owner_email', '')
            in_trash = record_info.get('in_trash', False)
            
            if owner_email:
                user_stats[owner_email]['total_owned'] += 1
                if in_trash:
                    user_stats[owner_email]['deleted_owned'] += 1
                else:
                    user_stats[owner_email]['active_owned'] += 1
        
            # Count total items each user has access to
            for (r_uid, user_id), _ in self._record_permissions.items():
                if r_uid == record_uid:
                    email = self._user_id_to_email.get(user_id, '')
                    if email:
                        user_stats[email]['total_items'] += 1
        
        # Convert to entries
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
        
        # Fetch compliance data
        self._fetch_preliminary_compliance_data()
        self._fetch_full_compliance_data()
        
        entries = []
        
        # Get team names
        team_names = {}
        for team in self._enterprise_data.teams.get_all_entities():
            team_names[team.team_uid] = team.name
        
        for folder_uid, folder_info in self._shared_folders.items():
            folder_teams = list(folder_info.get('teams', set()))
            folder_users = list(folder_info.get('users', set()))
            folder_records = list(folder_info.get('records', {}).keys())
            
            entry = SharedFolderReportEntry(
                shared_folder_uid=folder_uid,
                team_uid=folder_teams if folder_teams else None,
                team_name=[team_names.get(uid, uid) for uid in folder_teams] if folder_teams else None,
                record_uid=folder_records if folder_records else None,
                email=[self._user_id_to_email.get(uid, '') for uid in folder_users] if folder_users else None
            )
            entries.append(entry)
        
        return entries
    
    @staticmethod
    def get_headers(report_type: str) -> List[str]:
        """Get column headers for the specified report type.
        
        Args:
            report_type: Type of report ('default', 'team', 'record_access', 'summary', 'shared_folder')
            
        Returns:
            List of column header names
        """
        if report_type == 'default':
            return ['record_uid', 'title', 'record_type', 'username', 'permissions', 'url', 'in_trash', 'shared_folder_uid']
        elif report_type == 'team':
            return ['team_name', 'team_uid', 'shared_folder_name', 'shared_folder_uid', 'permissions', 'records', 'team_users']
        elif report_type == 'record_access':
            return ['vault_owner', 'record_uid', 'record_title', 'record_type', 'record_url', 'has_attachments', 
                    'in_trash', 'record_owner', 'ip_address', 'device', 'last_access', 'created', 
                    'last_pw_change', 'last_modified', 'last_rotation']
        elif report_type == 'summary':
            return ['email', 'total_items', 'total_owned', 'active_owned', 'deleted_owned']
        elif report_type == 'shared_folder':
            return ['shared_folder_uid', 'team_uid', 'team_name', 'record_uid', 'email']
        else:
            return []
    
    def generate_report_rows(self, report_type: str, blank_duplicate_uids: bool = False) -> Iterable[List[Any]]:
        """Generate report rows for the specified report type.
        
        Args:
            report_type: Type of report ('default', 'team', 'record_access', 'summary', 'shared_folder')
            blank_duplicate_uids: If True, blank out record UIDs for consecutive duplicate records (for table display)
            
        Yields:
            List of values for each row matching the headers
        """
        if report_type == 'default':
            entries = self.generate_default_report()
            
            # Sort entries by record_uid to group same records together (matching old code)
            entries.sort(key=lambda e: e.record_uid)
            
            last_record_uid = ''
            for entry in entries:
                # Show record UID only on first occurrence if blank_duplicate_uids is True
                display_uid = entry.record_uid
                if blank_duplicate_uids and entry.record_uid == last_record_uid:
                    display_uid = ''
                last_record_uid = entry.record_uid
                
                yield [
                    display_uid,
                    entry.title,
                    entry.record_type,
                    entry.username,
                    entry.permissions,
                    entry.url,
                    entry.in_trash,
                    entry.shared_folder_uid
                ]
        
        elif report_type == 'team':
            entries = self.generate_team_report()
            for entry in entries:
                yield [
                    entry.team_name,
                    entry.team_uid,
                    entry.shared_folder_name,
                    entry.shared_folder_uid,
                    entry.permissions,
                    entry.records,
                    entry.team_users
                ]
        
        elif report_type == 'record_access':
            entries = self.generate_record_access_report()
            for entry in entries:
                yield [
                    entry.vault_owner,
                    entry.record_uid,
                    entry.record_title,
                    entry.record_type,
                    entry.record_url,
                    entry.has_attachments,
                    entry.in_trash,
                    entry.record_owner,
                    entry.ip_address,
                    entry.device,
                    entry.last_access,
                    entry.created,
                    entry.last_pw_change,
                    entry.last_modified,
                    entry.last_rotation
                ]
        
        elif report_type == 'summary':
            entries = self.generate_summary_report()
            for entry in entries:
                yield [
                    entry.email,
                    entry.total_items,
                    entry.total_owned,
                    entry.active_owned,
                    entry.deleted_owned
                ]
        
        elif report_type == 'shared_folder':
            entries = self.generate_shared_folder_report()
            for entry in entries:
                yield [
                    entry.shared_folder_uid,
                    entry.team_uid,
                    entry.team_name,
                    entry.record_uid,
                    entry.email
                ]


# Convenience functions for quick report generation

def get_preliminary_compliance_data(
    enterprise_data: enterprise_types.IEnterpriseData,
    auth: keeper_auth.KeeperAuth
) -> Dict[str, Any]:
    """Convenience function to fetch preliminary compliance data.
    
    Args:
        enterprise_data: Enterprise data interface
        auth: Keeper authentication
        
    Returns:
        Dictionary of records with basic information
    """
    generator = ComplianceReportGenerator(enterprise_data, auth)
    generator._build_user_lookups()
    generator._fetch_preliminary_compliance_data()
    return generator._records
