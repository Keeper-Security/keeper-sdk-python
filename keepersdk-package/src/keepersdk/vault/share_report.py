"""Share report functionality for Keeper SDK.

This module provides functionality to generate comprehensive share reports
for records and shared folders in a Keeper vault.

Usage:
    from keepersdk.vault import share_report
    
    config = share_report.ShareReportConfig(
        show_ownership=True,
        verbose=True
    )
    generator = share_report.ShareReportGenerator(vault, enterprise, auth, config)
    entries = generator.generate_records_report()
"""

import dataclasses
import datetime
import logging
from enum import Enum
from typing import Optional, List, Dict, Any, Iterable, Set

logger = logging.getLogger(__name__)

from . import vault_online, vault_data, vault_types, vault_utils, vault_record
from . import share_management_utils
from ..authentication import keeper_auth
from ..enterprise import enterprise_data as enterprise_data_types


class SharePermissionType(Enum):
    """Types of share permissions."""
    USER = 'user'
    TEAM = 'team'
    SHARED_FOLDER = 'shared_folder'


@dataclasses.dataclass
class ShareReportEntry:
    """Represents a single entry in the share report."""
    record_uid: str
    record_title: str
    record_owner: str = ''
    shared_with: str = ''
    shared_with_count: int = 0
    folder_paths: List[str] = dataclasses.field(default_factory=list)
    share_date: Optional[str] = None
    expiration: Optional[datetime.datetime] = None


@dataclasses.dataclass
class SharedFolderReportEntry:
    """Represents a shared folder entry in the report."""
    folder_uid: str
    folder_name: str
    shared_to: str = ''
    permissions: str = ''
    folder_path: str = ''


@dataclasses.dataclass
class ShareSummaryEntry:
    """Represents a summary entry showing shares by target."""
    shared_to: str
    record_count: Optional[int] = None
    shared_folder_count: Optional[int] = None


@dataclasses.dataclass
class ShareReportConfig:
    """Configuration for share report generation.
    
    Attributes:
        record_filter: List of record UIDs or names to filter by
        user_filter: List of user emails or team names to filter by
        container_filter: List of container (folder) UIDs to filter by
        show_ownership: Include record ownership information
        show_share_date: Include share date information (requires enterprise admin)
        folders_only: Generate report for shared folders only (excludes records)
        verbose: Include detailed permission information
        show_team_users: Expand team memberships in the report
    """
    record_filter: Optional[List[str]] = None
    user_filter: Optional[List[str]] = None
    container_filter: Optional[List[str]] = None
    show_ownership: bool = False
    show_share_date: bool = False
    folders_only: bool = False
    verbose: bool = False
    show_team_users: bool = False


@dataclasses.dataclass
class UserPermissionInfo:
    """Information about a user's permission on a record."""
    username: str
    is_owner: bool = False
    is_share_admin: bool = False
    can_share: bool = False
    can_edit: bool = False
    expiration: int = 0


@dataclasses.dataclass
class RecordShareInfo:
    """Share information for a record."""
    record_uid: str
    record_title: str
    folder_paths: List[str]
    user_permissions: List[UserPermissionInfo]
    shared_folder_uids: List[str]


class ShareReportGenerator:
    """Generates share reports for records and shared folders.
    
    This class provides methods to generate detailed reports about record
    and folder sharing within a Keeper vault.
    
    Example:
        >>> config = ShareReportConfig(show_ownership=True, verbose=True)
        >>> generator = ShareReportGenerator(vault, enterprise, auth, config)
        >>> for entry in generator.generate_records_report():
        ...     print(f"{entry.record_title}: shared with {entry.shared_with}")
    """

    def __init__(
        self,
        vault: vault_online.VaultOnline,
        enterprise: Optional[enterprise_data_types.EnterpriseData] = None,
        auth: Optional[keeper_auth.KeeperAuth] = None,
        config: Optional[ShareReportConfig] = None
    ) -> None:
        """Initialize the ShareReportGenerator.
        
        Args:
            vault: The VaultOnline instance providing access to vault data
            enterprise: Optional EnterpriseData for team expansion and share date queries
            auth: Optional KeeperAuth for API calls (defaults to vault.keeper_auth)
            config: Configuration options for report generation
        """
        if vault is None:
            raise ValueError("vault cannot be None")
        self._vault = vault
        self._enterprise = enterprise
        self._auth = auth or vault.keeper_auth
        self._config = config or ShareReportConfig()
        self._share_info_cache: Optional[Dict[str, RecordShareInfo]] = None
        
        # Log vault state for debugging
        logger.debug(f"ShareReportGenerator initialized with vault: shared_folder_count={vault.vault_data.shared_folder_count}")

    @property
    def config(self) -> ShareReportConfig:
        """Get the current report configuration."""
        return self._config

    @property
    def vault(self) -> vault_online.VaultOnline:
        """Get the vault instance."""
        return self._vault
    
    @property
    def current_username(self) -> str:
        """Get the current user's username."""
        return self._auth.auth_context.username

    def generate_shared_folders_report(self) -> List[SharedFolderReportEntry]:
        """Generate a report of shared folders and their permissions.
        
        Returns:
            List of SharedFolderReportEntry objects containing folder share information
        """
        entries: List[SharedFolderReportEntry] = []
        
        # Get all shared folders from vault
        shared_folders_list = list(self._vault.vault_data.shared_folders())
        logger.debug(f"Found {len(shared_folders_list)} shared folders in vault")
        
        for sf_info in shared_folders_list:
            logger.debug(f"Processing shared folder: {sf_info.shared_folder_uid} - {sf_info.name} (users: {sf_info.users}, teams: {sf_info.teams})")
            
            sf = self._vault.vault_data.load_shared_folder(sf_info.shared_folder_uid)
            if not sf:
                logger.debug(f"  Could not load shared folder {sf_info.shared_folder_uid}")
                continue
            
            logger.debug(f"  Loaded shared folder with {len(sf.user_permissions)} user permissions")
            
            folder_path = vault_utils.get_folder_path(self._vault.vault_data, sf.shared_folder_uid)
            
            # Process user permissions
            for perm in sf.user_permissions:
                permissions = self._format_folder_permissions(perm)
                shared_to = perm.name or perm.user_uid
                logger.debug(f"  Permission: user_type={perm.user_type}, user_uid={perm.user_uid}, name={perm.name}, shared_to={shared_to}, permissions={permissions}")
                
                if perm.user_type == vault_types.SharedFolderUserType.Team:
                    shared_to = f'(Team) {shared_to}'
                    
                    # Expand team members if requested
                    if self._config.show_team_users and self._enterprise:
                        team_users = self._get_team_members(perm.user_uid)
                        for member in team_users:
                            entries.append(SharedFolderReportEntry(
                                folder_uid=sf.shared_folder_uid,
                                folder_name=sf.name,
                                shared_to=f'(Team User) {member}',
                                permissions=permissions,
                                folder_path=folder_path
                            ))
                
                entries.append(SharedFolderReportEntry(
                    folder_uid=sf.shared_folder_uid,
                    folder_name=sf.name,
                    shared_to=shared_to,
                    permissions=permissions,
                    folder_path=folder_path
                ))
        
        return entries

    def generate_records_report(self) -> List[ShareReportEntry]:
        """Generate a report of shared records.
        
        Returns:
            List of ShareReportEntry objects containing record share information
        """
        # If specific records are requested, resolve them directly
        if self._config.record_filter:
            record_uids = self._resolve_record_uids(self._config.record_filter)
        else:
            # For general reports, get all records and let API filter
            record_uids = {r.record_uid for r in self._vault.vault_data.records()}
        
        if not record_uids:
            return []
        
        share_info_map = self._fetch_share_info(list(record_uids))
        if not share_info_map:
            return []
        
        entries: List[ShareReportEntry] = []
        
        for uid, share_info in share_info_map.items():
            # Skip records that aren't actually shared (no permissions besides owner)
            non_owner_perms = [p for p in share_info.user_permissions if not p.is_owner]
            if not non_owner_perms and not self._config.record_filter:
                continue
            
            entry = self._build_share_entry(share_info)
            
            # Apply user filter if specified
            if self._config.user_filter:
                user_filter_lower = {u.lower() for u in self._config.user_filter}
                if not self._record_matches_user_filter(share_info, user_filter_lower):
                    continue
            
            entries.append(entry)
        
        return entries

    def generate_summary_report(self) -> List[ShareSummaryEntry]:
        """Generate a summary report showing share counts by target.
        
        This matches the old Commander logic:
        1. Get ALL shared records (both owned by user AND shared with user)
        2. For each record, collect ALL other users who have access
        3. Group by user and count records/shared folders
        
        The report shows: "Who else has access to records that I have access to"
        This includes:
        - Records I own and have shared with others
        - Records others own and have shared with me (shows other recipients)
        
        Returns:
            List of ShareSummaryEntry objects with aggregated share counts
        """
        record_shares: Dict[str, Set[str]] = {}  # user -> set of record UIDs
        sf_shares: Dict[str, Set[str]] = {}      # user -> set of shared folder UIDs
        
        # Step 1: Build shared folder user map AND track sf_shares per user
        sf_user_map: Dict[str, Set[str]] = {}  # SF UID -> users
        sf_records_map: Dict[str, Set[str]] = {}  # SF UID -> records in that folder
        
        for sf_info in self._vault.vault_data.shared_folders():
            sf = self._vault.vault_data.load_shared_folder(sf_info.shared_folder_uid)
            if sf:
                # Get ALL users in this shared folder (including current user for tracking)
                users_in_sf: Set[str] = set()
                for perm in sf.user_permissions:
                    target = perm.name or perm.user_uid
                    if target:
                        users_in_sf.add(target)
                sf_user_map[sf_info.shared_folder_uid] = users_in_sf
                
                # Get records in this shared folder
                folder = self._vault.vault_data.get_folder(sf_info.shared_folder_uid)
                if folder and folder.records:
                    sf_records_map[sf_info.shared_folder_uid] = set(folder.records)
        
        # Step 2: For each shared folder, add its records to each OTHER user's count
        for sf_uid, users in sf_user_map.items():
            records_in_sf = sf_records_map.get(sf_uid, set())
            for target in users:
                if target == self.current_username:
                    continue  # Skip current user
                # Track shared folders per user
                sf_shares.setdefault(target, set()).add(sf_uid)
                # Track records per user via shared folder access
                for record_uid in records_in_sf:
                    record_shares.setdefault(target, set()).add(record_uid)
        
        # Step 3: Get ALL records user has access to and fetch share info
        # This includes both records the user owns AND records shared with the user
        all_record_uids = [r.record_uid for r in self._vault.vault_data.records()]
        
        if all_record_uids:
            share_info_map = self._fetch_share_info(all_record_uids)
            
            for uid, share_info in share_info_map.items():
                # Add ALL users from user_permissions (not just non-owners)
                # This shows everyone who has access to records I can see
                for perm in share_info.user_permissions:
                    target = perm.username
                    # Skip current user only
                    if target == self.current_username:
                        continue
                    record_shares.setdefault(target, set()).add(uid)
        
        # Step 4: Remove current user from results (matches old code lines 1222-1225)
        if self.current_username in record_shares:
            del record_shares[self.current_username]
        if self.current_username in sf_shares:
            del sf_shares[self.current_username]
        
        # Step 5: Build summary entries
        all_targets = set(record_shares.keys()) | set(sf_shares.keys())
        entries: List[ShareSummaryEntry] = []
        
        for target in sorted(all_targets):
            entries.append(ShareSummaryEntry(
                shared_to=target,
                record_count=len(record_shares.get(target, set())) or None,
                shared_folder_count=len(sf_shares.get(target, set())) or None
            ))
        
        return entries

    def generate_report_rows(self) -> Iterable[List[Any]]:
        """Generate report rows suitable for tabular output.
        
        Yields:
            Lists of values representing report rows
        """
        if self._config.folders_only:
            for entry in self.generate_shared_folders_report():
                yield [entry.folder_uid, entry.folder_name, entry.shared_to,
                       entry.permissions, entry.folder_path]
        elif self._config.show_ownership:
            for entry in self.generate_records_report():
                shared_info = entry.shared_with if self._config.verbose else entry.shared_with_count
                yield [entry.record_owner, entry.record_uid, entry.record_title,
                       shared_info, '\n'.join(entry.folder_paths)]
        else:
            for entry in self.generate_summary_report():
                yield [entry.shared_to, entry.record_count, entry.shared_folder_count]

    @staticmethod
    def get_headers(folders_only: bool = False, ownership: bool = False) -> List[str]:
        """Get report headers based on configuration.
        
        Args:
            folders_only: True if generating shared folders report
            ownership: True if generating ownership report
            
        Returns:
            List of header column names
        """
        if folders_only:
            return ['folder_uid', 'folder_name', 'shared_to', 'permissions', 'folder_path']
        if ownership:
            return ['record_owner', 'record_uid', 'record_title', 'shared_with', 'folder_path']
        return ['shared_to', 'records', 'shared_folders']

    def _get_filtered_record_uids(self) -> Set[str]:
        """Get record UIDs based on configured filters.
        
        Returns:
            Set of record UIDs matching the filter criteria
        """
        vault_data_instance = self._vault.vault_data
        
        # If specific records are requested
        if self._config.record_filter:
            return self._resolve_record_uids(self._config.record_filter)
        
        # Default: all shared records (check using IsShared flag)
        all_records = set()
        for record_info in vault_data_instance.records():
            if record_info.flags & vault_record.RecordFlags.IsShared:
                all_records.add(record_info.record_uid)
        
        # Apply container filter if specified
        if self._config.container_filter:
            contained_records = self._get_contained_records(self._config.container_filter)
            all_records = all_records.intersection(contained_records)
        
        return all_records

    def _resolve_record_uids(self, record_refs: List[str]) -> Set[str]:
        """Resolve record names or UIDs to actual UIDs.
        
        Args:
            record_refs: List of record names or UIDs
            
        Returns:
            Set of resolved record UIDs
        """
        result: Set[str] = set()
        vault_data_instance = self._vault.vault_data
        
        for ref in record_refs:
            # Check if it's a direct UID
            record = vault_data_instance.get_record(ref)
            if record:
                result.add(ref)
                continue
            
            # Try to find by title
            for record_info in vault_data_instance.records():
                if record_info.title.lower() == ref.lower():
                    result.add(record_info.record_uid)
                    break
        
        return result

    def _get_contained_records(self, container_refs: List[str]) -> Set[str]:
        """Get all records contained in specified folders.
        
        Args:
            container_refs: List of folder paths or UIDs
            
        Returns:
            Set of record UIDs in the specified containers
        """
        result: Set[str] = set()
        vault_data_instance = self._vault.vault_data
        
        for ref in container_refs:
            folder = vault_data_instance.get_folder(ref)
            if folder:
                result.update(folder.records)
                # Include records from subfolders
                def collect_records(f: vault_types.Folder) -> None:
                    result.update(f.records)
                vault_utils.traverse_folder_tree(vault_data_instance, folder, collect_records)
        
        return result

    def _fetch_share_info(self, record_uids: List[str]) -> Dict[str, RecordShareInfo]:
        """Fetch share information for records using the API.
        
        Args:
            record_uids: List of record UIDs to fetch share info for
            
        Returns:
            Dictionary mapping record UIDs to RecordShareInfo objects
        """
        if not record_uids:
            return {}
        
        result: Dict[str, RecordShareInfo] = {}
        
        try:
            # Fetch raw share data from API
            shares_data = share_management_utils.get_record_shares(
                self._vault, record_uids, is_share_admin=False
            )
            
            if shares_data is None:
                # API returned None - return empty result
                return result
            
            # Process the raw share data
            for share_record in shares_data:
                record_uid = share_record.get('record_uid')
                if not record_uid:
                    continue
                
                # Get record info
                record_info = self._vault.vault_data.get_record(record_uid)
                record_title = record_info.title if record_info else record_uid
                
                # Get folder paths
                folder_paths = []
                folders = vault_utils.get_folders_for_record(self._vault.vault_data, record_uid)
                if folders:
                    for folder in folders:
                        path = vault_utils.get_folder_path(self._vault.vault_data, folder.folder_uid)
                        if path:
                            folder_paths.append(path)
                
                # Process user permissions
                user_permissions: List[UserPermissionInfo] = []
                shares = share_record.get('shares', {})
                for up in shares.get('user_permissions', []):
                    exp = up.get('expiration', 0)
                    if isinstance(exp, str):
                        try:
                            exp = int(exp)
                        except ValueError:
                            exp = 0
                    user_permissions.append(UserPermissionInfo(
                        username=up.get('username', ''),
                        is_owner=up.get('owner', False),
                        is_share_admin=up.get('share_admin', False),
                        can_share=up.get('shareable', False),
                        can_edit=up.get('editable', False),
                        expiration=exp
                    ))
                
                # Get shared folder UIDs
                sf_uids = [sp.get('shared_folder_uid') for sp in shares.get('shared_folder_permissions', [])]
                sf_uids = [uid for uid in sf_uids if uid]
                
                result[record_uid] = RecordShareInfo(
                    record_uid=record_uid,
                    record_title=record_title,
                    folder_paths=folder_paths,
                    user_permissions=user_permissions,
                    shared_folder_uids=sf_uids
                )
                
        except Exception:
            # Continue with whatever result we have
            pass
        
        return result

    def _build_share_entry(self, share_info: RecordShareInfo) -> ShareReportEntry:
        """Build a ShareReportEntry from RecordShareInfo.
        
        Args:
            share_info: The RecordShareInfo to convert
            
        Returns:
            ShareReportEntry containing the share information
        """
        # Get owner info
        owner = ''
        for perm in share_info.user_permissions:
            if perm.is_owner:
                owner = perm.username
                break
        
        # Count non-owner shares
        non_owner_shares = [p for p in share_info.user_permissions if not p.is_owner]
        shared_with_count = len(non_owner_shares)
        
        # Build shared_with info
        if self._config.verbose:
            shared_with = self._format_verbose_permissions(share_info, owner)
        else:
            shared_with = ''
        
        return ShareReportEntry(
            record_uid=share_info.record_uid,
            record_title=share_info.record_title,
            record_owner=owner,
            shared_with=shared_with,
            shared_with_count=shared_with_count,
            folder_paths=share_info.folder_paths
        )

    def _format_verbose_permissions(self, share_info: RecordShareInfo, owner: str) -> str:
        """Format detailed permission information.
        
        Args:
            share_info: The RecordShareInfo to format
            owner: The record owner (may or may not be included based on config)
            
        Returns:
            Formatted string with detailed permissions (usernames only)
        """
        lines: List[str] = []
        
        # Show all users who have access (including owner for record detail view)
        for perm in share_info.user_permissions:
            lines.append(perm.username)
            
            if perm.expiration > 0:
                dt = datetime.datetime.fromtimestamp(perm.expiration // 1000)
                lines.append(f'\t(expires on {dt})')
        
        return '\n'.join(lines)

    def _format_permission_text(self, perm: UserPermissionInfo) -> str:
        """Format permission as text."""
        if perm.can_edit and perm.can_share:
            return 'Can Edit & Share'
        elif perm.can_edit:
            return 'Can Edit'
        elif perm.can_share:
            return 'Can Share'
        else:
            return 'Read Only'

    def _format_folder_permissions(self, perm: vault_types.SharedFolderPermission) -> str:
        """Format shared folder permissions.
        
        Args:
            perm: The SharedFolderPermission object
            
        Returns:
            Formatted permissions string
        """
        if not perm.manage_users and not perm.manage_records:
            return "No User Permissions"
        elif not perm.manage_users and perm.manage_records:
            return "Can Manage Records"
        elif perm.manage_users and not perm.manage_records:
            return "Can Manage Users"
        else:
            return "Can Manage Users & Records"

    def _record_matches_user_filter(self, share_info: RecordShareInfo, user_filter: Set[str]) -> bool:
        """Check if a shared record matches the user filter.
        
        This matches old Commander logic - checks if user has access via:
        1. Direct shares (user_permissions)
        2. Shared folder membership
        
        Args:
            share_info: The RecordShareInfo to check
            user_filter: Set of lowercase user names to match
            
        Returns:
            True if the record has shares matching the filter
        """
        # Check direct shares
        for perm in share_info.user_permissions:
            if perm.username.lower() in user_filter:
                return True
        
        # Check shared folder memberships
        for sf_uid in share_info.shared_folder_uids:
            sf = self._vault.vault_data.load_shared_folder(sf_uid)
            if sf:
                for perm in sf.user_permissions:
                    target = (perm.name or perm.user_uid or '').lower()
                    if target in user_filter:
                        return True
        
        return False

    def _get_team_members(self, team_uid: str) -> List[str]:
        """Get team member usernames.
        
        Args:
            team_uid: The team UID to get members for
            
        Returns:
            List of team member usernames
        """
        if not self._enterprise:
            return []
        
        members: List[str] = []
        
        try:
            for team_user in self._enterprise.team_users.get_all_links():
                if team_user.team_uid == team_uid:
                    user = self._enterprise.users.get_entity(team_user.enterprise_user_id)
                    if user:
                        members.append(user.username)
        except Exception:
            pass
        
        return members


def generate_share_report(
    vault: vault_online.VaultOnline,
    enterprise: Optional[enterprise_data_types.EnterpriseData] = None,
    record_filter: Optional[List[str]] = None,
    user_filter: Optional[List[str]] = None,
    verbose: bool = False
) -> List[ShareReportEntry]:
    """Convenience function to generate a share report.
    
    Args:
        vault: The VaultOnline instance
        enterprise: Optional EnterpriseData for team expansion
        record_filter: Optional list of record UIDs/names to filter
        user_filter: Optional list of user emails to filter
        verbose: Include detailed permission information
        
    Returns:
        List of ShareReportEntry objects
    """
    config = ShareReportConfig(
        record_filter=record_filter,
        user_filter=user_filter,
        verbose=verbose
    )
    return ShareReportGenerator(vault, enterprise, config=config).generate_records_report()


def generate_shared_folders_report(
    vault: vault_online.VaultOnline,
    enterprise: Optional[enterprise_data_types.EnterpriseData] = None,
    show_team_users: bool = False
) -> List[SharedFolderReportEntry]:
    """Convenience function to generate a shared folders report.
    
    Args:
        vault: The VaultOnline instance
        enterprise: Optional EnterpriseData for team member expansion
        show_team_users: Expand team memberships in the report
        
    Returns:
        List of SharedFolderReportEntry objects
    """
    config = ShareReportConfig(
        folders_only=True,
        show_team_users=show_team_users
    )
    return ShareReportGenerator(vault, enterprise, config=config).generate_shared_folders_report()
