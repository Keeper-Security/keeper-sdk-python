"""Shared records report functionality for Keeper SDK.

This module provides functionality to generate comprehensive reports of shared records
for a logged-in user in a Keeper vault.

Usage:
    from keepersdk.vault import shared_records_report
    
    config = shared_records_report.SharedRecordsReportConfig(
        show_team_users=True,
        all_records=True
    )
    generator = shared_records_report.SharedRecordsReportGenerator(vault, enterprise, auth, config)
    entries = generator.generate_report()
"""

import dataclasses
from typing import Optional, List, Dict, Any, Iterable, Set

from . import vault_online, vault_types, vault_utils, vault_record
from . import share_management_utils
from ..authentication import keeper_auth
from ..enterprise import enterprise_data as enterprise_data_types


# Share types
SHARE_TYPE_DIRECT = 'Direct Share'
SHARE_TYPE_SHARED_FOLDER = 'Share Folder'
SHARE_TYPE_TEAM_FOLDER = 'Share Team Folder'

# Record versions to include
OWNED_RECORD_VERSIONS = (2, 3)
ALL_RECORD_VERSIONS = (0, 1, 2, 3, 5, 6)


@dataclasses.dataclass
class SharedRecordReportEntry:
    """Represents a single entry in the shared records report."""
    record_uid: str
    title: str
    owner: str = ''
    share_type: str = ''
    shared_to: str = ''
    permissions: str = ''
    folder_path: str = ''


@dataclasses.dataclass
class SharedRecordsReportConfig:
    """Configuration for shared records report generation.
    
    Attributes:
        folder_filter: List of folder UIDs or paths to filter by
        show_team_users: Expand team memberships to show individual team members
        all_records: Include all records in vault (not just owned records)
    """
    folder_filter: Optional[List[str]] = None
    show_team_users: bool = False
    all_records: bool = False


class SharedRecordsReportGenerator:
    """Generates shared records reports for a logged-in user.
    
    This class provides methods to generate detailed reports about shared records
    within a Keeper vault, showing who has access to records and through what mechanism.
    
    Example:
        >>> config = SharedRecordsReportConfig(show_team_users=True)
        >>> generator = SharedRecordsReportGenerator(vault, enterprise, auth, config)
        >>> for entry in generator.generate_report():
        ...     print(f"{entry.title}: shared with {entry.shared_to} via {entry.share_type}")
    """

    def __init__(
        self,
        vault: vault_online.VaultOnline,
        enterprise: Optional[enterprise_data_types.EnterpriseData] = None,
        auth: Optional[keeper_auth.KeeperAuth] = None,
        config: Optional[SharedRecordsReportConfig] = None
    ) -> None:
        """Initialize the SharedRecordsReportGenerator.
        
        Args:
            vault: The VaultOnline instance providing access to vault data
            enterprise: Optional EnterpriseData for team expansion
            auth: Optional KeeperAuth for API calls (defaults to vault.keeper_auth)
            config: Configuration options for report generation
        """
        self._vault = vault
        self._enterprise = enterprise
        self._auth = auth or vault.keeper_auth
        self._config = config or SharedRecordsReportConfig()
        self._team_membership: Optional[Dict[str, List[str]]] = None
        self._shares_cache: Dict[str, Dict[str, Any]] = {}

    @property
    def config(self) -> SharedRecordsReportConfig:
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

    @staticmethod
    def permissions_text(
        *,
        can_share: Optional[bool] = None,
        can_edit: Optional[bool] = None,
        can_view: bool = True
    ) -> str:
        """Generate human-readable permissions text.
        
        Args:
            can_share: Whether the user can share the record
            can_edit: Whether the user can edit the record
            can_view: Whether the user can view the record (default True)
            
        Returns:
            Human-readable permission string
        """
        if not can_edit and not can_share:
            return 'Read Only' if can_view else 'Launch Only'
        else:
            privs = [can_share and 'Share', can_edit and 'Edit']
            return f'Can {" & ".join([p for p in privs if p])}'

    def generate_report(self) -> List[SharedRecordReportEntry]:
        """Generate the shared records report.
        
        Returns:
            List of SharedRecordReportEntry objects containing share information
        """
        records = self._get_records_to_report()
        if not records:
            return []

        # Fetch share information for all records
        record_uids = list(records.keys())
        self._fetch_and_cache_shares(record_uids)

        # Build team membership cache if needed
        if self._config.show_team_users:
            self._build_team_membership_cache()

        entries: List[SharedRecordReportEntry] = []
        
        for record_uid, record_info in records.items():
            record_entries = self._process_record_shares(record_uid, record_info)
            entries.extend(record_entries)

        return entries

    def _fetch_and_cache_shares(self, record_uids: List[str]) -> None:
        """Fetch and cache share information for records."""
        shares_data = share_management_utils.get_record_shares(self._vault, record_uids)
        if shares_data:
            for share_record in shares_data:
                record_uid = share_record.get('record_uid')
                if record_uid:
                    self._shares_cache[record_uid] = share_record

    def _get_records_to_report(self) -> Dict[str, Any]:
        """Get records to include in the report based on configuration."""
        records: Dict[str, Any] = {}
        versions = ALL_RECORD_VERSIONS if self._config.all_records else OWNED_RECORD_VERSIONS
        filter_folders: Optional[Set[str]] = None

        if self._config.folder_filter:
            filter_folders = set()
            for folder_name in self._config.folder_filter:
                folder_uids = share_management_utils.get_folder_uids(self._vault, folder_name)
                if folder_uids:
                    for uid in folder_uids:
                        self._traverse_folder_for_records(uid, filter_folders, records, versions)
        else:
            # Get all shared records matching criteria
            for record_info in self._vault.vault_data.records():
                if not (record_info.flags & vault_record.RecordFlags.IsShared):
                    continue
                if record_info.version not in versions:
                    continue
                if not self._config.all_records:
                    # Check if user owns the record
                    if not (record_info.flags & vault_record.RecordFlags.IsOwner):
                        continue
                records[record_info.record_uid] = record_info

        return records

    def _traverse_folder_for_records(
        self,
        folder_uid: str,
        filter_folders: Set[str],
        records: Dict[str, Any],
        versions: tuple
    ) -> None:
        """Traverse a folder tree and collect records."""
        folder = self._vault.vault_data.get_folder(folder_uid)
        if not folder:
            return

        def on_folder(f: vault_types.Folder) -> None:
            filter_folders.add(f.folder_uid)
            for record_uid in f.records:
                if record_uid in records:
                    continue
                record_info = self._vault.vault_data.get_record(record_uid)
                if not record_info:
                    continue
                if not (record_info.flags & vault_record.RecordFlags.IsShared):
                    continue
                if record_info.version not in versions:
                    continue
                if not self._config.all_records:
                    if not (record_info.flags & vault_record.RecordFlags.IsOwner):
                        continue
                records[record_uid] = record_info

        vault_utils.traverse_folder_tree(self._vault.vault_data, folder, on_folder)

    def _build_team_membership_cache(self) -> None:
        """Build cache of team memberships for team expansion."""
        self._team_membership = {}
        
        if self._enterprise is None:
            return

        # Build user lookup
        user_lookup: Dict[int, str] = {}
        for user in self._enterprise.users.get_all_entities():
            if user.status == 'active':
                user_lookup[user.enterprise_user_id] = user.username

        # Build team membership
        for team_user in self._enterprise.team_users.get_all_links():
            team_uid = team_user.team_uid
            enterprise_user_id = team_user.enterprise_user_id
            if enterprise_user_id in user_lookup:
                if team_uid not in self._team_membership:
                    self._team_membership[team_uid] = []
                self._team_membership[team_uid].append(user_lookup[enterprise_user_id])

    def _process_record_shares(self, record_uid: str, record_info: Any) -> List[SharedRecordReportEntry]:
        """Process shares for a single record."""
        entries: List[SharedRecordReportEntry] = []
        
        # Get share info from cache
        shares_data = self._get_record_shares_data(record_uid)
        if not shares_data:
            return entries

        shares = shares_data.get('shares', {})
        owner = self._get_owner_from_shares(shares)
        folder_path = self._get_folder_path(record_uid)

        # Process user permissions (direct shares)
        for up in shares.get('user_permissions', []):
            username = up.get('username')
            if not username:
                continue
            if not self._config.all_records and username == self.current_username:
                continue

            permission = self.permissions_text(
                can_share=up.get('shareable'),
                can_edit=up.get('editable')
            )
            
            entries.append(SharedRecordReportEntry(
                record_uid=record_uid,
                title=record_info.title,
                owner=owner,
                share_type=SHARE_TYPE_DIRECT,
                shared_to=username,
                permissions=permission,
                folder_path=folder_path
            ))

        # Process shared folder permissions
        for sfp in shares.get('shared_folder_permissions', []):
            shared_folder_uid = sfp.get('shared_folder_uid')
            can_share = sfp.get('reshareable')
            can_edit = sfp.get('editable')
            base_permission = self.permissions_text(can_share=can_share, can_edit=can_edit)

            sf = self._vault.vault_data.load_shared_folder(shared_folder_uid)
            if sf:
                sf_folder_path = vault_utils.get_folder_path(self._vault.vault_data, shared_folder_uid)
                
                # Process users in shared folder
                for perm in sf.user_permissions:
                    if perm.user_type == vault_types.SharedFolderUserType.User:
                        username = perm.name or perm.user_uid
                        if not self._config.all_records and username == self.current_username:
                            continue
                        
                        entries.append(SharedRecordReportEntry(
                            record_uid=record_uid,
                            title=record_info.title,
                            owner=owner,
                            share_type=SHARE_TYPE_SHARED_FOLDER,
                            shared_to=username,
                            permissions=base_permission,
                            folder_path=sf_folder_path
                        ))
                    
                    elif perm.user_type == vault_types.SharedFolderUserType.Team:
                        team_uid = perm.user_uid
                        team_name = perm.name or team_uid
                        
                        # Calculate team-specific permissions
                        team_permission = self._get_team_permission(team_uid, can_share, can_edit)
                        
                        # Expand team members if requested
                        if self._team_membership and team_uid in self._team_membership:
                            for member in self._team_membership[team_uid]:
                                entries.append(SharedRecordReportEntry(
                                    record_uid=record_uid,
                                    title=record_info.title,
                                    owner=owner,
                                    share_type=SHARE_TYPE_TEAM_FOLDER,
                                    shared_to=f'({team_name}) {member}',
                                    permissions=team_permission,
                                    folder_path=sf_folder_path
                                ))
                        else:
                            entries.append(SharedRecordReportEntry(
                                record_uid=record_uid,
                                title=record_info.title,
                                owner=owner,
                                share_type=SHARE_TYPE_TEAM_FOLDER,
                                shared_to=team_name,
                                permissions=team_permission,
                                folder_path=sf_folder_path
                            ))
            else:
                # Shared folder not accessible
                entries.append(SharedRecordReportEntry(
                    record_uid=record_uid,
                    title=record_info.title,
                    owner=owner,
                    share_type=SHARE_TYPE_SHARED_FOLDER,
                    shared_to='***',
                    permissions=base_permission,
                    folder_path=shared_folder_uid
                ))

        return entries

    def _get_record_shares_data(self, record_uid: str) -> Optional[Dict[str, Any]]:
        """Get cached share data for a record."""
        return self._shares_cache.get(record_uid)

    def _get_owner_from_shares(self, shares: Dict) -> str:
        """Extract owner username from share data."""
        for up in shares.get('user_permissions', []):
            if up.get('owner') is True:
                return up.get('username', '')
        return ''

    def _get_folder_path(self, record_uid: str) -> str:
        """Get folder path(s) for a record."""
        paths: List[str] = []
        for folder in vault_utils.get_folders_for_record(self._vault.vault_data, record_uid):
            path = vault_utils.get_folder_path(self._vault.vault_data, folder.folder_uid)
            if path:
                paths.append(path)
        return '\n'.join(paths)

    def _get_team_permission(
        self,
        team_uid: str,
        can_share: Optional[bool],
        can_edit: Optional[bool]
    ) -> str:
        """Calculate team-specific permissions considering team restrictions."""
        # Try to get team restrictions from vault cache
        team = None
        for t_info in self._vault.vault_data.teams():
            if t_info.team_uid == team_uid:
                team = self._vault.vault_data.load_team(team_uid)
                break
        
        if team:
            return self.permissions_text(
                can_share=can_share and not team.restrict_share,
                can_edit=can_edit and not team.restrict_edit,
                can_view=not team.restrict_view
            )
        
        return self.permissions_text(can_share=can_share, can_edit=can_edit)

    def generate_report_rows(self) -> Iterable[List[Any]]:
        """Generate report rows suitable for tabular output.
        
        Yields:
            Lists of values representing report rows
        """
        for entry in self.generate_report():
            if self._config.all_records:
                yield [entry.owner, entry.record_uid, entry.title, entry.share_type,
                       entry.shared_to, entry.permissions, entry.folder_path]
            else:
                yield [entry.record_uid, entry.title, entry.share_type,
                       entry.shared_to, entry.permissions, entry.folder_path]

    @staticmethod
    def get_headers(all_records: bool = False) -> List[str]:
        """Get report headers based on configuration.
        
        Args:
            all_records: True if reporting on all records (includes owner column)
            
        Returns:
            List of header column names
        """
        if all_records:
            return ['owner', 'record_uid', 'title', 'share_type', 'shared_to', 'permissions', 'folder_path']
        return ['record_uid', 'title', 'share_type', 'shared_to', 'permissions', 'folder_path']


def generate_shared_records_report(
    vault: vault_online.VaultOnline,
    enterprise: Optional[enterprise_data_types.EnterpriseData] = None,
    folder_filter: Optional[List[str]] = None,
    show_team_users: bool = False,
    all_records: bool = False
) -> List[SharedRecordReportEntry]:
    """Convenience function to generate a shared records report.
    
    Args:
        vault: The VaultOnline instance
        enterprise: Optional EnterpriseData for team expansion
        folder_filter: Optional list of folder UIDs/paths to filter by
        show_team_users: Expand team memberships
        all_records: Include all records (not just owned)
        
    Returns:
        List of SharedRecordReportEntry objects
    """
    config = SharedRecordsReportConfig(
        folder_filter=folder_filter,
        show_team_users=show_team_users,
        all_records=all_records
    )
    return SharedRecordsReportGenerator(vault, enterprise, config=config).generate_report()

