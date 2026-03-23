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
from typing import Optional, List, Dict, Any, Iterable, Set, NamedTuple

from . import vault_online, vault_types, vault_utils
from . import share_management_utils
from ..authentication import keeper_auth
from ..enterprise import enterprise_data as enterprise_data_types

_SHARE_DATE_EVENT_TYPES = ['folder_add_record', 'record_add']
_AUDIT_EVENT_LIMIT = 1000
_SHARE_DATE_PAGINATION_MAX = 100
_logger = logging.getLogger(__name__)


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


class SharedFolderMaps(NamedTuple):
    """Maps for shared folder users and records."""
    user_map: Dict[str, Set[str]]
    records_map: Dict[str, Set[str]]


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
            
        Raises:
            ValueError: If vault is None
        """
        if vault is None:
            raise ValueError("vault parameter is required")
        self._vault = vault
        self._enterprise = enterprise
        self._auth = auth or vault.keeper_auth
        self._config = config or ShareReportConfig()
        self._share_info_cache: Optional[Dict[str, RecordShareInfo]] = None

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
        
        for sf_info in self._vault.vault_data.shared_folders():
            sf = self._vault.vault_data.load_shared_folder(sf_info.shared_folder_uid)
            if not sf:
                continue
            
            folder_path = vault_utils.get_folder_path(self._vault.vault_data, sf.shared_folder_uid)
            
            for perm in sf.user_permissions:
                permissions = self._format_folder_permissions(perm)
                shared_to = perm.name or perm.user_uid
                
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
        """Generate a report of shared records."""
        if self._config.record_filter:
            record_uids = self._resolve_record_uids(self._config.record_filter)
        else:
            record_uids = {r.record_uid for r in self._vault.vault_data.records()}
        
        if not record_uids:
            return []
        
        share_info_map = self._fetch_share_info(list(record_uids)) or {}
        entries: List[ShareReportEntry] = []
        processed_uids: Set[str] = set()

        user_filter_lower = (
            {u.lower() for u in self._config.user_filter} if self._config.user_filter else None
        )
        share_date_map: Dict[str, str] = {}
        if self._config.show_share_date and self._auth and self._enterprise:
            sf_records = (
                self._get_shared_folder_records_for_user(user_filter_lower)
                if user_filter_lower is not None
                else self._get_all_shared_folder_records()
            )
            all_uids = set(share_info_map.keys()) | sf_records
            if all_uids:
                share_date_map = self._fetch_share_dates(list(all_uids))

        for uid, share_info in share_info_map.items():
            if not self._should_include_record(share_info):
                continue

            if user_filter_lower and not self._record_matches_user_filter(share_info, user_filter_lower):
                continue

            entries.append(self._build_share_entry(share_info, share_date_map.get(uid)))
            processed_uids.add(uid)

        self._add_shared_folder_records(
            entries, processed_uids, share_info_map, user_filter_lower, share_date_map
        )

        return entries
    
    def _should_include_record(self, share_info: RecordShareInfo) -> bool:
        """Check if a record should be included in the report."""
        non_owner_perms = [p for p in share_info.user_permissions if not p.is_owner]
        has_owner = any(p.is_owner for p in share_info.user_permissions)
        
        if self._config.record_filter:
            return True
        
        if not non_owner_perms:
            return False
        
        return has_owner
    
    def _add_shared_folder_records(
        self,
        entries: List[ShareReportEntry],
        processed_uids: Set[str],
        share_info_map: Dict[str, RecordShareInfo],
        user_filter_lower: Optional[Set[str]],
        share_date_map: Optional[Dict[str, str]] = None
    ) -> None:
        """Add records from shared folders that weren't returned by the share API."""
        should_include = (
            self._config.user_filter or
            self._config.show_ownership or
            not self._config.record_filter
        )

        if not should_include:
            return

        sf_records = (
            self._get_shared_folder_records_for_user(user_filter_lower)
            if user_filter_lower
            else self._get_all_shared_folder_records()
        )
        share_dates = share_date_map or {}

        for record_uid in sf_records:
            if record_uid in processed_uids:
                continue

            record_info = self._vault.vault_data.get_record(record_uid)
            if not record_info:
                continue

            folder_paths = self._get_folder_paths(record_uid)
            owner = self._get_owner_from_share_info(share_info_map, record_uid)

            entries.append(ShareReportEntry(
                record_uid=record_uid,
                record_title=record_info.title,
                record_owner=owner,
                shared_with='',
                shared_with_count=0,
                folder_paths=folder_paths,
                share_date=share_dates.get(record_uid)
            ))
            processed_uids.add(record_uid)
    
    def _get_folder_paths(self, record_uid: str) -> List[str]:
        """Get folder paths for a record."""
        paths = []
        for folder in vault_utils.get_folders_for_record(self._vault.vault_data, record_uid):
            path = vault_utils.get_folder_path(self._vault.vault_data, folder.folder_uid)
            if path:
                paths.append(path)
        return paths
    
    def _get_owner_from_share_info(self, share_info_map: Dict[str, RecordShareInfo], record_uid: str) -> str:
        """Extract owner username from share info if available."""
        if record_uid not in share_info_map:
            return ''
        for perm in share_info_map[record_uid].user_permissions:
            if perm.is_owner:
                return perm.username
        return ''
    
    def _get_all_shared_folder_records(self) -> Set[str]:
        """Get all records in all shared folders."""
        return self._get_shared_folder_records_for_user(None)
    
    def _get_shared_folder_records_for_user(self, user_filter: Optional[Set[str]]) -> Set[str]:
        """Get records in shared folders, optionally filtered by user access."""
        result: Set[str] = set()
        
        for sf_info in self._vault.vault_data.shared_folders():
            if user_filter:
                sf = self._vault.vault_data.load_shared_folder(sf_info.shared_folder_uid)
                if not sf or not self._user_has_sf_access(sf, user_filter):
                    continue
            
            self._collect_folder_records(sf_info.shared_folder_uid, result)
        
        return result
    
    def _user_has_sf_access(self, sf: vault_types.SharedFolder, user_filter: Set[str]) -> bool:
        """Check if any user in the filter has access to the shared folder."""
        for perm in sf.user_permissions:
            target = (perm.name or perm.user_uid or '').lower()
            if target in user_filter:
                return True
        return False
    
    def _collect_folder_records(self, folder_uid: str, result: Set[str]) -> None:
        """Collect all records from a folder and its subfolders."""
        folder = self._vault.vault_data.get_folder(folder_uid)
        if not folder:
            return
        
        result.update(folder.records)
        
        def collect(f: vault_types.Folder) -> None:
            result.update(f.records)
        
        vault_utils.traverse_folder_tree(self._vault.vault_data, folder, collect)

    def generate_summary_report(self) -> List[ShareSummaryEntry]:
        """Generate a summary report showing share counts by target user."""
        record_shares: Dict[str, Set[str]] = {}
        sf_shares: Dict[str, Set[str]] = {}
        
        sf_maps = self._build_shared_folder_maps()
        self._aggregate_shared_folder_access(sf_maps.user_map, sf_maps.records_map, record_shares, sf_shares)
        self._aggregate_direct_shares(record_shares)
        self._remove_current_user(record_shares, sf_shares)
        
        return self._build_summary_entries(record_shares, sf_shares)
    
    def _build_shared_folder_maps(self) -> SharedFolderMaps:
        """Build maps of shared folder users and records.
        
        Returns:
            SharedFolderMaps containing user_map and records_map
        """
        sf_user_map: Dict[str, Set[str]] = {}
        sf_records_map: Dict[str, Set[str]] = {}
        
        for sf_info in self._vault.vault_data.shared_folders():
            sf = self._vault.vault_data.load_shared_folder(sf_info.shared_folder_uid)
            if not sf:
                continue
            
            users_in_sf: Set[str] = set()
            for perm in sf.user_permissions:
                target = perm.name or perm.user_uid
                if target:
                    users_in_sf.add(target)
            sf_user_map[sf_info.shared_folder_uid] = users_in_sf
            
            folder = self._vault.vault_data.get_folder(sf_info.shared_folder_uid)
            if folder and folder.records:
                sf_records_map[sf_info.shared_folder_uid] = set(folder.records)
        
        return SharedFolderMaps(user_map=sf_user_map, records_map=sf_records_map)
    
    def _aggregate_shared_folder_access(
        self,
        sf_user_map: Dict[str, Set[str]],
        sf_records_map: Dict[str, Set[str]],
        record_shares: Dict[str, Set[str]],
        sf_shares: Dict[str, Set[str]]
    ) -> None:
        """Aggregate record and folder counts from shared folder access."""
        for sf_uid, users in sf_user_map.items():
            records_in_sf = sf_records_map.get(sf_uid, set())
            for target in users:
                if target == self.current_username:
                    continue
                sf_shares.setdefault(target, set()).add(sf_uid)
                for record_uid in records_in_sf:
                    record_shares.setdefault(target, set()).add(record_uid)
    
    def _aggregate_direct_shares(self, record_shares: Dict[str, Set[str]]) -> None:
        """Aggregate record counts from direct share permissions."""
        all_record_uids = [r.record_uid for r in self._vault.vault_data.records()]
        if not all_record_uids:
            return
        
        share_info_map = self._fetch_share_info(all_record_uids)
        for uid, share_info in share_info_map.items():
            for perm in share_info.user_permissions:
                if perm.username != self.current_username:
                    record_shares.setdefault(perm.username, set()).add(uid)
    
    def _remove_current_user(
        self,
        record_shares: Dict[str, Set[str]],
        sf_shares: Dict[str, Set[str]]
    ) -> None:
        """Remove current user from share counts."""
        record_shares.pop(self.current_username, None)
        sf_shares.pop(self.current_username, None)
    
    def _build_summary_entries(
        self,
        record_shares: Dict[str, Set[str]],
        sf_shares: Dict[str, Set[str]]
    ) -> List[ShareSummaryEntry]:
        """Build sorted list of summary entries."""
        all_targets = set(record_shares.keys()) | set(sf_shares.keys())
        return [
            ShareSummaryEntry(
                shared_to=target,
                record_count=len(record_shares.get(target, set())) or None,
                shared_folder_count=len(sf_shares.get(target, set())) or None
            )
            for target in sorted(all_targets)
        ]

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
                row = [entry.record_owner, entry.record_uid, entry.record_title,
                       shared_info, '\n'.join(entry.folder_paths)]
                if self._config.show_share_date:
                    row.append(entry.share_date or '')
                yield row
        else:
            for entry in self.generate_summary_report():
                yield [entry.shared_to, entry.record_count, entry.shared_folder_count]

    @staticmethod
    def get_headers(
        folders_only: bool = False,
        ownership: bool = False,
        show_share_date: bool = False
    ) -> List[str]:
        """Get report headers based on configuration.
        
        Args:
            folders_only: True if generating shared folders report
            ownership: True if generating ownership report
            show_share_date: True to include share date column (ownership report only)
            
        Returns:
            List of header column names
        """
        if folders_only:
            return ['folder_uid', 'folder_name', 'shared_to', 'permissions', 'folder_path']
        if ownership:
            headers = ['record_owner', 'record_uid', 'record_title', 'shared_with', 'folder_path']
            if show_share_date:
                headers.append('share_date')
            return headers
        return ['shared_to', 'records', 'shared_folders']

    def _resolve_record_uids(self, record_refs: List[str]) -> Set[str]:
        """Resolve record names or UIDs to actual UIDs."""
        result: Set[str] = set()
        vault_data_instance = self._vault.vault_data
        
        for ref in record_refs:
            record = vault_data_instance.get_record(ref)
            if record:
                result.add(ref)
                continue
            
            for record_info in vault_data_instance.records():
                if record_info.title.lower() == ref.lower():
                    result.add(record_info.record_uid)
                    break
        
        return result

    def _fetch_share_info(self, record_uids: List[str]) -> Dict[str, RecordShareInfo]:
        """Fetch share information for records using the API."""
        if not record_uids:
            return {}
        
        result: Dict[str, RecordShareInfo] = {}
        
        try:
            shares_data = share_management_utils.get_record_shares(
                self._vault,
                record_uids,
                is_share_admin=self._config.show_share_date,
            )
            
            if not shares_data:
                return result
            
            for share_record in shares_data:
                record_uid = share_record.get('record_uid')
                if not record_uid:
                    continue
                
                record_info = self._vault.vault_data.get_record(record_uid)
                shares = share_record.get('shares', {})
                
                result[record_uid] = RecordShareInfo(
                    record_uid=record_uid,
                    record_title=record_info.title if record_info else record_uid,
                    folder_paths=self._get_folder_paths(record_uid),
                    user_permissions=self._parse_user_permissions(shares),
                    shared_folder_uids=[
                        sp.get('shared_folder_uid') 
                        for sp in shares.get('shared_folder_permissions', [])
                        if sp.get('shared_folder_uid')
                    ]
                )
        except Exception:
            pass
        
        return result

    def _fetch_share_dates(self, record_uids: List[str]) -> Dict[str, str]:
        """Fetch earliest share-related audit event date per record (enterprise only).
        Returns dict of record_uid -> formatted date string, or empty if not available.
        """
        if not record_uids or not self._auth or not self._enterprise:
            return {}
        record_uid_set = set(record_uids)
        min_ts: Dict[str, int] = {}
        search_min_ts = int(
            (datetime.datetime.now() - datetime.timedelta(days=365 * 5)).timestamp()
        )
        audit_filter: Dict[str, Any] = {
            'audit_event_type': _SHARE_DATE_EVENT_TYPES,
            'created': {'min': search_min_ts},
            'record_uid': record_uids,
        }
        rq: Dict[str, Any] = {
            'command': 'get_audit_event_reports',
            'scope': 'enterprise',
            'report_type': 'raw',
            'filter': audit_filter,
            'limit': _AUDIT_EVENT_LIMIT,
            'order': 'ascending',
        }
        iterations = 0
        try:
            while iterations < _SHARE_DATE_PAGINATION_MAX:
                iterations += 1
                rs = self._auth.execute_auth_command(rq)
                events = rs.get('audit_event_overview_report_rows') or []
                if not events:
                    break
                for event in events:
                    uid = event.get('record_uid') or ''
                    if uid not in record_uid_set:
                        continue
                    ts = event.get('created')
                    if ts is None:
                        continue
                    try:
                        ts_int = int(ts)
                    except (TypeError, ValueError):
                        continue
                    if uid not in min_ts or ts_int < min_ts[uid]:
                        min_ts[uid] = ts_int
                if len(events) < _AUDIT_EVENT_LIMIT:
                    break
                last_ts = max(int(e.get('created', 0)) for e in events)
                audit_filter['created'] = {'min': last_ts + 1}
        except Exception as e:
            _logger.debug('Failed to fetch share dates from audit: %s', e)
        # Format as date string (created may be Unix seconds or milliseconds)
        result: Dict[str, str] = {}
        for uid, ts in min_ts.items():
            try:
                if ts > 1e12:
                    ts = ts // 1000
                dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
                result[uid] = dt.strftime('%Y-%m-%d %H:%M UTC')
            except (OSError, ValueError):
                result[uid] = str(ts)
        return result

    def _parse_user_permissions(self, shares: Dict) -> List[UserPermissionInfo]:
        """Parse user permissions from share data."""
        permissions = []
        for up in shares.get('user_permissions', []):
            exp = up.get('expiration', 0)
            if isinstance(exp, str):
                try:
                    exp = int(exp)
                except ValueError:
                    exp = 0
            permissions.append(UserPermissionInfo(
                username=up.get('username', ''),
                is_owner=up.get('owner', False),
                is_share_admin=up.get('share_admin', False),
                can_share=up.get('shareable', False),
                can_edit=up.get('editable', False),
                expiration=exp
            ))
        return permissions

    def _build_share_entry(
        self, share_info: RecordShareInfo, share_date: Optional[str] = None
    ) -> ShareReportEntry:
        """Build a ShareReportEntry from RecordShareInfo."""
        owner = self._get_owner_from_share_info({share_info.record_uid: share_info}, share_info.record_uid)
        non_owner_shares = [p for p in share_info.user_permissions if not p.is_owner]

        shared_with = ''
        if self._config.verbose:
            shared_with = self._format_verbose_permissions(share_info)

        return ShareReportEntry(
            record_uid=share_info.record_uid,
            record_title=share_info.record_title,
            record_owner=owner,
            shared_with=shared_with,
            shared_with_count=len(non_owner_shares),
            folder_paths=share_info.folder_paths,
            share_date=share_date
        )

    def _format_verbose_permissions(self, share_info: RecordShareInfo) -> str:
        """Format user permissions as newline-separated usernames."""
        lines: List[str] = []
        for perm in share_info.user_permissions:
            lines.append(perm.username)
            if perm.expiration > 0:
                dt = datetime.datetime.fromtimestamp(perm.expiration // 1000)
                lines.append(f'\t(expires on {dt})')
        return '\n'.join(lines)

    def _format_folder_permissions(self, perm: vault_types.SharedFolderPermission) -> str:
        """Format shared folder permissions as human-readable text."""
        if perm.manage_users and perm.manage_records:
            return "Can Manage Users & Records"
        if perm.manage_records:
            return "Can Manage Records"
        if perm.manage_users:
            return "Can Manage Users"
        return "No User Permissions"

    def _record_matches_user_filter(self, share_info: RecordShareInfo, user_filter: Set[str]) -> bool:
        """Check if user has access via direct shares or shared folder membership."""
        for perm in share_info.user_permissions:
            if perm.username.lower() in user_filter:
                return True
        
        for folder in vault_utils.get_folders_for_record(self._vault.vault_data, share_info.record_uid):
            sf_uid = self._get_shared_folder_uid(folder)
            if sf_uid:
                sf = self._vault.vault_data.load_shared_folder(sf_uid)
                if sf and self._user_has_sf_access(sf, user_filter):
                    return True
        
        return False
    
    def _get_shared_folder_uid(self, folder: vault_types.Folder) -> Optional[str]:
        """Get the shared folder UID for a folder."""
        if folder.folder_type == 'shared_folder':
            return folder.folder_uid
        if folder.folder_type == 'shared_folder_folder' and folder.folder_scope_uid:
            return folder.folder_scope_uid
        return None

    def _get_team_members(self, team_uid: str) -> List[str]:
        """Get team member usernames."""
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
    """Generate a share report for records.
    
    Args:
        vault: The VaultOnline instance (required)
        enterprise: Optional EnterpriseData for team expansion
        record_filter: Optional list of record UIDs or names to filter by
        user_filter: Optional list of user emails to filter by
        verbose: Include detailed permission information
        
    Returns:
        List of ShareReportEntry objects
        
    Raises:
        ValueError: If vault is None
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
    """Generate a report of shared folders and their permissions.
    
    Args:
        vault: The VaultOnline instance (required)
        enterprise: Optional EnterpriseData for team expansion
        show_team_users: Expand team memberships in the report
        
    Returns:
        List of SharedFolderReportEntry objects
        
    Raises:
        ValueError: If vault is None
    """
    config = ShareReportConfig(folders_only=True, show_team_users=show_team_users)
    return ShareReportGenerator(vault, enterprise, config=config).generate_shared_folders_report()
