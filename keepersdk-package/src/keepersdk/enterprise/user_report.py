"""Enterprise user report functionality for Keeper SDK."""

import dataclasses
import datetime
from collections import defaultdict
from typing import Optional, List, Dict, Set, Any, Iterable

from ..authentication import keeper_auth
from . import enterprise_types


API_EVENT_SUMMARY_ROW_LIMIT = 1000
DEFAULT_LOOKBACK_DAYS = 365
LOGIN_EVENT_TYPES = ['login', 'login_console', 'chat_login', 'accept_invitation']


@dataclasses.dataclass
class UserReportEntry:
    """Represents a single user entry in the report."""
    enterprise_user_id: int
    email: str
    full_name: str = ''
    status: str = ''
    transfer_status: str = ''
    node_path: str = ''
    roles: Optional[List[str]] = None
    teams: Optional[List[str]] = None
    tfa_enabled: bool = False
    last_login: Optional[datetime.datetime] = None
    last_login_text: str = ''


@dataclasses.dataclass
class UserReportConfig:
    """Configuration for user report generation."""
    lookback_days: int = DEFAULT_LOOKBACK_DAYS
    include_last_login: bool = True
    include_roles: bool = True
    include_teams: bool = True
    simplified_report: bool = False


class UserReportGenerator:
    """Generates comprehensive user reports for enterprise users."""
    
    def __init__(
        self,
        enterprise_data: enterprise_types.IEnterpriseData,
        auth: keeper_auth.KeeperAuth,
        config: Optional[UserReportConfig] = None
    ) -> None:
        self._enterprise_data = enterprise_data
        self._auth = auth
        self._config = config or UserReportConfig()
        self._user_teams: Optional[Dict[int, Set[str]]] = None
        self._user_roles: Optional[Dict[int, Set[int]]] = None
        self._team_roles: Optional[Dict[str, Set[int]]] = None
        self._last_login_cache: Optional[Dict[str, int]] = None
    
    @property
    def enterprise_data(self) -> enterprise_types.IEnterpriseData:
        return self._enterprise_data
    
    @property
    def config(self) -> UserReportConfig:
        return self._config
    
    def _build_user_teams_lookup(self) -> Dict[int, Set[str]]:
        if self._user_teams is not None:
            return self._user_teams
        
        self._user_teams = defaultdict(set)
        for team_user in self._enterprise_data.team_users.get_all_links():
            self._user_teams[team_user.enterprise_user_id].add(team_user.team_uid)
        return self._user_teams
    
    def _build_user_roles_lookup(self) -> Dict[int, Set[int]]:
        if self._user_roles is not None:
            return self._user_roles
        
        self._user_roles = defaultdict(set)
        for role_user in self._enterprise_data.role_users.get_all_links():
            self._user_roles[role_user.enterprise_user_id].add(role_user.role_id)
        return self._user_roles
    
    def _build_team_roles_lookup(self) -> Dict[str, Set[int]]:
        if self._team_roles is not None:
            return self._team_roles
        
        self._team_roles = defaultdict(set)
        for role_team in self._enterprise_data.role_teams.get_all_links():
            self._team_roles[role_team.team_uid].add(role_team.role_id)
        return self._team_roles
    
    def _get_user_role_ids(self, user_id: int) -> Set[int]:
        """Get all role IDs for a user, including roles inherited from teams."""
        user_roles = self._build_user_roles_lookup()
        user_teams = self._build_user_teams_lookup()
        team_roles = self._build_team_roles_lookup()
        
        role_ids = set(user_roles.get(user_id, set()))
        for team_uid in user_teams.get(user_id, set()):
            role_ids.update(team_roles.get(team_uid, set()))
        
        return role_ids
    
    def _get_user_team_names(self, user_id: int) -> List[str]:
        user_teams = self._build_user_teams_lookup()
        team_names = []
        for team_uid in user_teams.get(user_id, set()):
            team = self._enterprise_data.teams.get_entity(team_uid)
            if team:
                team_names.append(team.name)
        return sorted(team_names, key=str.lower)
    
    def _get_user_role_names(self, user_id: int) -> List[str]:
        role_names = []
        for role_id in self._get_user_role_ids(user_id):
            role = self._enterprise_data.roles.get_entity(role_id)
            if role:
                role_names.append(role.name)
        return sorted(role_names, key=str.lower)
    
    @staticmethod
    def get_node_path(
        enterprise_data: enterprise_types.IEnterpriseData,
        node_id: int,
        omit_root: bool = False
    ) -> str:
        """Get the full path for a node as a backslash-separated string."""
        nodes: List[str] = []
        n_id = node_id
        while isinstance(n_id, int) and n_id > 0:
            node = enterprise_data.nodes.get_entity(n_id)
            if not node:
                break
            n_id = node.parent_id or 0
            if not omit_root or n_id > 0:
                node_name = node.name
                if not node_name and node.node_id == enterprise_data.root_node.node_id:
                    node_name = enterprise_data.enterprise_info.enterprise_name
                nodes.append(node_name)
        nodes.reverse()
        return '\\'.join(nodes)
    
    @staticmethod
    def get_user_status_text(user: enterprise_types.User) -> str:
        if user.status == 'invited':
            return 'Invited'
        if user.lock > 0:
            return 'Locked' if user.lock == 1 else 'Disabled'
        return 'Active'
    
    @staticmethod
    def get_user_transfer_status_text(user: enterprise_types.User) -> str:
        if isinstance(user.account_share_expiration, int) and user.account_share_expiration > 0:
            expire_at = datetime.datetime.fromtimestamp(user.account_share_expiration / 1000.0)
            if expire_at < datetime.datetime.now():
                return 'Blocked'
            return 'Pending Transfer'
        return ''
    
    def _query_last_login(self, usernames: List[str]) -> Dict[str, int]:
        """Query last login timestamps for usernames via audit API."""
        if self._last_login_cache is not None:
            return self._last_login_cache
        
        self._last_login_cache = {}
        if not usernames:
            return self._last_login_cache
        
        report_filter: Dict[str, Any] = {'audit_event_type': LOGIN_EVENT_TYPES}
        
        if self._config.lookback_days > 0:
            from_date = datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(days=self._config.lookback_days)
            report_filter['created'] = {'min': int(from_date.timestamp())}
        
        limit = API_EVENT_SUMMARY_ROW_LIMIT
        remaining = list(usernames)
        
        while remaining:
            batch = remaining[:limit]
            remaining = remaining[limit:]
            report_filter['username'] = batch
            
            rq = {
                'command': 'get_audit_event_reports',
                'report_type': 'span',
                'scope': 'enterprise',
                'aggregate': ['last_created'],
                'columns': ['username'],
                'filter': report_filter,
                'limit': limit
            }
            
            try:
                rs = self._auth.execute_auth_command(rq)
                for row in rs.get('audit_event_overview_report_rows', []):
                    username = row.get('username', '').lower()
                    last_created = row.get('last_created')
                    if username and last_created:
                        self._last_login_cache[username] = int(last_created)
            except Exception:
                pass
        
        return self._last_login_cache
    
    def generate_report(self) -> List[UserReportEntry]:
        """Generate the user report."""
        users = list(self._enterprise_data.users.get_all_entities())
        active_usernames = [u.username.lower() for u in users if u.status == 'active']
        
        last_login_data: Dict[str, int] = {}
        if self._config.include_last_login:
            last_login_data = self._query_last_login(active_usernames)
        
        report_entries: List[UserReportEntry] = []
        
        for user in users:
            entry = UserReportEntry(
                enterprise_user_id=user.enterprise_user_id,
                email=user.username,
                full_name=user.full_name or '',
                status=self.get_user_status_text(user),
                transfer_status=self.get_user_transfer_status_text(user),
                node_path=self.get_node_path(self._enterprise_data, user.node_id, omit_root=True),
                tfa_enabled=user.tfa_enabled
            )
            
            if self._config.include_roles:
                entry.roles = self._get_user_role_names(user.enterprise_user_id)
            
            if self._config.include_teams:
                entry.teams = self._get_user_team_names(user.enterprise_user_id)
            
            if self._config.include_last_login:
                last_login_ts = last_login_data.get(user.username.lower(), 0)
                if last_login_ts:
                    entry.last_login = datetime.datetime.fromtimestamp(last_login_ts, datetime.timezone.utc)
                    entry.last_login_text = str(entry.last_login)
                elif user.status == 'invited':
                    entry.last_login_text = 'N/A'
                elif self._config.lookback_days > 0:
                    entry.last_login_text = f'> {self._config.lookback_days} DAYS AGO'
                else:
                    entry.last_login_text = 'N/A'
            
            report_entries.append(entry)
        
        report_entries.sort(key=lambda x: x.email.lower())
        return report_entries
    
    def generate_report_rows(self) -> Iterable[List[Any]]:
        """Generate report rows suitable for tabular output."""
        simplified = self._config.simplified_report
        
        for entry in self.generate_report():
            if simplified:
                yield [entry.email, entry.full_name, entry.status, entry.transfer_status, entry.last_login_text]
            else:
                yield [
                    entry.email, entry.full_name, entry.status, entry.transfer_status,
                    entry.last_login_text, entry.node_path, entry.roles or [], entry.teams or []
                ]
    
    @staticmethod
    def get_headers(simplified: bool = False) -> List[str]:
        if simplified:
            return ['email', 'name', 'status', 'transfer_status', 'last_login']
        return ['email', 'name', 'status', 'transfer_status', 'last_login', 'node', 'roles', 'teams']


def generate_user_report(
    enterprise_data: enterprise_types.IEnterpriseData,
    auth: keeper_auth.KeeperAuth,
    lookback_days: int = DEFAULT_LOOKBACK_DAYS,
    simplified: bool = False
) -> List[UserReportEntry]:
    """Convenience function to generate a user report."""
    config = UserReportConfig(lookback_days=lookback_days, simplified_report=simplified)
    return UserReportGenerator(enterprise_data, auth, config).generate_report()
