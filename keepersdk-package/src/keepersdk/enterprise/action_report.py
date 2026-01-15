"""Enterprise action report functionality for Keeper SDK."""

import dataclasses
import datetime
import logging
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional, Set, Tuple

from ..authentication import keeper_auth
from . import enterprise_types

API_EVENT_SUMMARY_ROW_LIMIT = 2000
DEFAULT_DAYS_SINCE = 30
LOCKED_DEFAULT_DAYS = 90

logger = logging.getLogger(__name__)


class TargetUserStatus:
    NO_LOGON = 'no-logon'
    NO_UPDATE = 'no-update'
    LOCKED = 'locked'
    INVITED = 'invited'
    NO_RECOVERY = 'no-recovery'


class AdminAction:
    NONE = 'none'
    LOCK = 'lock'
    DELETE = 'delete'
    TRANSFER = 'transfer'


STATUS_EVENT_TYPES: Dict[str, List[str]] = {
    TargetUserStatus.NO_LOGON: ['login', 'login_console', 'chat_login', 'accept_invitation'],
    TargetUserStatus.NO_UPDATE: ['record_add', 'record_update'],
    TargetUserStatus.LOCKED: ['lock_user'],
    TargetUserStatus.INVITED: ['send_invitation', 'auto_invite_user'],
    TargetUserStatus.NO_RECOVERY: ['change_security_question', 'account_recovery_setup'],
}


@dataclasses.dataclass
class ActionReportEntry:
    enterprise_user_id: int
    email: str
    full_name: str = ''
    status: str = ''
    transfer_status: str = ''
    node_path: str = ''
    roles: Optional[List[str]] = None
    teams: Optional[List[str]] = None
    tfa_enabled: bool = False


@dataclasses.dataclass
class ActionReportConfig:
    target_user_status: str = TargetUserStatus.NO_LOGON
    days_since: Optional[int] = None
    node_name: Optional[str] = None
    apply_action: str = AdminAction.NONE
    target_user: Optional[str] = None
    dry_run: bool = False
    force: bool = False


@dataclasses.dataclass
class ActionResult:
    action: str
    status: str
    affected_count: int = 0
    server_message: str = 'n/a'
    
    def to_text(self) -> str:
        return (f'\tCOMMAND: {self.action}\n'
                f'\tSTATUS: {self.status}\n'
                f'\tSERVER MESSAGE: {self.server_message}\n'
                f'\tAFFECTED: {self.affected_count}')


class ActionReportGenerator:
    def __init__(
        self,
        enterprise_data: enterprise_types.IEnterpriseData,
        auth: keeper_auth.KeeperAuth,
        config: Optional[ActionReportConfig] = None
    ) -> None:
        self._enterprise_data = enterprise_data
        self._auth = auth
        self._config = config or ActionReportConfig()
        self._user_teams: Optional[Dict[int, Set[str]]] = None
        self._user_roles: Optional[Dict[int, Set[int]]] = None
        self._team_roles: Optional[Dict[str, Set[int]]] = None
        self._node_children: Optional[Dict[int, Set[int]]] = None
    
    @property
    def enterprise_data(self) -> enterprise_types.IEnterpriseData:
        return self._enterprise_data
    
    @property
    def config(self) -> ActionReportConfig:
        return self._config
    
    def _get_days_since(self) -> int:
        if self._config.days_since is not None:
            return self._config.days_since
        if self._config.target_user_status == TargetUserStatus.LOCKED:
            return LOCKED_DEFAULT_DAYS
        return DEFAULT_DAYS_SINCE
    
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
    
    def _build_node_children_lookup(self) -> Dict[int, Set[int]]:
        if self._node_children is not None:
            return self._node_children
        
        self._node_children = defaultdict(set)
        for node in self._enterprise_data.nodes.get_all_entities():
            if node.parent_id:
                self._node_children[node.parent_id].add(node.node_id)
        return self._node_children
    
    def _get_descendant_nodes(self, node_id: int) -> Set[int]:
        children_lookup = self._build_node_children_lookup()
        descendants = {node_id}
        queue = deque([node_id])
        
        while queue:
            current_id = queue.popleft()
            child_ids = children_lookup.get(current_id, set())
            for child_id in child_ids:
                if child_id not in descendants:
                    descendants.add(child_id)
                    queue.append(child_id)
        
        return descendants
    
    def _resolve_node(self, node_name: str) -> Optional[enterprise_types.Node]:
        if not node_name:
            return None
        
        if node_name.isnumeric():
            node = self._enterprise_data.nodes.get_entity(int(node_name))
            if node:
                return node
        
        node_name_lower = node_name.lower()
        if node_name_lower == self._enterprise_data.enterprise_info.enterprise_name.lower():
            return self._enterprise_data.root_node
        
        matching_nodes = [
            n for n in self._enterprise_data.nodes.get_all_entities()
            if n.name and n.name.lower() == node_name_lower
        ]
        
        if len(matching_nodes) == 1:
            return matching_nodes[0]
        elif len(matching_nodes) > 1:
            logger.warning(f'More than one node "{node_name}" found. Use Node ID.')
            return None
        
        return None
    
    def _get_user_role_ids(self, user_id: int) -> Set[int]:
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
        transfer_status = user.transfer_acceptance_status
        if transfer_status is not None:
            status_map = {1: '', 2: 'Not accepted', 3: 'Partially accepted', 4: 'Transfer accepted'}
            if transfer_status in status_map:
                return status_map[transfer_status]
        
        if isinstance(user.account_share_expiration, int) and user.account_share_expiration > 0:
            expire_at = datetime.datetime.fromtimestamp(user.account_share_expiration / 1000.0)
            if expire_at < datetime.datetime.now():
                return 'Blocked'
            return 'Pending Transfer'
        return ''
    
    def _get_users_by_status(self) -> Tuple[List[enterprise_types.User], List[enterprise_types.User], List[enterprise_types.User]]:
        active = []
        locked = []
        invited = []
        
        for user in self._enterprise_data.users.get_all_entities():
            if user.status == 'invited':
                invited.append(user)
            elif user.status == 'active':
                if user.lock > 0:
                    locked.append(user)
                else:
                    active.append(user)
        
        return active, locked, invited
    
    def _filter_users_by_node(self, users: List[enterprise_types.User]) -> List[enterprise_types.User]:
        node_name = self._config.node_name
        if not node_name:
            return users
        
        node = self._resolve_node(node_name)
        if not node:
            logger.warning(f'Node "{node_name}" not found')
            return []
        
        target_nodes = self._get_descendant_nodes(node.node_id)
        return [u for u in users if u.node_id in target_nodes]
    
    def _query_users_with_events(
        self,
        usernames: Set[str],
        event_types: List[str],
        days_since: int,
        username_field: str = 'username'
    ) -> Set[str]:
        if not usernames:
            return set()
        
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        min_dt = now - datetime.timedelta(days=days_since)
        
        users_with_events: Set[str] = set()
        limit = API_EVENT_SUMMARY_ROW_LIMIT
        username_list = list(usernames)
        
        while username_list:
            batch = username_list[:limit]
            username_list = username_list[limit:]
            
            report_filter: Dict[str, Any] = {
                'audit_event_type': event_types,
                'created': {'min': int(min_dt.timestamp())},
                username_field: batch
            }
            
            rq = {
                'command': 'get_audit_event_reports',
                'report_type': 'span',
                'scope': 'enterprise',
                'aggregate': ['last_created'],
                'columns': [username_field],
                'filter': report_filter,
                'limit': limit
            }
            
            try:
                rs = self._auth.execute_auth_command(rq)
                for event in rs.get('audit_event_overview_report_rows', []):
                    username = event.get(username_field, '').lower()
                    if username:
                        users_with_events.add(username)
            except Exception as e:
                logger.debug(f'Error querying audit events: {e}')
        
        return users_with_events
    
    def _get_target_users(self) -> List[enterprise_types.User]:
        active, locked, invited = self._get_users_by_status()
        active = self._filter_users_by_node(active)
        locked = self._filter_users_by_node(locked)
        invited = self._filter_users_by_node(invited)
        
        target_status = self._config.target_user_status
        days_since = self._get_days_since()
        
        if target_status == TargetUserStatus.NO_LOGON:
            candidates = active
            event_types = STATUS_EVENT_TYPES[TargetUserStatus.NO_LOGON]
            username_field = 'username'
        elif target_status == TargetUserStatus.NO_UPDATE:
            candidates = active
            event_types = STATUS_EVENT_TYPES[TargetUserStatus.NO_UPDATE]
            username_field = 'username'
        elif target_status == TargetUserStatus.LOCKED:
            candidates = locked
            event_types = STATUS_EVENT_TYPES[TargetUserStatus.LOCKED]
            username_field = 'to_username'
        elif target_status == TargetUserStatus.INVITED:
            candidates = invited
            event_types = STATUS_EVENT_TYPES[TargetUserStatus.INVITED]
            username_field = 'email'
        elif target_status == TargetUserStatus.NO_RECOVERY:
            candidates = active
            event_types = STATUS_EVENT_TYPES[TargetUserStatus.NO_RECOVERY]
            username_field = 'username'
        else:
            logger.warning(f'Invalid target_user_status: {target_status}')
            return []
        
        if not candidates:
            return []
        
        candidate_usernames = {u.username.lower() for u in candidates}
        users_with_actions = self._query_users_with_events(
            candidate_usernames, event_types, days_since, username_field
        )
        return [u for u in candidates if u.username.lower() not in users_with_actions]
    
    def generate_report(self) -> List[ActionReportEntry]:
        target_users = self._get_target_users()
        
        report_entries: List[ActionReportEntry] = []
        
        for user in target_users:
            entry = ActionReportEntry(
                enterprise_user_id=user.enterprise_user_id,
                email=user.username,
                full_name=user.full_name or '',
                status=self.get_user_status_text(user),
                transfer_status=self.get_user_transfer_status_text(user),
                node_path=self.get_node_path(self._enterprise_data, user.node_id, omit_root=False),
                tfa_enabled=user.tfa_enabled
            )
            
            entry.roles = self._get_user_role_names(user.enterprise_user_id)
            entry.teams = self._get_user_team_names(user.enterprise_user_id)
            
            report_entries.append(entry)
        
        report_entries.sort(key=lambda x: x.email.lower())
        return report_entries
    
    @staticmethod
    def get_allowed_actions(target_status: str) -> Set[str]:
        default_allowed = {AdminAction.NONE}
        
        status_actions = {
            TargetUserStatus.NO_LOGON: {*default_allowed, AdminAction.LOCK},
            TargetUserStatus.NO_UPDATE: default_allowed,
            TargetUserStatus.LOCKED: {*default_allowed, AdminAction.DELETE, AdminAction.TRANSFER},
            TargetUserStatus.INVITED: {*default_allowed, AdminAction.DELETE},
            TargetUserStatus.NO_RECOVERY: default_allowed,
        }
        
        return status_actions.get(target_status, default_allowed)
