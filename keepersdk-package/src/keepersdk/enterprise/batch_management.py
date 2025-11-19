import enum
import ipaddress
import json
from typing import Optional, Dict, Tuple, Any, List, Set, Iterable

from . import enterprise_types, enterprise_management, enterprise_constants
from .. import utils, crypto
from ..authentication import keeper_auth
from ..proto import enterprise_pb2, record_pb2


class _NilLogger(enterprise_management.IEnterpriseManagementLogger):
    def warning(self, message: str) -> None:
        pass


class UserAction(enum.Flag):
    Lock = enum.auto()
    Unlock = enum.auto()
    ExtendTransfer = enum.auto()
    ExpirePassword = enum.auto()
    DisableTfa = enum.auto()


class EntityAction(int, enum.Enum):
    Add = enum.auto()
    Update = enum.auto()
    Remove = enum.auto()


class BatchManagement(enterprise_management.IEnterpriseManagement):
    def __init__(self,
                 loader: enterprise_types.IEnterpriseLoader,
                 logger: enterprise_management.IEnterpriseManagementLogger):
        self.loader = loader
        self.logger = logger or _NilLogger()
        self._record_types: Optional[Dict[str, Tuple[int, record_pb2.RecordTypeScope]]] = None
        self._nodes: Optional[Dict[int, Tuple[EntityAction, enterprise_management.NodeEdit, int]]] = None
        self.task_no: int = 0
        self._roles: Optional[Dict[int, Tuple[EntityAction, enterprise_management.RoleEdit]]] = None
        self._teams: Optional[Dict[str, Tuple[EntityAction, enterprise_management.TeamEdit]]] = None
        self._users: Optional[Dict[int, Tuple[EntityAction, enterprise_management.UserEdit]]] = None
        self._user_actions: Optional[Dict[int, UserAction]] = None
        self._team_users: Optional[Dict[str, Tuple[EntityAction, enterprise_management.TeamUserEdit]]] = None
        self._role_users: Optional[Dict[str, Tuple[EntityAction, enterprise_management.RoleUserEdit]]] = None
        self._role_teams: Optional[Dict[str, Tuple[EntityAction, enterprise_management.RoleTeamEdit]]] = None
        self._managed_nodes: Optional[Dict[str, Tuple[EntityAction, enterprise_management.ManagedNodeEdit]]] = None
        self._role_enforcements: Optional[Dict[str, Tuple[EntityAction, enterprise_management.RoleEnforcementEdit]]] = None

        self._team_keys: Optional[Dict[str, keeper_auth.UserKeys]] = None
        self._role_keys: Optional[Dict[int, bytes]] = None

    def _is_valid_node_id(self, node_id: Any) -> bool:
        if isinstance(node_id, int):
            n = self.loader.enterprise_data.nodes.get_entity(node_id)
            if n:
                return True
            if self._nodes:
                return node_id in self._nodes
        return False

    def _is_valid_role_id(self, role_id: Any) -> bool:
        if isinstance(role_id, int):
            n = self.loader.enterprise_data.roles.get_entity(role_id)
            if n:
                return True
            if self._roles:
                return role_id in self._roles
        return False

    def _is_valid_team_uid(self, team_uid: Any) -> bool:
        if isinstance(team_uid, str):
            t = self.loader.enterprise_data.teams.get_entity(team_uid)
            if t:
                return True
            qt = self.loader.enterprise_data.queued_teams.get_entity(team_uid)
            if qt:
                return True
        return False

    def modify_nodes(self, *,
                     to_add: Optional[Iterable[enterprise_management.NodeEdit]]=None,
                     to_update: Optional[Iterable[enterprise_management.NodeEdit]] = None,
                     to_remove: Optional[Iterable[enterprise_management.NodeEdit]] = None,
                     ) -> None:
        enterprise_data = self.loader.enterprise_data

        n: Optional[enterprise_types.Node]
        node: enterprise_management.NodeEdit

        for node_list, action in ((to_add, EntityAction.Add), (to_update, EntityAction.Update), (to_remove, EntityAction.Remove)):
            if node_list is None:
                continue
            if self._nodes is None:
                self._nodes = {}
            for node in node_list:
                if not node.node_id or not isinstance(node.node_id, int):
                    node_name = node.name or node.node_id or ''
                    self.logger.warning(f'Node {action.name}: Node \"{node_name}\" has invalid node ID')
                    continue
                n = enterprise_data.nodes.get_entity(node.node_id)
                if n is not None:
                    if action == EntityAction.Add:
                        self.logger.warning(f'Node {action.name}: Node ID {node.node_id} already exists')
                        continue
                else:
                    if action == EntityAction.Update:
                        self.logger.warning(f'Node {action.name}: Node ID {node.node_id} does not exist')
                        continue
                    elif action == EntityAction.Add:
                        if not node.name:
                            self.logger.warning(f'Node {action.name}: Node ID {node.node_id}: Node name is required')
                    elif action == EntityAction.Remove:
                        if node.node_id in self._nodes:
                            del self._nodes[node.node_id]
                        else:
                            self.logger.warning(f'Node {action.name}: Node ID {node.node_id} does not exist')
                        continue
                if action in {EntityAction.Update, EntityAction.Add} and node.parent_id:
                    if not self._is_valid_node_id(node.parent_id):
                        self.logger.warning(f'Node {action.name}: Node ID {node.node_id}: Parent Node ID {node.parent_id} is invalid')
                        continue
                self.task_no += 1
                self._nodes[node.node_id] = (action, node, self.task_no)

    def modify_roles(self, *,
                     to_add: Optional[Iterable[enterprise_management.RoleEdit]]=None,
                     to_update: Optional[Iterable[enterprise_management.RoleEdit]] = None,
                     to_remove: Optional[Iterable[enterprise_management.RoleEdit]] = None) -> None:
        enterprise_data = self.loader.enterprise_data

        r: Optional[enterprise_types.Role]
        role: enterprise_management.RoleEdit
        for role_list, action in ((to_add, EntityAction.Add), (to_update, EntityAction.Update), (to_remove, EntityAction.Remove)):
            if role_list is None:
                continue
            if self._roles is None:
                self._roles = {}

            for role in role_list:
                r = enterprise_data.roles.get_entity(role.role_id)
                if r:
                    if action == EntityAction.Add:
                        self.logger.warning(f'Role {action.name}: Role ID {role.role_id} already exists')
                        continue
                else:
                    if action == EntityAction.Update:
                        self.logger.warning(f'Role {action.name}: Role ID {role.role_id} does not exist')
                        continue
                    elif action == EntityAction.Remove:
                        if role.role_id in self._roles:
                            del self._roles[role.role_id]
                        else:
                            self.logger.warning(f'Role {action.name}: Role ID {role.role_id} does not exist')
                            continue
                if role.node_id and not self._is_valid_node_id(role.node_id):
                    self.logger.warning(f'Role {action.name}: Role ID {role.role_id} has invalid node')
                    continue

                self._roles[role.role_id] = (action, role)

    def modify_teams(self, *,
                     to_add: Optional[Iterable[enterprise_management.TeamEdit]]=None,
                     to_update: Optional[Iterable[enterprise_management.TeamEdit]] = None,
                     to_remove: Optional[Iterable[enterprise_management.TeamEdit]] = None) -> None:
        enterprise_data = self.loader.enterprise_data

        t: Optional[enterprise_types.Team]
        team: enterprise_management.TeamEdit
        for team_list, action in ((to_add, EntityAction.Add), (to_update, EntityAction.Update), (to_remove, EntityAction.Remove)):
            if team_list is None:
                continue
            if self._teams is None:
                self._teams = {}
            for team in team_list:
                t = enterprise_data.teams.get_entity(team.team_uid)
                if t:
                    if action == EntityAction.Add:
                        self.logger.warning(f'Team {action.name}: Team UID {team.team_uid} already exists')
                        continue
                else:
                    if action == EntityAction.Update:
                        self.logger.warning(f'Team {action.name}: Team UID {team.team_uid} does not exist')
                        continue
                    elif action == EntityAction.Remove:
                        if team.team_uid in self._teams:
                            del self._teams[team.team_uid]
                        else:
                            self.logger.warning(f'Team {action.name}: Team UID {team.team_uid} does not exist')
                            continue
                if action == EntityAction.Add and not team.name:
                    self.logger.warning(f'Team {action.name}: Team UID {team.team_uid} name cannot be empty')
                    continue
                if team.node_id and not self._is_valid_node_id(team.node_id):
                    self.logger.warning(f'Role {action.name}: Team UID {team.team_uid} has invalid node')
                    continue

                self._teams[team.team_uid] = (action, team)

    def modify_users(self, *,
                     to_add: Optional[Iterable[enterprise_management.UserEdit]] = None,
                     to_update: Optional[Iterable[enterprise_management.UserEdit]] = None,
                     to_remove: Optional[Iterable[enterprise_management.UserEdit]] = None) -> None:
        enterprise_data = self.loader.enterprise_data

        u: Optional[enterprise_types.User]
        user: enterprise_management.UserEdit
        for user_list, action in ((to_add, EntityAction.Add), (to_update, EntityAction.Update), (to_remove, EntityAction.Remove)):
            if not user_list:
                continue
            if self._users is None:
                self._users = {}
            for user in user_list:
                u = enterprise_data.users.get_entity(user.enterprise_user_id)
                if action == EntityAction.Add:
                    if u:
                        self.logger.warning(f'User {action.name}: Team UID {user.enterprise_user_id} already exists')
                        continue
                    if not user.username:
                        self.logger.warning(f'User {action.name}: Team UID {user.enterprise_user_id} email cannot be empty')
                        continue
                else:
                    if not u:
                        self.logger.warning(f'User {action.name}: User ID {user.enterprise_user_id} does not exist')
                        continue

                if action in (EntityAction.Add, EntityAction.Update):
                    if user.node_id and not self._is_valid_node_id(user.node_id):
                        self.logger.warning(f'Role {EntityAction.Update}: User ID {user.enterprise_user_id} has invalid node')
                        continue

                self._users[user.enterprise_user_id] = (action, user)

    def user_actions(self, *,
                     to_lock: Optional[Iterable[int]] = None,
                     to_unlock: Optional[Iterable[int]] = None,
                     to_extend_transfer: Optional[Iterable[int]] = None,
                     to_expire_password: Optional[Iterable[int]] = None,
                     to_disable_tfa: Optional[Iterable[int]] = None) -> None:
        enterprise_data = self.loader.enterprise_data

        u: Optional[enterprise_types.User]
        for user_list, user_action in ((to_lock, UserAction.Lock), (to_unlock, UserAction.Unlock),
                                       (to_extend_transfer, UserAction.ExtendTransfer),
                                       (to_expire_password, UserAction.ExpirePassword),
                                       (to_disable_tfa, UserAction.DisableTfa)):
            if user_list is None:
                continue
            if self._user_actions is None:
                self._user_actions = {}
            for enterprise_user_id in user_list:
                u = enterprise_data.users.get_entity(enterprise_user_id)
                if u:
                    action = self._user_actions.get(enterprise_user_id) or UserAction(0)
                    action |= user_action
                    self._user_actions[enterprise_user_id] = action
                else:
                    self.logger.warning(f'User {user_action.name}: User ID {enterprise_user_id} does not exist')

    def modify_team_users(self, *,
                          to_add: Optional[Iterable[enterprise_management.TeamUserEdit]]=None,
                          to_remove: Optional[Iterable[enterprise_management.TeamUserEdit]] = None) -> None:
        enterprise_data = self.loader.enterprise_data

        team_user: enterprise_management.TeamUserEdit
        for team_user_list, action in ((to_add, EntityAction.Add), (to_remove, EntityAction.Remove)):
            if team_user_list is None:
                continue
            if self._team_users is None:
                self._team_users = {}
            for team_user in team_user_list:
                team_uid = team_user.team_uid
                team_exists = enterprise_data.teams.get_entity(team_uid) is not None
                if not team_exists:
                    team_exists = isinstance(self._teams, dict) and team_uid in self._teams
                if not team_exists:
                    self.logger.warning(f'Team-User {action.name}: Team UID {team_uid} does not exist')
                    continue

                enterprise_user_id = team_user.enterprise_user_id
                user_exists = enterprise_data.users.get_entity(enterprise_user_id) is not None
                if not user_exists:
                    user_exists = isinstance(self._users, dict) and enterprise_user_id in self._users
                if not user_exists:
                    self.logger.warning(f'Team-User {action.name}: User ID {enterprise_user_id} does not exist')
                    continue
                self._team_users[f'{team_uid}|{enterprise_user_id}'] = (action, team_user)

    def modify_role_users(self, *,
                          to_add: Optional[Iterable[enterprise_management.RoleUserEdit]]=None,
                          to_remove: Optional[Iterable[enterprise_management.RoleUserEdit]] = None) -> None:
        enterprise_data = self.loader.enterprise_data

        u: Optional[enterprise_types.User]
        role_user: enterprise_management.RoleUserEdit
        for role_user_list, action in ((to_add, EntityAction.Add), (to_remove, EntityAction.Remove)):
            if role_user_list is None:
                continue
            if self._role_users is None:
                self._role_users = {}

            for role_user in role_user_list:
                role_id = role_user.role_id
                role_exists = enterprise_data.roles.get_entity(role_id) is not None
                if not role_exists:
                    role_exists = isinstance(self._roles, dict) and role_id in self._roles
                if not role_exists:
                    self.logger.warning(f'Role-User {action.name}: Role ID {role_id} does not exist')
                    continue

                enterprise_user_id = role_user.enterprise_user_id
                u = enterprise_data.users.get_entity(enterprise_user_id)
                if u is None:
                    self.logger.warning(f'Role-User {action.name}: User ID {enterprise_user_id} does not exist')
                    continue
                self._role_users[f'{role_id}|{enterprise_user_id}'] = (action, role_user)

    def modify_role_teams(self, *,
                          to_add: Optional[Iterable[enterprise_management.RoleTeamEdit]] = None,
                          to_remove: Optional[Iterable[enterprise_management.RoleTeamEdit]] = None) -> None:
        enterprise_data = self.loader.enterprise_data

        role_team: enterprise_management.RoleTeamEdit
        for role_team_list, action in ((to_add, EntityAction.Add), (to_remove, EntityAction.Remove)):
            if role_team_list is None:
                continue
            if self._role_teams is None:
                self._role_teams = {}
            for role_team in role_team_list:
                role_id = role_team.role_id
                role_exists = enterprise_data.roles.get_entity(role_id) is not None
                if not role_exists:
                    role_exists = isinstance(self._roles, dict) and role_id in self._roles
                if not role_exists:
                    self.logger.warning(f'Role-Team {action.name}: Role ID {role_id} does not exist')
                    continue

                team_uid = role_team.team_uid
                team_exists = enterprise_data.teams.get_entity(team_uid) is not None
                if not team_exists:
                    team_exists = isinstance(self._teams, dict) and team_uid in self._teams
                if not team_exists:
                    self.logger.warning(f'Role-Team {action.name}: Team UID {team_uid} does not exist')
                    continue
                self._role_teams[f'{role_id}|{team_uid}'] = (action, role_team)

    def modify_managed_nodes(self, *,
                             to_add: Optional[Iterable[enterprise_management.ManagedNodeEdit]] = None,
                             to_update: Optional[Iterable[enterprise_management.ManagedNodeEdit]] = None,
                             to_remove: Optional[Iterable[enterprise_management.ManagedNodeEdit]] = None) -> None:
        enterprise_data = self.loader.enterprise_data

        mn: Optional[enterprise_types.ManagedNode]
        managed_node: enterprise_management.ManagedNodeEdit
        for mn_list, action in ((to_add, EntityAction.Add), (to_update, EntityAction.Update), (to_remove, EntityAction.Remove)):
            if mn_list is None:
                continue
            self._managed_nodes = {}
            for managed_node in mn_list:
                role_id = managed_node.role_id
                role_exists = enterprise_data.roles.get_entity(role_id) is not None
                if not role_exists:
                    role_exists = isinstance(self._roles, dict) and role_id in self._roles
                if not role_exists:
                    self.logger.warning(f'Managed Node {action.name}: Role ID {role_id} does not exist')
                    continue
                node_id = managed_node.managed_node_id
                node_exists = enterprise_data.nodes.get_entity(node_id) is not None
                if not node_exists:
                    node_exists = isinstance(self._nodes, dict) and node_id in self._nodes
                if not node_exists:
                    self.logger.warning(f'Managed Node {action.name}: Node ID {node_id} does not exist')
                    continue

                mn = enterprise_data.managed_nodes.get_link(role_id, node_id)
                key = f'{role_id}|{node_id}'
                if mn:
                    if action == EntityAction.Add:
                        self.logger.warning(f'Managed Node {action.name}: {key} already exists')
                        continue
                else:
                    if action == EntityAction.Update:
                        self.logger.warning(f'Managed Node {action.name}: {key} does not exist')
                        continue
                    elif action == EntityAction.Remove:
                        if key in self._managed_nodes:
                            del self._managed_nodes[key]
                        else:
                            self.logger.warning(f'Managed Node {action.name}: {key} does not exist')
                        continue

                self._managed_nodes[key] = (action, managed_node)

    def modify_role_enforcements(self, *,
                                 enforcements: Optional[Iterable[enterprise_management.RoleEnforcementEdit]] = None
                                 ) -> None:
        enterprise_data = self.loader.enterprise_data
        if enforcements is not None:
            if self._role_enforcements is None:
                self._role_enforcements = {}

            role_enforcement: enterprise_management.RoleEnforcementEdit
            for role_enforcement in enforcements:
                role_id = role_enforcement.role_id
                role_exists = enterprise_data.roles.get_entity(role_id) is not None
                if not role_exists:
                    role_exists = isinstance(self._roles, dict) and role_id in self._roles
                if not role_exists:
                    self.logger.warning(f'Role Enforcement: Role ID {role_id} does not exist')
                    continue

                enforcement_name = role_enforcement.name.lower()
                enforcement_type = enterprise_constants.ENFORCEMENTS.get(enforcement_name)
                if enforcement_type is None:
                    self.logger.warning(f'Role Enforcement: Enforcement {enforcement_name} does not exist')
                    continue

                ee = enterprise_data.role_enforcements.get_link(role_id, enforcement_name)
                key = f'{role_id}|{enforcement_name}'
                if ee is None:
                    if role_enforcement.value:
                        self._role_enforcements[key] = (EntityAction.Add, role_enforcement)
                    else:
                        if role_enforcement.value:
                            self._role_enforcements[key] = (EntityAction.Update, role_enforcement)
                        else:
                            self._role_enforcements[key] = (EntityAction.Remove, role_enforcement)

    @staticmethod
    def fix_data(d: bytes) -> bytes:
        idx = d.rfind(b'}')
        if idx < len(d) - 1:
            d = d[:idx+1]
        return d

    def decrypt_encrypted_data(self, existing_data: str, key_type: str) -> Dict[str, Any]:
        if not existing_data:
            return {}
        if key_type == 'no_key':
            return {'display_name': existing_data}
        try:
            encrypted_data = utils.base64_url_decode(existing_data)
            if key_type == 'encrypted_by_data_key':
                tree_key = self.loader.enterprise_data.enterprise_info.tree_key
                data = crypto.decrypt_aes_v1(encrypted_data, tree_key)
            else:
                raise Exception(f'Unsupported key type: {key_type}')
            data_json = self.fix_data(data)
            return json.loads(data_json.decode('utf-8'))
        except Exception:
            return {}

    def _to_node_requests(self) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        add_requests: List[Dict[str, Any]] = []
        remove_requests: List[Dict[str, Any]] = []
        if self._nodes:
            enterprise_data = self.loader.enterprise_data
            tree_key = enterprise_data.enterprise_info.tree_key

            nodes = list(self._nodes.values())
            nodes.sort(key=lambda x: x[2])
            for action, node, _ in nodes:
                try:
                    if action == EntityAction.Add and not node.parent_id:
                        node.parent_id = enterprise_data.root_node.node_id
                    rq = {
                        'command': 'node_' + ('add' if action == EntityAction.Add else 'update' if action == EntityAction.Update else 'delete'),
                        'node_id': node.node_id,
                    }
                    if action == EntityAction.Add or action == EntityAction.Update:
                        if isinstance(node.parent_id, int):
                            rq['parent_id'] = node.parent_id
                        existing_node: Optional[enterprise_types.Node]
                        existing_node = enterprise_data.nodes.get_entity(node.node_id) if action == EntityAction.Update else None
                        if isinstance(node.name, str) and len(node.name) > 0:
                            data: Dict[str, Any] = {}
                            if action == EntityAction.Update:
                                if existing_node is not None and existing_node.encrypted_data:
                                    data.update(
                                        self.decrypt_encrypted_data(existing_node.encrypted_data, key_type='encrypted_by_data_key'))
                            data['displayname'] = node.name
                            encrypted_data = crypto.encrypt_aes_v1(json.dumps(data).encode(), tree_key)
                            rq['encrypted_data'] = utils.base64_url_encode(encrypted_data)
                        else:
                            if existing_node is not None:
                                rq['encrypted_data'] = existing_node.encrypted_data
                            elif action == EntityAction.Add:
                                raise Exception('empty node name')
                        if isinstance(node.restrict_visibility, bool):
                            rq['restrict_visibility'] = '1' if node.restrict_visibility else '0'

                    (add_requests if action != EntityAction.Remove else remove_requests).append(rq)
                except Exception as e:
                    self.logger.warning(f'Node {action.name}: Node ID = \"{node.node_id}\": {e}')

        return add_requests, remove_requests

    def _to_role_requests(self) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        add_requests: List[Dict[str, Any]] = []
        remove_requests: List[Dict[str, Any]] = []
        if self._roles:
            enterprise_data = self.loader.enterprise_data
            tree_key = enterprise_data.enterprise_info.tree_key
            for action, role in self._roles.values():
                try:
                    if action == EntityAction.Add:
                        if not role.node_id:
                            role.node_id = enterprise_data.root_node.node_id
                        role.visible_below = role.visible_below or True
                        role.new_user_inherit = role.new_user_inherit or False
                    elif action == EntityAction.Update:
                        if isinstance(role.new_user_inherit, bool):
                            has_managed_node = any(
                                (True for x in enterprise_data.managed_nodes.get_all_links() if x.role_id == role.role_id))
                            if has_managed_node:
                                role.new_user_inherit = None
                    rq = {
                        'command': 'role_' + ('add' if action == EntityAction.Add else 'update' if action == EntityAction.Update else 'delete'),
                        'role_id': role.role_id,
                    }
                    if action == EntityAction.Add or action == EntityAction.Update:
                        if isinstance(role.node_id, int):
                            rq['node_id'] = role.node_id

                        existing_role = enterprise_data.roles.get_entity(role.role_id) if action == EntityAction.Update else None
                        if isinstance(role.name, str) and len(role.name) > 0:
                            data = {}
                            if action == EntityAction.Update:
                                if existing_role is not None and existing_role.encrypted_data:
                                    data.update(
                                        self.decrypt_encrypted_data(existing_role.encrypted_data, key_type=existing_role.key_type))
                            data['displayname'] = role.name
                            encrypted_data = crypto.encrypt_aes_v1(json.dumps(data).encode(), tree_key)
                            rq['encrypted_data'] = utils.base64_url_encode(encrypted_data)
                        else:
                            if existing_role is not None:
                                rq['encrypted_data'] = existing_role.encrypted_data
                            elif action == EntityAction.Add:
                                raise Exception('empty role name')
                        if isinstance(role.visible_below, bool):
                            rq['visible_below'] = role.visible_below
                        if isinstance(role.new_user_inherit, bool):
                            rq['new_user_inherit'] = role.new_user_inherit

                    (add_requests if action != EntityAction.Remove else remove_requests).append(rq)
                except Exception as e:
                    self.logger.warning(f'Role {action.name}: Role ID = \"{role.role_id}\": {e}')

        return add_requests, remove_requests

    def _to_team_requests(self) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        add_requests: List[Dict[str, Any]] = []
        remove_requests: List[Dict[str, Any]] = []

        if self._teams:
            enterprise_data = self.loader.enterprise_data
            auth = self.loader.keeper_auth
            tree_key = enterprise_data.enterprise_info.tree_key

            for action, team in self._teams.values():
                try:
                    if action == EntityAction.Add:
                        if not team.node_id:
                            team.node_id = enterprise_data.root_node.node_id
                        team.restrict_edit = team.restrict_edit or False
                        team.restrict_share = team.restrict_share or False
                        team.restrict_view = team.restrict_view or False
                        if not team.name:
                            raise Exception('empty team name')

                    rq: Dict[str, Any] = {
                        'command': 'team_' + ('add' if action == EntityAction.Add else 'update' if action == EntityAction.Update else 'delete'),
                        'team_uid': team.team_uid,
                    }
                    if action == EntityAction.Add or action == EntityAction.Update:
                        if isinstance(team.team_uid, str):
                            rq['node_id'] = team.node_id

                        existing_team = enterprise_data.teams.get_entity(team.team_uid) if action == EntityAction.Update else None
                        if not team.name and existing_team:
                            team.name = existing_team.name
                        if team.name:
                            rq['team_name'] = team.name
                        if isinstance(team.restrict_edit, bool):
                            rq['restrict_edit'] = team.restrict_edit
                        if isinstance(team.restrict_share, bool):
                            rq['restrict_share'] = team.restrict_share
                        if isinstance(team.restrict_view, bool):
                            rq['restrict_view'] = team.restrict_view
                    if action == EntityAction.Add:
                        rq['manage_only'] = False
                        team_keys = keeper_auth.UserKeys()
                        if not auth.auth_context.forbid_rsa:
                            rsa_private_key, rsa_public_key = crypto.generate_rsa_key()
                            rsa_private_data = crypto.unload_rsa_private_key(rsa_private_key)
                            rsa_private_data = crypto.encrypt_aes_v1(rsa_private_data, tree_key)
                            rsa_public_data = crypto.unload_rsa_public_key(rsa_public_key)
                            team_keys.rsa = rsa_public_data
                            rq['private_key'] = utils.base64_url_encode(rsa_private_data)
                            rq['public_key'] = utils.base64_url_encode(rsa_public_data)
                        ec_private_key, ec_public_key = crypto.generate_ec_key()
                        ec_private_data = crypto.unload_ec_private_key(ec_private_key)
                        ec_private_data = crypto.encrypt_aes_v2(ec_private_data, tree_key)
                        ec_public_data = crypto.unload_ec_public_key(ec_public_key)
                        team_keys.ec = ec_private_data
                        rq['ecc_private_key'] = utils.base64_url_encode(ec_private_data)
                        rq['ecc_public_key'] = utils.base64_url_encode(ec_public_data)
                        team_key = utils.generate_aes_key()
                        team_keys.aes = team_key
                        encrypted_team_key = crypto.encrypt_aes_v1(team_key, auth.auth_context.data_key)
                        rq['team_key'] = utils.base64_url_encode(encrypted_team_key)
                        encrypted_team_key = crypto.encrypt_aes_v2(team_key, tree_key)
                        rq['encrypted_team_key'] = utils.base64_url_encode(encrypted_team_key)
                        if self._team_keys is None:
                            self._team_keys = {}
                        self._team_keys[team.team_uid] = team_keys
                    (add_requests if action != EntityAction.Remove else remove_requests).append(rq)
                except Exception as e:
                    self.logger.warning(f'Team {action.name}: Team UID = \"{team.team_uid}\": {e}')

        return add_requests, remove_requests

    def _to_user_requests(self) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        add_requests: List[Dict[str, Any]] = []
        remove_requests: List[Dict[str, Any]] = []
        if self._users:
            enterprise_data = self.loader.enterprise_data
            tree_key = enterprise_data.enterprise_info.tree_key
            for action, user in self._users.values():
                try:
                    rq = {
                        'command': 'enterprise_user_' + ('add' if action == EntityAction.Add else 'update' if action == EntityAction.Update else 'delete'),
                        'enterprise_user_id': user.enterprise_user_id,
                    }
                    if action in (EntityAction.Add, EntityAction.Update):
                        if isinstance(user.node_id, int):
                            rq['node_id'] = user.node_id

                        existing_user = enterprise_data.users.get_entity(
                            user.enterprise_user_id) if action == EntityAction.Update else None
                        rq['enterprise_user_username'] = existing_user.username if existing_user else user.username

                        if user.full_name or user.job_title or not existing_user:
                            if existing_user and existing_user.encrypted_data:
                                data = self.decrypt_encrypted_data(existing_user.encrypted_data, existing_user.key_type)
                            else:
                                data = {}
                            if user.full_name:
                                rq['full_name'] = user.full_name
                                data['displayname'] = user.full_name
                            if user.job_title:
                                rq['job_title'] = user.job_title
                            encrypted_data = crypto.encrypt_aes_v1(json.dumps(data).encode('utf-8'), tree_key)
                            rq['encrypted_data'] = utils.base64_url_encode(encrypted_data)
                            rq['key_type'] = 'encrypted_by_data_key'
                        elif existing_user:
                            rq['encrypted_data'] = existing_user.encrypted_data
                            rq['key_type'] = existing_user.key_type

                    (add_requests if action != EntityAction.Remove else remove_requests).append(rq)
                except Exception as e:
                    self.logger.warning(f'User {action.name}: User ID = \"{user.enterprise_user_id}\": {e}')

        return add_requests, remove_requests

    def _to_disable_tfa_requests(self) -> Optional[enterprise_pb2.EnterpriseUserIds]:
        add_requests: Optional[enterprise_pb2.EnterpriseUserIds] = None
        if isinstance(self._user_actions, dict):
            user_ids = [user_id for user_id, action in self._user_actions.items() if action == UserAction.DisableTfa]
            if len(user_ids) > 0:
                add_requests = enterprise_pb2.EnterpriseUserIds()
                add_requests.enterpriseUserId.extend(user_ids)
        return add_requests

    def _to_user_actions(self) -> List[Dict[str, Any]]:
        requests: List[Dict[str, Any]] = []
        if self._user_actions:
            enterprise_data = self.loader.enterprise_data

            for enterprise_user_id, user_action in self._user_actions.items():
                try:
                    u = enterprise_data.users.get_entity(enterprise_user_id)
                    if not u:
                        raise Exception('user does not exist')
                    rq: Dict[str, Any] = {}
                    if user_action == UserAction.ExpirePassword:
                        rq['command'] = 'set_master_password_expire'
                        rq['username'] = u.username
                    else:
                        rq['enterprise_user_id'] = enterprise_user_id
                        if user_action in {UserAction.Lock, UserAction.Unlock}:
                            rq['command'] = 'enterprise_user_lock'
                            rq['lock'] = 'locked' if user_action == UserAction.Lock else 'unlocked'
                        elif user_action == UserAction.ExtendTransfer:
                            rq['command'] = 'extend_account_share_expiration'
                        else:
                            raise Exception('unsupported action')

                    requests.append(rq)
                except Exception as e:
                    self.logger.warning(f'{user_action.name}: User ID = \"{enterprise_user_id}\": {e}')

        return requests

    def _to_managed_node_requests(self) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        add_requests: List[Dict[str, Any]] = []
        remove_requests: List[Dict[str, Any]] = []

        if self._managed_nodes:
            enterprise_data = self.loader.enterprise_data
            for action, m_node in self._managed_nodes.values():
                try:
                    if action == EntityAction.Add:
                        if not isinstance(m_node.cascade_node_management, bool):
                            m_node.cascade_node_management = True
                    role_id = m_node.role_id
                    node_id = m_node.managed_node_id
                    r = enterprise_data.roles.get_entity(role_id)
                    if not r:
                        raise Exception('role not found')
                    n = enterprise_data.nodes.get_entity(node_id)
                    if not n:
                        raise Exception('node not found')

                    mn = enterprise_data.managed_nodes.get_link(role_id, node_id)
                    rq: Dict[str, Any] = {
                        'role_id': role_id,
                        'managed_node_id': node_id,
                    }
                    if action == EntityAction.Add:
                        if mn:
                            raise Exception('already exists')
                        rq['command'] = 'role_managed_node_add'
                        rq['cascade_node_management'] = m_node.cascade_node_management
                    else:
                        if not mn:
                            raise Exception('does not exist')
                        if action == EntityAction.Update:
                            if not isinstance(m_node.cascade_node_management, bool):
                                continue
                            if m_node.cascade_node_management == mn.cascade_node_management:
                                continue
                            rq['command'] = 'role_managed_node_update'
                            rq['cascade_node_management'] = m_node.cascade_node_management
                        elif action == EntityAction.Remove:
                            rq['command'] = 'role_managed_node_remove'
                except Exception as e:
                    self.logger.warning(f'Managed Node {action.name}: '
                                        f'Role ID = \"{m_node.role_id}\", Node ID = \"{m_node.managed_node_id}\": {e}')


        return add_requests, remove_requests

    def _to_managed_node_privileges(self) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        add_requests: List[Dict[str, Any]] = []
        remove_requests: List[Dict[str, Any]] = []

        if self._managed_nodes:
            auth = self.loader.keeper_auth
            enterprise_data = self.loader.enterprise_data
            tree_key = enterprise_data.enterprise_info.tree_key

            privilege: enterprise_types.RolePrivilege
            for action, m_node in self._managed_nodes.values():
                if m_node.privileges is None:
                    continue

                role_id = m_node.role_id
                node_id = m_node.managed_node_id
                for privilege, to_add in m_node.privileges.items():
                    try:
                        rq: Dict[str, Any] = {
                            'command': 'managed_node_privilege_' + ('add' if to_add else 'remove'),
                            'role_id': role_id,
                            'managed_node_id': node_id,
                            'privilege': privilege.name.lower(),
                        }
                        if to_add:
                            if privilege in (enterprise_types.RolePrivilege.ManageCompanies, enterprise_types.RolePrivilege.TransferAccount):
                                if not auth.auth_context.forbid_rsa:
                                    role_key = utils.generate_aes_key()
                                    encrypted_role_key = crypto.encrypt_aes_v2(role_key, tree_key)
                                    rq['role_key_enc_with_tree_key'] = utils.base64_url_encode(encrypted_role_key)
                                    rsa_private, rsa_public = crypto.generate_rsa_key()
                                    rsa_private_data = crypto.unload_rsa_private_key(rsa_private)
                                    rsa_private_data = crypto.encrypt_aes_v1(rsa_private_data, tree_key)
                                    rsa_public_data = crypto.unload_rsa_public_key(rsa_public)
                                    rq['role_public_key'] = utils.base64_url_encode(rsa_public_data)
                                    rq['role_private_key'] = utils.base64_url_encode(rsa_private_data)

                                    existing_user_ids = {x.enterprise_user_id for x in enterprise_data.role_users.get_all_links() if
                                                         x.role_id == role_id}
                                    usernames = [u.username for u in (enterprise_data.users.get_entity(x) for x in existing_user_ids) if u]
                                    if len(usernames) > 0:
                                        auth.load_user_public_keys(usernames, send_invites=False)
                                        rq['role_keys'] = []
                                        for user_id in existing_user_ids:
                                            u = enterprise_data.users.get_entity(user_id)
                                            if u:
                                                user_key = auth.get_user_keys(u.username)
                                                if user_key and user_key.rsa:
                                                    try:
                                                        rsa_key = crypto.load_rsa_public_key(user_key.rsa)
                                                        encrypted_role_key = crypto.encrypt_rsa(role_key, rsa_key)
                                                        rq['role_keys'].append({
                                                            'enterprise_user_id': user_id,
                                                            'role_key': utils.base64_url_encode(encrypted_role_key)
                                                        })
                                                    except Exception as e:
                                                        utils.get_logger().debug('Encryption error: %s', e)
                            elif privilege == enterprise_types.RolePrivilege.ManageCompanies:
                                # TODO
                                pass
                        (add_requests if to_add else remove_requests).append(rq)
                    except Exception as e:
                        self.logger.warning(f'Managed Node Privilege {action.name}: Role ID = \"{m_node.role_id}\", '
                                            f'Node ID = \"{m_node.managed_node_id}\", Privilege = \"{privilege}\": {e}')

        return add_requests, remove_requests

    def _to_role_enforcements(self) -> List[Dict[str, Any]]:
        requests: List[Dict[str, Any]] = []

        if self._role_enforcements:
            enterprise_data = self.loader.enterprise_data
            r: Optional[enterprise_types.Role]
            for action, role_enforcement in self._role_enforcements.values():
                if action == EntityAction.Remove and role_enforcement.value is not None:
                    role_enforcement.value = None
                try:
                    role_id = role_enforcement.role_id
                    r = enterprise_data.roles.get_entity(role_id)
                    if not r:
                        raise Exception('role does not exist')
                    enforcement = role_enforcement.name.lower()
                    existing_enforcement = enterprise_data.role_enforcements.get_link(role_id, enforcement)
                    enforcement_value = role_enforcement.value
                    if enforcement_value is not None:
                        enforcement_type = enterprise_constants.ENFORCEMENTS.get(enforcement)
                        if enforcement_type:
                            enforcement_value = self._to_enforcement_value(enforcement_type, enforcement_value)
                    rq = {
                        'role_id': role_id,
                        'enforcement': enforcement
                    }
                    if enforcement_value is not None:
                        rq['command'] = 'role_enforcement_update' if existing_enforcement else 'role_enforcement_add'
                        if not isinstance(enforcement_value, bool):
                            rq['value'] = enforcement_value
                    else:
                        if existing_enforcement:
                            rq['command'] = 'role_enforcement_remove'
                        else:
                            continue
                except Exception as e:
                    self.logger.warning(f'Role Enforcement {action.name}: Role ID = \"{role_enforcement.role_id}\", '
                                        f'Enforcement = \"{role_enforcement.name}\": {e}')

        return requests

    def _to_team_user_requests(self) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        add_requests: List[Dict[str, Any]] = []
        remove_requests: List[Dict[str, Any]] = []
        if self._team_users:
            enterprise_data = self.loader.enterprise_data

            u: Optional[enterprise_types.User]
            t: Optional[enterprise_types.Team]
            qt: Optional[enterprise_types.QueuedTeam]

            for action, team_user in self._team_users.values():
                try:
                    rq = {
                        'enterprise_user_id': team_user.enterprise_user_id,
                        'team_uid': team_user.team_uid,
                    }
                    if action == EntityAction.Add:
                        qt = None
                        t = enterprise_data.teams.get_entity(team_user.team_uid)
                        if not t:
                            qt = enterprise_data.queued_teams.get_entity(team_user.team_uid)
                            if not qt:
                                if isinstance(self._teams, dict) and team_user.team_uid in self._teams:
                                    te: enterprise_management.TeamEdit
                                    action, te = self._teams[team_user.team_uid]
                                    if action == EntityAction.Add and te.name and te.node_id:
                                        t = enterprise_types.Team(team_uid=te.team_uid, name=te.name or '', node_id=te.node_id)
                        u = enterprise_data.users.get_entity(team_user.enterprise_user_id)
                        if not u:
                            if isinstance(self._users, dict) and team_user.enterprise_user_id in self._users:
                                ue: enterprise_management.UserEdit
                                action, ue = self._users[team_user.enterprise_user_id]
                                if action == EntityAction.Add and ue.username and ue.node_id:
                                    u = enterprise_types.User(enterprise_user_id=ue.enterprise_user_id, username=ue.username, node_id=ue.node_id, status='inactive')
                        if not u:
                            raise Exception('user not found')
                        if not t and not qt:
                            raise Exception('team not found')
                        if u.status == 'active' and t:
                            team_keys: Optional[keeper_auth.UserKeys]
                            if self._team_keys and team_user.team_uid in self._team_keys:
                                team_keys = self._team_keys[team_user.team_uid]
                            else:
                                team_keys = self.loader.keeper_auth.get_team_keys(team_user.team_uid)
                            if not team_keys:
                                raise Exception('team key is not loaded')
                            if not team_keys.aes:
                                team = enterprise_data.teams.get_entity(team_user.team_uid)
                                if team:
                                    team_keys.aes = team.encrypted_team_key
                            user_keys = self.loader.keeper_auth.get_user_keys(u.username)
                            if not user_keys:
                                raise Exception('user key is not loaded')
                            rq['command'] = 'team_enterprise_user_add'
                            rq['user_type'] = 0
                            if self.loader.keeper_auth.auth_context.forbid_rsa:
                                if user_keys.ec:
                                    ec_public_key = crypto.load_ec_public_key(user_keys.ec)
                                    team_key = crypto.encrypt_ec(team_keys.aes, ec_public_key)
                                    rq['team_key'] = utils.base64_url_encode(team_key)
                                    rq['team_key_type'] = 'encrypted_by_public_key_ecc'
                            else:
                                if user_keys.rsa:
                                    rsa_public_key = crypto.load_rsa_public_key(user_keys.rsa)
                                    team_key = crypto.encrypt_rsa(team_keys.aes, rsa_public_key)
                                    rq['team_key'] = utils.base64_url_encode(team_key)
                                    rq['team_key_type'] = 'encrypted_by_public_key'
                        else:
                            rq['command'] = 'team_queue_user'
                    elif action == EntityAction.Remove:
                        tu = enterprise_data.team_users.get_link(team_user.team_uid, team_user.enterprise_user_id)
                        if tu:
                            rq['command'] = 'team_enterprise_user_remove'
                        else:
                            qtu = enterprise_data.queued_team_users.get_link(team_user.team_uid, team_user.enterprise_user_id)
                            if qtu:
                                rq['command'] = 'team_enterprise_user_remove'
                            else:
                                continue
                    else:
                        continue

                    (add_requests if action != EntityAction.Remove else remove_requests).append(rq)
                except Exception as e:
                    self.logger.warning(f'Team User {action.name}: Team UID = \"{team_user.team_uid}\", '
                                        f'User ID = \"{team_user.enterprise_user_id}\": {e}')

        return add_requests, remove_requests

    def _to_role_user_requests(self) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        add_requests: List[Dict[str, Any]] = []
        remove_requests: List[Dict[str, Any]] = []

        if self._role_users:
            enterprise_data = self.loader.enterprise_data
            tree_key = enterprise_data.enterprise_info.tree_key
            auth = self.loader.keeper_auth

            for action, role_user in self._role_users.values():
                u: Optional[enterprise_types.User]
                r: Optional[enterprise_types.Role]
                try:
                    is_admin_role = any(enterprise_data.managed_nodes.get_links_by_subject(role_user.role_id))
                    rq = {
                        'command': 'role_user_' + ('add' if action == EntityAction.Add else 'remove'),
                        'role_id': role_user.role_id,
                        'enterprise_user_id': role_user.enterprise_user_id,
                    }
                    if action == EntityAction.Add:
                        r = enterprise_data.roles.get_entity(role_user.role_id)
                        if not r:
                            raise Exception('role not found')
                        u = enterprise_data.users.get_entity(role_user.enterprise_user_id)
                        if not u:
                            raise Exception('user not found')
                        if u.status != 'active' and is_admin_role:
                            raise Exception('cannot add invited user to admin role')
                        if is_admin_role:
                            role_key = self.loader.get_role_keys(role_user.role_id)
                            user_keys = auth.get_user_keys(u.username)
                            if not user_keys:
                                raise Exception('user public key is not loaded')
                            if auth.auth_context.forbid_rsa:
                                if user_keys.ec:
                                    ec_key = crypto.load_ec_public_key(user_keys.ec)
                                    encrypted_tree_key = crypto.encrypt_ec(tree_key, ec_key)
                                    rq['tree_key'] = utils.base64_url_encode(encrypted_tree_key)
                                    rq['tree_key_type'] = 'encrypted_by_public_key_ecc'
                                    if role_key:
                                        encrypted_role_key = crypto.encrypt_ec(role_key, ec_key)
                                        rq['role_admin_key'] = utils.base64_url_encode(encrypted_role_key)
                                        rq['role_admin_key_type'] = 'encrypted_by_public_key_ecc'
                            else:
                                if user_keys.rsa:
                                    rsa_key = crypto.load_rsa_public_key(user_keys.rsa)
                                    encrypted_tree_key = crypto.encrypt_rsa(tree_key, rsa_key)
                                    rq['tree_key'] = utils.base64_url_encode(encrypted_tree_key)
                                    rq['tree_key_type'] = 'encrypted_by_public_key'
                                    if role_key:
                                        encrypted_role_key = crypto.encrypt_rsa(role_key, rsa_key)
                                        rq['role_admin_key'] = utils.base64_url_encode(encrypted_role_key)
                                        rq['role_admin_key_type'] = 'encrypted_by_public_key'

                    (add_requests if action != EntityAction.Remove else remove_requests).append(rq)
                except Exception as e:
                    self.logger.warning(f'Role User {action.name}: Team UID = \"{role_user.role_id}\", '
                                        f'User ID = \"{role_user.enterprise_user_id}\": {e}')
        return add_requests, remove_requests


    def _to_role_team_requests(self) -> Tuple[List[enterprise_pb2.RoleTeam], List[enterprise_pb2.RoleTeam]]:
        add_rt_requests: List[enterprise_pb2.RoleTeam] = []
        remove_rt_requests: List[enterprise_pb2.RoleTeam] = []
        if self._role_teams:
            for action, role_team in self._role_teams.values():
                rqs = add_rt_requests if action == EntityAction.Add else remove_rt_requests
                rt = enterprise_pb2.RoleTeam()
                rt.role_id = role_team.role_id
                rt.teamUid = utils.base64_url_decode(role_team.team_uid)
                rqs.append(rt)

        return add_rt_requests, remove_rt_requests

    def _execute_role_team(self, endpoint: str, requests: List[enterprise_pb2.RoleTeam]):
        while len(requests) > 0:
            chunk = requests[:99]
            requests = requests[99:]
            rt_rq = enterprise_pb2.RoleTeams()
            rt_rq.role_team.extend(chunk)
            try:
                self.loader.keeper_auth.execute_auth_rest(endpoint, rt_rq)
            except Exception as e:
                self.logger.warning(f'\"{endpoint}\" API failed: {e}')

    def _execute_batch(self, requests: List[Dict[str, Any]]) -> None:
        responses = self.loader.keeper_auth.execute_batch(requests)
        command: Optional[str]

        command_action: str
        values: Dict[str, Any] = {}
        for pos in range(len(responses)):
            if not (pos < len(requests) and pos < len(responses)):
                break
            rq = requests[pos]
            command = rq.get('command')
            if not command:
                continue

            rs = responses[pos]
            if rs.get('result') == 'success':
                continue
            result_code = rs.get('result_code') or ''
            message = rs.get('message') or ''
            values.clear()
            if command.startswith('node_'):
                command_action = 'Node ' + command[len('node_'):].capitalize()
                values['Node ID'] = rq.get('node_id')
            elif command.startswith('role_'):
                command_action = 'Role ' + command[len('role_'):].capitalize()
                values['Role ID'] = rq.get('role_id')
            elif command.startswith('team_'):
                command_action = 'Team ' + command[len('team_'):].capitalize()
                values['Team UID'] = rq.get('team_uid')
            elif command.startswith('enterprise_user_'):
                command_action = 'User ' + command[len('enterprise_user_'):].capitalize()
                values['User ID'] = rq.get('enterprise_user_id')
            elif command == 'extend_account_share_expiration':
                command_action = 'User Extend Transfer'
                values['User ID'] = rq.get('enterprise_user_id')
            elif command == 'set_master_password_expire':
                command_action = 'User Expire Master Password'
                values['User Email'] = rq.get('username')
            elif command.startswith('role_managed_node_'):
                command_action = 'Managed Node ' + command[len('role_managed_node_'):].capitalize()
                values['Role ID'] = rq.get('role_id')
                values['Node ID'] = rq.get('managed_node_id')
            elif command.startswith('managed_node_privilege_'):
                command_action = 'Role Privilege ' + command[len('managed_node_privilege_'):].capitalize()
                values['Role ID'] = rq.get('role_id')
                values['Node ID'] = rq.get('managed_node_id')
                values['Privilege'] = rq.get('privilege')
            elif command.startswith('role_enforcement_'):
                command_action = 'Role Enforcement ' + command[len('role_enforcement_'):].capitalize()
                values['Role ID'] = rq.get('role_id')
                values['Enforcement'] = rq.get('enforcement')
            elif command.startswith('team_enterprise_user_'):
                command_action = 'Team User ' + command[len('team_enterprise_user_'):].capitalize()
                values['Team UID'] = rq.get('team_uid')
                values['User ID'] = rq.get('enterprise_user_id')
            elif  command == 'team_queue_user':
                command_action = 'Queue Team User'
                values['Team UID'] = rq.get('team_uid')
                values['User ID'] = rq.get('enterprise_user_id')
            elif command.startswith('role_user_'):
                command_action = 'Role User ' + command[len('role_user_'):].capitalize()
                values['Role ID'] = rq.get('role_id')
                values['User ID'] = rq.get('enterprise_user_id') or 0
            else:
                command_action = 'Unsupported Error'
                values['Command'] = command
            parameters = [f'{x[0]} = "{x[1]}"' for x in values.items()]
            self.logger.warning(f'{command_action}: {(", ".join(parameters))}: error ({result_code}): {message}')

    def apply(self) -> None:
        # Preload keys
        enterprise_data = self.loader.enterprise_data
        auth = self.loader.keeper_auth
        user_ids: Set[int] = set()
        team_uids: Set[str] = set()
        admin_role_uids: Set[int] = set()
        if self._team_users:
            user_ids.update((x[1].enterprise_user_id for x in self._team_users.values() if x[0] == EntityAction.Add))
            team_uids.update((x[1].team_uid for x in self._team_users.values() if x[0] == EntityAction.Add))
        if self._role_users:
            admin_roles = {x.role_id for x in enterprise_data.managed_nodes.get_all_links()}
            user_ids.update((x[1].enterprise_user_id for x in self._role_users.values() if x[0] == EntityAction.Add and x[1].role_id in admin_roles))
            admin_role_uids.update((x[1].role_id for x in self._role_users.values() if x[0] == EntityAction.Add and x[1].role_id in admin_roles))
        if len(user_ids):
            usernames = [u.username for u in (enterprise_data.users.get_entity(x) for x in user_ids) if u]
            if usernames:
                auth.load_user_public_keys(usernames, send_invites=False)
        if len(team_uids) > 0:
            auth.load_team_keys(team_uids)
        if len(admin_role_uids) > 0:
            self.loader.load_role_keys(admin_role_uids)

        add_requests: List[Dict[str, Any]] = []
        remove_requests: List[Dict[str, Any]] = []

        add_rqs, remove_rqs = self._to_node_requests()
        add_requests = add_requests + add_rqs
        remove_requests = remove_rqs + remove_requests

        add_rqs, remove_rqs = self._to_role_requests()
        add_requests = add_requests + add_rqs
        remove_requests = remove_rqs + remove_requests

        add_rqs, remove_rqs = self._to_team_requests()
        add_requests = add_requests + add_rqs
        remove_requests = remove_rqs + remove_requests

        add_rqs, remove_rqs = self._to_user_requests()
        add_requests = add_requests + add_rqs
        remove_requests = remove_rqs + remove_requests

        add_rqs = self._to_user_actions()
        add_requests = add_requests + add_rqs

        add_rqs, remove_rqs = self._to_managed_node_requests()
        add_requests = add_requests + add_rqs
        remove_requests = remove_rqs + remove_requests

        add_rqs, remove_rqs = self._to_managed_node_privileges()
        add_requests = add_requests + add_rqs
        remove_requests = remove_rqs + remove_requests

        add_rqs = self._to_role_enforcements()
        add_requests = add_requests + add_rqs

        add_rqs, remove_rqs = self._to_team_user_requests()
        add_requests = add_requests + add_rqs
        remove_requests = remove_rqs + remove_requests

        add_rqs, remove_rqs = self._to_role_user_requests()
        add_requests = add_requests + add_rqs
        remove_requests = remove_rqs + remove_requests

        add_rt_rqs, remove_rt_rqs = self._to_role_team_requests()
        self._execute_role_team('enterprise/role_team_remove', remove_rt_rqs)
        self._execute_batch(remove_requests + add_requests)
        self._execute_role_team('enterprise/role_team_add', add_rt_rqs)

        try:
            tfs_rqs = self._to_disable_tfa_requests()
            if tfs_rqs is not None:
                self.loader.keeper_auth.execute_auth_rest('enterprise/disable_two_fa', tfs_rqs)
        except Exception as e:
            self.logger.warning(f'Disable TFA error: {e}')

        self.loader.load()

    def _to_enforcement_value(self, enforcement_type: str, enforcement_value: Any) -> Any:
        if not enforcement_value:
            return None
        if enforcement_type == 'string':
            if not isinstance(enforcement_value, str):
                enforcement_value = str(enforcement_value)
        elif enforcement_type == 'boolean':
            if isinstance(enforcement_value, str):
                if enforcement_value.lower() in {'true', 't', '1'}:
                    enforcement_value = True
                elif enforcement_value.lower() in {'false', 'f', '0'}:
                    enforcement_value = False
            if enforcement_value is False:
                enforcement_value = None
            else:
                raise Exception(f'{enforcement_type} \"{enforcement_value}\" is invalid')
        elif enforcement_type == 'long':
            if isinstance(enforcement_value, str):
                if enforcement_value.isnumeric():
                    enforcement_value = int(enforcement_value)
            if not isinstance(enforcement_value, int):
                raise Exception(f'{enforcement_type} \"{enforcement_value}\" is invalid')
        elif enforcement_type.startswith('ternary_'):
            if isinstance(enforcement_value, str):
                if enforcement_value in {'enforce', 'e'}:
                    enforcement_value = 'enforce'
                elif enforcement_value in {'disable', 'd'}:
                    enforcement_value = 'disable'
                elif enforcement_value in {'n', 'null'}:
                    enforcement_value = None
            else:
                raise Exception(f'{enforcement_type} \"{enforcement_value}\" is invalid')
        elif enforcement_value == 'two_factor_duration':
            if isinstance(enforcement_value, str):
                tfa = min((int(y) for y in (x.strip() for x in enforcement_value.split(',')) if y.isnumeric()), default=0)
                if tfa == 0:
                    enforcement_value = '0'
                elif 0 < tfa <= 12:
                    enforcement_value = '0,12'
                elif 12 < tfa <= 24:
                    enforcement_value = '0,12,24'
                elif 24 < tfa <= 30:
                    enforcement_value = '0,12,24,30'
                else:
                    enforcement_value = '0,12,24,30,9999'
        elif enforcement_type == 'ip_whitelist':
            if isinstance(enforcement_value, str):
                all_resolved = True
                ip_ranges = [x.strip().lower() for x in enforcement_value.split(',')]
                for i in range(len(ip_ranges)):
                    range_str = ip_ranges[i]
                    ranges = range_str.split('-')
                    if len(ranges) == 2:
                        try:
                            ip_addr1 = ipaddress.ip_address(ranges[0])
                            ip_addr2 = ipaddress.ip_address(ranges[1])
                            ip_ranges[i] = f'{ip_addr1}-{ip_addr2}'
                        except ValueError:
                            all_resolved = False
                    elif len(ranges) == 1:
                        try:
                            ip_addr = ipaddress.ip_address(range_str)
                            ip_ranges[i] = f'{ip_addr}-{ip_addr}'
                        except ValueError:
                            try:
                                ip_net = ipaddress.ip_network(range_str)
                                ip_ranges[i] = f'{ip_net[0]}-{ip_net[-1]}'
                            except ValueError:
                                all_resolved = False
                    else:
                        all_resolved = False
                    if not all_resolved:
                        raise Exception(f'IP address range \"{range_str}\" not valid')
                enforcement_value = ','.join(ip_ranges)
        elif enforcement_type == 'record_types':
            if self._record_types is None:
                raise Exception('Record types could not be loaded')
            record_types: Dict[str, List[int]] = {
                'std': [],
                'ent': []
            }
            rtypes = [x.strip().lower() for x in enforcement_value.split(',')]
            for rtype in rtypes:
                if rtype is self._record_types:
                    rt_id, rt_scope = self._record_types[rtype]
                    if rt_scope:
                        if rt_scope == record_pb2.RT_STANDARD:
                            record_types['std'].append(rt_id)
                        elif rt_scope == record_pb2.RT_ENTERPRISE:
                            record_types['ent'].append(rt_id)
                else:
                    self.logger.warning(f'Record type \"{rtype}\" does not exist')
            enforcement_value = record_types
        elif enforcement_type == 'account_share':
            account_role_id: Optional[int] = None
            if isinstance(enforcement_value, str):
                if enforcement_value.isnumeric():
                    account_role_id = int(enforcement_value)
                else:
                    value_l = enforcement_value.lower()
                    account_role_id = next((x.role_id for x in self.loader.enterprise_data.roles.get_all_entities() if x.name.lower() == value_l), None)
            elif isinstance(enforcement_value, int):
                account_role_id = enforcement_value
            if account_role_id is not None:
                r = self.loader.enterprise_data.roles.get_entity(account_role_id)
                if r:
                    is_admin_role = any((x for x in self.loader.enterprise_data.managed_nodes.get_links_by_subject(account_role_id)))
                    if is_admin_role:
                        enforcement_value = account_role_id
                    else:
                        raise Exception(f'Role \"{r.name}\" is not an admin role')
                else:
                    account_role_id = None
            if account_role_id is None:
                raise Exception(f'Role \"{enforcement_value}\" not found')

        return enforcement_value

    def _load_record_types(self):
        if self._record_types:
            return
        rt_rq = record_pb2.RecordTypesRequest()
        rt_rq.standard = True
        rt_rq.user = True
        rt_rq.enterprise = True
        record_types_rs = self.loader.keeper_auth.execute_auth_rest('vault/get_record_types', rt_rq,
                                                                    response_type=record_pb2.RecordTypesResponse)
        self._record_types = {}
        for rti in record_types_rs.recordTypes:
            try:
                rto = json.loads(rti.content)
                if '$id' in rto:
                    record_type = rto['$id'].lower()
                    if rti.scope == record_pb2.RT_STANDARD and rti.scope == record_pb2.RT_ENTERPRISE:
                        self._record_types[record_type] = (rti.recordTypeId, rti.scope)
            except Exception:
                pass


