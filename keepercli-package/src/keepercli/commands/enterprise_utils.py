import datetime
import os
from typing import Set, Dict, Iterable, List, Any, Union, Optional, Tuple

from keepersdk.authentication import keeper_auth
from keepersdk.enterprise import enterprise_types, enterprise_constants
from keepersdk.proto import enterprise_pb2
from . import base
from ..params import KeeperParams

BUSINESS_TRIAL = 'business_trial'

class NodeUtils:
    @staticmethod
    def get_node_name_lookup(enterprise_data: enterprise_types.IEnterpriseData
                             ) -> Dict[str, Union[enterprise_types.Node, List[enterprise_types.Node]]]:
        node_lookup: Dict[str, Union[enterprise_types.Node, List[enterprise_types.Node]]] = {}

        for node in enterprise_data.nodes.get_all_entities():
            node_lookup[str(node.node_id)] = node
            node_name = node.name
            if not node_name and node.node_id == enterprise_data.root_node.node_id:
                node_name = enterprise_data.enterprise_info.enterprise_name
            if node_name:
                node_name = node_name.lower()
                n = node_lookup.get(node_name)
                if n is None:
                    node_lookup[node_name] = node
                elif isinstance(n, list):
                    n.append(node)
                elif isinstance(n, enterprise_types.Node):
                    node_lookup[node_name] = [n, node]
        return node_lookup

    @staticmethod
    def resolve_existing_nodes(enterprise_data: enterprise_types.IEnterpriseData, node_names: Any) -> List[enterprise_types.Node]:
        found_nodes: Dict[int, enterprise_types.Node] = {}
        n: Optional[enterprise_types.Node]
        if isinstance(node_names, list):
            node_name_lookup = NodeUtils.get_node_name_lookup(enterprise_data)
            for node_name in node_names:
                n = None
                if isinstance(node_name, int):
                    n = enterprise_data.nodes.get_entity(node_name)
                elif isinstance(node_name, str):
                    if node_name.isnumeric():
                        n = enterprise_data.nodes.get_entity(int(node_name))
                    elif node_name.lower() == enterprise_data.enterprise_info.enterprise_name.lower():
                        n = enterprise_data.root_node
                    if n is None:
                        nn = node_name_lookup.get(node_name.lower())
                        if isinstance(nn, list):
                            if len(nn) == 1:
                                n = nn[0]
                            elif len(nn) >= 2:
                                raise base.CommandError(f'Node name "{node_name}" is not unique')
                        elif isinstance(nn, enterprise_types.Node):
                            n = nn
                if n is None:
                    raise base.CommandError(f'Node name "{node_name}" is not found')
                found_nodes[n.node_id] = n
        if len(found_nodes) == 0:
            raise base.CommandError('No nodes were found')
        return list(found_nodes.values())

    @staticmethod
    def resolve_single_node(enterprise_data: enterprise_types.IEnterpriseData, node_name: Any) -> enterprise_types.Node:
        node: Optional[enterprise_types.Node] = None
        if isinstance(node_name, int):
            node = enterprise_data.nodes.get_entity(node_name)
        elif isinstance(node_name, str):
            if node_name.isnumeric():
                node = enterprise_data.nodes.get_entity(int(node_name))
            elif node_name.lower() == enterprise_data.enterprise_info.enterprise_name.lower():
                node = enterprise_data.root_node
            if not node:
                ns = [x for x in enterprise_data.nodes.get_all_entities() if x.name.lower() == node_name.lower()]
                if len(ns) > 1:
                    raise base.CommandError(f'Node name \"{node_name}\" is not unique. Please use Node ID')
                elif len(ns) == 1:
                    node = ns[0]
        if node is None:
            raise base.CommandError(f'Node name \"{node_name}\" does not exist')
        return node

    @staticmethod
    def get_node_depth(enterprise_data: enterprise_types.IEnterpriseData,
                       node_id: Optional[int],
                       depth: int = 0) -> int:
        if not node_id:
            return depth
        node = enterprise_data.nodes.get_entity(node_id)
        if node:
            return NodeUtils.get_node_depth(enterprise_data, node.parent_id, depth + 1)
        else:
            return depth

    @staticmethod
    def get_node_path(enterprise_data: enterprise_types.IEnterpriseData, node_id: int, omit_root: bool=False) -> str:
        nodes: List[str] = []
        n_id = node_id
        while isinstance(n_id, int) and n_id > 0:
            node = enterprise_data.nodes.get_entity(n_id)
            if node:
                n_id = node.parent_id or 0
                if not omit_root or n_id > 0:
                    node_name = node.name
                    if not node_name and node.node_id == enterprise_data.root_node.node_id:
                        node_name = enterprise_data.enterprise_info.enterprise_name
                    nodes.append(node_name)
            else:
                break
        nodes.reverse()
        return '\\'.join(nodes)

    @staticmethod
    def get_subnodes(enterprise_data: enterprise_types.IEnterpriseData) ->  Dict[int, Set[int]]:
        subnodes: Dict[int, Set[int]] = {}
        for x in enterprise_data.nodes.get_all_entities():
            if isinstance(x.parent_id, int) and x.parent_id > 0:
                if x.parent_id not in subnodes:
                    subnodes[x.parent_id] = set()
                subnodes[x.parent_id].add(x.node_id)
        return subnodes


class RoleUtils:
    @staticmethod
    def get_role_name_lookup(e_data: enterprise_types.IEnterpriseData) -> Dict[str, Union[enterprise_types.Role, List[enterprise_types.Role]]]:
        role_lookup: Dict[str, Union[enterprise_types.Role, List[enterprise_types.Role]]] = {}

        for role in e_data.roles.get_all_entities():
            role_lookup[str(role.role_id)] = role
            if role.name:
                role_name = role.name.lower()
                n = role_lookup.get(role_name)
                if n is None:
                    role_lookup[role_name] = role
                elif isinstance(n, list):
                    n.append(role)
                elif isinstance(n, enterprise_types.Role):
                    role_lookup[role_name] = [n, role]
        return role_lookup

    @staticmethod
    def resolve_existing_roles(e_data: enterprise_types.IEnterpriseData, role_names: Any) -> List[enterprise_types.Role]:
        found_roles: Dict[int, enterprise_types.Role] = {}
        r: Optional[enterprise_types.Role]
        if isinstance(role_names, list):
            role_name_lookup = RoleUtils.get_role_name_lookup(e_data)
            for role_name in role_names:
                r = None
                if isinstance(role_name, int):
                    r = e_data.roles.get_entity(role_name)
                elif isinstance(role_name, str):
                    if role_name.isnumeric():
                        r = e_data.roles.get_entity(int(role_name))
                    if r is None:
                        rr = role_name_lookup.get(role_name.lower())
                        if isinstance(rr, list):
                            if len(rr) == 1:
                                r = rr[0]
                            elif len(rr) >= 2:
                                raise base.CommandError(f'Role name "{role_name}" is not unique. Use Role ID.')
                        elif isinstance(rr, enterprise_types.Role):
                            r = rr
                if r is None:
                    raise base.CommandError(f'Role name "{role_name}" is not found')
                found_roles[r.role_id] = r
        if len(found_roles) == 0:
            raise base.CommandError('No roles were found')
        return list(found_roles.values())

    @staticmethod
    def resolve_single_role(e_data: enterprise_types.IEnterpriseData, role_name: Any) -> enterprise_types.Role:
        role: Optional[enterprise_types.Role] = None
        if isinstance(role_name, int):
            role = e_data.roles.get_entity(role_name)
        elif isinstance(role_name, str):
            if role_name.isnumeric():
                role = e_data.roles.get_entity(int(role_name))
            if not role:
                rs = [x for x in e_data.roles.get_all_entities() if x.name.lower() == role_name.lower()]
                if len(rs) > 1:
                    raise base.CommandError(f'Node name \"{role_name}\" is not unique. Please use Node ID')
                elif len(rs) == 1:
                    role = rs[0]
        if role is None:
            raise base.CommandError(f'Role name \"{role_name}\" does not exist')
        return role


    @staticmethod
    def enforcement_value_from_file(filepath: str) -> str:
        filepath = os.path.expanduser(filepath)
        if os.path.isfile(filepath):
            with open(filepath, 'r') as f:
                return f.read()
        else:
            raise Exception(f'Could not load value in "{filepath}": No such file exists')

    @staticmethod
    def parse_enforcements(enforcement_names: Any) -> Tuple[Dict[str, Any], List[str]]:
        enforcements: Dict[str, Any] = {}
        errors: List[str] = []
        if isinstance(enforcements, str):
            enforcement_names = [enforcement_names]
        file_prefix = '$FILE='
        for enf in enforcement_names:
            tokens = enf.split(':')
            if len(tokens) != 2:
                errors.append(f'Enforcement "{enf}" is skipped. Expected format:  KEY:[VALUE]')
                continue

            key = tokens[0].strip().lower()
            enforcement_type = enterprise_constants.ENFORCEMENTS.get(key)
            if not enforcement_type:
                errors.append(f'Enforcement "{key}" does not exist')
                continue
            enforcement_value = tokens[1].strip()
            if enforcement_value.startswith(file_prefix):
                filepath = enforcement_value[len(file_prefix):]
                if filepath:
                    try:
                        enforcement_value = RoleUtils.enforcement_value_from_file(filepath)
                    except Exception as e:
                        errors.append(f'Enforcement "{key}": Load from file "{filepath}": {e}')
                        continue
                    if enforcement_value is None:
                        errors.append(f'Could not load enforcement value from "{filepath}"')
                        continue
                else:
                    errors.append(f'Enforcement {key} is skipped. Expected format: KEY:$FILE=<FILEPATH>')
                    continue
        return enforcements, errors


class UserUtils:
    @staticmethod
    def get_username_lookup(e_data: enterprise_types.IEnterpriseData) -> Dict[str, enterprise_types.User]:
        user_lookup: Dict[str, enterprise_types.User] = {}

        for user in e_data.users.get_all_entities():
            user_lookup[str(user.enterprise_user_id)] = user
            user_lookup[user.username] = user
        return user_lookup
    @staticmethod
    def resolve_existing_users(e_data: enterprise_types.IEnterpriseData, user_names: Any) -> List[enterprise_types.User]:
        found_users: Dict[int, enterprise_types.User] = {}
        u: Optional[enterprise_types.User]
        if isinstance(user_names, list):
            user_name_lookup = UserUtils.get_username_lookup(e_data)
            for user_name in user_names:
                u = None
                if isinstance(user_name, int):
                    u = e_data.users.get_entity(user_name)
                elif isinstance(user_name, str):
                    if user_name.isnumeric():
                        u = e_data.users.get_entity(int(user_name))
                    if u is None:
                        u = user_name_lookup.get(user_name.lower())
                if u is None:
                    raise base.CommandError(f'User "{user_name}" is not found')
                found_users[u.enterprise_user_id] = u
        if len(found_users) == 0:
            raise base.CommandError('No users were found')
        return list(found_users.values())

    @staticmethod
    def resolve_single_user(e_data: enterprise_types.IEnterpriseData, user_name: Any) -> enterprise_types.User:
        user: Optional[enterprise_types.User] = None
        if isinstance(user_name, int):
            user = e_data.users.get_entity(user_name)
        elif isinstance(user_name, str):
            if user_name.isnumeric():
                user = e_data.users.get_entity(int(user_name))
            if not user:
                us = [x for x in e_data.users.get_all_entities() if x.username.lower() == user_name.lower()]
                if len(us) > 1:
                    raise base.CommandError(f'User name \"{user_name}\" is not unique. Please use User ID')
                elif len(us) == 1:
                    user = us[0]
        if user is None:
            raise base.CommandError(f'User name \"{user_name}\" does not exist')
        return user

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

    @staticmethod
    def get_share_administrators(auth: keeper_auth.KeeperAuth, username: str) -> List[str]:
        rq = enterprise_pb2.GetSharingAdminsRequest()
        rq.username = username
        rs = auth.execute_auth_rest('enterprise/get_sharing_admins', rq, response_type=enterprise_pb2.GetSharingAdminsResponse)
        assert rs is not None
        return [x.email for x in rs.userProfileExts]


class TeamUtils:
    @staticmethod
    def get_team_name_lookup(e_data: enterprise_types.IEnterpriseData) -> Dict[str, Union[enterprise_types.Team, List[enterprise_types.Team]]]:
        team_lookup: Dict[str, Union[enterprise_types.Team, List[enterprise_types.Team]]] = {}

        for team in e_data.teams.get_all_entities():
            team_lookup[team.team_uid] = team
            team_name = team.name.lower()
            t = team_lookup.get(team_name)
            if t is None:
                team_lookup[team_name] = team
            elif isinstance(t, list):
                t.append(team)
            elif isinstance(t, enterprise_types.Team):
                team_lookup[team_name] = [t, team]
        return team_lookup

    @staticmethod
    def get_queued_team_name_lookup(e_data: enterprise_types.IEnterpriseData
                                    ) -> Dict[str, Union[enterprise_types.QueuedTeam, List[enterprise_types.QueuedTeam]]]:
        qteam_lookup: Dict[str, Union[enterprise_types.QueuedTeam, List[enterprise_types.QueuedTeam]]] = {}

        for qteam in e_data.queued_teams.get_all_entities():
            qteam_lookup[qteam.team_uid] = qteam
            team_name = qteam.name.lower()
            qt = qteam_lookup.get(team_name)
            if qt is None:
                qteam_lookup[team_name] = qteam
            elif isinstance(qt, list):
                qt.append(qteam)
            elif isinstance(qt, enterprise_types.Team):
                qteam_lookup[team_name] = [qt, qteam]
        return qteam_lookup

    @staticmethod
    def resolve_existing_teams(e_data: enterprise_types.IEnterpriseData,
                               team_names: Any
                               ) -> Tuple[List[enterprise_types.Team], List[Any]]:
        found_teams: Dict[str, enterprise_types.Team] = {}
        missing_teams = []
        t: Optional[enterprise_types.Team]
        if isinstance(team_names, list):
            team_name_lookup = TeamUtils.get_team_name_lookup(e_data)
            for team_name in team_names:
                t = None
                if isinstance(team_name, str):
                    t = e_data.teams.get_entity(team_name)
                    if t is None:
                        tt = team_name_lookup.get(team_name.lower())
                        if isinstance(tt, list):
                            if len(tt) == 1:
                                t = tt[0]
                            elif len(tt) >= 2:
                                raise base.CommandError(f'Team name "{team_name}" is not unique. Use Team UID.')
                        elif isinstance(tt, enterprise_types.Team):
                            t = tt
                if t is None:
                    missing_teams.append(team_name)
                    continue
                found_teams[t.team_uid] = t
        return list(found_teams.values()), missing_teams

    @staticmethod
    def resolve_queued_teams(e_data: enterprise_types.IEnterpriseData,
                             team_names: Any
                             ) -> Tuple[List[enterprise_types.QueuedTeam], List[Any]]:
        found_teams: Dict[str, enterprise_types.QueuedTeam] = {}
        missing_teams = []
        t: Optional[enterprise_types.QueuedTeam]
        if isinstance(team_names, list):
            team_name_lookup = TeamUtils.get_queued_team_name_lookup(e_data)
            for team_name in team_names:
                t = None
                if isinstance(team_name, str):
                    t = e_data.queued_teams.get_entity(team_name)
                    if t is None:
                        tt = team_name_lookup.get(team_name.lower())
                        if isinstance(tt, list):
                            if len(tt) == 1:
                                t = tt[0]
                            elif len(tt) >= 2:
                                raise base.CommandError(f'Queued team name "{team_name}" is not unique. Use Queued Team UID.')
                if t is None:
                    missing_teams.append(team_name)
                    continue
                found_teams[t.team_uid] = t
        return list(found_teams.values()), missing_teams

    @staticmethod
    def resolve_single_team(e_data: enterprise_types.IEnterpriseData, team_name: Any) -> Optional[enterprise_types.Team]:
        team: Optional[enterprise_types.Team] = None
        if isinstance(team_name, str):
            team = e_data.teams.get_entity(team_name)
            if not team:
                ts = [x for x in e_data.teams.get_all_entities() if x.name.lower() == team_name.lower()]
                if len(ts) > 1:
                    raise base.CommandError(f'Team name \"{team_name}\" is not unique. Please use Node UID')
                elif len(ts) == 1:
                    team = ts[0]
        return team


class EnterpriseMixin:

    @staticmethod
    def tokenize_row(r: List[Any]) -> Iterable[str]:
        for c in r:
            if isinstance(c, list):
                yield from (str(x) for x in c if x)
            else:
                yield str(c)

    @staticmethod
    def get_user_status_dict(user: enterprise_types.User) -> str:
        if user.status == 'active':
            if user.lock == 0:
                if isinstance(user.account_share_expiration, int) and user.account_share_expiration > 0:
                    expire_at = datetime.datetime.fromtimestamp(user.account_share_expiration // 1000.0)
                    return 'Blocked' if expire_at < datetime.datetime.now() else 'Pending Transfer'
                else:
                    return 'Active'
            else:
                return 'Locked' if user.lock == 1 else 'Disabled'
        else:
            return 'Invited'

    @staticmethod
    def filter_managed_nodes(enterprise_data: enterprise_types.IEnterpriseData, managed_nodes: Dict[int, Set[int]], root_node_id: int) -> Dict[int, Set[int]]:
        subnodes = NodeUtils.get_subnodes(enterprise_data)

        result: Dict[int, Set[int]] = {}
        for node_id, s_nodes in managed_nodes.items():
            if node_id == root_node_id:
                result[node_id] = set(s_nodes)
            elif node_id in s_nodes:
                nodes = [node_id]
                pos = 0
                while pos < len(nodes):
                    n_id = nodes[pos]
                    pos += 1
                    if n_id in subnodes:
                        nodes.extend(subnodes[n_id])
                result[node_id] = set(nodes)

        return result

    @staticmethod
    def expand_managed_nodes(managed_nodes: Dict[int, bool], subnodes: Dict[int, Set[int]]) -> Dict[int, Set[int]]:
        result: Dict[int, Set[int]] = {}
        for node_id, cascade in managed_nodes.items():
            nodes = [node_id]
            if cascade:
                pos = 0
                while pos < len(nodes):
                    n_id = nodes[pos]
                    pos += 1
                    if n_id in subnodes:
                        nodes.extend(subnodes[n_id])
                result[node_id] = set(nodes)
        # TODO get rid of duplicates
        return result

    @staticmethod
    def get_managed_nodes_for_user(enterprise_data: enterprise_types.IEnterpriseData, username: str) -> Dict[int, bool]:
        result: Dict[int, bool] = {}

        enterprise_user_id = next((x.enterprise_user_id for x in enterprise_data.users.get_all_entities()
                                   if x.username == username), None)
        if enterprise_user_id is None:
            return result

        user_roles = {x.role_id for x in enterprise_data.role_users.get_all_links()
                      if x.enterprise_user_id == enterprise_user_id}

        for x in enterprise_data.managed_nodes.get_all_links():
            if x.role_id not in user_roles:
                continue
            if x.managed_node_id == enterprise_data.root_node.node_id and x.cascade_node_management:
                result.clear()
                result[enterprise_data.root_node.node_id] = True
                break

            if x.managed_node_id not in result:
                result[x.managed_node_id] = x.cascade_node_management
            else:
                if x.cascade_node_management:
                    result[x.managed_node_id] = x.cascade_node_management
        return result


def is_addon_enabled(context: KeeperParams, addon_name: str) -> bool:
    keeper_licenses = context.enterprise_data.licenses.get_all_entities()
    for license in keeper_licenses:
        license.license_status
    if not keeper_licenses:
        raise base.CommandError('No licenses found')
    if next(iter(keeper_licenses), {}).license_status == BUSINESS_TRIAL:
        return True
    addons = [a for l in keeper_licenses for a in l.add_ons if a.name == addon_name]
    return any(a for a in addons if a.enabled or a.included_in_product)

'''
    def _load_managed_nodes(self, context: KeeperParams) -> None:
        enterprise_data = context.enterprise_data
        assert enterprise_data is not None
        nodes = enterprise_data.nodes
        current_user = context.auth.auth_context

        root_node_id = enterprise_data.root_node.node_id
        enterprise_user_id = next((x.enterprise_user_id for x in enterprise_data.users.get_all_entities()
                                   if x.username == current_user), None)
        assert enterprise_user_id is not None

        root_nodes: Set[int] = set()
        managed_nodes: Set[int] = set()

        current_user_roles = set((x.role_id for x in enterprise_data.role_users.get_links_by_object(enterprise_user_id)))
        is_main_admin = any(True for x in enterprise_data.managed_nodes.get_all_links()
                            if x.role_id in current_user_roles and x.cascade_node_management and x.managed_node_id == root_node_id)

        if is_main_admin:
            root_nodes.add(root_node_id)
            managed_nodes.update((x.node_id for x in enterprise_data.nodes.get_all_entities()))
        else:
            singles = []
            for mn in enterprise_data.managed_nodes.get_all_links():
                role_id = mn.role_id
                if role_id not in current_user_roles:
                    continue
                node_id = mn.managed_node_id
                if mn.cascade_node_management:
                    managed_nodes.add(node_id)
                else:
                    singles.append(node_id)

            missed = set()
            lookup = {x.node_id: x for x in nodes.get_all_entities()}
            for node in nodes.get_all_entities():
                node_id = node.node_id
                if node_id in managed_nodes:
                    continue

                stack = []
                while node_id in lookup:
                    if node_id in managed_nodes:
                        managed_nodes.update(stack)
                        stack.clear()
                        break
                    if node_id in missed:
                        break
                    stack.append(node_id)
                    node_id = lookup[node_id].parent_id or 0
                missed.update(stack)
            managed_nodes.update(singles)

            for mn in enterprise_data.managed_nodes.get_all_links():
                role_id = mn.role_id
                if role_id not in current_user_roles:
                    continue
                node_id = mn.managed_node_id
                if node_id in lookup:
                    parent_id = lookup[node_id].parent_id or 0
                    if parent_id not in managed_nodes:
                        root_nodes.add(node_id)

        self.user_root_nodes = list(root_nodes)
        self.user_managed_nodes = list(managed_nodes)

    def get_user_managed_nodes(self, context: KeeperParams) -> Iterable[int]:
        if self.user_managed_nodes is None:
            self._load_managed_nodes(context)

        for x in self.user_managed_nodes:
            yield x

    def get_user_root_nodes(self, context: KeeperParams) -> Iterable[int]:
        if self.user_managed_nodes is None:
            self._load_managed_nodes(context)

        for x in self.user_root_nodes:
            yield x


    def get_managed_nodes(self, context: KeeperParams) -> Tuple[Set[int], List[int]]:
        user_managed_nodes = set(self.get_user_managed_nodes(context))
        node_scope: Set[int] = set()
        root_nodes: List[int]

        if kwargs.get('node'):
            subnode = kwargs.get('node').lower()
            root_nodes = [x.node_id for x in self.resolve_nodes(context, subnode) if x.node_id in user_managed_nodes]
            if len(root_nodes) == 0:
                logger.warning('Node \"%s\" not found', subnode)
                return
            if len(root_nodes) > 1:
                logger.warning('More than one node \"%s\" found. Use Node ID.', subnode)
                return
            logger.info('Output is limited to \"%s\" node', subnode)

            node_tree = {}
            for node in context.enterprise_data.nodes.get_all_entities():
                if node.parent_id not in node_tree:
                    node_tree[node.parent_id] = []
                node_tree[node.parent_id].append(node.node_id)

            nl = [x for x in root_nodes]
            pos = 0
            while pos < len(nl):
                if nl[pos] in node_tree:
                    nl.extend(node_tree[nl[pos]])
                pos += 1
                if pos > 100:
                    break
            node_scope.update([x for x in nl if x in user_managed_nodes])
        else:
            node_scope.update((x.node_id for x in context.enterprise_data.nodes.get_all_entities()
                               if x.node_id in user_managed_nodes))
            root_nodes = list(self.get_user_root_nodes(context))

        return node_scope, root_nodes
'''