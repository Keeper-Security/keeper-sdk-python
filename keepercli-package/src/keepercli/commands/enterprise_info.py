import argparse
import asciitree
import collections
import json
from typing import Set, List, Dict, Tuple, Any, Optional

from keepersdk.enterprise import enterprise_types

from . import base, enterprise_command
from .. import api
from ..params import KeeperParams


class EnterpriseInfoCommand(base.GroupCommand):
    def __init__(self):
        super().__init__('Print Enterprise Information')
        self.register_command(EnterpriseInfoTreeCommand(), 'tree', 't')
        self.default_verb = 'tree'


class EnterpriseInfoTreeCommand(base.ArgparseCommand, enterprise_command.EnterpriseMixin):
    parser = argparse.ArgumentParser(prog='enterprise-info tree',
                                     description='Display a tree structure of your enterprise.',
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--node', dest='node', action='store', help='limit results to node (name or ID)')
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='print verbose information')

    def __init__(self):
        super().__init__(EnterpriseInfoTreeCommand.parser)

    def execute(self, context: KeeperParams, **kwargs):
        assert context.enterprise_data is not None
        assert context.auth is not None
        enterprise_data = context.enterprise_data

        logger = api.get_logger()

        subnodes = self.get_subnodes(enterprise_data)
        root_nodes: Dict[int, bool] = self.get_managed_nodes_for_user(enterprise_data, context.auth.auth_context.username)
        managed_nodes = self.expand_managed_nodes(root_nodes, subnodes)

        accessible_nodes: Set[int] = set()

        subnode: Optional[str] = kwargs.get('node')
        if isinstance(subnode, str) and subnode:
            for node_id, node_ids in managed_nodes.items():
                accessible_nodes.update(node_ids)

            subnode = subnode.lower()
            root_node = [x.node_id for x in self.resolve_nodes(context, subnode) if x.node_id in accessible_nodes]
            if len(root_node) == 0:
                logger.warning('Node \"%s\" not found', subnode)
                return
            if len(root_node) > 1:
                logger.warning('More than one node \"%s\" found. Use Node ID.', subnode)
                return
            logger.info('Output is limited to \"%s\" node', subnode)

            managed_nodes = self.filter_managed_nodes(enterprise_data, managed_nodes, root_node[0])

        accessible_nodes.clear()
        for node_id, node_ids in managed_nodes.items():
            accessible_nodes.update(node_ids)

        nodes = enterprise_data.nodes
        verbose = kwargs.get('verbose') is True
        users: Dict[int, List[enterprise_types.User]] = {}
        for user in enterprise_data.users.get_all_entities():
            if user.node_id not in accessible_nodes:
                continue
            if user.node_id not in users:
                users[user.node_id] = []
            users[user.node_id].append(user)

        roles: Dict[int, List[enterprise_types.Role]] = {}
        for role in enterprise_data.roles.get_all_entities():
            if role.node_id not in accessible_nodes:
                continue
            if role.node_id not in roles:
                roles[role.node_id] = []
            roles[role.node_id].append(role)

        teams: Dict[int, List[enterprise_types.Team]] = {}
        for team in enterprise_data.teams.get_all_entities():
            if team.node_id not in accessible_nodes:
                continue
            if team.node_id not in teams:
                teams[team.node_id] = []
            teams[team.node_id].append(team)

        queued_teams: Dict[int, List[enterprise_types.QueuedTeam]] = {}
        for queued_team in enterprise_data.queued_teams.get_all_entities():
            if queued_team.node_id not in accessible_nodes:
                continue
            if queued_team.node_id not in queued_teams:
                teams[queued_team.node_id] = []
            queued_teams[queued_team.node_id].append(queued_team)

        def tree_node(node: enterprise_types.Node) -> Tuple[str, Dict[str, dict]]:
            node_name = node.name
            if not node_name:
                node_name = enterprise_data.enterprise_info.enterprise_name
            if verbose:
                node_name += f' ({node.node_id})'
            node_name += ' |Isolated| ' if node.restrict_visibility else ''

            children = [x for x in (nodes.get_entity(y) for y in subnodes.get(node.node_id, set())) if x is not None]
            children.sort(key=lambda x: x.name)
            n = collections.OrderedDict()
            for ch in children:
                n_name, n_tree = tree_node(ch)
                n[n_name] = n_tree

            node_users = users.get(node.node_id)
            if isinstance(node_users, list) and len(node_users) > 0:
                if verbose:
                    node_users.sort(key=lambda x: x.username)
                    ud: Dict[str, Any] = collections.OrderedDict()
                    u: enterprise_types.User
                    for u in node_users:
                        extra = self.get_user_status_dict(u)
                        ud[f'{u.username} ({u.enterprise_user_id}) |{extra}|'] = {}
                    n['User(s)'] = ud
                else:
                    n[f'{len(node_users)} user(s)'] = {}

            node_roles = roles.get(node.node_id)
            if isinstance(node_roles, list) and len(node_roles) > 0:
                if verbose:
                    node_roles.sort(key=lambda x: x.name)
                    td: Dict[str, Any] = collections.OrderedDict()
                    r: enterprise_types.Role
                    for i, r in enumerate(node_roles):
                        td[f'{r.name} ({r.role_id})'] = {}
                        if i >= 50:
                            td[f'{len(node_roles) - i} more role(s)'] = {}
                            break
                    n['Role(s)'] = td
                else:
                    n[f'{len(node_roles)} role(s)'] = {}

            node_teams = teams.get(node.node_id)
            if isinstance(node_teams, list) and len(node_teams) > 0:
                if verbose:
                    node_teams.sort(key=lambda x: x.name)
                    td = collections.OrderedDict()
                    t: enterprise_types.Team
                    for i, t in enumerate(node_teams):
                        td[f'{t.name} ({t.team_uid})'] = {}
                        if i >= 50:
                            td[f'{len(node_teams) - i} more team(s)'] = {}
                            break
                    n['Teams(s)'] = td
                else:
                    n[f'{len(node_teams)} team(s)'] = {}

            node_queued_teams = queued_teams.get(node.node_id)
            if isinstance(node_queued_teams, list) and len(node_queued_teams) > 0:
                if verbose:
                    node_queued_teams.sort(key=lambda x: x.name)
                    td = collections.OrderedDict()
                    qt: enterprise_types.QueuedTeam
                    for i, qt in enumerate(node_queued_teams):
                        td[f'{qt.name} ({qt.team_uid})'] = {}
                        if i >= 50:
                            td[f'{len(node_queued_teams) - i} more queued team(s)'] = {}
                            break
                    n['Queued Teams(s)'] = td
                else:
                    n[f'{len(node_queued_teams)} queued team(s)'] = {}
            return node_name, n

        tree = collections.OrderedDict()
        for node_id in managed_nodes:
            node = enterprise_data.nodes.get_entity(node_id)
            if not node:
                continue
            r_name, r_tree = tree_node(node)
            tree[r_name] = r_tree
        if len(managed_nodes) > 1:
            tree = collections.OrderedDict([('', tree)])

        tr = asciitree.LeftAligned()
        return tr(tree)
