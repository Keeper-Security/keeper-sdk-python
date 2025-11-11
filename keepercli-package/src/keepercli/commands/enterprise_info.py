import argparse
import collections
from typing import Set, List, Dict, Tuple, Any, Optional, Union

import asciitree

from keepersdk.enterprise import enterprise_types
from . import base, enterprise_utils
from .. import api
from ..helpers import report_utils
from ..params import KeeperParams

SUPPORTED_NODE_COLUMNS = ['parent_node', 'user_count', 'users', 'team_count', 'teams', 'role_count', 'roles',
                          'provisioning']
SUPPORTED_USER_COLUMNS = ['name', 'status', 'transfer_status', 'node', 'role_count', 'roles', 'team_count', 'teams',
                          'queued_team_count', 'queued_teams', 'alias', '2fa_enabled']
SUPPORTED_TEAM_COLUMNS = ['restricts', 'node', 'user_count', 'users', 'queued_user_count', 'queued_users', 'role_count', 'roles']
SUPPORTED_ROLE_COLUMNS = ['visible_below', 'default_role', 'admin', 'node', 'user_count', 'users', 'team_count', 'teams']


class EnterpriseDownCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='enterprise-down', description='Download enterprise data.')
        parser.add_argument('--reset', dest='reset', action='store_true',
                            help='reload enterprise data')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        enterprise_loader = context.enterprise_loader
        assert enterprise_loader is not None

        reset: Optional[bool] = None
        if kwargs.get('reset') is True:
            reset = True
        enterprise_loader.load(reset=reset or False)


class EnterpriseInfoCommand(base.GroupCommand):
    def __init__(self):
        super().__init__('Print Enterprise Information')
        self.register_command(EnterpriseInfoTreeCommand(), 'tree')
        self.register_command(EnterpriseInfoNodeCommand(), 'node', 'n')
        self.register_command(EnterpriseInfoUserCommand(), 'user', 'u')
        self.register_command(EnterpriseInfoTeamCommand(), 'team', 't')
        self.register_command(EnterpriseInfoRoleCommand(), 'role', 'r')
        self.register_command(EnterpriseInfoManagedCompanyCommand(), 'managed-company', 'mc')
        self.default_verb = 'tree'


class EnterpriseInfoTreeCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='enterprise-info tree',
                                         description='Display a tree structure of your enterprise.',
                                         formatter_class=argparse.RawTextHelpFormatter)
        parser.add_argument('--node', dest='node', action='store', help='limit results to node (name or ID)')
        parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='print verbose information')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs):
        assert context.enterprise_data is not None
        assert context.auth is not None
        enterprise_data = context.enterprise_data

        logger = api.get_logger()

        subnodes =  enterprise_utils.NodeUtils.get_subnodes(enterprise_data)
        root_nodes: Dict[int, bool]
        if context.auth.auth_context.is_mc_superadmin:
            root_nodes = {
                enterprise_data.root_node.node_id: True
            }
        else:
            root_nodes = enterprise_utils.EnterpriseMixin.get_managed_nodes_for_user(enterprise_data, context.auth.auth_context.username)
        managed_nodes = enterprise_utils.EnterpriseMixin.expand_managed_nodes(root_nodes, subnodes)

        accessible_nodes: Set[int] = set()

        subnode: Optional[str] = kwargs.get('node')
        if isinstance(subnode, str) and subnode:
            for node_id, node_ids in managed_nodes.items():
                accessible_nodes.update(node_ids)

            subnode = subnode.lower()
            root_node = enterprise_utils.NodeUtils.resolve_single_node(enterprise_data, subnode)
            logger.info('Output is limited to \"%s\" node', subnode)

            managed_nodes = enterprise_utils.EnterpriseMixin.filter_managed_nodes(enterprise_data, managed_nodes, root_nodes[0])

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
                        extra = enterprise_utils.EnterpriseMixin.get_user_status_dict(u)
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


class EnterpriseInfoNodeCommand(base.ArgparseCommand, enterprise_utils.EnterpriseMixin):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='enterprise-info node', parents=[base.report_output_parser],
                                         description='Display node information.',
                                         formatter_class=argparse.RawTextHelpFormatter)
        parser.add_argument('-c', '--columns', dest='columns', action='store',
                            help='comma-separated list of available columns per argument: ' + ', '.join(SUPPORTED_NODE_COLUMNS))
        parser.add_argument('pattern', nargs='?', type=str, help='search pattern')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs):
        assert context.enterprise_data is not None
        enterprise_data = context.enterprise_data

        columns: Set[str] = set()
        show_columns = kwargs.get('columns')
        if show_columns:
            if show_columns == '*':
                columns.update(SUPPORTED_NODE_COLUMNS)
            else:
                columns.update((x.strip() for x in show_columns.split(',')))
        if len(columns) == 0:
            columns.update(('parent_node', 'user_count', 'team_count', 'role_count'))

        columns = columns.intersection(SUPPORTED_NODE_COLUMNS)
        pattern = (kwargs.get('pattern') or '').lower()

        users: Dict[int, List[str]] = {}
        for user in enterprise_data.users.get_all_entities():
            if user.node_id not in users:
                users[user.node_id] = []
            users[user.node_id].append(user.username)

        teams: Dict[int, List[str]] = {}
        for team in enterprise_data.teams.get_all_entities():
            if team.node_id not in teams:
                teams[team.node_id] = []
            teams[team.node_id].append(team.name)

        roles: Dict[int, List[str]] = {}
        for role in enterprise_data.roles.get_all_entities():
            if role.node_id not in roles:
                roles[role.node_id] = []
            roles[role.node_id].append(role.name)

        email_provisioning: Dict[int, str] = {}
        scim_provisioning: Dict[int, str] = {}
        bridge_provisioning: Dict[int, str] = {}
        sso_provisioning: Dict[int, Union[str, List[str]]] = {}

        displayed_columns = [x for x in SUPPORTED_NODE_COLUMNS if x in columns if x != 'provisioning']
        if 'provisioning' in columns:
            columns.remove('provisioning')
            for email in enterprise_data.email_provision.get_all_entities():
                email_provisioning[email.node_id] = email.domain
            if len(email_provisioning) > 0:
                displayed_columns.append('email_provisioning')

            for bridge in enterprise_data.bridges.get_all_entities():
                bridge_provisioning[bridge.node_id] = bridge.status
            if len(bridge_provisioning) > 0:
                displayed_columns.append('bridge_provisioning')

            for scim in enterprise_data.scims.get_all_entities():
                scim_provisioning[scim.node_id] = scim.status
            if len(scim_provisioning) > 0:
                displayed_columns.append('scim_provisioning')

            for sso in enterprise_data.sso_services.get_all_entities():
                if sso.node_id in sso_provisioning:
                    ssos = sso_provisioning[sso.node_id]
                    if not isinstance(ssos, list):
                        ssos = [ssos]
                    ssos.append(sso.name)
                    sso_provisioning[sso.node_id] = ssos
                else:
                    sso_provisioning[sso.node_id] = sso.name
            if len(sso_provisioning) > 0:
                displayed_columns.append('sso_provisioning')

        rows = []
        for n in enterprise_data.nodes.get_all_entities():
            node_id = n.node_id
            row: List[Any] = [node_id, n.name]
            for column in displayed_columns:
                if column == 'parent_node':
                    parent_id = n.parent_id or 0
                    row.append(enterprise_utils.NodeUtils.get_node_path(enterprise_data, parent_id) if parent_id > 0 else '')
                elif column in {'user_count', 'users'}:
                    us = users.get(node_id) or []
                    row.append(len(us) if column == 'user_count' else us)
                elif column in {'team_count', 'teams'}:
                    ts = teams.get(node_id) or []
                    row.append(len(ts) if column == 'team_count' else ts)
                elif column in {'role_count', 'roles'}:
                    rs = roles.get(node_id) or []
                    row.append(len(rs) if column == 'role_count' else rs)
                elif column == 'email_provisioning':
                    status = email_provisioning.get(node_id)
                    row.append(status)
                elif column == 'bridge_provisioning':
                    status = bridge_provisioning.get(node_id)
                    row.append(status)
                elif column == 'scim_provisioning':
                    status = scim_provisioning.get(node_id)
                    row.append(status)
                elif column == 'sso_provisioning':
                    sso_names = sso_provisioning.get(node_id)
                    row.append(sso_names)
                else:
                    row.append(None)

            if pattern:
                if not any(1 for x in self.tokenize_row(row) if x and str(x).lower().find(pattern) >= 0):
                    continue
            rows.append(row)

        rows.sort(key=lambda x: x[1])
        headers = ['node_id', 'name']
        headers.extend(displayed_columns)
        if kwargs.get('format') != 'json':
            headers = [report_utils.field_to_title(x) for x in headers]

        return report_utils.dump_report_data(rows, headers, fmt=kwargs.get('format'), filename=kwargs.get('output'))


class EnterpriseInfoUserCommand(base.ArgparseCommand, enterprise_utils.EnterpriseMixin):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='enterprise-info user', parents=[base.report_output_parser],
                                         description='Display user information.',
                                         formatter_class=argparse.RawTextHelpFormatter)
        parser.add_argument('-c', '--columns', dest='columns', action='store',
                            help='comma-separated list of available columns per argument: ' + ', '.join(SUPPORTED_USER_COLUMNS))
        parser.add_argument('pattern', nargs='?', type=str, help='search pattern')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs):
        assert context.enterprise_data is not None
        enterprise_data = context.enterprise_data

        columns: Set[str] = set()
        show_columns = kwargs.get('columns')
        if show_columns:
            if show_columns == '*':
                columns.update(SUPPORTED_USER_COLUMNS)
            else:
                columns.update((x.strip() for x in show_columns.split(',')))
        if len(columns) == 0:
            columns.update(('name', 'status', 'transfer_status', 'node'))

        columns = columns.intersection(SUPPORTED_USER_COLUMNS)
        pattern = (kwargs.get('pattern') or '').lower()

        team_users: Dict[int, Set[str]] = {}
        user_teams: Dict[str, Set[int]] = {}
        for team_user in enterprise_data.team_users.get_all_links():
            if team_user.enterprise_user_id not in team_users:
                team_users[team_user.enterprise_user_id] = set()
            team_users[team_user.enterprise_user_id].add(team_user.team_uid)
            if team_user.team_uid not in user_teams:
                user_teams[team_user.team_uid] = set()
            user_teams[team_user.team_uid].add(team_user.enterprise_user_id)

        role_users: Dict[int, Set[int]] = {}
        for role_user in enterprise_data.role_users.get_all_links():
            if role_user.enterprise_user_id not in role_users:
                role_users[role_user.enterprise_user_id] = set()
            role_users[role_user.enterprise_user_id].add(role_user.role_id)

        for role_team in enterprise_data.role_teams.get_all_links():
            if role_team.role_id not in role_users:
                role_users[role_team.role_id] = set()
            if role_team.team_uid in user_teams:
                role_users[role_team.role_id].update(user_teams[role_team.team_uid])

        user_aliases: Dict[int, Set[str]] = {}
        for alas in enterprise_data.user_aliases.get_all_links():
            if alas.enterprise_user_id not in user_aliases:
                user_aliases[alas.enterprise_user_id] = set()
            user_aliases[alas.enterprise_user_id].add(alas.username)

        displayed_columns = [x for x in SUPPORTED_USER_COLUMNS if x in columns]

        rows = []
        for u in enterprise_data.users.get_all_entities():
            user_id = u.enterprise_user_id
            row: List[Any] = [user_id, u.username]
            for column in displayed_columns:
                if column == 'name':
                    row.append(u.full_name)
                elif column == 'status':
                    row.append(enterprise_utils.UserUtils.get_user_status_text(u))
                elif column == 'transfer_status':
                    row.append(enterprise_utils.UserUtils.get_user_transfer_status_text(u))
                elif column == 'node':
                    row.append(enterprise_utils.NodeUtils.get_node_path(enterprise_data, u.node_id, omit_root=True))
                elif column == 'queued_team_count':
                    qts = {x.team_uid for x in enterprise_data.queued_team_users.get_links_by_object(user_id)}
                    row.append(len(qts) if qts else 0)
                elif column == 'queued_teams':
                    qts = {x.team_uid for x in enterprise_data.queued_team_users.get_links_by_object(user_id)}
                    if len(qts) > 0:
                        team_names: List[str] = []
                        teams = {t.name for t in (enterprise_data.teams.get_entity(x) for x in qts) if t}
                        if len(teams) > 0:
                            team_names.extend(teams)
                        queued_teams = [t.name for t in (enterprise_data.queued_teams.get_entity(x) for x in qts) if t]
                        if len(queued_teams) > 0:
                            team_names.extend(queued_teams)
                        team_names.sort()
                        row.append(team_names)
                    else:
                        row.append(None)
                elif column == 'team_count':
                    ts = team_users.get(user_id)
                    row.append(len(ts) if ts else 0)
                elif column == 'teams':
                    ts = team_users.get(user_id)
                    if ts is not None:
                        team_names = [t.name for t in (enterprise_data.teams.get_entity(x) for x in ts) if t]
                        team_names.sort()
                        row.append(team_names)
                    else:
                        row.append(None)
                elif column == 'role_count':
                    rs = role_users.get(user_id)
                    row.append(len(rs) if rs else 0)
                elif column == 'roles':
                    rs = role_users.get(user_id)
                    if rs is not None:
                        role_names = [r.name for r in (enterprise_data.roles.get_entity(x) for x in rs) if r]
                        role_names.sort()
                        row.append(role_names)
                    else:
                        row.append(None)
                elif column == 'alias':
                    aliases = user_aliases.get(user_id)
                    if aliases is not None:
                        asal = [x for x in aliases if x != u.username]
                        asal.sort()
                        row.append(asal)
                    else:
                        row.append(None)
                elif column == '2fa_enabled':
                    row.append(u.tfa_enabled)
                else:
                    row.append(None)

            if pattern:
                if not any(1 for x in self.tokenize_row(row) if x and str(x).lower().find(pattern) >= 0):
                    continue
            rows.append(row)

        rows.sort(key=lambda x: x[1])
        headers = ['user_id', 'email']
        headers.extend(displayed_columns)
        if kwargs.get('format') != 'json':
            headers = [report_utils.field_to_title(x) for x in headers]

        return report_utils.dump_report_data(rows, headers, fmt=kwargs.get('format'), filename=kwargs.get('output'))


class EnterpriseInfoTeamCommand(base.ArgparseCommand, enterprise_utils.EnterpriseMixin):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='enterprise-info team', parents=[base.report_output_parser],
                                         description='Display team information.',
                                         formatter_class=argparse.RawTextHelpFormatter)
        parser.add_argument('-c', '--columns', dest='columns', action='store',
                            help='comma-separated list of available columns per argument: ' + ', '.join(SUPPORTED_TEAM_COLUMNS))
        parser.add_argument('pattern', nargs='?', type=str, help='search pattern')
        super().__init__(parser)

    @staticmethod
    def restricts(team: enterprise_types.Team) -> str:
        rs = ''
        rs += 'R ' if team.restrict_view else '  '
        rs += 'W ' if team.restrict_edit else '  '
        rs += 'S' if team.restrict_share else ' '
        return rs

    def execute(self, context: KeeperParams, **kwargs):
        assert context.enterprise_data is not None
        enterprise_data = context.enterprise_data

        columns: Set[str] = set()
        show_columns = kwargs.get('columns')
        if show_columns:
            if show_columns == '*':
                columns.update(SUPPORTED_TEAM_COLUMNS)
            else:
                columns.update((x.strip() for x in show_columns.split(',')))
        if len(columns) == 0:
            columns.update(('restricts', 'node', 'user_count'))

        columns = columns.intersection(SUPPORTED_TEAM_COLUMNS)
        pattern = (kwargs.get('pattern') or '').lower()

        user_teams: Dict[str, Set[int]] = {}
        for team_user in enterprise_data.team_users.get_all_links():
            if team_user.team_uid not in user_teams:
                user_teams[team_user.team_uid] = set()
            user_teams[team_user.team_uid].add(team_user.enterprise_user_id)

        queued_user_teams: Dict[str, Set[int]] = {}
        for queued_user_team in enterprise_data.queued_team_users.get_all_links():
            if queued_user_team.team_uid not in queued_user_teams:
                queued_user_teams[queued_user_team.team_uid] = set()
            queued_user_teams[queued_user_team.team_uid].add(queued_user_team.enterprise_user_id)

        role_teams: Dict[str, Set[int]] = {}
        for role_team in enterprise_data.role_teams.get_all_links():
            if role_team.team_uid not in role_teams:
                role_teams[role_team.team_uid] = set()
            role_teams[role_team.team_uid].add(role_team.role_id)

        displayed_columns = [x for x in SUPPORTED_TEAM_COLUMNS if x in columns]

        rows = []
        row: List[Any]
        for t in enterprise_data.teams.get_all_entities():
            team_uid = t.team_uid
            row = [team_uid, t.name]
            for column in displayed_columns:
                if column == 'restricts':
                    row.append(self.restricts(t))
                elif column == 'node':
                    row.append(enterprise_utils.NodeUtils.get_node_path(enterprise_data, t.node_id, omit_root=True))
                elif column == 'user_count':
                    us = user_teams.get(team_uid)
                    row.append(len(us) if us else 0)
                elif column == 'users':
                    us = user_teams.get(team_uid)
                    if us is not None:
                        usernames = [u.username for u in (enterprise_data.users.get_entity(x) for x in us) if u]
                        usernames.sort()
                        row.append(usernames)
                    else:
                        row.append(None)
                elif column == 'queued_user_count':
                    qus = queued_user_teams.get(team_uid)
                    row.append(len(qus) if qus else 0)
                elif column == 'queued_users':
                    qus = queued_user_teams.get(team_uid)
                    if qus is not None:
                        usernames = [u.username for u in (enterprise_data.users.get_entity(x) for x in qus) if u]
                        usernames.sort()
                        row.append(usernames)
                    else:
                        row.append(None)
                elif column == 'role_count':
                    rs = role_teams.get(team_uid)
                    row.append(len(rs) if rs else 0)
                elif column == 'roles':
                    rs = role_teams.get(team_uid)
                    if rs is not None:
                        role_names = [r.name for r in (enterprise_data.roles.get_entity(x) for x in rs) if r]
                        role_names.sort()
                        row.append(role_names)
                    else:
                        row.append(None)
                else:
                    row.append(None)

            if pattern:
                if not any(1 for x in self.tokenize_row(row) if x and str(x).lower().find(pattern) >= 0):
                    continue
            rows.append(row)

        for qt in enterprise_data.queued_teams.get_all_entities():
            team_uid = qt.team_uid
            row = [team_uid, qt.name]
            for column in displayed_columns:
                if column == 'restricts':
                    row.append('Queued')
                elif column == 'node':
                    row.append(enterprise_utils.NodeUtils.get_node_path(enterprise_data, qt.node_id, omit_root=True))
                elif column == 'queued_user_count':
                    qus = queued_user_teams.get(team_uid)
                    row.append(len(qus) if qus else 0)
                elif column == 'queued_users':
                    qus = queued_user_teams.get(team_uid)
                    if qus is not None:
                        usernames = [u.username for u in (enterprise_data.users.get_entity(x) for x in qus) if u]
                        usernames.sort()
                        row.append(usernames)
                    else:
                        row.append(None)
                else:
                    row.append(None)
            if pattern:
                if not any(1 for x in row if x and str(x).lower().find(pattern) >= 0):
                    continue
            rows.append(row)

        rows.sort(key=lambda x: x[1])
        headers = ['team_uid', 'name']
        headers.extend(displayed_columns)
        if kwargs.get('format') != 'json':
            headers = [report_utils.field_to_title(x) for x in headers]

        return report_utils.dump_report_data(rows, headers, fmt=kwargs.get('format'), filename=kwargs.get('output'))


class EnterpriseInfoRoleCommand(base.ArgparseCommand, enterprise_utils.EnterpriseMixin):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='enterprise-info role', parents=[base.report_output_parser],
                                         description='Display role information.',
                                         formatter_class=argparse.RawTextHelpFormatter)
        parser.add_argument('-c', '--columns', dest='columns', action='store',
                            help='comma-separated list of available columns per argument: ' + ', '.join(SUPPORTED_ROLE_COLUMNS))
        parser.add_argument('pattern', nargs='?', type=str, help='search pattern')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs):
        assert context.enterprise_data is not None
        enterprise_data = context.enterprise_data

        columns: Set[str] = set()
        show_columns = kwargs.get('columns')
        if isinstance(show_columns, str):
            if show_columns == '*':
                columns.update(SUPPORTED_ROLE_COLUMNS)
            else:
                columns.update((x.strip() for x in show_columns.split(',')))
        if len(columns) == 0:
            columns.update(('default_role', 'admin', 'node', 'user_count'))

        columns = columns.intersection(SUPPORTED_ROLE_COLUMNS)
        pattern = (kwargs.get('pattern') or '').lower()

        role_users: Dict[int, Set[int]] = {}
        for role_user in enterprise_data.role_users.get_all_links():
            if role_user.role_id not in role_users:
                role_users[role_user.role_id] = set()
            role_users[role_user.role_id].add(role_user.enterprise_user_id)

        role_teams: Dict[int, Set[str]] = {}
        for role_team in enterprise_data.role_teams.get_all_links():
            if role_team.role_id not in role_teams:
                role_teams[role_team.role_id] = set()
            role_teams[role_team.role_id].add(role_team.team_uid)

        displayed_columns = [x for x in SUPPORTED_ROLE_COLUMNS if x in columns]

        rows = []
        for r in enterprise_data.roles.get_all_entities():
            role_id = r.role_id
            row: List[Any] = [role_id, r.name]
            for column in displayed_columns:
                if column == 'visible_below':
                    row.append(r.visible_below)
                elif column == 'default_role':
                    row.append(r.new_user_inherit)
                elif column == 'admin':
                    is_admin = any((True for x in enterprise_data.managed_nodes.get_links_by_subject(role_id)))
                    row.append(is_admin)
                elif column == 'node':
                    row.append(enterprise_utils.NodeUtils.get_node_path(enterprise_data, r.node_id, omit_root=True))
                elif column == 'user_count':
                    us = role_users.get(role_id)
                    row.append(len(us) if us else 0)
                elif column == 'users':
                    us = role_users.get(role_id)
                    if us is not None:
                        usernames = [u.username for u in (enterprise_data.users.get_entity(x) for x in us) if u]
                        usernames.sort()
                        row.append(usernames)
                    else:
                        row.append(None)
                elif column == 'team_count':
                    ts = role_teams.get(role_id)
                    row.append(len(ts) if ts else 0)
                elif column == 'teams':
                    ts = role_teams.get(role_id)
                    if ts is not None:
                        team_names = [t.name for t in (enterprise_data.teams.get_entity(x) for x in ts) if t]
                        team_names.sort()
                        row.append(team_names)
                    else:
                        row.append(None)
                else:
                    row.append(None)

            if pattern:
                if not any(1 for x in self.tokenize_row(row) if x and str(x).lower().find(pattern) >= 0):
                    continue
            rows.append(row)

        rows.sort(key=lambda x: x[1])
        headers = ['role_id', 'name']
        headers.extend(displayed_columns)
        if kwargs.get('format') != 'json':
            headers = [report_utils.field_to_title(x) for x in headers]

        return report_utils.dump_report_data(rows, headers, fmt=kwargs.get('format'), filename=kwargs.get('output'))


class EnterpriseInfoManagedCompanyCommand(base.ArgparseCommand, enterprise_utils.EnterpriseMixin):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='enterprise-info mc', parents=[base.report_output_parser],
                                         description='Display managed company information.',
                                         formatter_class=argparse.RawTextHelpFormatter)
        parser.add_argument('pattern', nargs='?', type=str, help='search pattern')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs):
        assert context.enterprise_data is not None
        enterprise_data = context.enterprise_data
        
        pattern = (kwargs.get('pattern') or '').lower()
        
        rows = []
        for idx, mc in enumerate(enterprise_data.managed_companies.get_all_entities(), 1):
            # Map product IDs to plan names
            plan_name = mc.product_id
            if mc.product_id == 'enterprise':
                plan_name = 'Enterprise'
            elif mc.product_id == 'enterprise_plus':
                plan_name = 'Enterprise Plus'
            elif mc.product_id == 'business':
                plan_name = 'Business'
            elif mc.product_id == 'businessPlus':
                plan_name = 'Business Plus'
            
            # Get storage info from file_plan_type
            storage = mc.file_plan_type if mc.file_plan_type else ''
            
            # Count add-ons
            addon_count = len(mc.add_ons) if mc.add_ons else 0
            
            # Get node name
            node_name = enterprise_utils.NodeUtils.get_node_path(enterprise_data, mc.msp_node_id, omit_root=True)

            allocated: Optional[int] = mc.number_of_seats
            if allocated == 2147483647:
                allocated = None
            
            # Get active users
            active = mc.number_of_users if mc.number_of_users else 0
            
            row = [mc.mc_enterprise_id, mc.mc_enterprise_name, node_name, plan_name, storage, addon_count, allocated, active]
            
            if pattern:
                if not any(1 for x in self.tokenize_row(row) if x and str(x).lower().find(pattern) >= 0):
                    continue
            rows.append(row)
        
        headers = ['company_id', 'company_name', 'node', 'plan', 'storage', 'addons', 'allocated', 'active']
        if kwargs.get('format') != 'json':
            headers = [report_utils.field_to_title(x) for x in headers]
        return report_utils.dump_report_data(rows, headers, fmt=kwargs.get('format'), filename=kwargs.get('output'))
