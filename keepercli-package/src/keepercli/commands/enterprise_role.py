import argparse
import json
from typing import Dict, List, Optional, Set, Any

from keepersdk.enterprise import enterprise_types, batch_management, enterprise_management, enterprise_constants
from keepersdk.vault import storage_types
from . import base, enterprise_utils
from .. import api, prompt_utils
from ..helpers import report_utils
from ..params import KeeperParams


class EnterpriseRoleCommand(base.GroupCommand):
    def __init__(self):
        super().__init__('Manage an enterprise role(s)')
        self.register_command(EnterpriseRoleViewCommand(), 'view', 'v')
        self.register_command(EnterpriseRoleAddCommand(), 'add', 'a')
        self.register_command(EnterpriseRoleEditCommand(), 'edit', 'e')
        self.register_command(EnterpriseRoleDeleteCommand(), 'delete')
        self.register_command(EnterpriseRoleAdminCommand(), 'admin')
        self.register_command(EnterpriseRoleMembershipCommand(), 'membership', 'm')
        self.register_command(EnterpriseRoleCopyCommand(), 'copy')


class EnterpriseRoleViewCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='enterprise-role view', parents=[base.json_output_parser], description='View enterprise role.')
        parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='print verbose information')
        parser.add_argument('role', help='Role Name or ID')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        assert context.enterprise_data is not None
        assert context.vault

        verbose = kwargs.get('verbose') is True

        enterprise_data = context.enterprise_data
        role = enterprise_utils.RoleUtils.resolve_single_role(enterprise_data, kwargs.get('role'))
        node_name = enterprise_utils.NodeUtils.get_node_path(enterprise_data, role.node_id, omit_root=False)
        role_obj: Dict[str, Any] = {
            'role_id': role.role_id,
            'role_name': role.name,
            'node_id': role.node_id,
            'node_name': node_name,
            'default_role': role.new_user_inherit,
            'visible_below': role.visible_below,
        }
        role_teams = [t for t in (enterprise_data.teams.get_entity(x.team_uid) for x in enterprise_data.role_teams.get_links_by_subject(role.role_id)) if t is not None]
        if len(role_teams) > 0:
            role_obj['role_teams'] = [{
                'team_uid': x.team_uid,
                'name': x.name,
            } for x in role_teams]

        user_ids = {x.enterprise_user_id for x in enterprise_data.role_users.get_links_by_subject(role.role_id)}

        role_users = [u for u in (enterprise_data.users.get_entity(x) for x in user_ids) if u is not None]
        if len(role_users) > 0:
            role_obj['role_users'] = [{
                'enterprise_user_id': x.enterprise_user_id,
                'username': x.username,
            } for x in role_users]

        managed_nodes = [x for x in enterprise_data.managed_nodes.get_links_by_subject(role.role_id)]
        if len(managed_nodes) > 0:
            managed_nodes_list = []
            for mn in managed_nodes:
                n = enterprise_data.nodes.get_entity(role.node_id)
                if n is None:
                    continue
                name = n.name
                if n.node_id == enterprise_data.root_node.node_id:
                    name = enterprise_data.enterprise_info.enterprise_name
                mn_obj = {
                    'cascade': mn.cascade_node_management,
                    'node_id': mn.managed_node_id,
                    'name': name,
                }
                rp = enterprise_data.role_privileges.get_link(role.role_id, mn.managed_node_id)
                if rp:
                    mn_obj['privileges'] = list(rp.to_set())
                managed_nodes_list.append(mn_obj)
            role_obj['managed_nodes'] = managed_nodes_list

        std_record_types: Dict[int, str] = {}
        ent_record_types: Dict[int, str] = {}

        for x in context.vault.vault_data.get_record_types():
            if x.scope == storage_types.RecordTypeScope.Standard:
                std_record_types[x.id] = x.name
            elif x.scope == storage_types.RecordTypeScope.Enterprise:
                ent_record_types[x.id] = x.name

        enforcement_groups: Dict[str, int] = {}
        for i in range(len(enterprise_constants.ENFORCEMENT_GROUPS)):
            enforcement_groups[enterprise_constants.ENFORCEMENT_GROUPS[i]] = i

        all_enforcements = [(x, enforcement_groups.get(x, 100)) for x in enterprise_constants.ENFORCEMENTS]
        all_enforcements.sort(key=lambda x: f'{x[1]}|{x[0]}')

        enforcements: Dict[str, str] = {}
        for re in enterprise_data.role_enforcements.get_links_by_subject(role.role_id):
            value_type = enterprise_constants.ENFORCEMENTS.get(re.enforcement_type)
            value: Any = re.value
            if value:
                if value_type == 'record_types':
                    try:
                        rto = value if isinstance(value, dict) else json.loads(value)
                        record_types = []
                        for record_type_id in rto.get('std'):
                            if record_type_id in std_record_types:
                                record_types.append(std_record_types[record_type_id])
                        for record_type_id in rto.get('ent'):
                            if record_type_id in ent_record_types:
                                record_types.append(ent_record_types[record_type_id])
                        value = record_types
                    except:
                        value = ''
                elif value_type == 'two_factor_duration':
                    value = [x.strip() for x in value.split(',')]
                    value = ['login' if x == '0' else
                             '12_hours' if x == '12' else
                             '24_hours' if x == '24' else
                             '30_days' if x == '30' else
                             'forever' if x == '9999' else x for x in value]
                    value = ', '.join(value)
                elif value_type == 'account_share':
                    try:
                        role_id = int(value)
                        r = enterprise_data.roles.get_entity(role_id)
                        if r:
                            value = f'{role.name} ({role.role_id})'
                    except:
                        value = ''
            else:
                value = ''
            if value:
                enforcements[re.enforcement_type] = value

        role_obj['role_enforcements'] = [{
                'name': key,
                'value': value
            } for key, value in enforcements.items()]

        if kwargs.get('format') == 'json':
            json_text = json.dumps(role_obj, indent=4)
            filename = kwargs.get('output')
            if filename is None:
                return json_text
            else:
                with open(filename, 'w') as f:
                    f.write(json_text)

        headers = ['role_id', 'role_name', 'node_name', 'default_role', 'role_users', 'role_teams']
        table = []
        for field in headers:
            field_title = report_utils.field_to_title(field)
            field_value =  role_obj.get(field)
            if field == 'role_users':
                if isinstance(field_value, list):
                    field_value = [x['username'] for x in field_value]
            elif field == 'role_teams':
                if isinstance(field_value, list):
                    field_value = [x['name'] for x in field_value]
            row = [field_title, field_value]
            if verbose:
                if field == 'node_name':
                    row.append(role_obj.get('node_id'))
            table.append(row)

        headers = ['', '']
        if verbose:
            headers.append('')
        report_utils.dump_report_data(table, headers=headers, no_header=True, right_align=[0])

        table = []
        last_group = ''
        for e_group, e_name in enterprise_constants.enforcement_list():
            value = enforcements.get(e_name)
            if not value and not verbose:
                continue
            if e_group != last_group:
                row = [e_group]
                last_group = e_group
            else:
                row = ['']
            row.extend([e_name, value])
            table.append(row)
        headers = ['Group', 'Name', 'Value']
        report_utils.dump_report_data(table, headers=headers, append=True, title='Role Enforcements')


        managed_node_list = role_obj.get('managed_nodes')
        if isinstance(managed_node_list, list):
            headers = ['Privilege']
            table = []
            p_lookup: Dict[str, Set[int]] = {}
            for mn_obj in managed_node_list:
                if not isinstance(mn_obj, dict):
                    continue
                node_id = mn_obj['node_id']
                if isinstance(node_id, int):
                    n_name = mn_obj.get('name')
                    if isinstance(n_name, str) and len(n_name) > 0:
                        headers.append(node_name)
                    else:
                        headers.append(str(node_id))
                    privileges = mn_obj['privileges']
                    if isinstance(privileges, list):
                        for p in privileges:
                            if p not in p_lookup:
                                p_lookup[p] = set()
                            p_lookup[p].add(node_id)

            privileges = [x for x in enterprise_types.RolePrivilege]
            for p in privileges:
                row = [p.title().replace('_', ' ')]
                p_nodes = p_lookup.get(p)
                for mn_obj in managed_node_list:
                    node_id = mn_obj['node_id']
                    row.append('X' if p_nodes and node_id in p_nodes else '')
                table.append(row)
            table.append(['------------------------'])
            row = ['Cascade Node Permissions']
            for mn_obj in managed_node_list:
                row.append('X' if mn_obj.get('cascade') is True else '')
            table.append(row)

            report_utils.dump_report_data(table, headers, title='Managed Node Privileges', append=True)


class EnterpriseRoleAddCommand(base.ArgparseCommand, enterprise_management.IEnterpriseManagementLogger):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='enterprise-role add', description='Create enterprise role(s).')
        parser.add_argument('--parent', dest='parent', action='store', help='Parent node name or ID')
        parser.add_argument('--new-user', dest='new_user', action='store', choices=['on', 'off'],
                            help='assign this role to new users')
        parser.add_argument('--visible-below', dest='visible_below', action='store', choices=['on', 'off'],
                            help='visible to all nodes. \'add\' only')
        parser.add_argument('--enforcement', dest='enforcements', action='append', metavar='KEY:VALUE',
                            help='sets role enforcement')
        parser.add_argument('-f', '--force', dest='force', action='store_true',
                            help='do not prompt for confirmation')
        parser.add_argument('role', type=str, nargs='+', help='Role Name. Can be repeated.')
        super().__init__(parser)
        self.logger = api.get_logger()

    def warning(self, message: str) -> None:
        self.logger.warning(message)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        assert context.auth is not None
        assert context.enterprise_loader is not None
        assert context.enterprise_data is not None

        parent_id: Optional[int]
        if kwargs.get('parent'):
            parent_node = enterprise_utils.NodeUtils.resolve_single_node(context.enterprise_data, kwargs.get('parent'))
            parent_id = parent_node.node_id
        else:
            parent_id = context.enterprise_data.root_node.node_id

        force = kwargs.get('force') is True
        role_name_lookup = enterprise_utils.RoleUtils.get_role_name_lookup(context.enterprise_data)
        roles = kwargs.get('role')
        role_names: Optional[Dict[str, str]] = None
        if isinstance(roles, list):
            role_names = {x.lower(): x for x in roles}
            for role_key, role_name in list(role_names.items()):
                r = role_name_lookup.get(role_key)
                if r is not None:
                    skip = False
                    if isinstance(r, enterprise_types.Role):
                        r = [r]
                    for r1 in r:
                        if r1.node_id == parent_id:
                            self.logger.info('Role \"%s\" already exists', r1.name)
                            skip = True
                            break
                        if not force:
                            answer = prompt_utils.user_choice('Do you want to create a role?', choice='yn', default='n')
                            skip = not answer.lower().startswith('y')
                    if skip:
                        del role_names[role_key]
        if role_names is None or len(role_names) == 0:
            raise base.CommandError('No roles to add')

        new_user_inherit: Optional[bool] = None
        visible_below: Optional[bool] = None
        nu = kwargs.get('new_user')
        if isinstance(nu, str):
            new_user_inherit = True if nu == 'on' else False if nu == 'off' else None
        vb = kwargs.get('visible_below')
        if isinstance(vb, str):
            visible_below = True if vb == 'on' else False if vb == 'off' else None

        roles_to_add = [enterprise_management.RoleEdit(
            role_id=context.enterprise_loader.get_enterprise_id(), name=x, node_id=parent_id,
            new_user_inherit=new_user_inherit, visible_below=visible_below)
            for x in role_names.values()]
        batch = batch_management.BatchManagement(loader=context.enterprise_loader, logger=self)
        batch.modify_roles(to_add=roles_to_add)

        enforcement_names = kwargs.get('enforcements')
        if enforcement_names:
            enforcements, errors = enterprise_utils.RoleUtils.parse_enforcements(enforcement_names)
            for error in errors:
                self.warning(error)
            for re in roles_to_add:
                enf_to_add = [enterprise_management.RoleEnforcementEdit(role_id=re.role_id, name=e_name, value=e_value)
                              for e_name, e_value in enforcements.items() if e_value]
                batch.modify_role_enforcements(enforcements=enf_to_add)
        batch.apply()


class EnterpriseRoleEditCommand(base.ArgparseCommand, enterprise_management.IEnterpriseManagementLogger):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='enterprise-role edit', description='Edit enterprise role(s).')
        parser.add_argument('--parent', dest='parent', action='store', help='Parent node name or ID')
        parser.add_argument('--name', dest='displayname', action='store', help='set role display name')
        parser.add_argument('--new-user', dest='new_user', action='store', choices=['on', 'off'],
                            help='assign this role to new users')
        parser.add_argument('--visible-below', dest='visible_below', action='store', choices=['on', 'off'],
                            help='visible to all nodes. \'add\' only')
        parser.add_argument('--enforcement', dest='enforcements', action='append', metavar='KEY:VALUE',
                            help='sets role enforcement')
        parser.add_argument('role', type=str, nargs='+', help='Role Name or ID. Can be repeated.')
        super().__init__(parser)
        self.logger = api.get_logger()

    def warning(self, message: str) -> None:
        self.logger.warning(message)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        assert context.auth is not None
        assert context.enterprise_loader is not None
        assert context.enterprise_data is not None

        role_list = enterprise_utils.RoleUtils.resolve_existing_roles(context.enterprise_data, kwargs.get('role'))
        role_name: Optional[str] = kwargs.get('displayname')
        if isinstance(role_name, str) and len(role_name) > 0:
            if len(role_list) > 1:
                raise Exception('Cannot change role name for more than one roles')
        else:
            role_name = None

        parent_id: Optional[int]
        if kwargs.get('parent'):
            parent_node = enterprise_utils.NodeUtils.resolve_single_node(context.enterprise_data, kwargs.get('parent'))
            parent_id = parent_node.node_id
        else:
            parent_id = context.enterprise_data.root_node.node_id

        new_user_inherit: Optional[bool] = None
        visible_below: Optional[bool] = None
        nu = kwargs.get('new_user')
        if isinstance(nu, str):
            new_user_inherit = True if nu == 'on' else False if nu == 'off' else None
        vb = kwargs.get('visible_below')
        if isinstance(vb, str):
            visible_below = True if vb == 'on' else False if vb == 'off' else None

        batch = batch_management.BatchManagement(loader=context.enterprise_loader, logger=self)

        roles_to_update = [enterprise_management.RoleEdit(
            role_id=x.role_id, name=role_name, node_id=parent_id,
            new_user_inherit=new_user_inherit, visible_below=visible_below)
            for x in role_list]
        batch.modify_roles(to_update=roles_to_update)

        enforcement_names = kwargs.get('enforcements')
        if enforcement_names:
            enforcements, errors = enterprise_utils.RoleUtils.parse_enforcements(enforcement_names)
            for error in errors:
                self.warning(error)
            for re in roles_to_update:
                enf_to_add = [enterprise_management.RoleEnforcementEdit(role_id=re.role_id, name=e_name, value=e_value)
                              for e_name, e_value in enforcements.items() if e_value]
                batch.modify_role_enforcements(enforcements=enf_to_add)
        batch.apply()


class EnterpriseRoleDeleteCommand(base.ArgparseCommand, enterprise_management.IEnterpriseManagementLogger):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='enterprise-role delete', description='Delete enterprise role(s).')
        parser.add_argument('role', type=str, nargs='+', help='Role Name or ID. Can be repeated.')
        super().__init__(parser)
        self.logger = api.get_logger()

    def warning(self, message: str) -> None:
        self.logger.warning(message)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        assert context.enterprise_data is not None

        role_list = enterprise_utils.RoleUtils.resolve_existing_roles(context.enterprise_data, kwargs.get('role'))
        batch = batch_management.BatchManagement(loader=context.enterprise_loader, logger=self)
        batch.modify_roles(to_remove=(enterprise_management.RoleEdit(role_id=x.role_id) for x in role_list))
        batch.apply()


class EnterpriseRoleCopyCommand(base.ArgparseCommand, enterprise_management.IEnterpriseManagementLogger):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='enterprise-role copy', description='Copy role with enforcements.')
        parser.add_argument('--node', dest='node', action='store', required=True,
                            help='New role node name or ID')
        parser.add_argument('--name', dest='displayname', action='store', required=True,
                            help='New role name')
        parser.add_argument('role', help='Role Name or ID.')
        super().__init__(parser)
        self.logger = api.get_logger()

    def warning(self, message: str) -> None:
        self.logger.warning(message)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        assert context.enterprise_data is not None

        role = enterprise_utils.RoleUtils.resolve_single_role(context.enterprise_data, kwargs.get('role'))
        node = enterprise_utils.NodeUtils.resolve_single_node(context.enterprise_data, kwargs.get('node'))
        role_name = kwargs.get('displayname')
        batch = batch_management.BatchManagement(loader=context.enterprise_loader, logger=self)
        role_id = context.enterprise_loader.get_enterprise_id()
        role_to_add = enterprise_management.RoleEdit(role_id=role_id, node_id=node.node_id, name=role_name, visible_below=role.visible_below,
                                                     new_user_inherit=role.new_user_inherit)
        batch.modify_roles(to_add=[role_to_add])

        enforcements = [enterprise_management.RoleEnforcementEdit(role_id=role_id, name=x.enforcement_type, value=x.value)
                        for x in context.enterprise_data.role_enforcements.get_links_by_subject(role.role_id)]
        batch.modify_role_enforcements(enforcements=enforcements)
        batch.apply()


class EnterpriseRoleMembershipCommand(base.ArgparseCommand, enterprise_management.IEnterpriseManagementLogger):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='enterprise-role membership', description='Manage enterprise role membership.')
        parser.add_argument('-au', '--add-user', action='append', metavar='EMAIL',
                            help='add user to role. Can be repeated.')
        parser.add_argument('-ru', '--remove-user', action='append', metavar='EMAIL',
                            help='remove user (Email, User ID, @all) from role. Can be repeated.')
        parser.add_argument('-at', '--add-team', action='append', metavar='TEAM',
                            help='add team to role. Can be repeated.')
        parser.add_argument('-rt', '--remove-team', action='append', metavar='TEAM',
                            help='remove team (Name, Team UID, @all) from role. Can be repeated.')
        parser.add_argument('role', type=str, nargs='+', help='Role Name or ID. Can be repeated.')
        super().__init__(parser)
        self.logger = api.get_logger()

    def warning(self, message: str) -> None:
        self.logger.warning(message)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        assert context.enterprise_data is not None

        role_list = enterprise_utils.RoleUtils.resolve_existing_roles(context.enterprise_data, kwargs.get('role'))
        users_to_add: Optional[List[enterprise_types.User]] = None
        teams_to_add: Optional[List[enterprise_types.Team]] = None
        users_to_remove: Optional[List[enterprise_types.User]] = None
        teams_to_remove: Optional[List[enterprise_types.Team]] = None
        add_users = kwargs.get('add_user')
        add_teams = kwargs.get('add_team')
        remove_users = kwargs.get('remove_user')
        has_remove_all_users: bool = False
        remove_teams = kwargs.get('remove_team')
        has_remove_all_teams: bool = False
        if isinstance(add_users, list):
            users_to_add = enterprise_utils.UserUtils.resolve_existing_users(context.enterprise_data, add_users)
        if isinstance(add_teams, list):
            teams_to_add, _ = enterprise_utils.TeamUtils.resolve_existing_teams(context.enterprise_data, add_teams)
        if isinstance(remove_users, list):
            has_remove_all_users = any((True for x in remove_users if x == '@all'))
            if not has_remove_all_users:
                users_to_remove = enterprise_utils.UserUtils.resolve_existing_users(context.enterprise_data, remove_users)
        if isinstance(remove_teams, list):
            has_remove_all_teams = any((True for x in remove_teams if x == '@all'))
            if not has_remove_all_teams:
                teams_to_remove, _ = enterprise_utils.TeamUtils.resolve_existing_teams(context.enterprise_data, remove_teams)

        batch = batch_management.BatchManagement(loader=context.enterprise_loader, logger=self)
        for role in role_list:
            existing_users = {x.enterprise_user_id for x in context.enterprise_data.role_users.get_links_by_subject(role.role_id)}
            existing_teams = {x.team_uid for x in context.enterprise_data.role_teams.get_links_by_subject(role.role_id)}
            if users_to_add:
                users_to_add = [x for x in users_to_add if x.enterprise_user_id not in existing_users]
                if users_to_add:
                    batch.modify_role_users(to_add=[enterprise_management.RoleUserEdit(
                        role_id=role.role_id, enterprise_user_id=x.enterprise_user_id) for x in users_to_add])
            if teams_to_add:
                teams_to_add = [x for x in teams_to_add if x.team_uid not in existing_teams]
                if teams_to_add:
                    batch.modify_role_teams(to_add=[enterprise_management.RoleTeamEdit(
                        role_id=role.role_id, team_uid=x.team_uid) for x in teams_to_add])
            if has_remove_all_users:
                batch.modify_role_users(to_remove=[enterprise_management.RoleUserEdit(
                    role_id=role.role_id, enterprise_user_id=x) for x in existing_users])
            elif users_to_remove:
                batch.modify_role_users(to_remove=[enterprise_management.RoleUserEdit(
                    role_id=role.role_id, enterprise_user_id=x.enterprise_user_id) for x in users_to_remove])
            if has_remove_all_teams:
                batch.modify_role_teams(to_remove=[enterprise_management.RoleTeamEdit(
                    role_id=role.role_id, team_uid=x) for x in existing_teams])
            elif teams_to_remove:
                batch.modify_role_teams(to_remove=[enterprise_management.RoleTeamEdit(
                    role_id=role.role_id, team_uid=x.team_uid) for x in teams_to_remove])

        batch.apply()


class EnterpriseRoleAdminCommand(base.ArgparseCommand, enterprise_management.IEnterpriseManagementLogger):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='enterprise-role admin', description='Manage enterprise admin role.')
        parser.add_argument('-aa', '--add-admin', action='append', metavar='NODE',
                            help='add managed node to role. Can be repeated.')
        parser.add_argument('-ra', '--remove-admin', action='append', metavar='NODE',
                            help='remove managed node from role. Can be repeated.')
        parser.add_argument('-ap', '--add-privilege', dest='add_privilege', action='append',
                            metavar='PRIVILEGE', help='add privilege to managed node. Can be repeated.')
        parser.add_argument('-rp', '--remove-privilege', dest='remove_privilege', action='append',
                            metavar='PRIVILEGE', help='remove privilege from managed node. Can be repeated.')
        parser.add_argument('--cascade', dest='cascade', action='store', choices=['on', 'off'],
                            help='apply to the child nodes. "--add-admin" only')
        parser.add_argument('role', help='Role Name or ID.')
        super().__init__(parser)
        self.logger = api.get_logger()

    def warning(self, message: str) -> None:
        self.logger.warning(message)

    def execute(self, context: KeeperParams, **kwargs):
        assert context.enterprise_data is not None

        role = enterprise_utils.RoleUtils.resolve_single_role(context.enterprise_data, kwargs.get('role'))
        nodes_to_add: Optional[List[enterprise_types.Node]] = None
        nodes_to_remove: Optional[List[enterprise_types.Node]] = None
        cascade: Optional[bool] = None
        add_admins = kwargs.get('add_admin')
        if isinstance(add_admins, list):
            nodes_to_add = enterprise_utils.NodeUtils.resolve_existing_nodes(context.enterprise_data, add_admins)

        remove_admins = kwargs.get('remove_admin')
        if isinstance(remove_admins, list):
            nodes_to_remove = enterprise_utils.NodeUtils.resolve_existing_nodes(context.enterprise_data, remove_admins)

        cascade_arg = kwargs.get('cascade')
        if cascade_arg:
            cascade = True if cascade_arg == 'on' else False

        add_privileges = kwargs.get('add_privilege')
        remove_privileges = kwargs.get('remove_privilege')

        existing_nodes = {x.managed_node_id: x for x in context.enterprise_data.managed_nodes.get_links_by_subject(role.role_id)}

        batch = batch_management.BatchManagement(loader=context.enterprise_loader, logger=self)
        if nodes_to_add is not None:
            aps: Optional[Set[str]] = None
            rps: Optional[Set[str]] = None
            if isinstance(add_privileges, list):
                privilege = enterprise_types.RolePrivileges(role_id=0, managed_node_id=0)
                for p in add_privileges:
                    if not privilege.set_by_name(p, True):
                        self.logger.info('Invalid privilege "%s"', p)
                aps = privilege.to_set()

            if isinstance(remove_privileges, list):
                privilege = enterprise_types.RolePrivileges(role_id=0, managed_node_id=0)
                for p in remove_privileges:
                    if not privilege.set_by_name(p, False):
                        self.logger.info('Invalid privilege "%s"', p)
                rps = privilege.to_set()

            for node in nodes_to_add:
                mne = enterprise_management.ManagedNodeEdit(
                    role_id=role.role_id, managed_node_id=node.node_id, cascade_node_management=cascade)
                if aps and len(aps) > 0:
                    if mne.privileges is None:
                        mne.privileges = {}
                    for p in aps:
                        mne.privileges[p] = True
                if rps and len(rps) > 0:
                    if mne.privileges is None:
                        mne.privileges = {}
                    for p in rps:
                        mne.privileges[p] = False
                if node.node_id in existing_nodes:
                    en = existing_nodes[node.node_id]
                    assert en
                    if (isinstance(cascade, bool) and en.cascade_node_management != cascade) or aps or rps:
                        batch.modify_managed_nodes(to_update=[mne])
                else:
                    batch.modify_managed_nodes(to_add=[mne])

        if nodes_to_remove is not None:
            for node in nodes_to_remove:
                if node.node_id in existing_nodes:
                    batch.modify_managed_nodes(to_remove=[enterprise_management.ManagedNodeEdit(
                        role_id=role.role_id, managed_node_id=node.node_id)])

        batch.apply()


