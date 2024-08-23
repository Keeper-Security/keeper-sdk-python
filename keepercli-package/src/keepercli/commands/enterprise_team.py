import argparse
import json
from typing import Dict, List, Optional, Any

from keepersdk import utils
from keepersdk.enterprise import enterprise_types, batch_management, enterprise_management
from . import base, enterprise_utils
from .. import api, prompt_utils
from ..helpers import report_utils
from ..params import KeeperParams


class EnterpriseTeamCommand(base.GroupCommand):
    def __init__(self):
        super().__init__('Manage an enterprise team(s)')
        self.register_command(EnterpriseTeamViewCommand(), 'view', 'v')
        self.register_command(EnterpriseTeamAddCommand(), 'add', 'a')
        self.register_command(EnterpriseTeamEditCommand(), 'edit', 'e')
        self.register_command(EnterpriseTeamDeleteCommand(), 'delete')
        self.register_command(EnterpriseTeamMembershipCommand(), 'membership', 'm')


class EnterpriseTeamViewCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='enterprise-team view', parents=[base.json_output_parser], description='View enterprise team.')
        parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='print verbose information')
        parser.add_argument('team', help='Team Name or UID')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        assert context.enterprise_data is not None
        assert context.vault

        verbose = kwargs.get('verbose') is True

        enterprise_data = context.enterprise_data
        team = enterprise_utils.TeamUtils.resolve_single_team(enterprise_data, kwargs.get('team'))
        node_name = enterprise_utils.NodeUtils.get_node_path(enterprise_data, team.node_id, omit_root=False)
        team_obj = {
            'team_uid': team.team_uid,
            'team_name': team.name,
            'node_id': team.node_id,
            'node_name': node_name,
            'restrict_edit': team.restrict_edit,
            'restrict_share': team.restrict_share,
            'restrict_view': team.restrict_view,
        }
        role_ids = {x.role_id for x in enterprise_data.role_teams.get_links_by_object(team.team_uid)}
        if role_ids:
            roles = [r for r in (enterprise_data.roles.get_entity(x) for x in role_ids) if r]
            if len(roles) > 0:
                team_obj['team_roles'] = [{
                    'role_id': x.role_id,
                    'role_name': x.name,
                } for x in roles]

        user_ids = {x.enterprise_user_id for x in enterprise_data.team_users.get_links_by_subject(team.team_uid)}
        if len(user_ids) > 0:
            users = [u for u in (enterprise_data.users.get_entity(x) for x in user_ids) if u is not None]
            if len(users) > 0:
                team_obj['team_users'] = [{
                    'enterprise_user_id': x.enterprise_user_id,
                    'username': x.username,
                } for x in users]

        user_ids = {x.enterprise_user_id for x in enterprise_data.queued_team_users.get_links_by_subject(team.team_uid)}
        if len(user_ids) > 0:
            users = [u for u in (enterprise_data.users.get_entity(x) for x in user_ids) if u]
            if len(users) > 0:
                team_obj['queued_team_users'] = [{
                    'enterprise_user_id': x.enterprise_user_id,
                    'username': x.username,
                } for x in users]


        if kwargs.get('format') == 'json':
            json_text = json.dumps(team_obj, indent=4)
            filename = kwargs.get('output')
            if filename is None:
                return json_text
            else:
                with open(filename, 'w') as f:
                    f.write(json_text)

        headers = ['team_uid', 'team_name', 'node_name', 'restrict_edit', 'restrict_share', 'restrict_view']
        table = []
        for field in headers:
            field_title = report_utils.field_to_title(field)
            field_value = team_obj.get(field)
            if field_value is not None:
                row = [field_title, field_value]
                if verbose:
                    if field == 'node':
                        row.append(team_obj.get('node_id'))
                table.append(row)

        trs = team_obj.get('team_roles')
        if isinstance(trs, list) and len(trs) > 0:
            row = ['Role(s)']
            row.append([x['role_name'] for x in trs])
            if verbose:
                row.append([x['role_id'] for x in trs])
            table.append(row)

        tus = team_obj.get('team_users')
        if isinstance(tus, list) and len(tus) > 0:
            row = ['User(s)']
            row.append([x['username'] for x in tus])
            if verbose:
                row.append([x['enterprise_user_id'] for x in tus])
            table.append(row)

        qtus = team_obj.get('queued_team_users')
        if isinstance(qtus, list) and len(qtus) > 0:
            row = ['Queued User(s)']
            row.append([x['username'] for x in qtus])
            if verbose:
                row.append([x['enterprise_user_id'] for x in qtus])
            table.append(row)

        headers = ['', '']
        if verbose:
            headers.append('')
        report_utils.dump_report_data(table, headers=headers, no_header=True, right_align=[0])


class EnterpriseTeamAddCommand(base.ArgparseCommand, enterprise_management.IEnterpriseManagementLogger):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='enterprise-team add', description='Create enterprise team(s).')
        parser.add_argument('-f', '--force', dest='force', action='store_true',
                            help='do not prompt for confirmation')
        parser.add_argument('--parent', dest='parent', action='store', help='Parent node name or ID')
        parser.add_argument('--restrict-edit', dest='restrict_edit', choices=['on', 'off'],
                            action='store', help='disable record edits')
        parser.add_argument('--restrict-share', dest='restrict_share', choices=['on', 'off'],
                            action='store', help='disable record re-shares')
        parser.add_argument('--restrict-view', dest='restrict_view', choices=['on', 'off'],
                            action='store', help='disable view/copy passwords')
        parser.add_argument('team', type=str, nargs='+', help='Team Name or Queued Team UID. Can be repeated.')
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

        teams = kwargs.get('team')
        queued_teams, teams = enterprise_utils.TeamUtils.resolve_queued_teams(context.enterprise_data, teams)
        team_names: Optional[Dict[str, str]] = None
        if teams:
            team_name_lookup = enterprise_utils.TeamUtils.get_team_name_lookup(context.enterprise_data)
            if isinstance(teams, list):
                team_names = {x.lower(): x for x in teams}
                for team_key, team_name in list(team_names.items()):
                    t = team_name_lookup.get(team_key)
                    if t is not None:
                        skip = False
                        if isinstance(t, enterprise_types.Team):
                            t = [t]
                        for t1 in t:
                            if t1.node_id == parent_id:
                                self.logger.info('Team \"%s\" already exists', t1.name)
                                skip = True
                                break
                            if not force:
                                answer = prompt_utils.user_choice('Do you want to create a team?', choice='yn', default='n')
                                skip = not answer.lower().startswith('y')
                        if skip:
                            del team_names[team_key]
        if not queued_teams and (team_names is None or len(team_names) == 0):
            raise base.CommandError('No teams to add')

        restrict_edit: Optional[bool] = None
        r_edit = kwargs.get('restrict_edit')
        if r_edit is not None:
            restrict_edit = r_edit == 'on'
        restrict_share: Optional[bool] = None
        r_share = kwargs.get('restrict_share')
        if r_share is not None:
            restrict_share = r_share == 'on'
        restrict_view: Optional[bool] = None
        r_view = kwargs.get('restrict_view')
        if r_view is not None:
            restrict_view = r_view == 'on'

        batch = batch_management.BatchManagement(loader=context.enterprise_loader, logger=self)
        if team_names:
            teams_to_add = [enterprise_management.TeamEdit(
                team_uid=utils.generate_uid(), name=x, node_id=parent_id,
                restrict_edit=restrict_edit, restrict_share=restrict_share, restrict_view=restrict_view)
                for x in team_names.values()]
            batch.modify_teams(to_add=teams_to_add)

        if queued_teams:
            teams_to_add = [enterprise_management.TeamEdit(
                team_uid=x.team_uid, name=x.name, node_id=parent_id,
                restrict_edit=restrict_edit, restrict_share=restrict_share, restrict_view=restrict_view)
                for x in queued_teams]
            batch.modify_teams(to_add=teams_to_add)

        batch.apply()

class EnterpriseTeamEditCommand(base.ArgparseCommand, enterprise_management.IEnterpriseManagementLogger):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='enterprise-team edit', description='Edit enterprise team(s).')
        parser.add_argument('-f', '--force', dest='force', action='store_true',
                            help='do not prompt for confirmation')
        parser.add_argument('--name', dest='displayname', action='store', help='set team display name')
        parser.add_argument('--parent', dest='parent', action='store', help='Parent node name or ID')
        parser.add_argument('--restrict-edit', dest='restrict_edit', choices=['on', 'off'],
                            action='store', help='disable record edits')
        parser.add_argument('--restrict-share', dest='restrict_share', choices=['on', 'off'],
                            action='store', help='disable record re-shares')
        parser.add_argument('--restrict-view', dest='restrict_view', choices=['on', 'off'],
                            action='store', help='disable view/copy passwords')
        parser.add_argument('team', type=str, nargs='+', help='Team Name or UID. Can be repeated.')
        super().__init__(parser)
        self.logger = api.get_logger()

    def warning(self, message: str) -> None:
        self.logger.warning(message)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        assert context.auth is not None
        assert context.enterprise_loader is not None
        assert context.enterprise_data is not None

        team_list, missing_names = enterprise_utils.TeamUtils.resolve_existing_teams(context.enterprise_data, kwargs.get('team'))
        if isinstance(missing_names, list) and len(missing_names) > 0:
            mn = ', '.join((str(x) for x in missing_names))
            raise base.CommandError(f'Team name(s) \"{mn}\" could not be resolved')

        team_name: Optional[str] = kwargs.get('displayname')
        if isinstance(team_name, str) and len(team_name) > 0:
            if len(team_list) > 1:
                raise Exception('Cannot change team name for more than one teams')
        else:
            team_name = None

        parent_id: Optional[int]
        if kwargs.get('parent'):
            parent_node = enterprise_utils.NodeUtils.resolve_single_node(context.enterprise_data, kwargs.get('parent'))
            parent_id = parent_node.node_id
        else:
            parent_id = context.enterprise_data.root_node.node_id

        restrict_edit: Optional[bool] = None
        r_edit = kwargs.get('restrict_edit')
        if r_edit is not None:
            restrict_edit = r_edit == 'on'
        restrict_share: Optional[bool] = None
        r_share = kwargs.get('restrict_share')
        if r_share is not None:
            restrict_share = r_share == 'on'
        restrict_view: Optional[bool] = None
        r_view = kwargs.get('restrict_view')
        if r_view is not None:
            restrict_view = r_view == 'on'

        teams_to_edit = [enterprise_management.TeamEdit(
            team_uid=x.team_uid, name=team_name, node_id=parent_id,
            restrict_edit=restrict_edit, restrict_share=restrict_share, restrict_view=restrict_view)
            for x in team_list]

        batch = batch_management.BatchManagement(loader=context.enterprise_loader, logger=self)
        batch.modify_teams(to_update=teams_to_edit)


class EnterpriseTeamDeleteCommand(base.ArgparseCommand, enterprise_management.IEnterpriseManagementLogger):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='enterprise-team delete', description='Delete enterprise team(s).')
        parser.add_argument('team', type=str, nargs='+', help='Team Name or UID. Can be repeated.')
        super().__init__(parser)
        self.logger = api.get_logger()

    def warning(self, message: str) -> None:
        self.logger.warning(message)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        assert context.enterprise_data is not None

        team_list, missing_names = enterprise_utils.TeamUtils.resolve_existing_teams(context.enterprise_data, kwargs.get('team'))
        if isinstance(missing_names, list) and len(missing_names) > 0:
            mn = ', '.join((str(x) for x in missing_names))
            raise base.CommandError(f'Team name(s) \"{mn}\" could not be resolved')
        batch = batch_management.BatchManagement(loader=context.enterprise_loader, logger=self)
        batch.modify_teams(to_remove=(enterprise_management.TeamEdit(team_uid=x.team_uid) for x in team_list))
        batch.apply()


class EnterpriseTeamMembershipCommand(base.ArgparseCommand, enterprise_management.IEnterpriseManagementLogger):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='enterprise-team membership', description='Manage enterprise team membership.')
        parser.add_argument('-au', '--add-user', action='append', help='add user to team')
        parser.add_argument('-ru', '--remove-user', action='append', help='remove user from team. @all')
        parser.add_argument('-ar', '--add-role', action='append', help='add user to team')
        parser.add_argument('-rr', '--remove-role', action='append', help='remove user from team, @all')
        parser.add_argument('team', type=str, nargs='+', help='Team Name or UID. Can be repeated.')
        super().__init__(parser)
        self.logger = api.get_logger()

    def warning(self, message: str) -> None:
        self.logger.warning(message)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        assert context.enterprise_data is not None

        team_list, missing_names = enterprise_utils.TeamUtils.resolve_existing_teams(context.enterprise_data, kwargs.get('team'))
        queued_team_list: List[enterprise_types.QueuedTeam]
        if missing_names:
            queued_team_list, missing_names = enterprise_utils.TeamUtils.resolve_queued_teams(context.enterprise_data, missing_names)
        else:
            queued_team_list = []
        if isinstance(missing_names, list) and len(missing_names) > 0:
            mn = ', '.join((str(x) for x in missing_names))
            raise base.CommandError(f'Team name(s) \"{mn}\" could not be resolved')

        users_to_add: Optional[List[enterprise_types.User]] = None
        roles_to_add: Optional[List[enterprise_types.Role]] = None
        users_to_remove: Optional[List[enterprise_types.User]] = None
        roles_to_remove: Optional[List[enterprise_types.Role]] = None
        has_remove_all_users: bool = False
        has_remove_all_roles: bool = False

        add_users = kwargs.get('add_user')
        if isinstance(add_users, list):
            users_to_add = enterprise_utils.UserUtils.resolve_existing_users(context.enterprise_data, add_users)
        add_roles = kwargs.get('add_role')
        if isinstance(add_roles, list):
            roles_to_add = enterprise_utils.RoleUtils.resolve_existing_roles(context.enterprise_data, add_roles)
        remove_users = kwargs.get('remove_user')
        if isinstance(remove_users, list):
            has_remove_all_users = any((True for x in remove_users if x == '@all'))
            if not has_remove_all_users:
                users_to_remove = enterprise_utils.UserUtils.resolve_existing_users(context.enterprise_data, remove_users)
        remove_roles = kwargs.get('remove_role')
        if isinstance(remove_roles, list):
            has_remove_all_roles = any((True for x in remove_roles if x == '@all'))
            if not has_remove_all_roles:
                roles_to_remove = enterprise_utils.RoleUtils.resolve_existing_roles(context.enterprise_data, remove_roles)

        batch = batch_management.BatchManagement(loader=context.enterprise_loader, logger=self)
        for team in team_list:
            existing_users = {x.enterprise_user_id for x in context.enterprise_data.team_users.get_links_by_subject(team.team_uid)}
            existing_roles = {x.role_id for x in context.enterprise_data.role_teams.get_links_by_object(team.team_uid)}
            if users_to_add:
                users_to_add = [x for x in users_to_add if x.enterprise_user_id not in existing_users]
                if users_to_add:
                    batch.modify_team_users(to_add=[enterprise_management.TeamUserEdit(
                        team_uid=team.team_uid, enterprise_user_id=x.enterprise_user_id) for x in users_to_add])
            if roles_to_add:
                roles_to_add = [x for x in roles_to_add if x.role_id not in existing_roles]
                if roles_to_add:
                    batch.modify_role_teams(to_add=[enterprise_management.RoleTeamEdit(
                        role_id=x.role_id, team_uid=team.team_uid) for x in roles_to_add])
            if has_remove_all_users:
                batch.modify_team_users(to_remove=[enterprise_management.TeamUserEdit(
                    team_uid=team.team_uid, enterprise_user_id=x) for x in existing_users])
            elif users_to_remove:
                batch.modify_team_users(to_remove=[enterprise_management.TeamUserEdit(
                    team_uid=team.team_uid, enterprise_user_id=x.enterprise_user_id) for x in users_to_remove])
            if has_remove_all_roles:
                batch.modify_role_teams(to_remove=[enterprise_management.RoleTeamEdit(
                    role_id=x, team_uid=team.team_uid) for x in existing_roles])
            elif roles_to_remove:
                batch.modify_role_teams(to_remove=[enterprise_management.RoleTeamEdit(
                    role_id=x.role_id, team_uid=team.team_uid) for x in roles_to_remove])

        for queued_team in queued_team_list:
            existing_users = {x.enterprise_user_id for x in context.enterprise_data.queued_team_users.get_links_by_subject(queued_team.team_uid)}
            if users_to_add:
                users_to_add = [x for x in users_to_add if x.enterprise_user_id not in existing_users]
                if users_to_add:
                    batch.modify_team_users(to_add=[enterprise_management.TeamUserEdit(
                        team_uid=queued_team.team_uid, enterprise_user_id=x.enterprise_user_id) for x in users_to_add])
            if has_remove_all_users:
                batch.modify_team_users(to_remove=[enterprise_management.TeamUserEdit(
                    team_uid=queued_team.team_uid, enterprise_user_id=x) for x in existing_users])
            elif users_to_remove:
                batch.modify_team_users(to_remove=[enterprise_management.TeamUserEdit(
                    team_uid=queued_team.team_uid, enterprise_user_id=x.enterprise_user_id) for x in users_to_remove])

        batch.apply()
