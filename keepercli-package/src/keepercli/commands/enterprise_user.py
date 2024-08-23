import argparse
import json
from typing import Dict, List, Optional, Any, Set

from keepersdk.enterprise import batch_management, enterprise_management
from keepersdk.proto import APIRequest_pb2
from . import base, enterprise_utils
from .. import api, prompt_utils
from ..helpers import report_utils
from ..params import KeeperParams


class EnterpriseUserCommand(base.GroupCommand):
    def __init__(self):
        super().__init__('Manage an enterprise users(s)')
        self.register_command(EnterpriseUserViewCommand(), 'view', 'v')
        self.register_command(EnterpriseUserAddCommand(), 'add', 'a')
        self.register_command(EnterpriseUserEditCommand(), 'edit', 'e')
        self.register_command(EnterpriseUserDeleteCommand(), 'delete')
        self.register_command(EnterpriseUserActionCommand(), 'action')
        self.register_command(EnterpriseUserAliasCommand(), 'alias')


class EnterpriseUserViewCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='enterprise-user view', parents=[base.json_output_parser], description='View enterprise user.')
        parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='print verbose information')
        parser.add_argument('team', help='User email or UID')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        assert context.enterprise_data is not None
        assert context.vault
        assert context.auth

        verbose = kwargs.get('verbose') is True

        enterprise_data = context.enterprise_data
        user = enterprise_utils.UserUtils.resolve_single_user(enterprise_data, kwargs.get('team'))
        node_name = enterprise_utils.NodeUtils.get_node_path(enterprise_data, user.node_id, omit_root=False)

        user_obj = {
            'enterprise_user_id': user.enterprise_user_id,
            'username': user.username,
            'node_id': user.node_id,
            'node_name': node_name,
            'full_name': user.full_name,
            'status': enterprise_utils.UserUtils.get_user_status_text(user),
            'tfa_enabled': user.tfa_enabled,
        }
        transfer_status = enterprise_utils.UserUtils.get_user_transfer_status_text(user)
        if user:
            user_obj['transfer_status'] = transfer_status

        aliases = [x.username for x in enterprise_data.user_aliases.get_links_by_subject(user.enterprise_user_id) if x.username != user.username]
        if len(aliases) > 0:
            user_obj['aliases'] = aliases

        team_uids = {x.team_uid for x in enterprise_data.team_users.get_links_by_object(user.enterprise_user_id)}
        if len(team_uids) > 0:
            teams = [t for t in (enterprise_data.teams.get_entity(x) for x in team_uids) if t]
            if len(teams) > 0:
                user_obj['teams'] = [{
                    'team_uid': x.team_uid,
                    'name': x.name,
                } for x in teams]

        queued_team_uids = {x.team_uid for x in enterprise_data.queued_team_users.get_links_by_object(user.enterprise_user_id)}
        if len(queued_team_uids) > 0:
            qt_objs: List[Dict[str, Any]] = []
            for team_uid in queued_team_uids:
                t = enterprise_data.teams.get_entity(team_uid)
                if t:
                    qt_objs.append({
                        'team_uid': t.team_uid,
                        'name': t.name,
                    })
                else:
                    qt = enterprise_data.queued_teams.get_entity(team_uid)
                    if qt:
                        qt_objs.append({
                            'team_uid': qt.team_uid,
                            'name': qt.name,
                        })
            if len(qt_objs) > 0:
                user_obj['queued_teams'] = qt_objs

        role_ids = {x.role_id for x in enterprise_data.role_users.get_links_by_object(user.enterprise_user_id)}
        if len(role_ids) > 0:
            roles = [r for r in (enterprise_data.roles.get_entity(x) for x in role_ids) if r]
            if len(roles) > 0:
                user_obj['roles'] = [{
                    'role_id': x.role_id,
                    'name': x.name,
                } for x in roles]

        share_admins = enterprise_utils.UserUtils.get_share_administrators(context.auth, user.username)
        if len(share_admins) > 0:
            user_obj['share_admins'] = share_admins

        if kwargs.get('format') == 'json':
            json_text = json.dumps(user_obj, indent=4)
            filename = kwargs.get('output')
            if filename is None:
                return json_text
            else:
                with open(filename, 'w') as f:
                    f.write(json_text)

        headers = ['user_id', 'email', 'full_name', 'node_name', 'status', 'transfer_status', 'tfa_enabled']
        table = []
        for field in headers:
            field_value = user_obj.get(field)
            if field_value is not None:
                row = [report_utils.field_to_title(field), field_value]
                if verbose:
                    if field == 'node_name':
                        row.append(user_obj.get('node_id'))
                    else:
                        row.append(None)
                table.append(row)

        objs = user_obj.get('aliases')
        if isinstance(objs, list) and len(objs) > 0:
            row = ['Email Alias(es)', objs]
            if verbose:
                row.append(None)
            table.append(row)

        objs = user_obj.get('teams')
        if isinstance(objs, list) and len(objs) > 0:
            row = ['Team(s)']
            names = [x.get('name') for x in objs]
            row.append(names)
            if verbose:
                row.append([x.get('team_uid') for x in objs])
            table.append(row)

        objs = user_obj.get('queued_teams')
        if isinstance(objs, list) and len(objs) > 0:
            row = ['Queued Team(s)']
            names = [x.get('name') for x in objs]
            row.append(names)
            if verbose:
                row.append([x.get('team_uid') for x in objs])
            table.append(row)

        objs = user_obj.get('roles')
        if isinstance(objs, list) and len(objs) > 0:
            row = ['Role(s)']
            names = [x.get('name') for x in objs]
            row.append(names)
            if verbose:
                row.append([x.get('role_id') for x in objs])
            table.append(row)

        objs = user_obj.get('share_admins')
        if isinstance(objs, list) and len(objs) > 0:
            row = ['Share Admin(s)', objs]
            if verbose:
                row.append(None)
            table.append(row)

        headers = ['', '']
        if verbose:
            headers.append('')
        report_utils.dump_report_data(table, headers=headers, no_header=True, right_align=[0])


class EnterpriseUserAddCommand(base.ArgparseCommand, enterprise_management.IEnterpriseManagementLogger):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='enterprise-user add', description='Create enterprise user(s).')
        parser.add_argument('--parent', dest='parent', action='store', help='Parent node name or ID')
        parser.add_argument('--full-name', dest='full_name', action='store', help='set user full name')
        parser.add_argument('--job-title', dest='job_title', action='store', help='set user job title')
        parser.add_argument('--add-role', dest='add_role', action='append', help='role name or role ID')
        parser.add_argument('--add-team', dest='add_team', action='append', help='team name or team UID')
        parser.add_argument('-hsf', '--hide-shared-folders', dest='hide_shared_folders', action='store',
                            choices=['on', 'off'], help='User does not see shared folders. --add-team only')
        parser.add_argument('email', type=str, nargs='+', help='User email. Can be repeated.')
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

        unique_emails: Set[str] = set()
        emails = kwargs.get('email')
        if emails:
            if isinstance(emails, list):
                for email in emails:
                    email = email.lower()
                    u = context.enterprise_data.users.get_entity(email)
                    if u is None:
                        unique_emails.add(email)
                    else:
                        self.logger.info('User \"%s\" already exists', u.username)
        if len(unique_emails) == 0:
            raise base.CommandError('No users to add')

        full_name: Optional[str] = kwargs.get('full_name')
        job_title: Optional[str] = kwargs.get('job_title')
        roles_to_add: Optional[Set[int]] = None
        teams_to_add: Optional[Set[str]] = None
        add_roles = kwargs.get('add_role')
        if isinstance(add_roles, list):
            roles = enterprise_utils.RoleUtils.resolve_existing_roles(context.enterprise_data, add_roles)
            if len(roles) > 0:
                roles_to_add = {x.role_id for x in roles}
        add_teams = kwargs.get('add_team')
        if isinstance(add_teams, list):
            teams, add_teams = enterprise_utils.TeamUtils.resolve_existing_teams(context.enterprise_data, add_teams)
            queued_teams, add_teams = enterprise_utils.TeamUtils.resolve_queued_teams(context.enterprise_data, add_teams)
            if len(add_teams) > 0:
                raise Exception(f'')
            if len(teams) > 0 or len(queued_teams) > 0:
                teams_to_add = set()
                if len(teams) > 0:
                    teams_to_add.update((x.team_uid for x in teams))
                if len(queued_teams) > 0:
                    teams_to_add.update((x.team_uid for x in queued_teams))

        batch = batch_management.BatchManagement(loader=context.enterprise_loader, logger=self)
        users_to_add = [enterprise_management.UserEdit(
            enterprise_user_id=context.enterprise_loader.get_enterprise_id(), node_id=parent_id, username=x,
            full_name=full_name, job_title=job_title)
            for x in unique_emails]
        batch.modify_users(to_add=users_to_add)

        if roles_to_add:
            role_membership_to_add: List[enterprise_management.RoleUserEdit] = []
            for user in users_to_add:
                for role_id in roles_to_add:
                    role_membership_to_add.append(enterprise_management.RoleUserEdit(enterprise_user_id=user.enterprise_user_id, role_id=role_id))
            batch.modify_role_users(to_add=role_membership_to_add)
        if teams_to_add:
            team_membership_to_add: List[enterprise_management.TeamUserEdit] = []
            hide_shared_folders: Optional[bool] = None
            hsf = kwargs.get('hide_shared_folders')
            if isinstance(hsf, str) and len(hsf) > 0:
                hide_shared_folders = True if hsf == 'on' else False
            user_type: Optional[int] = None
            if isinstance(hide_shared_folders, bool):
                user_type = 0 if hide_shared_folders else 2
            for user in users_to_add:
                for team_uid in teams_to_add:
                    team_membership_to_add.append(enterprise_management.TeamUserEdit(
                        enterprise_user_id=user.enterprise_user_id, team_uid=team_uid, user_type=user_type))
            batch.modify_team_users(to_add=team_membership_to_add)

        batch.apply()


class EnterpriseUserEditCommand(base.ArgparseCommand, enterprise_management.IEnterpriseManagementLogger):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='enterprise-user edit', description='Edit enterprise user(s).')
        parser.add_argument('--parent', dest='parent', action='store', help='Parent node name or ID')
        parser.add_argument('--full-name', dest='full_name', action='store', help='set user full name')
        parser.add_argument('--job-title', dest='job_title', action='store', help='set user job title')
        parser.add_argument('--add-role', dest='add_role', action='append', help='role name or role ID')
        parser.add_argument('--remove-role', dest='remove_role', action='append', help='role name or role ID')
        parser.add_argument('--add-team', dest='add_team', action='append', help='team name or team UID')
        parser.add_argument('--remove-team', dest='remove_team', action='append', help='team name or team UID')
        parser.add_argument('-hsf', '--hide-shared-folders', dest='hide_shared_folders', action='store',
                            choices=['on', 'off'], help='User does not see shared folders. --add-team only')
        parser.add_argument('email', type=str, nargs='+', help='User email or ID. Can be repeated.')
        super().__init__(parser)
        self.logger = api.get_logger()

    def warning(self, message: str) -> None:
        self.logger.warning(message)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        assert context.enterprise_data is not None

        parent_id: Optional[int]
        if kwargs.get('parent'):
            parent_node = enterprise_utils.NodeUtils.resolve_single_node(context.enterprise_data, kwargs.get('parent'))
            parent_id = parent_node.node_id
        else:
            parent_id = context.enterprise_data.root_node.node_id

        users = enterprise_utils.UserUtils.resolve_existing_users(context.enterprise_data, kwargs.get('email'))
        if len(users) == 0:
            raise base.CommandError('No users to edit')

        full_name: Optional[str] = kwargs.get('full_name')
        job_title: Optional[str] = kwargs.get('job_title')
        roles_to_add: Optional[Set[int]] = None
        roles_to_remove: Optional[Set[int]] = None
        teams_to_add: Optional[Set[str]] = None
        teams_to_remove: Optional[Set[str]] = None
        add_roles = kwargs.get('add_role')
        if isinstance(add_roles, list):
            roles = enterprise_utils.RoleUtils.resolve_existing_roles(context.enterprise_data, add_roles)
            if len(roles) > 0:
                roles_to_add = {x.role_id for x in roles}
        remove_roles = kwargs.get('remove_role')
        if isinstance(remove_roles, list):
            roles = enterprise_utils.RoleUtils.resolve_existing_roles(context.enterprise_data, remove_roles)
            if len(roles) > 0:
                roles_to_remove = {x.role_id for x in roles}
        add_teams = kwargs.get('add_team')
        if isinstance(add_teams, list):
            teams, add_teams = enterprise_utils.TeamUtils.resolve_existing_teams(context.enterprise_data, add_teams)
            queued_teams, add_teams = enterprise_utils.TeamUtils.resolve_queued_teams(context.enterprise_data, add_teams)
            if len(add_teams) > 0:
                missing_teams = ', '.join(add_teams)
                raise Exception(f'Team(s) {missing_teams} cannot be found')
            if len(teams) > 0 or len(queued_teams) > 0:
                teams_to_add = set()
                if len(teams) > 0:
                    teams_to_add.update((x.team_uid for x in teams))
                if len(queued_teams) > 0:
                    teams_to_add.update((x.team_uid for x in queued_teams))
        remove_teams = kwargs.get('remove_team')
        if isinstance(remove_teams, list):
            teams, remove_teams = enterprise_utils.TeamUtils.resolve_existing_teams(context.enterprise_data, remove_teams)
            queued_teams, remove_teams = enterprise_utils.TeamUtils.resolve_queued_teams(context.enterprise_data, remove_teams)
            if len(remove_teams) > 0:
                missing_teams = ', '.join(remove_teams)
                raise Exception(f'Team(s) {missing_teams} cannot be found')
            if len(teams) > 0 or len(queued_teams) > 0:
                teams_to_remove = set()
                if len(teams) > 0:
                    teams_to_remove.update((x.team_uid for x in teams))
                if len(queued_teams) > 0:
                    teams_to_remove.update((x.team_uid for x in queued_teams))
        if teams_to_remove and teams_to_add:
            intersect = teams_to_add.intersection(teams_to_remove)
            if len(intersect) > 0:
                teams_to_add = teams_to_add.difference(intersect)
                teams_to_remove = teams_to_remove.difference(intersect)

        batch = batch_management.BatchManagement(loader=context.enterprise_loader, logger=self)

        if parent_id or full_name or job_title:
            users_to_update = [enterprise_management.UserEdit(
                enterprise_user_id=x.enterprise_user_id, node_id=parent_id, full_name=full_name, job_title=job_title)
                for x in users]
            batch.modify_users(to_update=users_to_update)

        if roles_to_add and len(roles_to_add) > 0:
            role_membership_to_add: List[enterprise_management.RoleUserEdit] = []
            for user in users:
                for role_id in roles_to_add:
                    role_membership_to_add.append(enterprise_management.RoleUserEdit(enterprise_user_id=user.enterprise_user_id, role_id=role_id))
            batch.modify_role_users(to_add=role_membership_to_add)

        if roles_to_remove and len(roles_to_remove) > 0:
            role_membership_to_remove: List[enterprise_management.RoleUserEdit] = []
            for user in users:
                for role_id in roles_to_remove:
                    role_membership_to_remove.append(enterprise_management.RoleUserEdit(enterprise_user_id=user.enterprise_user_id, role_id=role_id))
            batch.modify_role_users(to_remove=role_membership_to_remove)

        if teams_to_add and len(teams_to_add) > 0:
            team_membership_to_add: List[enterprise_management.TeamUserEdit] = []
            hide_shared_folders: Optional[bool] = None
            hsf = kwargs.get('hide_shared_folders')
            if isinstance(hsf, str) and len(hsf) > 0:
                hide_shared_folders = True if hsf == 'on' else False
            user_type: Optional[int] = None
            if isinstance(hide_shared_folders, bool):
                user_type = 0 if hide_shared_folders else 2
            for user in users:
                for team_uid in teams_to_add:
                    team_membership_to_add.append(enterprise_management.TeamUserEdit(
                        enterprise_user_id=user.enterprise_user_id, team_uid=team_uid, user_type=user_type))
            batch.modify_team_users(to_add=team_membership_to_add)

        if teams_to_remove and len(teams_to_remove) > 0:
            team_membership_to_remove: List[enterprise_management.TeamUserEdit] = []
            for user in users:
                for team_uid in teams_to_remove:
                    team_membership_to_remove.append(enterprise_management.TeamUserEdit(
                        enterprise_user_id=user.enterprise_user_id, team_uid=team_uid))
            batch.modify_team_users(to_remove=team_membership_to_remove)

        batch.apply()


class EnterpriseUserDeleteCommand(base.ArgparseCommand, enterprise_management.IEnterpriseManagementLogger):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='enterprise-user delete', description='Delete enterprise user(s).')
        parser.add_argument('-f', '--force', dest='force', action='store_true',
                            help='do not prompt for confirmation')
        parser.add_argument('email', type=str, nargs='+', help='User email or ID. Can be repeated.')
        super().__init__(parser)
        self.logger = api.get_logger()

    def warning(self, message: str) -> None:
        self.logger.warning(message)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        assert context.enterprise_data is not None

        users = enterprise_utils.UserUtils.resolve_existing_users(context.enterprise_data, kwargs.get('email'))
        if len(users) == 0:
            raise base.CommandError('No users to delete')

        active_users = [x for x in users if x.status == 'active']
        if len(active_users) > 0:
            if kwargs.get('force') is not True:
                alert = prompt_utils.get_formatted_text('\nALERT!\n', prompt_utils.COLORS.FAIL)
                prompt_utils.output_text(
                    alert,'Deleting a user will also delete any records owned and shared by this user.\n' +
                          'Before you delete this user(s), we strongly recommend you lock their account\n' +
                          'and transfer any important records to other user(s).\n' +
                          'This action cannot be undone.\n')
                answer = prompt_utils.user_choice('Do you want to proceed with deletion?', 'yn', 'n')
                if answer.lower() not in ('y', 'yes'):
                    return

        batch = batch_management.BatchManagement(loader=context.enterprise_loader, logger=self)
        users_to_delete = [enterprise_management.UserEdit(enterprise_user_id=x.enterprise_user_id) for x in users]
        batch.modify_users(to_remove=users_to_delete)
        batch.apply()


class EnterpriseUserActionCommand(base.ArgparseCommand, enterprise_management.IEnterpriseManagementLogger):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='enterprise-user action', description='Enterprise user actions.')
        actions = parser.add_mutually_exclusive_group(required=True)
        actions.add_argument('--expire', dest='expire', action='store_true', help='expire master password')
        actions.add_argument('--extend', dest='extend', action='store_true',
                             help='extend vault transfer consent by 7 days. Supports the following pseudo users: @all')
        actions.add_argument('--lock', dest='lock', action='store_true', help='lock user')
        actions.add_argument('--unlock', dest='unlock', action='store_true', help='unlock user')
        actions.add_argument('--disable-2fa', dest='disable_2fa', action='store_true',
                             help='disable 2fa for user')
        parser.add_argument('email', type=str, nargs='+', help='User email or ID. Can be repeated.')
        super().__init__(parser)
        self.logger = api.get_logger()

    def warning(self, message: str) -> None:
        self.logger.warning(message)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        assert context.enterprise_data is not None

        users = enterprise_utils.UserUtils.resolve_existing_users(context.enterprise_data, kwargs.get('email'))
        if len(users) == 0:
            raise base.CommandError('No users to delete')

        inactive_users = [x for x in users if x.status != 'active']
        if len(inactive_users) > 0:
            names = ', '.join((x.username for x in inactive_users))
            self.logger.warning(f'Inactive users {names} are skipped')
        users = [x for x in users if x.status == 'active']
        if len(users) == 0:
            return

        batch = batch_management.BatchManagement(loader=context.enterprise_loader, logger=self)
        if kwargs.get('expire') is True:
            batch.user_actions(to_expire_password=[x.enterprise_user_id for x in users])
        elif kwargs.get('extend') is True:
            batch.user_actions(to_extend_transfer=[x.enterprise_user_id for x in users])
        elif kwargs.get('lock') is True:
            batch.user_actions(to_lock=[x.enterprise_user_id for x in users])
        elif kwargs.get('unlock') is True:
            batch.user_actions(to_unlock=[x.enterprise_user_id for x in users])
        elif kwargs.get('disable_2fa') is True:
            batch.user_actions(to_disable_tfa=[x.enterprise_user_id for x in users])
        else:
            return

        batch.apply()


class EnterpriseUserAliasCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='enterprise-user alias', description='Manage user aliases.')
        actions = parser.add_mutually_exclusive_group(required=True)
        actions.add_argument('--add-alias', dest='add_alias', action='store',
                             help='adds user alias')
        actions.add_argument('--remove-alias', dest='remove_alias', action='store',
                             help='removes user alias')
        parser.add_argument('email', help='User email or ID')
        super().__init__(parser)
        self.logger = api.get_logger()

    def execute(self, context: KeeperParams, **kwargs) -> None:
        assert context.enterprise_data is not None
        assert context.auth

        user = enterprise_utils.UserUtils.resolve_single_user(context.enterprise_data, kwargs.get('email'))
        aliases = context.enterprise_data.user_aliases.get_links_by_subject(user.enterprise_user_id)
        add_user = kwargs.get('add_alias')
        if isinstance(add_user, str):
            add_user = add_user.lower()
            if user.username == add_user:
                self.logger.info(f'User "%s" alias already exists', add_user)
            has_alias = any((True for x in aliases if x.username == add_user))
            if has_alias:
                alias_rq = APIRequest_pb2.EnterpriseUserAliasRequest()
                alias_rq.enterpriseUserId = user.enterprise_user_id
                alias_rq.alias = add_user
                context.auth.execute_auth_rest('enterprise/enterprise_user_set_primary_alias', alias_rq)
            else:
                add_rq = APIRequest_pb2.EnterpriseUserAddAliasRequestV2()
                alias_request = APIRequest_pb2.EnterpriseUserAddAliasRequest()
                alias_request.enterpriseUserId = user.enterprise_user_id
                alias_request.alias = add_user
                alias_request.primary = True
                add_rq.enterpriseUserAddAliasRequest.append(alias_request)
                add_rs = context.auth.execute_auth_rest(
                    'enterprise/enterprise_user_add_alias', add_rq, response_type=APIRequest_pb2.EnterpriseUserAddAliasResponse)
                assert add_rs
                for rs in add_rs.status:
                    if rs.status != 'success':
                        raise base.CommandError(f'Add alias {add_user} failed ({rs.status})')

        remove_alias = kwargs.get('remove_alias')
        if isinstance(remove_alias, str):
            remove_alias = remove_alias.lower()
            has_alias = remove_alias == user.username or any((True for x in aliases if x.username == add_user))
            if has_alias:
                return
            alias_rq = APIRequest_pb2.EnterpriseUserAliasRequest()
            alias_rq.enterpriseUserId = user.enterprise_user_id
            alias_rq.alias = remove_alias
            context.auth.execute_auth_rest('enterprise/enterprise_user_delete_alias', alias_rq)

        context.enterprise_loader.load()


