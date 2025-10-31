import argparse
import json
import datetime
from keepersdk.enterprise.enterprise_types import DeviceApprovalRequest
import time
from typing import Dict, List, Optional, Any, Set, TypedDict

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from keepersdk import utils
from keepersdk.enterprise import batch_management, enterprise_management
from keepersdk.proto import APIRequest_pb2,enterprise_pb2
from . import base, enterprise_utils
from .. import api, prompt_utils
from ..helpers import report_utils
from ..params import KeeperParams

from cryptography.hazmat.primitives.asymmetric import ec


logger = api.get_logger()

# Constants for EnterpriseDeviceApprovalCommand
GET_ENTERPRISE_USER_DATA_KEY_ENDPOINT = 'enterprise/get_enterprise_user_data_key'
GET_USER_DATA_KEY_SHARED_TO_ENTERPRISE_ENDPOINT = 'enterprise/get_user_data_key_shared_to_enterprise'
APPROVE_USER_DEVICES_ENDPOINT = 'enterprise/approve_user_devices'

AUDIT_REPORT_COMMAND = 'get_audit_event_reports'
AUDIT_REPORT_TYPE = 'span'
AUDIT_REPORT_SCOPE = 'enterprise'
AUDIT_REPORT_COLUMNS = ['ip_address', 'username']
AUDIT_EVENT_TYPE_LOGIN = 'login'
AUDIT_EVENT_LIMIT = 1000

TRUSTED_IP_LOOKBACK_DAYS = 365
TOKEN_PREFIX_LENGTH = 10
ECC_PUBLIC_KEY_LENGTH = 65
TIMESTAMP_MILLISECONDS_TO_SECONDS = 1000.0

DEVICE_REPORT_HEADERS = [
    'Date',
    'Email',
    'Device ID',
    'Device Name',
    'Device Type',
    'IP Address',
    'Client Version',
    'Location'
]


class AuditEventCreatedFilter(TypedDict):
    min: int


class AuditEventFilter(TypedDict):
    audit_event_type: str
    created: AuditEventCreatedFilter
    username: List[str]


class AuditEventReportRequest(TypedDict):
    command: str
    report_type: str
    scope: str
    columns: List[str]
    filter: AuditEventFilter
    limit: int


class EnterpriseUserCommand(base.GroupCommand):
    def __init__(self):
        super().__init__('Manage an enterprise users(s)')
        self.register_command(EnterpriseUserViewCommand(), 'view', 'v')
        self.register_command(EnterpriseUserAddCommand(), 'add', 'a')
        self.register_command(EnterpriseUserEditCommand(), 'edit', 'e')
        self.register_command(EnterpriseUserDeleteCommand(), 'delete')
        self.register_command(EnterpriseUserActionCommand(), 'action')
        self.register_command(EnterpriseUserAliasCommand(), 'alias')
        self.register_command(EnterpriseDeviceApprovalCommand(), 'device-approve')


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
                alias_request = APIRequest_pb2.EnterpriseUserAddAliasRequest()
                alias_request.enterpriseUserId = user.enterprise_user_id
                alias_request.alias = add_user
                alias_request.primary = True
                add_rs = context.auth.execute_auth_rest(
                    'enterprise/enterprise_user_add_alias', alias_request, response_type=APIRequest_pb2.EnterpriseUserAddAliasResponse)
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


class EnterpriseDeviceApprovalCommand(base.ArgparseCommand, enterprise_management.IEnterpriseManagementLogger):
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='device-approve', parents=[base.report_output_parser],
            description='Approve Cloud SSO Devices.',
            formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )
        EnterpriseDeviceApprovalCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser) -> None:
        parser.add_argument('--reload', '-r', dest='reload', action='store_true',
                                        help='reload list of pending approval requests')
        parser.add_argument('--approve', '-a', dest='approve', action='store_true',
                                        help='approve user devices')
        parser.add_argument('--deny', '-d', dest='deny', action='store_true', help='deny user devices')
        parser.add_argument('--trusted-ip', dest='check_ip', action='store_true',
                                        help='approve only devices coming from a trusted IP address')
        parser.add_argument('device', type=str, nargs='?', action="append", help='User email or device ID')

    def warning(self, message: str) -> None:
        logger.warning(message)

    @staticmethod
    def token_to_string(token: bytes) -> str:
        """Convert device token bytes to hexadecimal string representation."""
        src = token[0:TOKEN_PREFIX_LENGTH]
        if src.hex:
            return src.hex()
        return ''.join('{:02x}'.format(x) for x in src)
        
    def execute(self, context: KeeperParams, **kwargs) -> None:
        """Main execution method for device approval command."""
        assert context.enterprise_data is not None
        assert context.auth
        assert context.enterprise_loader is not None

        if kwargs.get('reload'):
            context.enterprise_loader.load()
        
        enterprise_data = context.enterprise_data
        
        approval_requests = self._load_approval_requests(enterprise_data)
        if not approval_requests:
            return

        if kwargs.get('approve') and kwargs.get('deny'):
            raise base.CommandError('Cannot approve and deny devices at the same time')

        matching_devices = self._filter_matching_devices(approval_requests, enterprise_data, kwargs.get('device'))
        if not matching_devices:
            return

        if kwargs.get('approve') and kwargs.get('check_ip'):
            matching_devices = self._filter_trusted_ip_devices(context, enterprise_data, matching_devices)
            if not matching_devices:
                return

        if kwargs.get('approve') or kwargs.get('deny'):
            self._process_approval_denial(context, enterprise_data, matching_devices, kwargs)
        else:
            self._display_report(enterprise_data, matching_devices, kwargs)

    def _load_approval_requests(self, enterprise_data) -> List[DeviceApprovalRequest]:
        """Load and return all pending device approval requests."""
        approval_requests: List[DeviceApprovalRequest] = list(enterprise_data.device_approval_requests.get_all_entities())
        if len(approval_requests) == 0:
            logger.info('No pending approval requests')
            return []
        return approval_requests

    def _filter_matching_devices(self, approval_requests: List[DeviceApprovalRequest], 
                                  enterprise_data, device_filters) -> Dict[str, DeviceApprovalRequest]:
        """Filter devices based on device ID or user email filters."""
        matching_devices = {}
        
        for device in approval_requests:
            device_id = device.encrypted_device_token
            if not device_id:
                continue
            device_id = EnterpriseDeviceApprovalCommand.token_to_string(utils.base64_url_decode(device_id))
            
            if self._device_matches_filter(device, device_id, enterprise_data, device_filters):
                matching_devices[device_id] = device

        if len(matching_devices) == 0:
            logger.info('No matching devices found')
        return matching_devices

    def _device_matches_filter(self, device: DeviceApprovalRequest, device_id: str,
                               enterprise_data, device_filters) -> bool:
        """Check if a device matches any of the provided filters."""
        if not isinstance(device_filters, (list, tuple)):
            return True
        
        for name in device_filters:
            if not name:
                return True
            if device_id.startswith(name):
                return True
            ent_user_id = device.enterprise_user_id
            user = next((x for x in enterprise_data.users.get_all_entities() 
                        if x.enterprise_user_id == ent_user_id), None)
            if user and user.username == name:
                return True
        return False

    def _filter_trusted_ip_devices(self, context: KeeperParams, enterprise_data,
                                   matching_devices: Dict[str, DeviceApprovalRequest]) -> Dict[str, DeviceApprovalRequest]:
        """Filter devices to only include those from trusted IP addresses."""
        user_ids = set([x.enterprise_user_id for x in matching_devices.values()])
        emails = self._get_user_emails(enterprise_data, user_ids)
        
        ip_map = self._get_trusted_ip_map(context, list(emails.values()))
        
        trusted_devices = {}
        for device_id, device in matching_devices.items():
            username = emails.get(device.enterprise_user_id)
            ip_address = device.ip_address
            is_trusted = username and ip_address and username in ip_map and ip_address in ip_map[username]
            
            if is_trusted:
                trusted_devices[device_id] = device
            else:
                logger.warning("The user %s attempted to login from an unstrusted IP (%s). "
                              "To force the approval, run the same command without the --trusted-ip argument", 
                              username, ip_address)

        if len(trusted_devices) == 0:
            logger.info('No matching devices found')
        return trusted_devices

    def _get_user_emails(self, enterprise_data, user_ids: Set[int]) -> Dict[int, str]:
        """Build a mapping of user IDs to usernames."""
        emails = {}
        for user in enterprise_data.users.get_all_entities():
            user_id = user.enterprise_user_id
            if user_id in user_ids:
                emails[user_id] = user.username
        return emails

    def _get_trusted_ip_map(self, context: KeeperParams, emails: List[str]) -> Dict[str, Set[str]]:
        """Get mapping of usernames to their trusted IP addresses from audit logs."""
        last_year = datetime.datetime.now() - datetime.timedelta(days=TRUSTED_IP_LOOKBACK_DAYS)
        audit_request: AuditEventReportRequest = {
            'command': AUDIT_REPORT_COMMAND,
            'report_type': AUDIT_REPORT_TYPE,
            'scope': AUDIT_REPORT_SCOPE,
            'columns': AUDIT_REPORT_COLUMNS,
            'filter': {
                'audit_event_type': AUDIT_EVENT_TYPE_LOGIN,
                'created': {
                    'min': int(last_year.timestamp())
                },
                'username': emails
            },
            'limit': AUDIT_EVENT_LIMIT
        }

        response = context.auth.execute_auth_command(audit_request)
        ip_map = {}
        
        if response.get('audit_event_overview_report_rows'):
            for row in response.get('audit_event_overview_report_rows'):
                username = row.get('username')
                if username:
                    if username not in ip_map:
                        ip_map[username] = set()
                    ip_map[username].add(row.get('ip_address'))
        
        return ip_map

    def _process_approval_denial(self, context: KeeperParams, enterprise_data,
                                 matching_devices: Dict[str, DeviceApprovalRequest], kwargs: Dict[str, Any]) -> None:
        """Process device approval or denial requests."""
        approve_rq = enterprise_pb2.ApproveUserDevicesRequest()
        data_keys = {}
        
        if kwargs.get('approve'):
            data_keys = self._collect_user_data_keys(context, enterprise_data, matching_devices)
        
        device_requests = self._build_device_requests(matching_devices, data_keys, kwargs)
        if not device_requests:
            return
        
        approve_rq.deviceRequests.extend(device_requests)
        context.auth.execute_auth_rest(APPROVE_USER_DEVICES_ENDPOINT, approve_rq, 
                                       response_type=enterprise_pb2.ApproveUserDevicesResponse)
        context.enterprise_loader.load()

    def _collect_user_data_keys(self, context: KeeperParams, enterprise_data,
                                matching_devices: Dict[str, DeviceApprovalRequest]) -> Dict[int, bytes]:
        """Collect user data keys using ECC and RSA methods."""
        data_keys: Dict[int, bytes] = {}
        user_ids = set([x.enterprise_user_id for x in matching_devices.values()])
        
        # Try ECC method first
        ecc_user_ids = user_ids.copy()
        ecc_user_ids.difference_update(data_keys.keys())
        if ecc_user_ids:
            ecc_keys = self._get_ecc_data_keys(context, enterprise_data, ecc_user_ids)
            data_keys.update(ecc_keys)
        
        # Try RSA method for remaining users (Account Transfer)
        rsa_user_ids = user_ids.copy()
        rsa_user_ids.difference_update(data_keys.keys())
        if rsa_user_ids and not context.auth.auth_context.forbid_rsa:
            rsa_keys = self._get_rsa_data_keys(context, enterprise_data, rsa_user_ids)
            data_keys.update(rsa_keys)
        
        return data_keys

    def _get_ecc_data_keys(self, context: KeeperParams, enterprise_data, user_ids: Set[int]) -> Dict[int, bytes]:
        """Get user data keys using ECC encryption."""
        data_keys: Dict[int, bytes] = {}
        curve = ec.SECP256R1()
        ecc_private_key = self._get_ecc_private_key(enterprise_data, curve)
        
        if not ecc_private_key:
            return data_keys
        
        data_key_rq = APIRequest_pb2.UserDataKeyRequest()
        data_key_rq.enterpriseUserId.extend(user_ids)
        data_key_rs = context.auth.execute_auth_rest(
            GET_ENTERPRISE_USER_DATA_KEY_ENDPOINT, data_key_rq, 
            response_type=APIRequest_pb2.EnterpriseUserDataKeys)
        
        for key in data_key_rs.keys:
            enc_data_key = key.userEncryptedDataKey
            if enc_data_key:
                try:
                    ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                        curve, enc_data_key[:ECC_PUBLIC_KEY_LENGTH])
                    shared_key = ecc_private_key.exchange(ec.ECDH(), ephemeral_public_key)
                    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                    digest.update(shared_key)
                    enc_key = digest.finalize()
                    data_key = utils.crypto.decrypt_aes_v2(enc_data_key[ECC_PUBLIC_KEY_LENGTH:], enc_key)
                    data_keys[key.enterpriseUserId] = data_key
                except Exception as e:
                    logger.debug(e)
        
        return data_keys

    def _get_ecc_private_key(self, enterprise_data, curve) -> Optional[Any]:
        """Extract and decrypt the ECC private key from enterprise data."""
        if not enterprise_data.enterprise_info.keys:
            return None
        if not enterprise_data.enterprise_info.keys.ecc_encrypted_private_key:
            return None
        
        try:
            keys = enterprise_data.get_enterprise_data_keys()
            ecc_private_key_data = utils.base64_url_decode(keys.ecc_encrypted_private_key)
            ecc_private_key_data = utils.crypto.decrypt_aes_v2(
                ecc_private_key_data, enterprise_data.enterprise_info.tree_key)
            private_value = int.from_bytes(ecc_private_key_data, byteorder='big', signed=False)
            return ec.derive_private_key(private_value, curve, default_backend())
        except Exception as e:
            logger.debug(e)
            return None

    def _get_rsa_data_keys(self, context: KeeperParams, enterprise_data, user_ids: Set[int]) -> Dict[int, bytes]:
        """Get user data keys from Account Transfer using RSA encryption."""
        data_keys: Dict[int, bytes] = {}
        data_key_rq = APIRequest_pb2.UserDataKeyRequest()
        data_key_rq.enterpriseUserId.extend(user_ids)
        data_key_rs = context.auth.execute_auth_rest(
            GET_USER_DATA_KEY_SHARED_TO_ENTERPRISE_ENDPOINT, data_key_rq,
            response_type=APIRequest_pb2.UserDataKeyResponse)
        
        if data_key_rs.noEncryptedDataKey:
            user_ids_without_key = set(data_key_rs.noEncryptedDataKey)
            usernames = [x.username for x in enterprise_data.users.get_all_entities() 
                        if x.enterprise_user_id in user_ids_without_key]
            if usernames:
                logger.info('User(s) \"%s\" have no accepted account transfers or did not share encryption key', 
                           ', '.join(usernames))
        
        if data_key_rs.accessDenied:
            denied_user_ids = set(data_key_rs.accessDenied)
            usernames = [x.username for x in enterprise_data.users.get_all_entities() 
                        if x.enterprise_user_id in denied_user_ids]
            if usernames:
                logger.info('You cannot manage these user(s): %s', ', '.join(usernames))
        
        if data_key_rs.userDataKeys:
            for dk in data_key_rs.userDataKeys:
                try:
                    role_key = utils.crypto.decrypt_aes_v2(dk.roleKey, enterprise_data.enterprise_info.tree_key)
                    encrypted_private_key = utils.base64_url_decode(dk.privateKey)
                    decrypted_private_key = utils.crypto.decrypt_aes_v1(encrypted_private_key, role_key)
                    private_key = utils.crypto.load_rsa_private_key(decrypted_private_key)
                    
                    for user_dk in dk.enterpriseUserIdDataKeyPairs:
                        if user_dk.enterpriseUserId not in data_keys:
                            if user_dk.keyType in (enterprise_pb2.KT_NO_KEY, enterprise_pb2.KT_ENCRYPTED_BY_PUBLIC_KEY):
                                data_key = utils.crypto.decrypt_rsa(user_dk.encryptedDataKey, private_key)
                                data_keys[user_dk.enterpriseUserId] = data_key
                except Exception as ex:
                    logger.debug(ex)
        
        return data_keys

    def _build_device_requests(self, matching_devices: Dict[str, DeviceApprovalRequest],
                               data_keys: Dict[int, bytes], kwargs: Dict[str, Any]) -> List[Any]:
        """Build device approval/denial request messages."""
        device_requests = []
        curve = ec.SECP256R1()
        is_denial = kwargs.get('deny')
        is_approval = kwargs.get('approve')
        
        for device in matching_devices.values():
            device_rq = enterprise_pb2.ApproveUserDeviceRequest()
            device_rq.enterpriseUserId = device.enterprise_user_id
            device_rq.encryptedDeviceToken = utils.base64_url_decode(device.encrypted_device_token)
            device_rq.denyApproval = is_denial
            
            if is_approval:
                if not device.device_public_key or len(device.device_public_key) == 0:
                    continue
                
                data_key = data_keys.get(device.enterprise_user_id)
                if not data_key:
                    continue
                
                encrypted_data_key = self._encrypt_device_data_key(device, data_key, curve)
                if not encrypted_data_key:
                    continue
                
                device_rq.encryptedDeviceDataKey = encrypted_data_key
            
            device_requests.append(device_rq)
        
        return device_requests

    def _encrypt_device_data_key(self, device: DeviceApprovalRequest, data_key: bytes, curve) -> Optional[bytes]:
        """Encrypt data key for device using ECDH key exchange."""
        try:
            ephemeral_key = ec.generate_private_key(curve, default_backend())
            device_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                curve, utils.base64_url_decode(device.device_public_key))
            shared_key = ephemeral_key.exchange(ec.ECDH(), device_public_key)
            
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(shared_key)
            enc_key = digest.finalize()
            
            encrypted_data_key = utils.crypto.encrypt_aes_v2(data_key, enc_key)
            ephemeral_public_key = ephemeral_key.public_key().public_bytes(
                serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
            
            return ephemeral_public_key + encrypted_data_key
        except Exception as e:
            logger.info(e)
            return None

    def _display_report(self, enterprise_data, matching_devices: Dict[str, DeviceApprovalRequest],
                       kwargs: Dict[str, Any]) -> None:
        """Display device approval request report."""
        logger.info('')
        headers = DEVICE_REPORT_HEADERS.copy()
        
        if kwargs.get('format') == 'json':
            headers = [x.replace(' ', '_').lower() for x in headers]

        rows = []
        for device_id, device in matching_devices.items():
            user = next((x for x in enterprise_data.users.get_all_entities()
                        if x.enterprise_user_id == device.enterprise_user_id), None)
            if not user:
                continue

            date_formatted = time.strftime('%Y-%m-%d %H:%M:%S', 
                                          time.gmtime(device.date / TIMESTAMP_MILLISECONDS_TO_SECONDS))

            rows.append([
                date_formatted,
                user.username,
                device_id,
                device.device_name,
                device.device_type,
                device.ip_address,
                device.client_version,
                device.location
            ])
        
        rows.sort(key=lambda x: x[0])
        return report_utils.dump_report_data(rows, headers, fmt=kwargs.get('format'), 
                                            filename=kwargs.get('output'))