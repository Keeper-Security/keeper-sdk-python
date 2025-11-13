import argparse
import json
from typing import Dict, List, Optional, Any, Tuple

from keepersdk import utils, crypto
from keepersdk.enterprise import enterprise_types, batch_management, enterprise_management
from . import base, enterprise_utils
from .. import api, prompt_utils
from ..helpers import report_utils
from ..params import KeeperParams


logger = api.get_logger()


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
        team_name =  kwargs.get('team')
        team = enterprise_utils.TeamUtils.resolve_single_team(enterprise_data, team_name)
        if team is None:
            raise base.CommandError(f'Team name \"{team_name}\" does not exist')
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
        restrict_edit = r_edit == 'on'

        restrict_share: Optional[bool] = None
        r_share = kwargs.get('restrict_share')
        restrict_share = r_share == 'on'
        
        restrict_view: Optional[bool] = None
        r_view = kwargs.get('restrict_view')
        restrict_view = r_view == 'on'

        teams_to_edit = [enterprise_management.TeamEdit(
            team_uid=x.team_uid, name=team_name, node_id=parent_id,
            restrict_edit=restrict_edit, restrict_share=restrict_share, restrict_view=restrict_view)
            for x in team_list]

        batch = batch_management.BatchManagement(loader=context.enterprise_loader, logger=self)
        batch.modify_teams(to_update=teams_to_edit)
        batch.apply()


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


class TeamApproveCommand(base.ArgparseCommand):

    def __init__(self):
        self.parser = argparse.ArgumentParser(
            prog='team-approve', parents=[base.report_output_parser],
            description='Enable or disable automated team and user approvals'
        )
        TeamApproveCommand.add_arguments_to_parser(self.parser)
        super().__init__(self.parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser) -> None:
        parser.add_argument('--team', dest='team', action='store_true', help='Approve teams only.')
        parser.add_argument('--email', dest='user', action='store_true', help='Approve team users only.')
        parser.add_argument('--restrict-edit', dest='restrict_edit', choices=['on', 'off'], action='store',
                                        help='disable record edits')
        parser.add_argument('--restrict-share', dest='restrict_share', choices=['on', 'off'], action='store',
                                        help='disable record re-shares')
        parser.add_argument('--restrict-view', dest='restrict_view', choices=['on', 'off'], action='store',
                                        help='disable view/copy passwords')
        parser.add_argument('--dry-run', dest='dry_run', action='store_true',
                                        help='Report on run approval commands only. Do not run.')
    
    def execute(self, context: KeeperParams, **kwargs) -> None:
        self._validate_vault(context)
        
        approve_teams, approve_users = self._determine_approval_flags(kwargs)
        teams = self._build_teams_lookup(context.enterprise_data)
        active_users = self._build_active_users_lookup(context.enterprise_data)
        
        request_batch = []
        added_team_keys = {}
        added_teams = {}
        
        if approve_teams:
            team_requests, team_keys, new_teams = self._build_team_approval_requests(
                context, kwargs, teams
            )
            request_batch.extend(team_requests)
            added_team_keys.update(team_keys)
            added_teams.update(new_teams)
            teams.update(new_teams)
        
        if approve_users:
            user_requests = self._build_user_approval_requests(
                context, teams, added_teams, added_team_keys, active_users
            )
            request_batch.extend(user_requests)
        
        if request_batch:
            if kwargs.get('dry_run'):
                self._generate_dry_run_report(request_batch, teams, active_users, kwargs)
            else:
                self._execute_batch_and_report(context, request_batch)
    
    def _determine_approval_flags(self, kwargs: Dict[str, Any]) -> Tuple[bool, bool]:
        """Determine which approval types to process based on kwargs."""
        approve_teams = True
        approve_users = True
        if kwargs.get('team') or kwargs.get('user'):
            approve_teams = kwargs.get('team', False)
            approve_users = kwargs.get('user', False)
        return approve_teams, approve_users
    
    def _build_teams_lookup(self, enterprise_data) -> Dict[str, Any]:
        """Build a dictionary mapping team_uid to team objects."""
        return {team.team_uid: team for team in enterprise_data.teams.get_all_entities()}
    
    def _build_active_users_lookup(self, enterprise_data) -> Dict[int, str]:
        """Build a dictionary mapping user_id to username for active users."""
        return {
            x.enterprise_user_id: x.username 
            for x in enterprise_data.users.get_all_entities() 
            if x.status == 'active' and x.lock == 0
        }
    
    def _build_team_approval_requests(
        self, context: KeeperParams, kwargs: Dict[str, Any], teams: Dict[str, Any]
    ) -> Tuple[List[Dict[str, Any]], Dict[str, bytes], Dict[str, Any]]:
        """Build approval requests for queued teams."""
        request_batch = []
        added_team_keys = {}
        added_teams = {}
        enterprise_data = context.enterprise_data
        
        queued_teams = enterprise_data.queued_teams.get_all_entities()
        if not queued_teams:
            return request_batch, added_team_keys, added_teams
        
        tree_key = enterprise_data.enterprise_info.tree_key
        data_key = context.auth.auth_context.data_key
        forbid_rsa = context.auth.auth_context.forbid_rsa
        
        for queued_team in queued_teams:
            team_uid = queued_team.team_uid
            team_key = utils.generate_aes_key()
            added_team_keys[team_uid] = team_key
            added_teams[team_uid] = queued_team
            
            request = self._create_team_add_request(
                queued_team, team_key, tree_key, data_key, forbid_rsa, kwargs
            )
            request_batch.append(request)
        
        return request_batch, added_team_keys, added_teams
    
    def _create_team_add_request(
        self, queued_team, team_key: bytes, tree_key: bytes, 
        data_key: bytes, forbid_rsa: bool, kwargs: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create a single team_add request with all required encryption."""
        encrypted_team_key = crypto.encrypt_aes_v1(team_key, data_key)
        
        request = {
            'command': 'team_add',
            'team_uid': queued_team.team_uid,
            'team_name': queued_team.name,
            'restrict_edit': kwargs.get('restrict_edit') == 'on',
            'restrict_share': kwargs.get('restrict_share') == 'on',
            'restrict_view': kwargs.get('restrict_view') == 'on',
            'node_id': queued_team.node_id,
            'team_key': utils.base64_url_encode(encrypted_team_key),
            'encrypted_team_key': utils.base64_url_encode(crypto.encrypt_aes_v2(team_key, tree_key)),
            'manage_only': True
        }
        
        ec_private_key, ec_public_key = crypto.generate_ec_key()
        encrypted_ec_private_key = crypto.encrypt_aes_v2(
            crypto.unload_ec_private_key(ec_private_key), team_key
        )
        request['ecc_private_key'] = utils.base64_url_encode(encrypted_ec_private_key)
        request['ecc_public_key'] = utils.base64_url_encode(crypto.unload_ec_public_key(ec_public_key))
        
        if not forbid_rsa:
            rsa_pri_key, rsa_pub_key = crypto.generate_rsa_key()
            encrypted_rsa_private_key = crypto.encrypt_aes_v1(
                crypto.unload_rsa_private_key(rsa_pri_key), team_key
            )
            request['private_key'] = utils.base64_url_encode(encrypted_rsa_private_key)
            request['public_key'] = utils.base64_url_encode(crypto.unload_rsa_public_key(rsa_pub_key))
        
        return request
    
    def _build_user_approval_requests(
        self, context: KeeperParams, teams: Dict[str, Any], 
        added_teams: Dict[str, Any], added_team_keys: Dict[str, bytes],
        active_users: Dict[int, str]
    ) -> List[Dict[str, Any]]:
        """Build approval requests for queued team users."""
        enterprise_data = context.enterprise_data
        vault = context.vault
        
        queued_team_users = enterprise_data.queued_team_users.get_all_links()
        if not queued_team_users or not enterprise_data.teams.get_all_entities() or not enterprise_data.users.get_all_entities():
            return []
        
        team_keys, all_users = self._collect_team_keys_and_users(
            queued_team_users, teams, added_teams, active_users
        )
        
        if not team_keys or not all_users:
            return []
        
        self._load_team_and_user_keys(vault, team_keys, added_team_keys, all_users)
        
        return self._create_user_add_requests(
            context, queued_team_users, team_keys, active_users
        )
    
    def _collect_team_keys_and_users(
        self, queued_team_users, teams: Dict[str, Any], 
        added_teams: Dict[str, Any], active_users: Dict[int, str]
    ) -> Tuple[Dict[str, Any], set]:
        """Collect team UIDs that need keys loaded and all user emails."""
        team_keys = {}
        all_users = set()
        
        for qtu in queued_team_users:
            team_uid = qtu.team_uid
            if team_uid not in teams and team_uid not in added_teams:
                continue
            
            email = active_users.get(qtu.enterprise_user_id)
            if email:
                email = email.lower()
                if team_uid in teams and team_uid not in team_keys:
                    team_keys[team_uid] = None
                if email not in all_users:
                    all_users.add(email)
        
        return team_keys, all_users
    
    def _load_team_and_user_keys(
        self, vault, team_keys: Dict[str, Any], 
        added_team_keys: Dict[str, bytes], all_users: set
    ) -> None:
        """Load team keys and user public keys from the vault."""
        vault.keeper_auth.load_team_keys(list(team_keys.keys()))
        
        for team_uid in team_keys.keys():
            team_key = vault.keeper_auth.get_team_keys(team_uid)
            if team_key and team_key.aes:
                team_keys[team_uid] = team_key.aes
        
        team_keys.update(added_team_keys)
        vault.keeper_auth.load_user_public_keys(list(all_users), False)
    
    def _create_user_add_requests(
        self, context: KeeperParams, queued_team_users, 
        team_keys: Dict[str, bytes], active_users: Dict[int, str]
    ) -> List[Dict[str, Any]]:
        """Create user add requests for queued team users."""
        request_batch = []
        forbid_rsa = context.auth.auth_context.forbid_rsa
        vault = context.vault
        
        for qtu in queued_team_users:
            team_uid = qtu.team_uid
            team_key = team_keys.get(team_uid)
            if not team_key:
                continue
            
            for u_id in qtu.get('users') or []:
                username = active_users.get(u_id)
                if not username:
                    continue
                
                keys = vault.keeper_auth.get_user_keys(username.lower())
                if not keys:
                    continue
                
                request = self._create_single_user_add_request(
                    team_uid, u_id, team_key, keys, username, forbid_rsa
                )
                if request:
                    request_batch.append(request)
        
        return request_batch
    
    def _create_single_user_add_request(
        self, team_uid: str, user_id: int, team_key: bytes, 
        keys, username: str, forbid_rsa: bool
    ) -> Optional[Dict[str, Any]]:
        """Create a single user add request with appropriate encryption."""
        request = {
            'command': 'team_enterprise_user_add',
            'team_uid': team_uid,
            'enterprise_user_id': user_id,
            'user_type': 0,
        }
        
        try:
            if forbid_rsa:
                if not keys.ec:
                    logger.warning('User %s does not have EC key. Skipping', username)
                    return None
                ec_key = crypto.load_ec_public_key(keys.ec)
                encrypted_team_key = crypto.encrypt_ec(team_key, ec_key)
                request['team_key'] = utils.base64_url_encode(encrypted_team_key)
                request['team_key_type'] = 'encrypted_by_public_key_ecc'
            else:
                if not keys.rsa:
                    logger.warning('User %s does not have RSA key. Skipping', username)
                    return None
                rsa_key = crypto.load_rsa_public_key(keys.rsa)
                encrypted_team_key = crypto.encrypt_rsa(team_key, rsa_key)
                request['team_key'] = utils.base64_url_encode(encrypted_team_key)
                request['team_key_type'] = 'encrypted_by_public_key'
            
            return request
        except Exception as e:
            logger.warning('Cannot approve user "%s" to team "%s": %s', username, team_uid, e)
            return None
    
    def _execute_batch_and_report(self, context: KeeperParams, request_batch: List[Dict[str, Any]]) -> None:
        """Execute the batch request and report results."""
        vault = context.vault
        rs = vault.keeper_auth.execute_batch(request_batch)
        
        if rs:
            stats = self._calculate_batch_stats(rs)
            self._log_batch_results(stats)
        
        context.enterprise_loader.load(reset=True)
    
    def _calculate_batch_stats(self, results: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculate success/failure statistics from batch results."""
        stats = {
            'team_add_success': 0,
            'team_add_failure': 0,
            'user_add_success': 0,
            'user_add_failure': 0
        }
        
        for status in results:
            is_team = status['command'] == 'team_add'
            if 'result' in status:
                if status['result'] == 'success':
                    if is_team:
                        stats['team_add_success'] += 1
                    else:
                        stats['user_add_success'] += 1
                else:
                    if is_team:
                        stats['team_add_failure'] += 1
                    else:
                        stats['user_add_failure'] += 1
        
        return stats
    
    def _log_batch_results(self, stats: Dict[str, int]) -> None:
        """Log batch execution results."""
        if stats['team_add_success'] or stats['team_add_failure']:
            logger.info(
                'Team approval: success %s; failure %s',
                stats['team_add_success'], stats['team_add_failure']
            )
        if stats['user_add_success'] or stats['user_add_failure']:
            logger.info(
                'Team User approval: success %s; failure %s',
                stats['user_add_success'], stats['user_add_failure']
            )
    
    def _generate_dry_run_report(
        self, request_batch: List[Dict[str, Any]], 
        teams: Dict[str, Any], active_users: Dict[int, str], kwargs: Dict[str, Any]
    ) -> None:
        """Generate and display dry-run report."""
        table = []
        for rq in request_batch:
            team_uid = rq['team_uid']
            team_name = team_uid
            if team_uid in teams:
                team_name = teams[team_uid].name
            
            username = ''
            action = 'Approve Team'
            if rq['command'] == 'team_enterprise_user_add':
                action = 'Approve User'
                user_id = rq['enterprise_user_id']
                username = active_users.get(user_id, user_id)
            
            table.append([action, team_name, username])
        
        headers = ['Action', 'Team', 'User']
        report_utils.dump_report_data(
            table, headers, fmt=kwargs.get('format'), filename=kwargs.get('output')
        )
    
    def _validate_vault(self, context: KeeperParams):
        """Validate that vault is initialized."""
        if not context.vault:
            raise base.CommandError('Vault is not initialized. Login to initialize the vault.')