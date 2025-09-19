import argparse
import fnmatch
from functools import reduce
import re

from typing import Set, Dict, List, Any

from . import base
from .. import api, prompt_utils
from ..params import KeeperParams
from ..helpers import folder_utils, report_utils, share_utils
from keepersdk import utils
from keepersdk.proto import enterprise_pb2
from keepersdk.vault import record_management, vault_data, vault_types, vault_record, vault_utils


logger = api.get_logger()


class RecordListCommand(base.ArgparseCommand):
    parser = argparse.ArgumentParser(prog='list', description='List records', parents=[base.report_output_parser])
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='verbose output')
    parser.add_argument('-t', '--type', dest='record_type', action='append',
                             help='List records of certain types. Can be repeated')
    parser.add_argument('search_text', nargs='?', type=str, action='store', help='search text')

    def __init__(self) -> None:
        super().__init__(RecordListCommand.parser)

    def execute(self, context: KeeperParams, **kwargs):
        assert context.vault is not None
        verbose = kwargs.get('verbose') is True
        fmt = kwargs.get('format', 'table')
        search_text = kwargs.get('search_text')
        record_types = kwargs.get('record_type')
        record_version = set()
        if record_types:
            record_type = set()
            if isinstance(record_types, str):
                record_types = [record_types]
            for rt in record_types:
                if rt == 'app':
                    record_version.add(5)
                elif rt == 'file':
                    record_version.update((3, 4))
                    record_type.add('file')
                elif rt in ('general', 'legacy'):
                    record_version.update((1, 2))
                elif rt == 'pam':
                    record_version.add(6)
                else:
                    record_version.update((3, 6))
                    record_type.add(rt)
        else:
            record_version.update((1, 2, 3))
            record_type = None

        records = [x for x in context.vault.vault_data.find_records(
            criteria=search_text, record_type=record_type, record_version=record_version)]
        if any(records):
            headers = ['record_uid', 'type', 'title', 'description', 'shared']
            if fmt == 'table':
                headers = [report_utils.field_to_title(x) for x in headers]
            table = []
            for record in records:
                row = [record.record_uid, record.record_type, record.title, record.description, bool(record.flags & vault_record.RecordFlags.IsShared)]
                table.append(row)
            table.sort(key=lambda x: str(x[2] or '').lower())

            return report_utils.dump_report_data(table, headers, fmt=fmt, filename=kwargs.get('output'),
                                    row_number=True, column_width=None if verbose else 40)
        else:
            logger.info('No records are found')


class SharedFolderListCommand(base.ArgparseCommand):

    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='list-sf', parents=[base.report_output_parser], 
            description='Displays shared folders'
        )
        SharedFolderListCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser) -> None:
        parser.add_argument('--verbose', '-v', dest='verbose', action='store_true',
                            help='verbose output')
        parser.add_argument('pattern', nargs='?', metavar='pattern', help='pattern, or UID. Optional')

    def execute(self, context: KeeperParams, **kwargs):
        if not context.vault:
            raise ValueError("Vault is not initialized.")
        
        pattern = kwargs.get('pattern')
        shared_folders = self._find_shared_folders(context, pattern)
        
        if not shared_folders:
            logger.info('No shared folders are found')
            return None
            
        return self._build_shared_folders_report(shared_folders, kwargs)

    def _find_shared_folders(self, context: KeeperParams, pattern: str):
        """Find shared folders matching the given pattern."""
        return context.vault.vault_data.find_shared_folders(criteria=pattern)

    def _build_shared_folders_report(self, shared_folders, kwargs):
        """Build and format the shared folders report."""
        headers = self._get_shared_folders_headers(kwargs.get('format', 'table'))
        table = self._build_shared_folders_table(shared_folders)
        
        return report_utils.dump_report_data(
            table, 
            headers, 
            fmt=kwargs.get('format', 'table'), 
            filename=kwargs.get('output'), 
            row_number=True, 
            column_width=None if kwargs.get('verbose') else 40
        )

    def _get_shared_folders_headers(self, format_type: str):
        """Get headers for shared folders report."""
        headers = ['shared_folder_uid', 'name']
        if format_type == 'table':
            headers = [report_utils.field_to_title(x) for x in headers]
        return headers

    def _build_shared_folders_table(self, shared_folders):
        """Build table data for shared folders."""
        return [
            [shared_folder.shared_folder_uid, shared_folder.name] 
            for shared_folder in shared_folders
        ]


class TeamListCommand(base.ArgparseCommand):

    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='list-team', parents=[base.report_output_parser], description='Displays teams'
        )
        TeamListCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            '-v', '--verbose', dest='verbose', action='store_true', 
            help='verbose output (include team membership info)'
        )
        parser.add_argument(
            '-vv', '--very-verbose', dest='very_verbose', action='store_true', 
            help='more verbose output (fetches team membership info not in cache)'
        )
        parser.add_argument(
            '-a', '--all', dest='all', action='store_true', 
            help='show all teams in your contacts (including those outside your primary organization)'
        )
        parser.add_argument(
            '--sort', dest='sort', choices=['company', 'team_uid', 'name'], default='company', 
            help='sort teams by column (default: company)'
        )

    def execute(self, context: KeeperParams, **kwargs):
        if not context.vault:
            raise ValueError("Vault is not initialized.")
        
        teams = self._get_teams(context, kwargs)
        
        if not teams:
            logger.info('No teams are found')
            return None
            
        return self._build_teams_report(teams, kwargs)

    def _get_teams(self, context: KeeperParams, kwargs):
        """Get teams based on filters and options."""
        show_all_teams = kwargs.get('all', False)
        show_team_users = kwargs.get('verbose') or kwargs.get('very_verbose', False)
        fetch_missing_users = kwargs.get('very_verbose', False)
        
        # Get teams from share objects
        teams = self._get_teams_from_share_objects(context, show_all_teams)
        
        # Add additional teams if needed
        teams = self._add_additional_teams(context, teams)
        
        # Add team members if requested
        if show_team_users:
            teams = self.get_team_members(context, teams, fetch_missing_users)
            
        return teams

    def _get_teams_from_share_objects(self, context: KeeperParams, show_all_teams: bool):
        """Get teams from share objects with enterprise filtering."""
        share_objects = share_utils.get_share_objects(vault=context.vault)
        teams_data = share_objects.get('teams', {})
        orgs = share_objects.get('enterprises', {})
        
        enterprise_id = self._get_current_enterprise_id(context)
        is_included = lambda t: show_all_teams or t.get('enterprise_id') == enterprise_id
        
        teams = []
        for team_uid, team_info in teams_data.items():
            if not is_included(team_info):
                continue
            teams.append({
                'team_uid': team_uid,
                'name': team_info.get('name'),
                'enterprise_id': orgs.get(str(team_info.get('enterprise_id')))
            })
        
        return teams

    def _get_current_enterprise_id(self, context: KeeperParams):
        """Get the current user's enterprise ID."""
        if context.auth.auth_context.license:
            return context.auth.auth_context.license.get('enterpriseId')
        return None

    def _add_additional_teams(self, context: KeeperParams, teams):
        """Add additional teams if the current list is large enough."""
        if len(teams) >= 500:
            team_uids = {team['team_uid'] for team in teams}
            available_teams = vault_utils.load_available_teams(auth=context.vault.keeper_auth)
            
            additional_teams = [
                {
                    'team_uid': team.team_uid, 
                    'name': team.name, 
                    'enterprise_id': self._get_current_enterprise_id(context)
                } 
                for team in available_teams 
                if team.team_uid not in team_uids
            ]
            teams.extend(additional_teams)
        
        return teams

    def _build_teams_report(self, teams, kwargs):
        """Build and format the teams report."""
        headers = self._get_teams_headers(kwargs)
        table = self._build_teams_table(teams, kwargs)
        table = self._sort_teams_table(table, kwargs.get('sort', 'company'))
        
        return report_utils.dump_report_data(
            table, 
            headers, 
            fmt=kwargs.get('format', 'table'), 
            filename=kwargs.get('output'),
            row_number=True
        )

    def _get_teams_headers(self, kwargs):
        """Get headers for teams report."""
        show_team_users = kwargs.get('verbose') or kwargs.get('very_verbose', False)
        fmt = kwargs.get('format', 'table')
        
        headers = ['company', 'team_uid', 'name']
        if show_team_users:
            headers.append('member')
        
        if fmt != 'json':
            headers = [report_utils.field_to_title(x) for x in headers]
        
        return headers

    def _build_teams_table(self, teams, kwargs):
        """Build table data for teams."""
        show_team_users = kwargs.get('verbose') or kwargs.get('very_verbose', False)
        
        table = []
        for team in teams:
            row = [team.get('enterprise_id'), team.get('team_uid'), team.get('name')]
            if show_team_users:
                row.append(team.get('members'))
            table.append(row)
        
        return table

    def _sort_teams_table(self, table, sort_column):
        """Sort teams table by the specified column."""
        if sort_column == 'company':
            table.sort(key=lambda x: (x[0] or '').lower())
        elif sort_column == 'team_uid':
            table.sort(key=lambda x: x[1].lower())
        elif sort_column == 'name':
            table.sort(key=lambda x: x[2].lower())
        
        return table
    
    @classmethod
    def get_team_members(self, context: KeeperParams, teams: List[Dict[str, Any]], allow_fetch: bool) -> List[Dict[str, Any]]:
        if not context.enterprise_data:
            return teams

        def get_enterprise_teams():
            if not context.enterprise_data:
                return {}
            users = {x.enterprise_user_id: x.username for x in context.enterprise_data.users.get_all_entities()}
            return reduce(
                lambda a, b: {**a, b.team_uid: [*a.get(b.team_uid, []), users.get(b.enterprise_user_id)]},
                context.enterprise_data.team_users.get_all_links(),
                dict()
            )

        def fetch_members(team_uid: str) -> List[str]:
            if not allow_fetch:
                return []
            rq = enterprise_pb2.GetTeamMemberRequest()
            rq.teamUid = utils.base64_url_decode(team_uid)
            rs = context.vault.keeper_auth.execute_auth_rest(
                rest_endpoint='vault/get_team_members',
                request=rq,
                response_type=enterprise_pb2.GetTeamMemberResponse
            )
            return [x.email for x in rs.enterpriseUser]

        enterprise_teams = get_enterprise_teams()
        for t in teams:
            t['members'] = enterprise_teams.get(t.get('team_uid')) if enterprise_teams.get(t.get('team_uid')) else fetch_members(t.get('team_uid'))

        return teams

class ShortcutCommand(base.GroupCommand):
    def __init__(self):
        super(ShortcutCommand, self).__init__('Manage record shortcuts')
        self.register_command(ShortcutListCommand(), 'list', 'l')
        self.register_command(ShortcutKeepCommand(), 'keep')
        self.default_verb = 'list'

    @staticmethod
    def get_record_shortcuts(vault: vault_data.VaultData) -> Dict[str, Set[str]]: # Dict[record_uid, Set[folder_uid]]
        records: Dict[str, Set[str]] = {}
        for folder in vault.folders():
            for record_uid in folder.records:
                record = vault.get_record(record_uid)
                if record and record.version in (2, 3):
                    if record_uid not in records:
                        records[record_uid] = set()
                    records[record_uid].add(folder.folder_uid or '')

        shortcuts = [k for k, v in records.items() if len(v) <= 1]
        for record_uid in shortcuts:
            del records[record_uid]

        return records

class ShortcutListCommand(base.ArgparseCommand):
    parser = argparse.ArgumentParser(prog='shortcut list', parents=[base.report_output_parser],
                                     description='Displays shortcuts')
    parser.add_argument('--verbose', '-v', dest='verbose', action='store_true',
                        help='verbose output')
    parser.add_argument('-R', '--recursive', dest='recursive', action='store_true',
                        help='traverse recursively through subfolders')

    parser.add_argument('target', nargs='?', metavar='PATH', help='record/folder path, pattern, or UID. Optional')

    def __init__(self):
        super().__init__(ShortcutListCommand.parser)

    def execute(self, context: KeeperParams, **kwargs):
        assert context.vault is not None
        records = ShortcutCommand.get_record_shortcuts(context.vault.vault_data)
        if len(records) == 0:
            raise base.CommandError('Vault does not have shortcuts')

        uid_to_show = set()

        def add_records(fol: vault_types.Folder) -> None:
            nonlocal uid_to_show
            for r_uid in fol.records:
                if r_uid in records:
                    uid_to_show.add(r_uid)

        target = kwargs.get('target')
        recursive = kwargs.get('recursive') is True
        if target:
            record = context.vault.vault_data.get_record(target)
            if record is not None:
                if record.record_uid in records:
                    uid_to_show.add(record.record_uid)
            else:
                folder = context.vault.vault_data.get_folder(target)
                if folder is not None:
                    if recursive:
                        vault_utils.traverse_folder_tree(context.vault.vault_data, folder, add_records)
                    else:
                        add_records(folder)
                else:
                    folder, path = folder_utils.try_resolve_path(context, target)
                    if path:
                        regex = re.compile(fnmatch.translate(path)).match
                        for record_uid in folder.records:
                            if record_uid in records:
                                record = context.vault.vault_data.get_record(record_uid)
                                if record and record.version in (2, 3):
                                    if regex(record.title):
                                        uid_to_show.add(folder.folder_uid)
                    else:
                        if recursive:
                            vault_utils.traverse_folder_tree(context.vault.vault_data, folder, add_records)
                        else:
                            add_records(folder)

            if len(uid_to_show) == 0:
                raise base.CommandError(f'Target path {target} should be existing record or folder')
        else:
            uid_to_show.update(records.keys())

        verbose = kwargs.get('verbose') is True
        uid_to_show.intersection_update(records.keys())
        for record_uid in list(records.keys()):
            if record_uid not in uid_to_show:
                del records[record_uid]
        del uid_to_show

        folders = set()
        for f in records.values():
            folders.update(f)
        folder_names = {x: vault_utils.get_folder_path(context.vault.vault_data, x) for x in folders}
        del folders

        table = []
        fmt = kwargs.get('format')
        for record_uid, folder_uids in records.items():
            record = context.vault.vault_data.get_record(record_uid)
            if record:
                fs = {(folder_names.get(y.folder_uid) or ''): y for y in (context.vault.vault_data.get_folder(x) if x else context.vault.vault_data.root_folder for x in folder_uids) if y is not None}
                fo: List[Any] = []
                for folder_path in sorted(fs.keys()):
                    folder =  fs[folder_path]
                    is_shared = False if folder.folder_type == 'user_folder' else True
                    if fmt == 'json':
                        fo.append({
                            'folder_uid': folder.folder_uid,
                            'path': f'/{folder_path}',
                            'shared': is_shared
                        })
                    else:
                        folder_name = '[Shared] ' if is_shared else '[ User ] '
                        folder_name += '/' + folder_path
                        if verbose and folder.folder_uid:
                            folder_name += f' ({folder.folder_uid})'
                        fo.append(folder_name)
                table.append([record.record_uid, record.title, fo])

        headers = ['record_uid', 'record_title', 'folder']
        if fmt != 'json':
            headers = [report_utils.field_to_title(x) for x in headers]
        return report_utils.dump_report_data(table, headers, fmt=fmt, filename=kwargs.get('output'))

class ShortcutKeepCommand(base.ArgparseCommand):
    parser = argparse.ArgumentParser(prog='shortcut keep', description='Removes shortcuts except one')
    parser.add_argument('--dry-run', dest='dry_run', action='store_true',
                        help='dry-run mode: do not apply any changes')
    parser.add_argument('-f', '--force', dest='force', action='store_true',
                        help='do not prompt for confirmation')
    parser.add_argument('target', metavar='PATH', help='record/folder path to keep')

    def __init__(self):
        super().__init__(ShortcutKeepCommand.parser)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        assert context.vault is not None
        target = kwargs.get('target')
        if not target:
            raise base.CommandError('Target parameter cannot be empty')

        records = ShortcutCommand.get_record_shortcuts(context.vault.vault_data)
        to_keep: Dict[str, str] = {}

        record = context.vault.vault_data.get_record(target)
        if record:
            if record.record_uid in records:
                if (context.current_folder or '') in records[record.record_uid]:
                    to_keep[record.record_uid] = context.current_folder or ''
        else:
            folder = context.vault.vault_data.get_folder(target)
            if folder:
                for record_uid in folder.records.intersection(records.keys()):
                    if folder.folder_uid in records[record_uid]:
                        to_keep[record_uid] = folder.folder_uid
            else:
                folder, pattern = folder_utils.try_resolve_path(context, target)
                if not pattern:
                    pattern = '*'
                regex = re.compile(fnmatch.translate(pattern)).match
                for record_uid in folder.records.intersection(records.keys()):
                    record = context.vault.vault_data.get_record(record_uid)
                    if record and regex(record.title):
                        if folder.folder_uid in records[record_uid]:
                            to_keep[record_uid] = folder.folder_uid

        if len(to_keep) == 0:
            raise base.CommandError(f'There are no shortcut found for path "{target}"')

        dry_run = kwargs.get('dry_run') is True
        force = kwargs.get('force')
        for record_uid in list(records.keys()):
            if record_uid in to_keep:
                folder_uid = to_keep[record_uid]
                folders = records[record_uid]
                assert folder_uid in folders
                folders.remove(folder_uid)
            else:
                del records[record_uid]

        if dry_run:
            table = []
            headers = ['Record UID', 'Record Title', 'Folder to Keep', 'Folder(s) to Delete']
            for record_uid, folder_uid in to_keep.items():
                record = context.vault.vault_data.get_record(record_uid)
                folders = records[record_uid]
                table.append([record_uid, record.title if record else '',
                       '/' + vault_utils.get_folder_path(context.vault.vault_data, folder_uid),
                       ['/' + vault_utils.get_folder_path(context.vault.vault_data, x) for x in folders]])
                report_utils.dump_report_data(table, headers, title='Delete Shortcuts Changes')
        else:
            def delete_confirm(message: str) -> bool:
                if force:
                    return True
                prompt_utils.output_text(message)
                answer =  prompt_utils.user_choice('Do you want to proceed with deletion?', 'yn', default='n')
                return answer.lower() in ('y', 'yes')

            to_delete = [vault_types.RecordPath(folder_uid=folder_uid, record_uid=record_uid)
                         for record_uid in records.keys() for folder_uid in records[record_uid]]
            record_management.delete_vault_objects(context.vault, to_delete, delete_confirm)
