import argparse
import fnmatch
import functools
import itertools
import json
import logging
import re
import shutil
from collections import OrderedDict
from typing import Iterable, List, Tuple, Optional, Callable, Any, Dict, Set

from asciitree import LeftAligned
from colorama import Style
from keepersdk.proto import folder_pb2
from keepersdk import crypto, utils

from keepersdk.vault import vault_data, vault_types, vault_record, folder_management, record_management, vault_utils, vault_online
from . import base
from .. import prompt_utils, constants, api
from ..helpers import folder_utils, report_utils
from ..params import KeeperParams


class _FolderMixin:
    @staticmethod
    def resolve_single_folder(folder_name: Optional[str], context: KeeperParams):
        if not folder_name:
            raise base.CommandError('Folder cannot be empty')
        assert context.vault is not None
        folder = context.vault.vault_data.get_folder(folder_name)
        if not folder:
            folder, pattern = folder_utils.try_resolve_path(context, folder_name)
            if pattern:
                folder = None

        if not folder:
            raise base.CommandError(f'Folder "{folder_name}" not found')
        return folder

    @staticmethod
    def resolve_single_folder_or_default(name: Optional[str], context: KeeperParams):
        return _FolderMixin.resolve_single_folder(name or context.current_folder or '/', context)


class FolderCdCommand(base.ArgparseCommand, _FolderMixin):
    parser = argparse.ArgumentParser(prog='cd', description='Change current folder')
    parser.add_argument('folder', nargs='?', type=str, action='store', metavar='FOLDER', help='folder path or UID')

    def __init__(self):
        super().__init__(FolderCdCommand.parser)

    def execute(self, context: KeeperParams, **kwargs):
        folder = self.resolve_single_folder(kwargs.get('folder'), context)
        context.current_folder = folder.folder_uid


class FolderListCommand(base.ArgparseCommand):
    parser = argparse.ArgumentParser(prog='ls', description='List folder contents')
    parser.add_argument('-l', '--list', dest='detail', action='store_true', help='show detailed list')
    parser.add_argument('-f', '--folders', dest='folders', action='store_true', help='display folders')
    parser.add_argument('-r', '--records', dest='records', action='store_true', help='display records')
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='display long names')
    parser.add_argument('pattern', nargs='?', type=str, action='store', metavar='FOLDER', help='search pattern')

    def __init__(self):
        super().__init__(FolderListCommand.parser)

    @staticmethod
    def folder_match_strings(folder: vault_types.Folder) -> Iterable[str]:
        return filter(lambda f: isinstance(f, str) and len(f) > 0, [folder.name, folder.folder_uid])

    @staticmethod
    def chunk_list(names: List[str], n: int) -> List[List[str]]:
        rows = []
        for i in range(0, len(names), n):
            rows.append(names[i:i+n])
        return rows

    def execute(self, context: KeeperParams, **kwargs):
        assert context.vault is not None
        show_folders = kwargs['folders'] if 'folders' in kwargs else None
        show_records = kwargs['records'] if 'records' in kwargs else None
        show_detail = kwargs['detail'] if 'detail' in kwargs else False
        if not show_folders and not show_records:
            show_folders = True
            show_records = True

        pattern = kwargs['pattern'] if 'pattern' in kwargs else None
        if pattern:
            folder, pattern = folder_utils.try_resolve_path(context, kwargs['pattern'])
        else:
            if context.current_folder:
                folder = context.vault.vault_data.get_folder(context.current_folder) or context.vault.vault_data.root_folder
            else:
                folder = context.vault.vault_data.root_folder

        regex: Optional[Callable[[str], Any]] = None
        if pattern:
            regex = re.compile(fnmatch.translate(pattern), re.IGNORECASE).match

        folders: List[vault_types.Folder] = []
        records: List[vault_record.KeeperRecordInfo] = []

        if show_folders:
            for folder_uid in folder.subfolders:
                f = context.vault.vault_data.get_folder(folder_uid)
                if f:
                    if regex:
                        ff = next((x for x in FolderListCommand.folder_match_strings(f) if regex(x)), None)
                        if ff is None:
                            continue
                    folders.append(f)

        if show_records:
            for record_uid in folder.records:
                record_info = context.vault.vault_data.get_record(record_uid)
                if not record_info:
                    continue
                if record_info.version not in (2, 3):
                    continue

                if regex and not regex(record_info.title):
                    continue
                records.append(record_info)

        if len(folders) == 0 and len(records) == 0:
            if pattern:
                raise base.CommandError(f'"{pattern}": No such folder or record')
        else:
            if show_detail:
                table = []
                headers = ['Flags', 'UID', 'Name', 'Type']
                if len(folders) > 0:
                    folders.sort(key=lambda fo: fo.name.casefold())
                    for x in folders:
                        flag = 'f--'
                        flag += 'S' if x.folder_type != 'user_folder' else '-'
                        table.append([flag, x.folder_uid, x.name, ''])
                if len(records) > 0:
                    records.sort(key=lambda rec: rec.title.casefold())
                    for record in records:
                        flag = 'r'
                        flag += 'O' if record.flags & vault_record.RecordFlags.IsOwner else '-'
                        flag += 'A' if record.flags & vault_record.RecordFlags.HasAttachments else '-'
                        flag += 'S' if record.flags & vault_record.RecordFlags.IsShared else '-'
                        table.append([flag, record.record_uid, record.title, record.record_type])
                return report_utils.dump_report_data(table, headers, row_number=True)
            else:
                names: List[str] = []
                for f in folders:
                    name = f.name or f.folder_uid
                    if len(name) > 40:
                        name = name[:25] + '...' + name[-12:]
                    names.append(name + '/')
                names.sort()

                rnames: List[str] = []
                for r in records:
                    name = r.title or r.record_uid
                    if len(name) > 40:
                        name = name[:25] + '...' + name[-12:]
                    rnames.append(name)
                rnames.sort()

                names.extend(rnames)

                width, _ = shutil.get_terminal_size(fallback=(1, 1))
                max_name = functools.reduce(lambda val, elem: len(elem) if len(elem) > val else val, names, 0)
                cols = width // max_name
                if cols == 0:
                    cols = 1

                while ((max_name * cols) + (cols - 1) * 2) > width:
                    if cols > 2:
                        cols = cols - 1
                    else:
                        break

                tbl = FolderListCommand.chunk_list([x.ljust(max_name) if cols > 1 else x for x in names], cols)
                rows = ['  '.join(x) for x in tbl]
                prompt_utils.output_text(*rows)


class FolderTreeCommand(base.ArgparseCommand, _FolderMixin):
    parser = argparse.ArgumentParser(prog='tree', description='Display the folder structure')
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='print ids')
    parser.add_argument('-r', '--records', action='store_true', help='show records within each folder')
    show_shares_help = 'show share permissions info (shown in parentheses) for each shared folder'
    parser.add_argument('-s', '--shares', action='store_true', help=show_shares_help)
    perms_key_help = 'hide share permissions key (valid only when used with --shares flag, which shows key by default)'
    parser.add_argument('-hk', '--hide-shares-key', action='store_true', help=perms_key_help)
    parser.add_argument('-t', '--title', action='store', help='show optional title for folder structure')
    parser.add_argument('folder', nargs='?', type=str, action='store', metavar='FOLDER',
                        help='folder path or UID')

    def __init__(self):
        super().__init__(FolderTreeCommand.parser)

    def execute(self, context: KeeperParams, **kwargs):
        verbose: bool = kwargs.get('verbose') is True
        show_records: bool = kwargs.get('records') is True
        show_shares: bool = kwargs.get('shares') is True

        def tree_node(node: vault_types.Folder) -> Tuple[str, dict]:
            assert context.vault is not None
            name = node.name
            children: dict = OrderedDict()
            if verbose and node.folder_uid:
                name += f' ({node.folder_uid})'

            if node.folder_type == 'shared_folder':
                name += f' {Style.BRIGHT}[Shared]{Style.NORMAL}'
                if show_shares:
                    sf = context.vault.vault_data.load_shared_folder(node.folder_uid)
                    if sf:
                        for up in sf.user_permissions:
                            perm_text = FolderTreeCommand.user_permission_to_text(up.manage_users, up.manage_records)
                            if up.user_type == vault_types.SharedFolderUserType.User:
                                perm_type = 'User'
                                user = context.vault.vault_data.get_user_email(up.user_uid)
                                if user:
                                    perm_name = user.username
                                    if verbose:
                                        perm_name += f' ({user.account_uid})'
                                else:
                                    perm_name = up.user_uid
                            else:
                                perm_type = 'Team'
                                team = context.vault.vault_data.get_team(up.user_uid)
                                if team:
                                    perm_name = team.name
                                    if verbose:
                                        perm_name += f' ({team.team_uid})'
                                else:
                                    perm_name = f'({up.user_uid})'
                            children[f'{Style.DIM}{perm_name}: {perm_text} [{perm_type}]{Style.NORMAL}'] = {}

            subfolders = [y for y in (context.vault.vault_data.get_folder(x) for x in node.subfolders) if y is not None]
            subfolders.sort(key=lambda x: x.name.casefold())
            children.update((tree_node(x) for x in subfolders))
            if show_records:
                records = [y.title for y in (context.vault.vault_data.get_record(x) for x in node.records) if y is not None]
                records.sort(key=lambda x: x.casefold())
                children.update(((f'{Style.DIM}{x} [Record]{Style.NORMAL}', {}) for x in records))

            return name, children

        folder = self.resolve_single_folder_or_default(kwargs.get('folder'), context)
        key, value = tree_node(folder)
        tree = {key: value}

        title = kwargs.get('title')
        if title:
            print(title)
        tr = LeftAligned()
        print(tr(tree))
        print()

    @staticmethod
    def user_permission_to_text(manage_users: bool, manage_records: bool) -> str:
        if manage_users and manage_records:
            return 'Can Manage Users & Records'
        if manage_users:
            return 'Can Manage Users'
        if manage_records:
            return 'Can Manage Records'
        return 'No User Permissions'

    @staticmethod
    def record_permission_to_text(can_edit: bool, can_share: bool) -> str:
        if can_edit and can_share:
            return 'Can Edit & Share'
        if can_edit:
            return 'Can Edit'
        if can_share:
            return 'Can Share'
        return 'View Only'


class FolderMakeCommand(base.ArgparseCommand):
    parser = argparse.ArgumentParser(prog='mkdir', description='Create a folder')
    folder_type = parser.add_mutually_exclusive_group()
    folder_type.add_argument('-sf', '--shared-folder', dest='shared_folder', action='store_true',
                             help='create shared folder')
    folder_type.add_argument('-uf', '--user-folder', dest='user_folder', action='store_true',
                             help='create user folder')
    parser.add_argument('-a', '--all', dest='grant', action='store_true',
                        help='anyone has all permissions by default')
    parser.add_argument('-u', '--manage-users', dest='manage_users', action='store_true',
                        help='anyone can manage users by default')
    parser.add_argument('-r', '--manage-records', dest='manage_records', action='store_true',
                        help='anyone can manage records by default')
    parser.add_argument('-s', '--can-share', dest='can_share', action='store_true',
                        help='anyone can share records by default')
    parser.add_argument('-e', '--can-edit', dest='can_edit', action='store_true',
                        help='anyone can edit records by default')
    parser.add_argument('folder', nargs='?', type=str, action='store', metavar='FOLDER',
                        help='folder path')
    
    def __init__(self) -> None:
        super().__init__(FolderMakeCommand.parser)

    def execute(self, context: KeeperParams, **kwargs):
        assert context.vault is not None
        name = kwargs.get('folder')
        if not name:
            raise base.CommandError('Folder cannot be empty')

        base_folder, folder_name = folder_utils.try_resolve_path(context, name)
        if not folder_name:
            raise base.CommandError(f'Folder "{name}" already exists')
        folder_name = folder_name.strip().replace('//', '/')

        shared_folder = kwargs.get('shared_folder') is True
        user_folder = kwargs.get('user_folder') is True

        is_shared_folder = False
        manage_users = kwargs.get('manage_users')
        manage_records = kwargs.get('manage_records')
        can_edit = kwargs.get('can_edit')
        can_share = kwargs.get('can_share')

        if shared_folder:
            if base_folder.folder_type == 'user_folder':
                is_shared_folder = True
            else:
                raise base.CommandError('Shared folders cannot be nested')
        elif user_folder:
            pass
        else:
            if base_folder.folder_type == 'user_folder':
                inp = prompt_utils.user_choice('Do you want to create a shared folder?', 'yn', default='n')
                if inp.lower() in ('y', 'yes'):
                    is_shared_folder = True
                    pq = 'Default user permissions: (A)ll | Manage (U)sers / (R)ecords; Can (E)dit / (S)hare records?'
                    inp = prompt_utils.user_choice(pq, 'aures', multi_choice=True)
                    if 'a' in inp:
                        manage_users = True
                        manage_records = True
                        can_edit = True
                        can_share = True
                    else:
                        if 'u' in inp:
                            manage_users = True
                        if 'r' in inp:
                            manage_records = True
                        if 'e' in inp:
                            can_edit = True
                        if 's' in inp:
                            can_share = True

        try:
            folder_uid = folder_management.add_folder(
                context.vault, folder_name, is_shared_folder, base_folder.folder_uid, manage_users, manage_records, can_edit, can_share)
            context.environment_variables[constants.LAST_FOLDER_UID] = folder_uid
            if is_shared_folder:
                context.environment_variables[constants.LAST_SHARED_FOLDER_UID] = folder_uid
            return folder_uid
        except Exception as e:
            raise base.CommandError(str(e))


class FolderRemoveCommand(base.ArgparseCommand):
    parser = argparse.ArgumentParser(prog='rmdir', description='Remove a folder and its contents')
    parser.add_argument('-f', '--force', dest='force', action='store_true',
                        help='remove folder without prompting')
    parser.add_argument('-q', '--quiet', dest='quiet', action='store_true',
                        help='remove folder without folder info')
    parser.add_argument('pattern', nargs='*', type=str, action='store', metavar='FOLDER',
                        help='folder path or UID')

    def __init__(self) -> None:
        super().__init__(FolderRemoveCommand.parser)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        assert context.vault is not None
        folder_uids = set()
        pattern_list = kwargs.get('pattern')
        if not isinstance(pattern_list, (tuple, list, set)):
            pattern_list = [pattern_list]

        for pattern in pattern_list:
            base_folder, name = folder_utils.try_resolve_path(context, pattern)
            if name:
                if name in base_folder.subfolders:
                    folder_uids.add(name)
                else:
                    regex = re.compile(fnmatch.translate(name)).match
                    for uid in base_folder.subfolders:
                        f = context.vault.vault_data.get_folder(uid)
                        if f is None:
                            continue
                        if regex(f.name):
                            folder_uids.add(f.folder_uid)
            else:
                if base_folder.folder_uid:
                    folder_uids.add(base_folder.folder_uid)

        if len(folder_uids) == 0:
            raise base.CommandError('Enter name of an existing folder.')

        if len(folder_uids) > 1:
            for folder_uid in list(folder_uids):
                f = context.vault.vault_data.get_folder(folder_uid)
                while f and f.parent_uid:
                    if f.parent_uid in folder_uids:
                        folder_uids.remove(folder_uid)
                        break
                    f = context.vault.vault_data.get_folder(f.parent_uid)

        force = kwargs.get('force') is True
        quiet = kwargs.get('quiet') is True

        if not quiet or not force:
            names = [vault_utils.get_folder_path(context.vault.vault_data, x) for x in folder_uids]
            names.sort()
            prompt_utils.output_text(f'\nThe following folder(s) will be removed:\n{", ".join((x for x in names if x))}\n')
        def delete_confirmation(delete_summary: str) -> bool:
            if force:
                return True
            if not quiet:
                prompt_utils.output_text(delete_summary)
            prompt_msg = '\nDo you want to proceed with the folder deletion?'
            answer = prompt_utils.user_choice(prompt_msg, 'yn', default='n')
            return answer.lower() in ('y', 'yes')

        try:
            record_management.delete_vault_objects(context.vault, list(folder_uids), delete_confirmation)
        except Exception as e:
            raise base.CommandError(str(e))


class FolderRenameCommand(base.ArgparseCommand, _FolderMixin):
    parser = argparse.ArgumentParser(prog='rndir', description='Rename a folder')
    parser.add_argument('-n', '--name', dest='name', action='store', required=True, help='folder new name')
    parser.add_argument('-q', '--quiet', action='store_true', help='rename folder without folder info')
    parser.add_argument('folder', nargs='?', type=str, action='store', metavar='FOLDER',
                        help='folder path or UID')

    def __init__(self) -> None:
        super().__init__(FolderRenameCommand.parser)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        assert context.vault is not None
        folder = self.resolve_single_folder(kwargs.get('folder'), context)
        if not folder:
            raise base.CommandError('Enter the path or UID of existing folder.')
        if not folder.folder_uid:
            raise base.CommandError('Cannot rename the root folder.')

        new_name = kwargs.get('name')
        if not new_name:
            raise base.CommandError('New folder name parameter is required.')

        try:
            folder_management.update_folder(context.vault, folder.folder_uid, new_name)
            api.get_logger().info('Folder \"%s\" has been renamed to \"%s\"', folder.name, new_name)
        except Exception as e:
            raise base.CommandError(str(e))


class FolderMoveCommand(base.ArgparseCommand, _FolderMixin):
    parser = argparse.ArgumentParser(prog='mv', description='Move a record or folder to another folder')
    parser.add_argument('-l', '--link', dest='link', action='store_true', help='do not delete source')
    parser.add_argument('-f', '--force', dest='force', action='store_true', help='do not prompt')
    parser.add_argument('-R', '--recursive', dest='recursive', action='store_true',
                       help='apply search pattern to folders as well')
    parser.add_argument('-s', '--can-reshare', dest='can_reshare', action='store', choices=['on', 'off'],
                           help='apply \"Can Share\" record permission')
    parser.add_argument('-e', '--can-edit', dest='can_edit', action='store', choices=['on', 'off'],
                        help='apply \"Can Edit\" record permission')
    parser.add_argument('src', nargs='+', type=str, metavar='PATH',
                           help='source path to folder/record, search pattern or record UID')
    parser.add_argument('dst', type=str,
                        help='destination folder or UID')

    def __init__(self) -> None:
        super().__init__(FolderMoveCommand.parser)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        assert context.vault is not None
        logger = api.get_logger()
        src_paths = kwargs.get('src')
        dst_path = kwargs.get('dst')
        if not src_paths or not dst_path or not isinstance(src_paths, list):
            FolderMoveCommand.parser.print_help()
            return

        can_edit = kwargs.get('can_edit')
        if isinstance(can_edit, str):
            can_edit = can_edit == 'on'
        can_share = kwargs.get('can_share')
        if isinstance(can_share, str):
            can_share = can_share == 'on'

        dst_folder = self.resolve_single_folder(dst_path, context)
        if not dst_folder:
            raise base.CommandError(f'Destination \"{dst_path}\": Enter the path or UID of existing folder.')

        source_uids = set()
        source_records: Dict[str, Set[str]] = {}
        for src_path in src_paths:
            folder = context.vault.vault_data.get_folder(src_path)
            if folder:
                source_uids.add(src_path)
                continue
            record = context.vault.vault_data.get_record(src_path)
            if record:
                source_uids.add(src_path)
                continue
            folder, record_name = folder_utils.try_resolve_path(context, src_path)
            if record_name:
                if record_name in folder.records:
                    if folder.folder_uid not in source_records:
                        source_records[folder.folder_uid] = set()
                    source_records[folder.folder_uid].add(record_name)
                else:
                    regex = re.compile(fnmatch.translate(record_name), re.IGNORECASE).match
                    added = False
                    if kwargs.get('recursive') is True:
                        for folder_uid in folder.subfolders:
                            sub_f = context.vault.vault_data.get_folder(folder_uid)
                            if sub_f and regex(sub_f.name):
                                added = True
                                source_uids.add(sub_f.folder_uid)
                    for record_uid in folder.records:
                        record = context.vault.vault_data.get_record(record_uid)
                        if record:
                            if regex(record.title):
                                added = True
                                if folder.folder_uid not in source_records:
                                    source_records[folder.folder_uid] = set()
                                source_records[folder.folder_uid].add(record.record_uid)
                    if not added:
                        raise base.CommandError(
                            f'Source \"{src_path}\": Folder and/or record not found.')
            else:
                source_uids.add(folder.folder_uid)

        def on_warning(message: str):
            logger.warning(message)
        record_paths = (vault_types.RecordPath(folder_uid=x, record_uid=y) for x in source_records for y in source_records[x])
        record_management.move_vault_objects(context.vault,
                                             src_objects=itertools.chain(source_uids, record_paths),
                                             dst_folder_uid=dst_folder.folder_uid,
                                             is_link=kwargs.get('link') is True,
                                             can_edit=can_edit, can_share=can_share,
                                             on_warning=on_warning)


class FolderTransformCommand(base.ArgparseCommand, _FolderMixin):
    # Constants
    MAX_RECORDS_PER_BATCH = 1000
    MAX_FOLDERS_PER_CHUNK = 990
    MAX_DELETE_CHUNK_SIZE = 450
    DELETE_SUFFIX = '@delete'
    FOLDER_TYPES = {
        'user_folder': 'user_folder',
        'shared_folder': 'shared_folder', 
        'shared_folder_folder': 'shared_folder_folder'
    }
    FOLDER_TYPE_CHOICES = ['personal', 'shared']
    CONFIRMATION_CHOICES = 'yn'
    DEFAULT_CONFIRMATION = 'n'

    def __init__(self):
        self.parser = argparse.ArgumentParser(prog='transform-folder', description='Move folders to another location')
        FolderTransformCommand.add_arguments_to_parser(self.parser)
        super().__init__(self.parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('folder', nargs='+', type=str, action='store', metavar='FOLDER',
                        help='folder path or UID (can specify multiple folders)')
        parser.add_argument('-t', '--target', type=str,
                        help='target folder UID or path/name (root folder if not specified)')
        parser.add_argument('-f', '--force', action='store_true',
                        help='Skip confirmation prompt and minimize output')
        parser.add_argument('--link', action='store_true',
                        help='Do not delete the source folder(s)')
        parser.add_argument('--dry-run', action='store_true',
                        help='Dry run mode: do not apply any changes')
        parser.add_argument('--folder-type', choices=FolderTransformCommand.FOLDER_TYPE_CHOICES,
                        help='Folder type: Personal or Shared if target folder parameter is omitted')

    @staticmethod
    def _get_folder_encryption_key(folder):
        """Get the encryption key for a folder based on its type."""
        if folder.folder_type == FolderTransformCommand.FOLDER_TYPES['user_folder']:
            return folder.folder_key
        elif folder.folder_type == FolderTransformCommand.FOLDER_TYPES['shared_folder']:
            return folder.folder_key
        elif folder.folder_type == FolderTransformCommand.FOLDER_TYPES['shared_folder_folder']:
            return folder.folder_key
        return None

    @staticmethod
    def _create_rename_request(folder_uid, folder):
        """Create a rename request for a folder."""
        encryption_key = FolderTransformCommand._get_folder_encryption_key(folder)
        if not encryption_key:
            return None

        rq = {
            'command': 'folder_update',
            'folder_uid': folder_uid,
            'folder_type': folder.folder_type,
        }

        # Add shared folder UID for shared folder types
        if folder.folder_type == FolderTransformCommand.FOLDER_TYPES['shared_folder']:
            rq['shared_folder_uid'] = folder_uid
        elif folder.folder_type == FolderTransformCommand.FOLDER_TYPES['shared_folder_folder']:
            rq['shared_folder_uid'] = folder.folder_scope_uid

        # Create encrypted data with delete suffix
        new_name = f'{folder.name}{FolderTransformCommand.DELETE_SUFFIX}'
        data = {'name': new_name}
        encrypted_data = crypto.encrypt_aes_v1(json.dumps(data).encode(), encryption_key)
        rq['data'] = utils.base64_url_encode(encrypted_data)
        
        # Add encrypted name for shared folders
        if folder.folder_type == FolderTransformCommand.FOLDER_TYPES['shared_folder']:
            rq['name'] = utils.base64_url_encode(crypto.encrypt_aes_v1(new_name.encode('utf-8'), encryption_key))
        
        return rq

    @staticmethod
    def rename_source_folders(vault: vault_online.VaultOnline, source_folders):
        """Rename source folders by appending @delete to mark them for deletion."""
        rename_rqs = []
        
        for folder_uid in source_folders:
            folder = vault.vault_data.get_folder(folder_uid)
            if not folder:
                continue

            rename_rq = FolderTransformCommand._create_rename_request(folder_uid, folder)
            if rename_rq:
                rename_rqs.append(rename_rq)
        
        if rename_rqs:
            try:
                vault.keeper_auth.execute_batch(rename_rqs)
            except Exception as e:
                logging.debug('Error renaming source folders: %s', e)

    @staticmethod
    def _get_folder_scope(folder):
        """Get the scope UID for a folder based on its type."""
        if folder.folder_type == FolderTransformCommand.FOLDER_TYPES['shared_folder']:
            return folder.folder_uid
        elif folder.folder_type == FolderTransformCommand.FOLDER_TYPES['shared_folder_folder']:
            return folder.folder_scope_uid
        return ''

    @staticmethod
    def _get_scope_key(vault, dst_scope):
        """Get the encryption key for a destination scope."""
        if dst_scope:
            shared_folder = vault.vault_data.get_folder(dst_scope)
            return shared_folder.folder_key
        return vault.keeper_auth.auth_context.data_key

    @staticmethod
    def _get_source_type(src_folder):
        """Get the source type string for a folder."""
        if src_folder.folder_type == FolderTransformCommand.FOLDER_TYPES['shared_folder']:
            return 'shared_folder'
        elif src_folder.folder_type == FolderTransformCommand.FOLDER_TYPES['shared_folder_folder']:
            return 'shared_folder_folder'
        return 'user_folder'

    @staticmethod
    def _get_record_permissions(vault, sf_uid, r_uid, record_permissions_cache):
        """Get record permissions for a record in a shared folder."""
        if sf_uid in record_permissions_cache:
            return record_permissions_cache[sf_uid].get(r_uid)

        shared_folder_details = vault.vault_data.get_folder(sf_uid)
        if not shared_folder_details:
            return None

        record_permissions_cache[sf_uid] = {}
        shared_folder = vault.vault_data.load_shared_folder(shared_folder_uid=sf_uid)
        
        for record_uid in shared_folder_details.records:
            record_perm = shared_folder.record_permissions.get(record_uid)
            if record_perm:
                can_share = record_perm.can_share or False
                can_edit = record_perm.can_edit or False
                record_permissions_cache[sf_uid][record_uid] = (can_edit, can_share)

        return record_permissions_cache[sf_uid].get(r_uid)

    @staticmethod
    def _create_transition_key(vault, record_uid, scope_key):
        """Create a transition key for moving a record between scopes."""
        record = vault.vault_data.get_record(record_uid)
        if not record:
            return None

        record_key = vault.vault_data.get_record_key(record_uid)
        if record.version < 3:
            transfer_key = crypto.encrypt_aes_v1(record_key, scope_key)
        else:
            transfer_key = crypto.encrypt_aes_v2(record_key, scope_key)

        return {
            'uid': record_uid,
            'key': utils.base64_url_encode(transfer_key)
        }

    @staticmethod
    def _create_move_request(dst_folder, dst_scope, is_link):
        """Create a base move request structure."""
        return {
            'command': 'move',
            'to_type': 'shared_folder_folder' if dst_scope else 'user_folder',
            'to_uid': dst_folder.folder_uid,
            'link': is_link,
            'move': [],
            'transition_keys': []
        }

    @staticmethod
    def _process_record_chunk(vault, chunk, src_folder, dst_folder, src_scope, dst_scope, 
                            scope_key, src_type, is_link, record_permissions_cache):
        """Process a chunk of records and create move requests."""
        move_rqs = []
        records = list(chunk)
        
        while records:
            rq = FolderTransformCommand._create_move_request(dst_folder, dst_scope, is_link)
            record_chunk = records[:FolderTransformCommand.MAX_FOLDERS_PER_CHUNK]
            records = records[FolderTransformCommand.MAX_FOLDERS_PER_CHUNK:]
            
            for record_uid in record_chunk:
                move = {
                    'type': 'record',
                    'uid': record_uid,
                    'from_type': src_type,
                    'from_uid': src_folder.folder_uid,
                    'cascade': False,
                }
                
                # Add permissions if moving between different scopes
                if scope_key and src_scope and dst_scope:
                    perms = FolderTransformCommand._get_record_permissions(
                        vault, src_scope, record_uid, record_permissions_cache)
                    if isinstance(perms, tuple):
                        move['can_edit'] = perms[0]
                        move['can_reshare'] = perms[1]

                rq['move'].append(move)
                
                # Add transition key if needed
                if scope_key:
                    transition_key = FolderTransformCommand._create_transition_key(
                        vault, record_uid, scope_key)
                    if transition_key:
                        rq['transition_keys'].append(transition_key)
            
            move_rqs.append(rq)
        
        return move_rqs

    @staticmethod
    def _execute_move_requests_in_batches(vault, move_rqs):
        """Execute move requests in batches respecting the maximum records per batch limit."""
        while move_rqs:
            record_count = 0
            requests = []
            
            while move_rqs:
                rq = move_rqs.pop()
                record_rq_count = len(rq['move'])
                
                if (record_count + record_rq_count) > FolderTransformCommand.MAX_RECORDS_PER_BATCH:
                    if record_count > 0:
                        move_rqs.append(rq)  # Put it back for next batch
                    else:
                        requests.append(rq)  # Single large request
                    break
                else:
                    requests.append(rq)
                    record_count += record_rq_count
            
            if requests:
                vault.keeper_auth.execute_batch(requests)

    @staticmethod
    def move_records(vault: vault_online.VaultOnline, folder_map, is_link):
        """Move records from source folders to destination folders."""
        move_rqs = []
        record_permissions_cache = {}
        
        for src_folder_uid, dst_folder_uid in folder_map:
            src_folder = vault.vault_data.get_folder(src_folder_uid)
            dst_folder = vault.vault_data.get_folder(dst_folder_uid)
            
            if not src_folder or not dst_folder:
                continue

            src_scope = FolderTransformCommand._get_folder_scope(src_folder)
            dst_scope = FolderTransformCommand._get_folder_scope(dst_folder)
            
            # Determine if we need a scope key for encryption
            scope_key = None
            if dst_scope != src_scope:
                scope_key = FolderTransformCommand._get_scope_key(vault, dst_scope)
            
            src_type = FolderTransformCommand._get_source_type(src_folder)
            
            # Process records in chunks
            folder_move_rqs = FolderTransformCommand._process_record_chunk(
                vault, src_folder.records, src_folder, dst_folder, src_scope, dst_scope,
                scope_key, src_type, is_link, record_permissions_cache)
            
            move_rqs.extend(folder_move_rqs)

        # Execute all move requests in batches
        FolderTransformCommand._execute_move_requests_in_batches(vault, move_rqs)

    @staticmethod
    def _get_folder_scope_for_deletion(folder):
        """Get the scope for a folder when organizing for deletion."""
        if folder.folder_type == FolderTransformCommand.FOLDER_TYPES['user_folder']:
            return ''
        elif folder.folder_type == FolderTransformCommand.FOLDER_TYPES['shared_folder']:
            return folder.folder_uid
        elif folder.folder_type == FolderTransformCommand.FOLDER_TYPES['shared_folder_folder']:
            return folder.folder_scope_uid
        return None

    @staticmethod
    def _organize_folders_by_scope(vault, folders_to_remove):
        """Organize folders by their scope for deletion."""
        folder_by_scope = {}
        
        for folder_uid in folders_to_remove:
            folder = vault.vault_data.get_folder(folder_uid)
            if not folder:
                continue
                
            folder_scope = FolderTransformCommand._get_folder_scope_for_deletion(folder)
            if folder_scope is None:
                continue
                
            if folder_scope not in folder_by_scope:
                folder_by_scope[folder_scope] = []
            folder_by_scope[folder_scope].append(folder_uid)
        
        # Separate user folders from shared folders
        user_folders = folder_by_scope.pop('', None)
        scopes = list(folder_by_scope.values())
        if user_folders:
            scopes.append(user_folders)
        
        return scopes

    @staticmethod
    def _filter_folder_roots(vault, folder_chunk):
        """Filter out child folders from a chunk, keeping only root folders."""
        folder_roots = set(folder_chunk)
        
        for folder_uid in folder_chunk:
            if folder_uid in folder_roots:
                folder = vault.vault_data.get_folder(folder_uid)
                if folder:
                    vault_utils.traverse_folder_tree(
                        vault.vault_data, folder,
                        lambda f: folder_roots.difference_update(f.subfolders or [])
                    )
        
        return [x for x in folder_chunk if x in folder_roots]

    @staticmethod
    def _create_delete_object_request(folder, vault):
        """Create a delete object request for a folder."""
        rq = {
            'delete_resolution': 'unlink',
            'object_uid': folder.folder_uid,
            'object_type': folder.folder_type,
        }

        if folder.parent_uid:
            parent_folder = vault.vault_data.get_folder(folder.parent_uid)
            if parent_folder:
                rq['from_uid'] = parent_folder.folder_uid
                rq['from_type'] = parent_folder.folder_type
        else:
            rq['from_type'] = folder.folder_type
        
        return rq

    @staticmethod
    def _execute_pre_delete(vault, delete_objects):
        """Execute pre-delete command and return the token."""
        delete_rq = {
            'command': 'pre_delete',
            'objects': delete_objects,
        }
        
        try:
            delete_rs = vault.keeper_auth.execute_auth_command(delete_rq)
            if 'pre_delete_response' in delete_rs:
                pre_delete = delete_rs['pre_delete_response']
                return pre_delete.get('pre_delete_token', '')
        except Exception as e:
            logging.debug('Error executing pre-delete: %s', e)
        
        return ''

    @staticmethod
    def _execute_delete(vault, token):
        """Execute the actual delete command with the token."""
        if not token:
            return
            
        delete_rq = {
            'command': 'delete',
            'pre_delete_token': token
        }
        
        try:
            vault.keeper_auth.execute_auth_command(delete_rq)
        except Exception as e:
            logging.debug('Error executing delete: %s', e)

    @staticmethod
    def _delete_folder_chunk(vault, folder_chunk):
        """Delete a chunk of folders."""
        # Filter to only include root folders (not children of other folders in the chunk)
        root_folders = FolderTransformCommand._filter_folder_roots(vault, folder_chunk)
        
        # Create delete object requests
        delete_objects = []
        for folder_uid in root_folders:
            folder = vault.vault_data.get_folder(folder_uid)
            if folder:
                delete_obj = FolderTransformCommand._create_delete_object_request(folder, vault)
                delete_objects.append(delete_obj)
        
        if not delete_objects:
            return
        
        # Execute pre-delete and get token
        token = FolderTransformCommand._execute_pre_delete(vault, delete_objects)
        
        # Execute actual delete
        FolderTransformCommand._execute_delete(vault, token)

    @staticmethod
    def delete_source_tree(vault: vault_online.VaultOnline, folders_to_remove):
        """Delete source folders organized by scope."""
        scopes = FolderTransformCommand._organize_folders_by_scope(vault, folders_to_remove)
        
        for folders in scopes:
            while folders:
                # Process folders in chunks
                chunk_size = FolderTransformCommand.MAX_DELETE_CHUNK_SIZE
                chunk = folders[-chunk_size:]
                folders = folders[:-chunk_size]
                
                FolderTransformCommand._delete_folder_chunk(vault, chunk)

    @staticmethod
    def _create_folder_request_structure(dst_folder_uid, dst_parent_uid, dst_scope_uid):
        """Create the basic folder request structure."""
        sf = folder_pb2.FolderRequest()
        sf.folderUid = utils.base64_url_decode(dst_folder_uid)
        
        if dst_scope_uid:
            sf.folderType = folder_pb2.shared_folder_folder
            if dst_parent_uid != dst_scope_uid:
                sf.parentFolderUid = utils.base64_url_decode(dst_parent_uid)
            sf.sharedFolderFolderFields.sharedFolderUid = utils.base64_url_decode(dst_scope_uid)
        else:
            sf.folderType = folder_pb2.user_folder
            sf.parentFolderUid = utils.base64_url_decode(dst_parent_uid)
        
        return sf

    @staticmethod
    def _encrypt_folder_data(folder_name, folder_key, scope_key):
        """Encrypt folder data and key."""
        folder_data = {'name': folder_name}
        encrypted_data = crypto.encrypt_aes_v1(json.dumps(folder_data).encode('utf-8'), folder_key)
        encrypted_key = crypto.encrypt_aes_v1(folder_key, scope_key)
        return encrypted_data, encrypted_key

    @staticmethod
    def create_target_folder(vault: vault_data.VaultData, source_folder_uid, dst_parent_uid, dst_scope_uid, dst_scope_key):
        """Create a target folder request for a source folder."""
        src_subfolder = vault.get_folder(source_folder_uid)
        if not src_subfolder:
            return None
            
        dst_folder_uid = utils.generate_uid()
        sf = FolderTransformCommand._create_folder_request_structure(dst_folder_uid, dst_parent_uid, dst_scope_uid)
        
        subfolder_key = utils.generate_aes_key()
        encrypted_data, encrypted_key = FolderTransformCommand._encrypt_folder_data(
            src_subfolder.name, subfolder_key, dst_scope_key)
        
        sf.folderData = encrypted_data
        sf.encryptedFolderKey = encrypted_key
        
        return sf

    def _resolve_target_folder(self, target, context):
        """Resolve the target folder from the target parameter."""
        if target:
            return self.resolve_single_folder(target, context).folder_uid
        return None

    def _resolve_source_folders(self, folder_names, context):
        """Resolve source folders from folder names."""
        if not folder_names:
            raise base.CommandError('At least one folder parameter is required. Example: transform-folder folder1_UID -t target_folder')
        
        if isinstance(folder_names, str):
            folder_names = [folder_names]

        source_folder_uids = set()
        for folder_name in folder_names:
            folder = self.resolve_single_folder(folder_name, context)
            if not folder:
                raise base.CommandError(f'Folder "{folder_name}" cannot be found')
            source_folder_uids.add(folder.folder_uid)
        
        return source_folder_uids

    def _validate_folder_operations(self, vault, source_folder_uids, target_folder_uid):
        """Validate that folder operations are valid."""
        for folder_uid in source_folder_uids:
            src_folder = vault.vault_data.get_folder(folder_uid)
            if target_folder_uid and src_folder.parent_uid == target_folder_uid:
                raise base.CommandError(f'Folder "{src_folder.folder_uid}" is already in the target')

            # Check for parent-child relationships in source folders
            current_folder = src_folder
            while current_folder and current_folder.parent_uid:
                if current_folder.parent_uid in source_folder_uids:
                    raise base.CommandError(
                        f'Folder "{current_folder.parent_uid}" is a parent of "{folder_uid}"\n'
                        f'Move folder "{folder_uid}" first'
                    )
                current_folder = vault.vault_data.get_folder(current_folder.parent_uid)

    def _determine_target_folder_type(self, source_folder, target_folder_uid, kwargs):
        """Determine the target folder type based on source and parameters."""
        if target_folder_uid is None:
            if source_folder.parent_uid:
                is_target_shared = kwargs.get('folder_type') in ['shared', 'shared_folder']
            else:
                is_target_shared = source_folder.folder_type == FolderTransformCommand.FOLDER_TYPES['user_folder']
            return 'shared_folder' if is_target_shared else 'user_folder'
        return None

    def _create_root_folder_request(self, source_folder, target_folder_uid, target_scope_uid, 
                                  target_scope_key, target_key, folder_key, kwargs):
        """Create a folder request for the root folder."""
        target_uid = utils.generate_uid()
        f = folder_pb2.FolderRequest()
        f.folderUid = utils.base64_url_decode(target_uid)
        
        data = {'name': source_folder.name}
        f.folderData = crypto.encrypt_aes_v1(json.dumps(data).encode('utf-8'), folder_key)
        
        if target_folder_uid is None:
            folder_type = self._determine_target_folder_type(source_folder, target_folder_uid, kwargs)
            if folder_type == 'shared_folder':
                f.folderType = 'shared_folder'
                f.sharedFolderFields.encryptedFolderName = crypto.encrypt_aes_v1(source_folder.name.encode(), folder_key)
            else:
                f.folderType = 'user_folder'
        else:
            # This will be handled in the calling method where we have access to vault
            return None, None

        f.encryptedFolderKey = crypto.encrypt_aes_v1(folder_key, target_key)
        return f, target_uid

    def _count_folder_contents(self, vault_data, source_folder, src_to_dst_map, target_scope_uid, target_scope_key, folders_to_create, folders_to_remove):
        """Count subfolders and records in a folder tree."""
        subfolder_count = 0
        record_count = 0
        
        def add_subfolders(folder: vault_types.Folder):
            nonlocal subfolder_count, record_count
            subfolder_count += 1
            records = folder.records
            if isinstance(records, set):
                record_count += len(records)

            dst_folder_uid = src_to_dst_map.get(folder.folder_uid)
            if dst_folder_uid:
                for src_subfolder_uid in folder.subfolders:
                    folder_rq = self.create_target_folder(
                        vault_data, src_subfolder_uid, dst_folder_uid, target_scope_uid, target_scope_key)
                    if folder_rq:
                        dst_subfolder_uid = utils.base64_url_encode(folder_rq.folderUid)
                        folders_to_create.append(folder_rq)
                        folders_to_remove.append(src_subfolder_uid)
                        src_to_dst_map[src_subfolder_uid] = dst_subfolder_uid

        vault_utils.traverse_folder_tree(vault_data, source_folder, add_subfolders)
        return subfolder_count, record_count

    def _create_folder_structure(self, vault, source_folder_uids, target_folder_uid, kwargs):
        """Create the folder structure for transformation."""
        folders_to_remove = []
        folders_to_create = []
        src_to_dst_map = {}
        table = []
        
        for source_uid in source_folder_uids:
            source_folder = vault.vault_data.get_folder(source_uid)
            if not source_folder:
                continue

            target_scope_uid = ''
            target_scope_key = vault.keeper_auth.auth_context.data_key
            target_key = vault.keeper_auth.auth_context.data_key
            folder_key = utils.generate_aes_key()

            # Create root folder request
            if target_folder_uid is None:
                folder_request, target_uid = self._create_root_folder_request(
                    source_folder, target_folder_uid, target_scope_uid, target_scope_key, target_key, folder_key, kwargs)
                
                if folder_request is None:
                    continue
                
                # Update scope information for shared folders
                if folder_request.folderType == 'shared_folder':
                    target_scope_uid = target_uid
                    target_scope_key = folder_key
            else:
                # Handle target folder case
                target_folder = vault.vault_data.get_folder(target_folder_uid)
                if not target_folder:
                    continue
                    
                target_uid = utils.generate_uid()
                folder_request = folder_pb2.FolderRequest()
                folder_request.folderUid = utils.base64_url_decode(target_uid)
                
                data = {'name': source_folder.name}
                folder_request.folderData = crypto.encrypt_aes_v1(json.dumps(data).encode('utf-8'), folder_key)
                
                if target_folder.folder_type == FolderTransformCommand.FOLDER_TYPES['user_folder']:
                    folder_request.folderType = 'user_folder'
                    folder_request.parentFolderUid = utils.base64_url_decode(target_folder.folder_uid)
                elif target_folder.folder_type == FolderTransformCommand.FOLDER_TYPES['shared_folder']:
                    folder_request.folderType = 'shared_folder_folder'
                    target_scope_uid = target_folder.folder_uid
                    target_scope_key = vault.vault_data.get_shared_folder_key(target_folder.folder_uid)
                    target_key = target_scope_key
                    folder_request.sharedFolderFolderFields.sharedFolderUid = utils.base64_url_decode(target_scope_uid)
                elif target_folder.folder_type == FolderTransformCommand.FOLDER_TYPES['shared_folder_folder']:
                    folder_request.folderType = 'shared_folder_folder'
                    target_scope_uid = target_folder.folder_scope_uid
                    target_scope_key = vault.vault_data.get_shared_folder_key(target_scope_uid)
                    target_key = target_scope_key
                    folder_request.sharedFolderFolderFields.sharedFolderUid = utils.base64_url_decode(target_scope_uid)
                    folder_request.parentFolderUid = utils.base64_url_decode(target_folder.folder_uid)
                else:
                    continue
                
                folder_request.encryptedFolderKey = crypto.encrypt_aes_v1(folder_key, target_key)

            folders_to_create.append(folder_request)
            folders_to_remove.append(source_uid)
            src_to_dst_map[source_uid] = target_uid

            # Count contents and create subfolder requests
            subfolder_count, record_count = self._count_folder_contents(
                vault.vault_data, source_folder, src_to_dst_map, target_scope_uid, target_scope_key, folders_to_create, folders_to_remove)
            
            folder_path = vault_utils.get_folder_path(vault.vault_data, source_uid)
            table.append([folder_path, subfolder_count, record_count])

        return folders_to_remove, folders_to_create, src_to_dst_map, table

    def _display_transformation_preview(self, table, is_link, target_folder_uid, vault_data):
        """Display the transformation preview to the user."""
        headers = ['Source Folder', 'Folder Count', 'Record Count']
        operation = 'copied' if is_link else 'moved'
        target_name = vault_utils.get_folder_path(vault_data, target_folder_uid) if target_folder_uid else 'My Vault'
        title = f'The following folders will be {operation} to "{target_name}"'
        report_utils.dump_report_data(table, headers=headers, title=title)

    def _confirm_transformation(self, kwargs):
        """Get user confirmation for the transformation."""
        if kwargs.get('force') is not True:
            inp = prompt_utils.user_choice(
                'Are you sure you want to proceed with this action?', 
                FolderTransformCommand.CONFIRMATION_CHOICES, 
                default=FolderTransformCommand.DEFAULT_CONFIRMATION)
            if inp.lower() == 'y':
                logging.info('Executing transformation(s)...')
                return True
            else:
                logging.info('Cancelled.')
                return False
        return True

    def _create_folders_in_batches(self, vault, folders_to_create):
        """Create folders in batches."""
        while folders_to_create:
            chunk = folders_to_create[:FolderTransformCommand.MAX_FOLDERS_PER_CHUNK]
            folders_to_create = folders_to_create[FolderTransformCommand.MAX_FOLDERS_PER_CHUNK:]
            
            rq = folder_pb2.ImportFolderRecordRequest()
            for folder_request in chunk:
                rq.folderRequest.append(folder_request)
            
            rs = vault.keeper_auth.execute_auth_rest(
                request=rq, 
                rest_endpoint='folder/import_folders_and_records', 
                response_type=folder_pb2.ImportFolderRecordResponse)
            
            errors = [x for x in rs.folderResponse if x.status.upper() != 'SUCCESS']
            if errors:
                raise base.CommandError(f'Failed to re-create folder structure: {errors[0].status}')

    def _execute_transformation_steps(self, vault, source_folder_uids, src_to_dst_map, 
                                    folders_to_remove, folders_to_create, is_link):
        """Execute the transformation steps."""
        # Create folders
        self._create_folders_in_batches(vault, folders_to_create)
        vault.sync_down()

        # Rename source folders (if not linking)
        if not is_link:
            self.rename_source_folders(vault, source_folder_uids)
            vault.sync_down()

        # Move records
        self.move_records(vault, src_to_dst_map.items(), is_link)
        vault.sync_down()

        # Delete source tree (if not linking)
        if not is_link:
            self.delete_source_tree(vault, folders_to_remove)

        vault.sync_down()

    def execute(self, context: KeeperParams, **kwargs):
        """Execute the folder transformation command."""
        assert context.vault is not None
        vault = context.vault

        # Resolve target and source folders
        target_folder_uid = self._resolve_target_folder(kwargs.get('target'), context)
        source_folder_uids = self._resolve_source_folders(kwargs.get('folder'), context)

        # Validate operations
        self._validate_folder_operations(vault, source_folder_uids, target_folder_uid)

        is_link = kwargs.get('link') is True

        # Create folder structure
        folders_to_remove, folders_to_create, src_to_dst_map, table = self._create_folder_structure(
            vault, source_folder_uids, target_folder_uid, kwargs)

        # Display preview and get confirmation
        self._display_transformation_preview(table, is_link, target_folder_uid, vault.vault_data)
        
        if kwargs.get('dry_run') is True:
            return

        if not self._confirm_transformation(kwargs):
            return

        # Execute transformation
        self._execute_transformation_steps(vault, source_folder_uids, src_to_dst_map, 
                                         folders_to_remove, folders_to_create, is_link)