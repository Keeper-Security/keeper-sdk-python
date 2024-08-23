import argparse
import fnmatch
import functools
import itertools
import re
import shutil
from collections import OrderedDict
from typing import Iterable, List, Tuple, Optional, Callable, Any, Dict, Set

from asciitree import LeftAligned
from colorama import Style

from keepersdk.vault import vault_types, vault_record, folder_management, record_management, vault_utils
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
                    folders.sort(key=lambda f: f.name.casefold())
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
    group = parser.add_mutually_exclusive_group()
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
