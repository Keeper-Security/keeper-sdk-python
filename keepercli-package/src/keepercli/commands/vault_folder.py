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
        parser.add_argument('--folder-type', choices=['personal', 'shared'],
                        help='Folder type: Personal or Shared if target folder parameter is omitted')

    @staticmethod
    def rename_source_folders(vault: vault_online.VaultOnline, source_folders):
        """Rename source folders by appending @delete to mark them for deletion."""
        rename_rqs = []
        
        for folder_uid in source_folders:
            folder = vault.vault_data.get_folder(folder_uid)
            if not folder:
                continue

            rq = {
                'command': 'folder_update',
                'folder_uid': folder_uid,
                'folder_type': folder.folder_type,
            }

            if folder.folder_type == 'user_folder':                
                encryption_key = folder.folder_key
                # encrypted_data = folder
            elif folder.folder_type == 'shared_folder':
                rq['shared_folder_uid'] = folder_uid
                encryption_key = folder.folder_key
                # encrypted_data = folder
            elif folder.folder_type == 'shared_folder_folder':
                rq['shared_folder_uid'] = folder.folder_scope_uid
                encryption_key = folder.folder_key
                # encrypted_data = folder

            # decrypted_data = crypto.decrypt_aes_v1(utils.base64_url_decode(encrypted_data), encryption_key)
            # data = json.loads(decrypted_data)
            # folder_name = data.get('name') or ''
            # folder_name = f'{folder_name}@delete'
            data = {}
            data['name'] = f'{folder.name}@delete'
            encrypted_data = crypto.encrypt_aes_v1(json.dumps(data).encode(), encryption_key)
            rq['data'] = utils.base64_url_encode(encrypted_data)
            if (folder.folder_type == 'shared_folder'):
                rq['name'] = utils.base64_url_encode(crypto.encrypt_aes_v1(data['name'].encode('utf-8'), encryption_key))
            rename_rqs.append(rq)
        try:
            vault.keeper_auth.execute_batch(rename_rqs)
        except Exception as e:
            logging.debug('Error renaming source folders: %s', e)

    @staticmethod
    def move_records(vault: vault_online.VaultOnline, folder_map, is_link):
        """Move records from source folders to destination folders."""
        move_rqs = []
        record_permissions = {}
        def get_record_permissions(sf_uid, r_uid):
            nonlocal record_permissions
            if sf_uid in record_permissions:
                return record_permissions[sf_uid].get(r_uid)

            shared_folder_details = vault.vault_data.get_folder(sf_uid)
            if shared_folder_details:
                record_permissions[sf_uid] = {}
                records = shared_folder_details.records
                shared_folder = vault.vault_data.load_shared_folder(shared_folder_uid=sf_uid)
                for record_uid in records:
                    can_share = shared_folder.record_permissions.get(record_uid).can_share or False
                    can_edit = shared_folder.record_permissions.get(record_uid).can_edit or False
                    record_permissions[sf_uid][record_uid] = (can_edit, can_share)

        for src_folder_uid, dst_folder_uid in folder_map:
            src_folder = vault.vault_data.get_folder(src_folder_uid)
            dst_folder = vault.vault_data.get_folder(dst_folder_uid)
            if not src_folder:
                continue
            if not dst_folder:
                continue
            src_scope = ''
            dst_scope = ''
            if src_folder.folder_type == 'shared_folder':
                src_scope = src_folder.folder_uid
            elif src_folder.folder_type == 'shared_folder_folder':
                src_scope = src_folder.folder_scope_uid

            if dst_folder.folder_type == 'shared_folder':
                dst_scope = dst_folder.folder_uid
            elif dst_folder.folder_type == 'shared_folder_folder':
                dst_scope = dst_folder.folder_scope_uid

            if dst_scope != src_scope:
                if dst_scope:
                    shared_folder = vault.vault_data.get_folder(dst_scope)
                    scope_key = shared_folder.folder_key
                else:
                    scope_key = vault.keeper_auth.auth_context.data_key
            else:
                scope_key = None
            if src_scope:
                src_type = 'shared_folder' if src_folder.folder_type == 'shared_folder' else 'shared_folder_folder'
            else:
                src_type = 'user_folder'

            records = list(src_folder.records)
            while len(records) > 0:
                rq = {
                    'command': 'move',
                    'to_type': 'shared_folder_folder' if dst_scope else 'user_folder',
                    'to_uid': dst_folder.folder_uid,
                    'link': is_link,
                    'move': [],
                    'transition_keys': []
                }
                chunk = records[:990]
                records = records[990:]
                for record_uid in chunk:
                    move = {
                        'type': 'record',
                        'uid': record_uid,
                        'from_type': src_type,
                        'from_uid': src_folder.folder_uid,
                        'cascade': False,
                    }
                    if scope_key and src_scope and dst_scope:
                        perms = get_record_permissions(src_scope, record_uid)
                        if isinstance(perms, tuple):
                            move['can_edit'] = perms[0]
                            move['can_reshare'] = perms[1]

                    rq['move'].append(move)
                    if scope_key:
                        record = vault.vault_data.get_record(record_uid)
                        if record:
                            version = record.version
                            record_key = vault.vault_data.get_record_key(record_uid)
                            if version < 3:
                                transfer_key = crypto.encrypt_aes_v1(record_key, scope_key)
                            else:
                                transfer_key = crypto.encrypt_aes_v2(record_key, scope_key)
                            tko = {
                                'uid': record_uid,
                                'key': utils.base64_url_encode(transfer_key)
                            }
                            rq['transition_keys'].append(tko)
                move_rqs.append(rq)


        while len(move_rqs) > 0:
            record_count = 0
            requests = []
            while len(move_rqs) > 0:
                rq = move_rqs.pop()
                record_rq = len(rq['move'])
                if (record_count + record_rq) > 1000:
                    if record_count > 0:
                        move_rqs.append(rq)
                    else:
                        requests.append(rq)
                    break
                else:
                    requests.append(rq)
            rs = vault.keeper_auth.execute_batch(requests)

    @staticmethod
    def delete_source_tree(vault: vault_online.VaultOnline, folders_to_remove):
        # chunk into scopes
        folder_by_scope = {}
        
        for folder_uid in folders_to_remove:
            folder = vault.vault_data.get_folder(folder_uid)
            if folder.folder_type == 'user_folder':
                folder_scope = ''
            elif folder.folder_type == 'shared_folder':
                folder_scope = folder.folder_uid
            elif folder.folder_type == 'shared_folder_folder':
                folder_scope = folder.folder_scope_uid
            else:
                continue
            if folder_scope not in folder_by_scope:
                folder_by_scope[folder_scope] = []
            folder_by_scope[folder_scope].append(folder_uid)
        user_folders = folder_by_scope.pop('', None)
        scopes = list(folder_by_scope.values())
        if user_folders:
            scopes.append(user_folders)
        for folders in scopes:
            while len(folders) > 0:
                chunk = folders[-450:]
                folders = folders[:-450]
                folder_roots = set(chunk)
                for folder_uid in chunk:
                    if folder_uid in folder_roots:
                        folder = vault.vault_data.get_folder(folder_uid)
                        if folder:
                            vault_utils.traverse_folder_tree(vault.vault_data, folder,
                                                             lambda f: folder_roots.difference_update(f.subfolders or []))
                chunk = [x for x in chunk if x in folder_roots]

                delete_rq = {
                    'command': 'pre_delete',
                    'objects': [],
                }

                for folder_uid in chunk:
                    folder = vault.vault_data.get_folder(folder_uid)
                    if folder is None:
                        continue

                    rq = {
                        'delete_resolution': 'unlink',
                        'object_uid': folder.folder_uid,
                        'object_type': folder.folder_type,
                    }

                    if folder.parent_uid:
                        folder = vault.vault_data.get_folder(folder.parent_uid)
                        if folder:
                            rq['from_uid'] = folder.folder_uid
                            rq['from_type'] = folder.folder_type
                    else:
                        rq['from_type'] = folder.folder_type
                    delete_rq['objects'].append(rq)
                try:
                    delete_rs = vault.keeper_auth.execute_auth_command(delete_rq)
                except Exception as e:
                    logging.debug('Error deleting source tree: %s', e)
                    continue

                token = ''
                if 'pre_delete_response' in delete_rs:
                    pre_delete = delete_rs['pre_delete_response']
                    if 'pre_delete_token' in pre_delete:
                        token = pre_delete['pre_delete_token']

                if token:
                    delete_rq = {
                        'command': 'delete',
                        'pre_delete_token': token
                    }
                    try:
                        vault.keeper_auth.execute_auth_command(delete_rq)
                    except Exception as e:
                        logging.debug('Error deleting source tree: %s', e)

    @staticmethod
    def create_target_folder(vault: vault_data.VaultData, source_folder_uid, dst_parent_uid, dst_scope_uid, dst_scope_key):
        src_subfolder = vault.get_folder(source_folder_uid)
        dst_folder_uid = utils.generate_uid()
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

        subfolder_key = utils.generate_aes_key()
        subfolder_data = {'name': src_subfolder.name}
        sf.folderData = crypto.encrypt_aes_v1(json.dumps(subfolder_data).encode('utf-8'), subfolder_key)
        sf.encryptedFolderKey = crypto.encrypt_aes_v1(subfolder_key, dst_scope_key)
        return sf

    def execute(self, context: KeeperParams, **kwargs):
        assert context.vault is not None
        vault = context.vault

        target = kwargs.get('target')
        if target:
            target_folder_uid = self.resolve_single_folder(target, context).folder_uid
        else:
            target_folder_uid = None

        source_folder_uids = set()
        folder_names = kwargs.get('folder')
        if not folder_names:
            raise base.CommandError('At least one folder parameter is required. Example: transform-folder folder1_UID -t target_folder')
        
        if isinstance(folder_names, str):
            folder_names = [folder_names]

        for folder_name in folder_names:
            folder = self.resolve_single_folder(folder_name, context)
            if not folder:
                raise base.CommandError(f'Folder "{folder_name}" cannot be found')
            source_folder_uids.add(folder.folder_uid)

        for folder_uid in source_folder_uids:
            src_folder = vault.vault_data.get_folder(folder_uid)
            if target_folder_uid and src_folder.parent_uid == target_folder_uid:
                raise base.CommandError(f'Folder "{src_folder.folder_uid}" is already in the target')

            while src_folder and src_folder.parent_uid:
                if src_folder.parent_uid in source_folder_uids:
                    raise base.CommandError(
                        f'Folder "{src_folder.parent_uid}" is a parent of "{folder_uid}"\n'
                        f'Move folder "{folder_uid}" first'
                    )
                src_folder = vault.vault_data.get_folder(src_folder.parent_uid)

        is_link = kwargs.get('link') is True

        table = []
        headers = ['Source Folder', 'Folder Count', 'Record Count']

        folders_to_remove = []
        folders_to_create = []
        src_to_dst_map = {}
        for source_uid in source_folder_uids:
            target_scope_uid = ''
            target_scope_key = vault.keeper_auth.auth_context.data_key

            source_folder = vault.vault_data.get_folder(source_uid)
            if not source_folder:
                continue
            target_uid = utils.generate_uid()
            target_key = vault.keeper_auth.auth_context.data_key
            f = folder_pb2.FolderRequest()
            f.folderUid = utils.base64_url_decode(target_uid)
            folder_key = utils.generate_aes_key()
            data = {'name': source_folder.name}
            f.folderData = crypto.encrypt_aes_v1(json.dumps(data).encode('utf-8'), folder_key)
            if target_folder_uid is None:
                if source_folder.parent_uid:
                    is_target_shared = kwargs.get('folder_type') == 'shared_folder' or kwargs.get('folder_type') == 'shared_folder_folder'
                else:
                    is_target_shared = source_folder.folder_type == 'user_folder'
                if is_target_shared:
                    f.folderType = 'shared_folder'
                    f.sharedFolderFields.encryptedFolderName = crypto.encrypt_aes_v1(source_folder.name.encode(), folder_key)
                    target_scope_uid = target_uid
                    target_scope_key = folder_key
                else:
                    f.folderType = 'user_folder'
            else:
                target_folder = vault.vault_data.get_folder(target_folder_uid)
                assert target_folder is not None
                if target_folder.folder_type == 'user_folder':
                    f.folderType = 'user_folder'
                    target_scope_key = vault.keeper_auth.auth_context.data_key
                    f.parentFolderUid = utils.base64_url_decode(target_folder.folder_uid)
                elif target_folder.folder_type == 'shared_folder':
                    f.folderType = 'shared_folder_folder'
                    shared_folder = vault.vault_data.get_shared_folder(target_folder.folder_uid)
                    if not shared_folder:
                        raise base.CommandError(f'Shared Folder "{target_folder.folder_uid}" not found')
                    target_scope_key = vault.vault_data.get_shared_folder_key(target_folder.folder_uid)
                    target_scope_uid = target_folder.folder_uid
                    f.sharedFolderFolderFields.sharedFolderUid = utils.base64_url_decode(target_scope_uid)
                    target_key = target_scope_key
                elif target_folder.folder_type == 'shared_folder_folder':
                    f.folderType = 'shared_folder_folder'
                    target_scope_uid = target_folder.folder_scope_uid
                    shared_folder = vault.vault_data.get_shared_folder(target_scope_uid)
                    if not shared_folder:
                        raise base.CommandError(f'Shared Folder "{target_folder.folder_uid}" not found')
                    target_scope_key = vault.vault_data.get_shared_folder_key(target_scope_uid)
                    target_key = target_scope_key
                    f.sharedFolderFolderFields.sharedFolderUid = utils.base64_url_decode(target_scope_uid)
                    f.parentFolderUid = utils.base64_url_decode(target_folder.folder_uid)
                else:
                    continue

            f.encryptedFolderKey = crypto.encrypt_aes_v1(folder_key, target_key)
            folders_to_create.append(f)
            folders_to_remove.append(source_uid)
            src_to_dst_map[source_uid] = target_uid

            subfolder_count = 0
            record_count = 0
            source_folder = vault.vault_data.get_folder(source_uid)
            if source_folder is None:
                continue

            vault_data = vault.vault_data
            def add_subfolders(folder: vault_types.Folder):
                nonlocal subfolder_count
                nonlocal record_count
                subfolder_count += 1
                records = folder.records
                if isinstance(records, set):
                    record_count += len(records)

                dst_folder_uid = src_to_dst_map.get(folder.folder_uid)
                if dst_folder_uid:
                    for src_subfolder_uid in folder.subfolders:
                        folder_rq = self.create_target_folder(
                            vault_data, src_subfolder_uid, dst_folder_uid, target_scope_uid, target_scope_key)
                        dst_subfolder_uid = utils.base64_url_encode(folder_rq.folderUid)
                        folders_to_create.append(folder_rq)
                        folders_to_remove.append(src_subfolder_uid)
                        src_to_dst_map[src_subfolder_uid] = dst_subfolder_uid

            vault_utils.traverse_folder_tree(vault_data, source_folder, add_subfolders)
            folder_path = vault_utils.get_folder_path(vault_data, source_uid)
            table.append([folder_path, subfolder_count, record_count])

        # Display statistics
        operation = 'copied' if is_link else 'moved'
        target_name = vault_utils.get_folder_path(vault_data, target_folder_uid) if target_folder_uid else 'My Vault'
        title = f'The following folders will be {operation} to "{target_name}"'
        report_utils.dump_report_data(table, headers=headers, title=title)
        if kwargs.get('dry_run') is True:
            return
        if kwargs.get('force') is not True:
            inp = prompt_utils.user_choice('Are you sure you want to proceed with this action?', 'yn', default='n')
            if inp.lower() == 'y':
                logging.info('Executing transformation(s)...')
            else:
                logging.info('Cancelled.')
                return

        while len(folders_to_create) > 0:
            chunk = folders_to_create[:990]
            folders_to_create = folders_to_create[990:]
            rq = folder_pb2.ImportFolderRecordRequest()
            for e in chunk:
                rq.folderRequest.append(e)
            rs = vault.keeper_auth.execute_auth_rest(request=rq, rest_endpoint='folder/import_folders_and_records', response_type=folder_pb2.ImportFolderRecordResponse)
            errors = [x for x in rs.folderResponse if x.status.upper() != 'SUCCESS']
            if len(errors) > 0:
                raise base.CommandError(f'Failed to re-create folder structure: {errors[0].status}')
        vault.sync_down()

        # Rename source folders
        if not is_link:
            self.rename_source_folders(vault, source_folder_uids)
            vault.sync_down()

        # Move records
        self.move_records(vault, src_to_dst_map.items(), is_link)
        vault.sync_down()

        # Delete source tree
        if not is_link:
            self.delete_source_tree(vault, folders_to_remove)

        vault.sync_down()