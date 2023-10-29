import argparse
import fnmatch
import re

from typing import Set, Dict

from . import base
from ..params import KeeperParams
from ..helpers import report_utils, folder_utils
from .. import api, prompt_utils
from keepersdk.vault import vault_data, vault_utils, vault_types, record_management

class RecordListCommand(base.ArgparseCommand):
    parser = argparse.ArgumentParser(prog='list', description='List records', parents=[base.report_output_parser])
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='verbose output')
    parser.add_argument('-t', '--type', dest='record_type', action='append',
                             help='List records of certain types. Can be repeated')
    parser.add_argument('search_text', nargs='?', type=str, action='store', help='search text')

    def __init__(self) -> None:
        super().__init__(RecordListCommand.parser)

    def execute(self, context: KeeperParams, **kwargs):
        verbose = kwargs.get('verbose') is True
        fmt = kwargs.get('format', 'table')
        search_text = kwargs.get('search_text')
        record_types = kwargs.get('record_type')
        if record_types:
            record_version = set()
            record_type = set()
            if isinstance(record_types, str):
                record_types = [record_types]
            for rt in record_types:
                if rt == 'app':
                    record_version.add(5)
                elif rt == 'file':
                    record_version.update((3, 4))
                    record_type.add('file')
                elif rt == 'general':
                    record_version.update((1, 2))
                if rt == 'pam':
                    record_version.add(6)
                else:
                    record_version.update((3, 6))
                    record_type.add(rt)
        else:
            record_version = None if verbose else (1, 2, 3)
            record_type = None

        records = [x for x in context.vault.find_records(
            criteria=search_text, record_type=record_type, record_version=record_version)]
        if any(records):
            headers = ['record_uid', 'type', 'title', 'description', 'shared']
            if fmt == 'table':
                headers = [report_utils.field_to_title(x) for x in headers]
            table = []
            for record in records:
                row = [record.record_uid, record.record_type, record.title, record.description, record.shared]
                table.append(row)
            table.sort(key=lambda x: (x[2] or '').lower())

            return report_utils.dump_report_data(table, headers, fmt=fmt, filename=kwargs.get('output'),
                                    row_number=True, column_width=None if verbose else 40)
        else:
            api.get_logger().info('No records are found')


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
        records = ShortcutCommand.get_record_shortcuts(context.vault)
        if len(records) == 0:
            raise base.CommandError('Vault does not have shortcuts')

        uid_to_show = set()

        def add_records(fol: vault_types.Folder) -> None:
            for r_uid in fol.records:
                if r_uid in records:
                    uid_to_show.add(r_uid)

        target = kwargs.get('target')
        recursive = kwargs.get('recursive') is True
        if target:
            record = context.vault.get_record(target)
            if record is not None:
                if record.record_uid in records:
                    uid_to_show.add(record.record_uid)
            else:
                folder = context.vault.get_folder(target)
                if folder is not None:
                    if recursive:
                        vault_utils.traverse_folder_tree(context.vault, folder, add_records)
                    else:
                        add_records(folder)
                else:
                    folder, path = folder_utils.try_resolve_path(context, target)
                    if path:
                        regex = re.compile(fnmatch.translate(path)).match
                        for record_uid in folder.records:
                            if record_uid in records:
                                record = context.vault.get_record(record_uid)
                                if record and record.version in (2, 3):
                                    if regex(record.title):
                                        uid_to_show.add(folder.folder_uid)
                    else:
                        if recursive:
                            vault_utils.traverse_folder_tree(context.vault, folder, add_records)
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
        folder_names = {x: folder_utils.get_folder_path(context.vault, x) for x in folders}
        del folders

        table = []
        fmt = kwargs.get('format')
        for record_uid, folder_uids in records.items():
            record = context.vault.get_record(record_uid)
            if record:
                fs = {folder_names.get(y.folder_uid): y for y in (context.vault.get_folder(x) if x else context.vault.root_folder for x in folder_uids) if y is not None}
                f = []
                for folder_path in sorted(fs.keys()):
                    folder =  fs[folder_path]
                    is_shared = False if folder.folder_type == 'user_folder' else True
                    if fmt == 'json':
                        f.append({
                            'folder_uid': folder.folder_uid,
                            'path': f'/{folder_path}',
                            'shared': is_shared
                        })
                    else:
                        folder_name = '[Shared] ' if is_shared else '[ User ] '
                        folder_name += '/' + folder_path
                        if verbose and folder.folder_uid:
                            folder_name += f' ({folder.folder_uid})'
                        f.append(folder_name)
                table.append([record.record_uid, record.title, f])

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

    def execute(self, context, **kwargs):
        target = kwargs.get('target')
        if not target:
            raise base.CommandError(f'Target parameter cannot be empty')

        records = ShortcutCommand.get_record_shortcuts(context.vault)
        to_keep: Dict[str, str] = {}  # Dict[record_uid, folder_uid]

        record = context.vault.get_record(target)
        if record:
            if record.record_uid in records:
                if (context.current_folder or '') in records[record.record_uid]:
                    to_keep[record.record_uid] = context.current_folder or ''
        else:
            folder = context.vault.get_folder(target)
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
                    record = context.vault.get_record(record_uid)
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
                record = context.vault.get_record(record_uid)
                folders = records[record_uid]
                table.append([record_uid, record.title if record else '',
                       '/' + folder_utils.get_folder_path(context.vault, folder_uid),
                       ['/' + folder_utils.get_folder_path(context.vault, x) for x in folders]])
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
            context.sync_data = True
