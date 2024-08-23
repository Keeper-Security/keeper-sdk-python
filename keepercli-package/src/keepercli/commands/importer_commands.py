import argparse
import datetime
import os
from typing import Optional, Set, List, Union, Dict, Any

from keepersdk import utils
from keepersdk.importer import import_utils, import_data, keeper_format
from keepersdk.vault import batch_operations, vault_types, vault_utils, vault_record
from . import base
from .. import params, api, prompt_utils
from ..helpers import folder_utils, report_utils
from ..params import KeeperParams

MAX_ATTACHMENT_SIZE = 10 * 1024 * 1024


class ImportData(batch_operations.BatchLogger, import_data.IImportLogger):
    def __init__(self, dry_run: bool):
        super().__init__()

        self.dry_run = dry_run
        self._logger = utils.get_logger()
        self.table: List[List[str]] = []
        self.header = ['Folder', 'Title', 'Username', 'URL', 'Last Modified', 'Record UID']

    def added_record(self, import_record: import_data.Record, update_existing: bool,
                      keeper_record: Union[vault_record.PasswordRecord, vault_record.TypedRecord]) -> None:
        if self.dry_run:
            record_folder = ''
            if isinstance(import_record.folders, list) and len(import_record.folders) > 0:
                f = import_record.folders[0]
                record_folder = f.domain or ''
                if f.path:
                    if record_folder:
                        record_folder += '\\'
                    record_folder += f.path
            modification_time = ''
            if isinstance(import_record.last_modified, int) and import_record.last_modified > 0:
                ts = import_record.last_modified
                if ts > 2000000000:
                    ts = int(ts / 1000)
                if 1000000000 < ts < 2000000000:
                    dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
                    modification_time = dt.astimezone().strftime('%x %X')
            record_uid = keeper_record.record_uid if update_existing else ''
            self.table.append([record_folder, import_record.title or '', import_record.login or '',
                               import_record.login_url or '', modification_time, record_uid])

    def failed_record(self, record_name: str, message: str) -> None:
        self._logger.warning('%s', message)

    def confirm_import(self) -> bool:
        return not self.dry_run

class ImportCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='import', description='Import data into Keeper')
        parser.add_argument('--display-csv', '-dc', dest='display_csv', action='store_true',
                            help='display Keeper CSV import instructions')
        parser.add_argument('--display-json', '-dj', dest='display_json', action='store_true',
                            help='display Keeper JSON import instructions')
        parser.add_argument('--format', choices=['json', 'csv', 'keepass', 'lastpass', '1password',
                                                 'bitwarden', 'thycotic'], required=True, help='file format')

        parser.add_argument('--dry-run', dest='dry_run', action='store_true',
                            help='display records to be imported without importing them')

        parser.add_argument('--folder', dest='import_into', action='store',
                            help='import into a separate folder.')
        parser.add_argument('--filter-folder', dest='filter_folder', action='store',
                            help='import data from the specific folder only.')
        parser.add_argument('-s', '--shared', dest='shared', action='store_true',
                            help='import folders as Keeper shared folders')
        parser.add_argument('-p', '--permissions', dest='permissions', action='store',
                            help='default shared folder permissions: manage (U)sers, manage (R)ecords, can (E)dit, can (S)hare, or (A)ll, (N)one')
        parser.add_argument('--record-type', dest='record_type', action='store',
                            help='Import legacy records as record type. login if empty')
        parser.add_argument('--show-skipped', dest='show_skipped', action='store_true',
                            help='Display skipped records')
        parser.add_argument('name',
                            help='file name (json, csv, keepass, 1password), account name (lastpass_lib), or URL (Thycotic)')
        super().__init__(parser)

    def execute(self, context: params.KeeperParams, **kwargs):
        assert context.auth
        assert context.vault
        if 'restrict_import' in context.auth.auth_context.enforcements:
            if context.auth.auth_context.enforcements.get('restrict_import') is True:
                raise base.CommandError('"import" is restricted by Keeper Administrator')

        import_format = kwargs.get('format')
        if not import_format:
            raise base.CommandError('"--format" parameter is mandatory')

        import_name = kwargs.get('name')
        if not import_name:
            raise base.CommandError('"name" parameter is mandatory')

        importer: import_data.BaseImporter
        if import_format == 'json':
            importer = keeper_format.KeeperJsonImporter(import_name)
        elif import_format == 'lastpass':
            from ..import_plugins import lastpass
            prompt_utils.output_text(f'...{"LastPass Username":>30}: {import_name}')
            password = prompt_utils.input_password(f'...{"LastPass Password":>30}: ')
            prompt_utils.output_text('Press <Enter> if account is not protected with Multi-factor Authentication')
            twofa_code = prompt_utils.input_password(f'...{"Multi-factor Password":>30}: ')
            importer = lastpass.LastPassImporter(import_name, password, twofa_code if len(twofa_code) > 0 else None)
        elif import_format == 'keepass':
            try:
                from ..import_plugins import keepass
                prompt_utils.output_text('Press <Enter> if your Keepass file is not protected with a master password')
                password = prompt_utils.input_password(f'...{"Keepass Password":>30}: ')
                prompt_utils.output_text('Press Enter if your Keepass file is not protected with a key file')
                keyfile = prompt_utils.input_text(f'...{"Path to Key file":>30}: ')
                if keyfile:
                    keyfile = os.path.expanduser(keyfile)
                importer = keepass.KeepassImporter(
                    filename=import_name, password=password, keyfile=keyfile if len(keyfile) > 0 else None)
            except ModuleNotFoundError:
                raise base.CommandError('"pykeepass" package is not installed')
        else:
            raise base.CommandError(f'Import format "{import_format}" is not supported')

        args = {}
        filter_folder = kwargs.get('filter_folder')
        dry_run = kwargs.get('dry_run') is True
        if isinstance(filter_folder, str) and len(filter_folder) > 0:
            args['filter_folder'] = filter_folder

        import_logger = ImportData(dry_run)
        import_utils.do_import_vault(context.vault, importer, import_logger=import_logger, dry_run=dry_run, **args)
        importer.cleanup()

        if dry_run:
            report_utils.dump_report_data(import_logger.table, import_logger.header)
        else:
            if len(import_logger.record_added) > 0:
                logger = utils.get_logger()
                logger.info('%d records imported successfully', len(import_logger.record_added))


class ExportCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='export', description='Export data from Keeper')
        parser.add_argument('--format', dest='format', choices=['json', 'csv', 'keepass'], required=True,
                            help='file format')
        parser.add_argument('--max-size', dest='max_size',
                            help='Maximum file attachment file. Example: 100K, 50M, 2G. Default: 10M')
        parser.add_argument('--file-password', dest='file_password', action='store',
                            help='Password for the exported file')
        parser.add_argument('--zip', dest='zip_archive', action='store_true',
                            help='Create ZIP archive for file attachments. JSON only')
        parser.add_argument('--force', dest='force', action='store_true',
                            help='Suppress user interaction. Assume "yes"')
        parser.add_argument('--folder', dest='folder', action='store',
                            help='Export data from the specific folder only.')
        parser.add_argument('name', type=str, nargs='?',
                            help='file name or console output if omitted (except keepass)')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs):
        assert context.auth
        assert context.vault

        logger = api.get_logger()

        if 'restrict_export' in context.auth.auth_context.enforcements:
            if context.auth.auth_context.enforcements.get('restrict_export') is True:
                raise base.CommandError('"export" is restricted by Keeper Administrator')

        export_format = kwargs.get('format')
        if not export_format:
            raise base.CommandError('"--format" parameter is mandatory')

        export_name = kwargs.get('name') or ''

        context.vault.sync_down()

        folder_filter: Optional[Set[str]] = None
        record_filter: Optional[Set[str]] = None
        folder_path = kwargs.get('folder')
        if folder_path:
            folder: Optional[vault_types.Folder] = None
            rs = folder_utils.try_resolve_path(context, folder_path)
            if rs:
                f, rest = rs
                if not rest:
                    folder = f
            if not folder:
                raise base.CommandError(f'Folder \"{folder_path}\" not found', )
            folder_filter = set()
            record_filter = set()

            def on_folder(base_folder: vault_types.Folder) -> None:
                folder_filter.add(base_folder.folder_uid)
                if base_folder.records:
                    record_filter.update(base_folder.records)

            vault_utils.traverse_folder_tree(context.vault.vault_data, folder, on_folder)

        max_size = MAX_ATTACHMENT_SIZE
        msize = kwargs.get('max_size')
        if isinstance(msize, str):
            multiplier = 1
            scale = msize[-1].upper()
            if scale == 'K':
                multiplier = 1024
            elif scale == 'M':
                multiplier = 1024 ** 2
            elif scale == 'G':
                multiplier = 1024 ** 3

            if multiplier != 1:
                msize = msize[:-1]
            try:
                max_size = int(msize) * multiplier
            except ValueError:
                raise base.CommandError(f'Invalid maximum attachment file size parameter: {msize}')

        exporter: import_data.BaseExporter
        if export_format == 'json':
            zip_archive = kwargs.get('zip_archive') is True
            exporter = keeper_format.KeeperJsonExporter(export_name, zip_archive)
        else:
            raise base.CommandError(f'Export format "{export_format}" is not supported')

        force = kwargs.get('force', False)
        if not force and not exporter.supports_v3_record():
            answer = prompt_utils.user_choice(f'Export to {export_format} format may not support all custom fields, data will be exported as best effort\n\n'
                                              'Do you want to continue?', 'yn', 'n')
            if answer.lower() != 'y':
                return

        to_export: List[Union[import_data.Record, import_data.SharedFolder, import_data.Team]] = []
        if exporter.has_shared_folders():
            sfs = [x for x in context.vault.vault_data.shared_folders()]
            sfs.sort(key=lambda x: x.name.lower(), reverse=False)
            for sf in sfs:
                if folder_filter is not None and sf.shared_folder_uid not in folder_filter:
                    continue
                shared_folder = context.vault.vault_data.load_shared_folder(sf.shared_folder_uid)
                if shared_folder is None:
                    continue
                isf = import_utils.to_import_shared_folder(context.vault.vault_data, shared_folder)
                to_export.append(isf)
        sf_count = len(to_export)

        for record_info in context.vault.vault_data.records():
            if record_filter:
                if record_info.record_uid not in record_filter:
                    continue
            if record_info.version not in (2, 3):
                continue

            record = context.vault.vault_data.load_record(record_info.record_uid)
            if record is None:
                continue
            ir = import_utils.to_import_record(record)
            if ir is None:
                continue
            if exporter.has_attachments() and record_info.flags & vault_record.RecordFlags.HasAttachments:
                import_attachments: List[import_data.Attachment] = []
                if isinstance(record, vault_record.PasswordRecord):
                    if isinstance(record.attachments, list):
                        names = set()
                        atta: vault_record.AttachmentFile
                        for atta in record.attachments:
                            orig_name = atta.title or atta.name or 'attachment'
                            if atta.size > max_size:
                                logger.info(
                                    'Record "{0}": File "{1}" was skipped because it exceeds the file size limit.',
                                    record.title, orig_name)
                                continue
                            name = orig_name
                            counter = 0
                            while name in names:
                                counter += 1
                                name = "{0}-{1}".format(orig_name, counter)
                            names.add(name)
                            ia = import_data.KeeperAttachment(context.vault, record.record_uid, atta.id)
                            ia.name = name
                            ia.size = atta.size
                            ia.mime = atta.mime_type or ''
                            assert isinstance(ia, import_data.Attachment)
                            import_attachments.append(ia)

                elif isinstance(record, vault_record.TypedRecord):
                    file_ref = record.get_typed_field('fileRef')
                    if file_ref and isinstance(file_ref.value, list):
                        for file_uid in file_ref.value:
                            file = context.vault.vault_data.load_record(file_uid)
                            file_key = context.vault.vault_data.get_record_key(file_uid)
                            if isinstance(file, vault_record.FileRecord) and file_key:
                                if isinstance(file.size, int) and file.size > max_size:
                                    logger.info(
                                        'Record "{0}": File "{1}" was skipped because it exceeds the file size limit.',
                                        record.title, file.file_name)
                                    continue
                                ia = import_data.KeeperAttachment(context.vault, record.record_uid, file_uid)
                                ia.name = file.file_name
                                ia.size = file.size
                                ia.mime = file.mime_type or ''
                                import_attachments.append(ia)

                if import_attachments:
                    ir.attachments = import_attachments

            for folder in vault_utils.get_folders_for_record(context.vault.vault_data, record.record_uid):
                if folder_filter:
                    if folder.folder_uid not in folder_filter:
                        continue
                if ir.folders is None:
                    ir.folders = []
                import_folder = import_data.Folder()
                import_folder.uid = folder.folder_uid
                folder_path = vault_utils.get_folder_path(
                        context.vault.vault_data, folder.folder_uid, import_data.PathDelimiter)
                if folder.folder_type == 'user_folder':
                    import_folder.path = folder_path
                else:
                    assert folder.folder_scope_uid
                    shared_folder = context.vault.vault_data.load_shared_folder(folder.folder_scope_uid)
                    if shared_folder:
                        import_folder.domain = vault_utils.get_folder_path(
                            context.vault.vault_data, shared_folder.shared_folder_uid, import_data.PathDelimiter)
                        if shared_folder.record_permissions:
                            perm = next((x for x in shared_folder.record_permissions if x.record_uid == record.record_uid), None)
                            if perm:
                                import_folder.can_share = perm.can_share
                                import_folder.can_edit = perm.can_edit
                        import_folder.path = folder_path[len(folder_path):]
                    else:
                        import_folder.path = folder_path
                ir.folders.append(import_folder)

            to_export.append(ir)
        record_count = len(to_export) - sf_count

        args: Dict[str, Any] = {}
        exporter.vault_export(to_export, **args)

        caep = context.vault.client_audit_event_plugin()
        if caep:
            caep.schedule_audit_event('exported_records', file_format=export_format)

        msg = f'{record_count} records exported' if to_export \
            else 'Search results contain 0 records to be exported.\nDid you, perhaps, filter by (an) empty folder(s)?'
        logger.info(msg)


class DownloadMembershipCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='download-membership',
                                         description='Unload shared folder membership to JSON file')
        parser.add_argument('--source', dest='source', choices=['keeper', 'lastpass', 'thycotic'],
                            required=True, help='Shared folder membership source')
        parser.add_argument('-p', '--permissions', dest='permissions', action='store',
                            help='force shared folder permissions: manage (U)sers, manage (R)ecords')
        parser.add_argument('-r', '--restrictions', dest='restrictions', action='store',
                            help='force shared folder restrictions: manage (U)sers, manage (R)ecords')
        parser.add_argument('--folders-only', dest='folders_only', action='store_true',
                            help='Unload shared folders only. Skip teams')
        parser.add_argument('--sub-folder', '-sf', dest='sub_folder', action='store',
                            choices=['ignore', 'flatten'], help='shared sub-folder handling')
        parser.add_argument('name', type=str, nargs='?',
                            help='Output file name. "shared_folder_membership.json" if omitted.')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs):
        assert context.vault is not None
        assert context.enterprise_data is not None
        source = kwargs.get('source') or 'keeper'
        file_name = kwargs.get('name') or 'shared_folder_membership.json'
        folders_only = kwargs.get('folders_only') is True

        override_users: Optional[bool] = None
        override_records: Optional[bool] = None
        permissions = kwargs.get('permissions')
        if permissions:
            permissions = permissions.lower()
            if 'u' in permissions:
                override_users = True
            if 'r' in permissions:
                override_records = True

        restrictions = kwargs.get('restrictions')
        if restrictions:
            restrictions = restrictions.lower()
            if 'u' in restrictions:
                override_users = False
            if 'r' in restrictions:
                override_records = False

        downloader: import_data.BaseDownloadMembership
        if source == 'keeper':
            downloader = keeper_format.KeeperMembershipDownload(vault=context.vault, enterprise=context.enterprise_data)
        else:
            raise base.CommandError(f'Membership download source "{source}" is not supported')

        added_folders: List[import_data.SharedFolder] = []
        added_teams: List[import_data.Team] = []

        for obj in downloader.download_membership(folders_only=folders_only):
            if isinstance(obj, import_data.SharedFolder) and isinstance(obj.path, str):
                obj.path = obj.path.strip()
                if isinstance(obj.permissions, list):
                    for p in obj.permissions:
                        if isinstance(override_users, bool):
                            p.manage_users = override_users
                        if isinstance(override_records, bool):
                            p.manage_records = override_records
                added_folders.append(obj)
            elif isinstance(obj, import_data.Team):
                added_teams.append(obj)

        # process shared sub folders
        for f in added_folders:
            if isinstance(f.path, str) and len(f.path) > 0:
                if f.path[0] == import_data.PathDelimiter or f.path[-1] == import_data.PathDelimiter:
                    path = f.path.replace(2 * import_data.PathDelimiter, '\0')
                    path = path.strip(import_data.PathDelimiter)
                    f.path = path.replace('\0', import_data.PathDelimiter)
        sub_folder_action = kwargs.get('sub_folder') or 'ignore'
        sf = {x.path.lower(): x for x in added_folders if x.path}
        paths = list(sf.keys())
        paths.sort()
        pos = 0
        while pos < len(paths):
            next_pos = 1
            p1 = paths[pos]
            while pos + next_pos < len(paths):
                p2 = paths[pos + next_pos]
                if p2.startswith(p1 + import_data.PathDelimiter):
                    if sub_folder_action == 'flatten':
                        folder = sf[p2]
                        if folder.path:
                            folder.path = (folder.path[:len(p1)] +
                                           folder.path[len(p1):].replace(import_data.PathDelimiter, ' - ', ))
                    else:
                        del sf[p2]
                    next_pos += 1
                else:
                    break
            pos += next_pos

        added_folders = list(sf.values())

        shared_folders: Dict[str, import_data.SharedFolder] = {}
        teams: Dict[str, import_data.Team] = {}

        if os.path.exists(file_name):
            json_importer = keeper_format.KeeperJsonImporter(file_name)
            try:
                for obj in json_importer.vault_import():
                    if isinstance(obj, import_data.SharedFolder):
                        if obj.uid:
                            shared_folders[obj.uid] = obj
                    elif isinstance(obj, import_data.Team):
                        if obj.uid:
                            teams[obj.uid] = obj
            except Exception:
                pass

        if added_folders or added_teams:
            for asf in added_folders:
                if asf.uid and asf.uid in shared_folders:
                    del shared_folders[asf.uid]
            for at in added_teams:
                if at.uid and at.uid in teams:
                    del teams[at.uid]

            memberships: List[Union[import_data.Record, import_data.SharedFolder, import_data.Team]] = []
            memberships.extend(shared_folders.values())
            memberships.extend(teams.values())
            memberships.extend(added_folders)
            memberships.extend(added_teams)
            json_exporter = keeper_format.KeeperJsonExporter(file_name)
            json_exporter.vault_export(memberships)
            if len(added_folders) > 0:
                api.get_logger().info('%d shared folder memberships added.', len(added_folders))
            if len(added_teams) > 0:
                api.get_logger().info('%d team memberships added.', len(added_teams))
        else:
            api.get_logger().info('No folder memberships downloaded.')


class ApplyMembershipCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='apply-membership',
                                         description='Loads shared folder membership from JSON file into Keeper')
        parser.add_argument('--full-sync', dest='full_sync', action='store_true',
                            help='Update and remove membership also.')
        parser.add_argument('name', type=str, nargs='?',
                            help='Input file name. "shared_folder_membership.json" if omitted')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs):
        assert context.vault is not None
        assert context.enterprise_data is not None
        assert context.auth is not None

        logger = api.get_logger()
        file_name = kwargs.get('name') or 'shared_folder_membership.json'
        if not os.path.exists(file_name):
            raise base.CommandError(f'Shared folder membership file "{file_name}" not found')

        shared_folders: List[import_data.SharedFolder] = []
        teams: List[import_data.Team] = []

        json_importer = keeper_format.KeeperJsonImporter(file_name)
        for obj in json_importer.vault_import():
            if isinstance(obj, import_data.SharedFolder):
                shared_folders.append(obj)
            if isinstance(obj, import_data.Team):
                teams.append(obj)

        full_sync = kwargs.get('full_sync') is True
        if len(shared_folders) > 0:
            membership_summary = import_utils.import_user_permissions(context.vault, shared_folders, full_sync)
            if membership_summary.teams_added > 0:
                logger.info("%d team(s) added to shared folders", membership_summary.teams_added)
            if membership_summary.users_added > 0:
                logger.info("%d user(s) added to shared folders", membership_summary.users_added)
            if membership_summary.teams_updated > 0:
                logger.info("%d team(s) updated in shared folders", membership_summary.teams_updated)
            if membership_summary.users_updated > 0:
                logger.info("%d user(s) updated in shared folders", membership_summary.users_updated)
            if membership_summary.teams_removed > 0:
                logger.info("%d team(s) removed from shared folders", membership_summary.teams_removed)
            if membership_summary.users_removed > 0:
                logger.info("%d user(s) removed from shared folders", membership_summary.users_removed)

        if len(teams) > 0:
            team_summary = import_utils.import_teams(context.enterprise_data, context.auth, teams, full_sync)
            if team_summary.users_added > 0:
                logger.info("%d user(s) added to teams", team_summary.users_added)
            if team_summary.users_removed > 0:
                logger.info("%d user(s) removed from teams", team_summary.users_removed)

            context.enterprise_down()


