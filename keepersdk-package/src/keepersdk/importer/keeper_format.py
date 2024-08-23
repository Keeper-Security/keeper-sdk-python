import io
import json
import os.path
import pathlib
import sys
import zipfile
from contextlib import contextmanager
from typing import List, Optional, Any, Dict, Union, Iterable

from keepersdk import utils
from keepersdk.enterprise import enterprise_types
from keepersdk.importer import import_data, import_utils
from keepersdk.proto import enterprise_pb2
from keepersdk.vault import record_types, storage_types, vault_online, vault_types


class KeeperJsonMixin:
    @staticmethod
    def json_to_record(j_record: Dict[str, Any]) -> Optional[import_data.Record]:
        record = import_data.Record()
        record.uid = j_record.get('uid')
        if '$type' in j_record:
            record.type = j_record['$type']
        record.title = j_record.get('title') or ''
        record.login = j_record.get('login') or ''
        record.password = j_record.get('password') or ''
        record.login_url = j_record.get('login_url') or ''
        record.notes = j_record.get('notes') or ''
        if 'last_modified' in j_record:
            lm = j_record['last_modified']
            if isinstance(lm, int):
                record.last_modified = lm
        custom_fields = j_record.get('custom_fields')
        if type(custom_fields) is dict:
            for name in custom_fields:
                value = custom_fields[name]
                if name[0] == '$':
                    pos = name.find(':')
                    if pos > 0:
                        field_type = name[1:pos].strip()
                        field_name = name[pos+1:].strip()
                    else:
                        field_type = name[1:].strip()
                        field_name = ''
                else:
                    field_type = ''
                    field_name = name

                is_multiple = False
                if field_type:
                    ft = record_types.RecordFields.get(field_type)
                    if ft:
                        is_multiple = ft.multiple != record_types.Multiple.Never

                if isinstance(value, list) and not is_multiple:
                    for v in value:
                        field = import_data.RecordField()
                        field.type = field_type
                        field.label = field_name
                        field.value = v
                        record.fields.append(field)
                else:
                    field = import_data.RecordField()
                    field.type = field_type
                    field.label = field_name
                    field.value = value
                    record.fields.append(field)
        if 'schema' in j_record:
            record.schema = []
            for s in j_record['schema']:
                pos = s.find(':')
                if pos > 0:
                    schema_ref = s[0:pos].strip()
                    schema_label = s[pos+1:].strip()
                else:
                    schema_ref = s
                    schema_label = ''
                if schema_ref[0] == '$':
                    schema_ref = schema_ref[1:]

                sf = import_data.RecordSchemaField()
                sf.ref = schema_ref
                sf.label = schema_label
                record.schema.append(sf)
        if 'references' in j_record:
            record.references = []
            for ref_name in j_record['references']:
                if not ref_name:
                    continue
                ref_value = j_record['references'][ref_name]
                if not ref_value:
                    continue
                if not isinstance(ref_value, list):
                    ref_value = [ref_value]
                ref_type = ref_name
                ref_label = ''
                pos = ref_name.find(':')
                if pos > 0:
                    ref_type = ref_name[1:pos].strip()
                    ref_label = ref_name[pos+1].strip()
                if ref_type[0] == '$':
                    ref_type = ref_type[1:]
                rr = import_data.RecordReferences()
                rr.type = ref_type
                rr.label = ref_label
                rr.uids.extend(ref_value)
                record.references.append(rr)
        if 'folders' in j_record:
            record.folders = []
            for f in j_record['folders']:
                folder = import_data.Folder()
                folder.domain = f.get('shared_folder')
                folder.path = f.get('folder')
                folder.can_edit = f.get('can_edit')
                folder.can_share = f.get('can_share')
                record.folders.append(folder)
        return record


class ZipAttachment(import_data.Attachment):
    def __init__(self, zip_filename, file_uid):
        super().__init__()
        self.zip_filename = zip_filename
        self.file_uid = file_uid

    @contextmanager
    def open(self):
        with zipfile.ZipFile(self.zip_filename, mode='r') as zf:
            yield io.BytesIO(zf.read(f'files/{self.file_uid}'))

    def prepare(self):
        try:
            with zipfile.ZipFile(self.zip_filename, mode='r') as zf:
                try:
                    zi = zf.getinfo(f'files/{self.file_uid}')
                    self.size = zi.file_size
                except KeyError:
                    utils.get_logger().debug('ZipAttachment: file \"%s\" not found', self.file_uid)
        except Exception as e:
            utils.get_logger().debug('ZipAttachment: %s', e)
            self.size = 0


class KeeperJsonImporter(import_data.BaseFileImporter, KeeperJsonMixin):
    def __init__(self, filename: str) -> None:
        super().__init__(filename)

    def vault_import(self, **kwargs):
        if not os.path.isfile(self.filename):
            zip_name = pathlib.Path(self.filename).with_suffix('.zip').name
            if os.path.isfile(zip_name):
                if zipfile.is_zipfile(zip_name):
                    self.filename = zip_name
        file_path = pathlib.Path(self.filename)
        zip_archive = file_path.suffix == '.zip'
        if zip_archive:
            with zipfile.ZipFile(self.filename, 'r') as zf:
                export = json.loads(zf.read('export.json'))
        else:
            with open(self.filename, "r", encoding='utf-8') as jf:
                export = json.load(jf)

        records = None
        folders = None
        teams = None
        if isinstance(export, list):
            records = export

        elif isinstance(export, dict):
            records = export.get('records')
            folders = export.get('shared_folders')

        if folders:
            for shf in folders:
                fol = import_data.SharedFolder()
                fol.uid = shf.get('uid')
                fol.path = shf.get('path')
                fol.manage_records = shf.get('manage_records') or False
                fol.manage_users = shf.get('manage_users') or False
                fol.can_edit = shf.get('can_edit') or False
                fol.can_share = shf.get('can_share') or False
                if 'permissions' in shf:
                    fol.permissions = []
                    permissions = shf['permissions']
                    if not isinstance(permissions, list):
                        permissions = [permissions]
                    for perm in permissions:
                        if isinstance(perm, dict):
                            p = import_data.Permission()
                            p.uid = perm.get('uid')
                            p.name = perm.get('name')
                            if p.uid or p.name:
                                p.manage_records = perm.get('manage_records') or False
                                p.manage_users = perm.get('manage_users') or False
                                fol.permissions.append(p)

                yield fol

        if isinstance(teams, list):
            for t in teams:
                team = import_data.Team()
                team.name = t.get('name')
                if team.name:
                    team.uid = t.get('uid')
                    ms = t.get('members')
                    if isinstance(ms, list):
                        team.members = [x for x in ms if isinstance(x, str) and len(x) > 3]
                    yield team

        if records:
            for r in records:
                record = KeeperJsonMixin.json_to_record(r)
                if zip_archive and 'attachments' in r:
                    attachments = r['attachments']
                    record.attachments = []
                    if isinstance(attachments, list):
                        for atta in attachments:
                            file_uid = atta.get('file_uid')
                            a = ZipAttachment(self.filename, file_uid)
                            a.name = atta.get('name') or file_uid
                            a.mime = atta.get('mime')
                            record.attachments.append(a)
                yield record

    def extension(self):
        return 'json'

    def description(self) -> str:
        return 'JSON format'


class KeeperJsonExporter(import_data.BaseExporter):
    def __init__(self, filename: str, zip_archive: bool = False):
        super().__init__()
        if filename:
            filename = os.path.expanduser(filename)
            if filename.find('.') < 0:
                ext = self.extension()
                if ext:
                    filename = filename + '.' + ext
        elif not self.supports_stdout():
            raise Exception('File name parameter is required.')
        if zip_archive is True and not filename:
            raise ValueError('Please provide zip archive file name')
        self.filename = filename
        self.zip_archive = zip_archive


    def vault_export(self,
                     items: List[Union[import_data.Record, import_data.SharedFolder, import_data.Team]],
                     **kwargs) -> None:
        shared_folders: List[import_data.SharedFolder] = []
        records: List[import_data.Record] = []
        teams: List[import_data.Team] = []

        for item in items:
            if isinstance(item, import_data.Record):
                records.append(item)
            elif isinstance(item, import_data.SharedFolder):
                shared_folders.append(item)
            elif isinstance(item, import_data.Team):
                teams.append(item)

        ts = []
        for t in teams:
            team: Dict[str, Any] = {}
            if t.name:
                team['name'] = t.name
            if t.uid:
                team['uid'] = t.uid
            if t.members:
                team['members'] = [x for x in t.members]
            ts.append(team)

        sfs = []
        for sf in shared_folders:
            sfo: Dict[str, Any] = {
                'path': sf.path,
            }
            if sf.uid:
                sfo['uid'] = sf.uid
            if sf.manage_users is not None:
                sfo['manage_users'] = sf.manage_users or False
            if sf.manage_records is not None:
                sfo['manage_records'] = sf.manage_records or False
            if sf.can_edit is not None:
                sfo['can_edit'] = sf.can_edit or False
            if sf.can_share is not None:
                sfo['can_share'] = sf.can_share or False

            if sf.permissions:
                sfo['permissions'] = []
                for perm in sf.permissions:
                    po = {
                        'name': perm.name,
                        'manage_users': perm.manage_users,
                        'manage_records': perm.manage_records
                    }
                    if perm.uid:
                        po['uid'] = perm.uid
                    sfo['permissions'].append(po)
            sfs.append(sfo)

        rs = []
        atta = {}
        for r in records:
            ro: Dict[str, Any] = {
                'title': r.title or ''
            }
            if r.uid:
                ro['uid'] = r.uid
            if r.login:
                ro['login'] = r.login
            if r.password:
                ro['password'] = r.password
            if r.login_url:
                ro['login_url'] = r.login_url
            if r.notes:
                ro['notes'] = r.notes
            if r.type:
                ro['$type'] = r.type
            if r.uid:
                ro['uid'] = r.uid
            if isinstance(r.last_modified, int) and r.last_modified > 0:
                ro['last_modified'] = int(r.last_modified / 1000)

            if r.fields:
                ro['custom_fields'] = {}
                for field in r.fields:
                    if not field.type and field.label and field.label.startswith('$'):
                        field.type = 'text'
                    if field.type and field.label:
                        name = f'${field.type}:{field.label}'
                    elif field.type:
                        name = f'${field.type}'
                    else:
                        name = field.label or '<No Name>'
                    value = field.value
                    if name in ro['custom_fields']:
                        orig_value = ro['custom_fields'][name]
                        if orig_value:
                            orig_value = orig_value if type(orig_value) is list else [orig_value]
                        else:
                            orig_value = []
                        if value:
                            orig_value.append(value)
                        value = orig_value
                    ro['custom_fields'][name] = value

            if r.schema:
                ro['schema'] = []
                for rsf in r.schema:
                    name = f'${rsf.ref}'
                    if rsf.label:
                        name += f':{rsf.label}'
                    ro['schema'].append(name)

            if r.references:
                ro['references'] = {}
                for ref in r.references:
                    ref_name = f'${ref.type}:{ref.label}' if ref.type and ref.label else f'${ref.type}' if ref.type else ref.label or ''
                    refs = ro['references'].get(ref_name)
                    if refs is None:
                        refs = []
                        ro['references'][ref_name] = refs
                    refs.extend(ref.uids)

            if r.folders:
                ro['folders'] = []
                for folder in r.folders:
                    if folder.domain or folder.path:
                        fo: Dict[str, Any] = {}
                        ro['folders'].append(fo)
                        if folder.domain:
                            fo['shared_folder'] = folder.domain
                        if folder.path:
                            fo['folder'] = folder.path
                        if folder.can_edit:
                            fo['can_edit'] = True
                        if folder.can_share:
                            fo['can_share'] = True

            if r.attachments and self.zip_archive:
                ro['attachments'] = []
                for at in r.attachments:
                    file_uid = at.file_uid or utils.generate_uid()
                    atta[file_uid] = at
                    a = {
                        'file_uid': file_uid,
                        'name': at.name
                    }
                    if at.mime:
                        a['mime'] = at.mime
                    ro['attachments'].append(a)

            rs.append(ro)

        jo = {}
        if ts:
            jo['teams'] = ts
        if sfs:
            jo['shared_folders'] = sfs
        if rs:
            jo['records'] = rs

        if self.zip_archive and self.filename:
            zip_name = pathlib.Path(self.filename).with_suffix('.zip').name
            with zipfile.ZipFile(zip_name, mode='w', compresslevel=zipfile.ZIP_DEFLATED) as zf:
                export_data = json.dumps(jo, indent=2, ensure_ascii=False)
                zf.writestr('export.json', export_data)
                total = len(atta)
                if total > 0:
                    utils.get_logger().info('Downloading attachments...')
                    i = 1
                    for file_uid, at in atta.items():
                        utils.get_logger().info(f'{i:>3} of {total:3} {at.name}')
                        i += 1
                        with at.open() as fs:
                            data = fs.read()
                            if data:
                                zf.writestr(f'files/{file_uid}', data)
        elif self.filename:
            with open(self.filename, mode="w", encoding='utf-8') as f:
                json.dump(jo, f, indent=2, ensure_ascii=False)
        else:
            json.dump(jo, sys.stdout, indent=2, ensure_ascii=False)

    def has_shared_folders(self):
        return True

    def has_attachments(self):
        return self.zip_archive

    def extension(self):
        return 'json'

    def supports_stdout(self):
        return True

    def supports_v3_record(self):
        return True


class KeeperMembershipDownload(import_data.BaseDownloadMembership):
    def __init__(self, vault: vault_online.VaultOnline, enterprise: enterprise_types.IEnterpriseData):
        super().__init__()
        self.vault = vault
        self.enterprise = enterprise

    def download_membership(self,
                            folders_only: Optional[bool] = False, **kwargs
                            ) -> Iterable[Union[import_data.SharedFolder, import_data.Team]]:
        teams: Dict[str, str] = {}
        for shared_folder_info in self.vault.vault_data.shared_folders():
            shared_folder = self.vault.vault_data.load_shared_folder(shared_folder_info.shared_folder_uid)
            if not shared_folder:
                continue
            for u in shared_folder.user_permissions:
                if u.user_type == storage_types.SharedFolderUserType.Team:
                    if u.name:
                        teams[u.user_uid] = u.name
            yield import_utils.to_import_shared_folder(self.vault.vault_data, shared_folder)

        if folders_only is True:
            return

        enterprise_teams: Dict[str, List[str]] = {}
        if self.enterprise is not None:
            user_lookup = {x.enterprise_user_id: x.username for x in self.enterprise.users.get_all_entities()
                           if x.status == 'active'}
            for tu in self.enterprise.team_users.get_all_links():
                if tu.enterprise_user_id in user_lookup:
                    enterprise_teams[tu.team_uid] = []
                enterprise_teams[tu.team_uid].append(user_lookup[tu.enterprise_user_id])

        if teams and self.vault.keeper_auth.auth_context.enterprise_ec_public_key:
            for team_uid in teams:
                t = import_data.Team()
                t.uid = team_uid
                t.name = teams[team_uid]
                if team_uid in enterprise_teams:
                    t.members = list(enterprise_teams[team_uid])
                else:
                    rq = enterprise_pb2.GetTeamMemberRequest()
                    rq.teamUid = utils.base64_url_decode(team_uid)
                    rs = self.vault.keeper_auth.execute_auth_rest(
                        'vault/get_team_members', rq, response_type=enterprise_pb2.GetTeamMemberResponse)
                    assert rs is not None
                    t.members = [x.email for x in rs.enterpriseUser]
                yield t


class KeeperRecordTypeDownload(import_data.BaseDownloadRecordType):
    def __init__(self, vault: vault_online.VaultOnline) -> None:
        super().__init__()
        self.vault = vault

    def download_record_type(self, **kwargs) -> Iterable[import_data.RecordType]:
        for ert in self.vault.vault_data.get_record_types():
            if ert.scope == vault_types.RecordTypeScope.Enterprise:
                continue
            rt = import_data.RecordType()
            rt.name = ert.name
            rt.description = ert.description
            for ertf in ert.fields:
                rtf = import_data.RecordTypeField()
                rtf.type = ertf.type
                rtf.label = ertf.label
                if isinstance(ertf.required, bool):
                    rtf.required = ertf.required
                rt.fields.append(rtf)
                yield rt
