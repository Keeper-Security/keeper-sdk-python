import datetime
import io
import logging
import re
import urllib.parse
import uuid
from typing import List, Optional, Iterable, Union, Any, Dict
from xml.sax.saxutils import escape

from pykeepass import PyKeePass, create_database
from pykeepass.attachment import Attachment as KeepassAttachment
from pykeepass.exceptions import CredentialsError
from pykeepass.group import Group

from keepersdk import utils
from keepersdk.importer import import_data, import_utils
from keepersdk.vault import vault_utils

_REFERENCE = r'\{REF:([TUPAN])@([IT]):([^\}]+)\}'


class XmlUtils(object):
    @staticmethod
    def escape_string(plain):   # type: (str) -> str
        if not plain:
            return ''
        output = escape(plain)
        return output.replace('\'', '&apos;').replace('\"', '&quot;')


class KeepassImporter(import_data.BaseFileImporter):
    def __init__(self, filename: str, password: Optional[str], keyfile: Optional[str]):
        super().__init__(filename)
        self.password = password
        self.keyfile = keyfile

    @staticmethod
    def get_folder(group):  # type: (Group) -> str
        g = group
        path = ''
        comp = ''
        while isinstance(g, Group):
            if comp:
                if len(path) > 0:
                    path = import_data.PathDelimiter + path
                path = comp + path
                comp = ''

            nm = g.name
            if nm:
                comp = nm.replace(import_data.PathDelimiter, import_data.PathDelimiter*2)
            g = g.group
        return path

    def description(self) -> str:
        return 'keepass'

    def vault_import(self, **kwargs) -> Iterable[Union[import_data.Record, import_data.SharedFolder]]:
        try:
            with PyKeePass(self.filename, password=self.password, keyfile=self.keyfile) as kdb:
                root = kdb.root_group
                if not root:
                    return
                groups: List[Group] = [root]
                pos = 0
                while pos < len(groups):
                    g = groups[pos]
                    groups.extend(g.subgroups)
                    pos = pos + 1

                records = []
                for group in groups:
                    entries = group.entries
                    if len(entries) > 0:
                        folder = KeepassImporter.get_folder(group)
                        for entry in entries:
                            totp_secret = ''
                            totp_issuer = ''
                            totp_period = 0
                            totp_digits = 0
                            record = import_data.Record()
                            fol = import_data.Folder()
                            fol.path = folder
                            record.folders = [fol]
                            if entry.uuid:
                                record.uid = utils.base64_url_encode(entry.uuid.bytes)
                            if entry.title:
                                record.title = entry.title
                            if entry.username:
                                record.login = entry.username
                            if entry.password:
                                record.password = entry.password
                            if entry.url:
                                record.login_url = entry.url
                            if entry.notes:
                                record.notes = entry.notes
                            if hasattr(entry, 'ctime'):
                                ctime = entry.ctime
                                if isinstance(ctime, datetime.datetime):
                                    record.last_modified = int(ctime.timestamp())
                            for key, value in entry.custom_properties.items():
                                if key == '$type':
                                    record.type = value
                                    continue
                                rest, sep, no = key.rpartition('#')
                                if sep:
                                    if no.isdigit():
                                        key = rest
                                if key.startswith('$'):
                                    ftype, sep, flabel = key.partition(':')
                                    field_type = ftype[1:]
                                    field_label = flabel
                                else:
                                    field_type = ''
                                    field_label = key
                                if field_label in ('TOTPSecret', 'TOTPPeriod', 'TOTPDigits', 'TOTPIssuer', 'ModifyTOTPSettings', 'ViewTOTPSettings'):
                                    if field_label == 'TOTPSecret':
                                        totp_secret = value
                                    elif field_label == 'TOTPIssuer':
                                        totp_issuer = value
                                    elif field_label == 'TOTPPeriod':
                                        try:
                                            totp_period = int(value)
                                        except Exception:
                                            pass
                                    elif field_label == 'TOTPDigits':
                                        try:
                                            totp_digits = int(value)
                                        except Exception:
                                            pass
                                else:
                                    field = import_data.RecordField()
                                    field.type = field_type
                                    field.label = field_label
                                    field.value = import_utils.adjust_typed_field(field_type, value)
                                    record.fields.append(field)
                            if totp_secret:
                                value = f'otpauth://totp/?secret={totp_secret}'
                                if totp_issuer:
                                    value += f'&issuer={urllib.parse.quote_plus(totp_issuer)}'
                                if totp_period > 0:
                                    value += f'&period={totp_period}'
                                if totp_digits > 0:
                                    value += f'&digits={totp_digits}'
                                field = import_data.RecordField()
                                field.type = 'oneTimeCode'
                                field.value = import_utils.adjust_typed_field(field_type, value)
                                record.fields.append(field)

                            if entry.attachments:
                                for a in entry.attachments:
                                    if isinstance(a, KeepassAttachment):
                                        if record.attachments is None:
                                            record.attachments = []
                                        atta = import_data.BytesAttachment(a.filename, a.binary)
                                        atta.file_uid = a.id
                                        record.attachments.append(atta)

                            records.append(record)
                id_map = None
                title_map = None
                ref_re = re.compile(_REFERENCE, re.IGNORECASE)

                def resolve_references(text):
                    nonlocal id_map
                    nonlocal title_map

                    if not text:
                        return text
                    matches = list(ref_re.finditer(text))
                    if not matches:
                        return text
                    values = []
                    for match in matches:
                        comps = match.groups()
                        val = match.group(0)
                        if len(comps) == 3:
                            rec = None
                            if comps[1].upper() == 'I':
                                if id_map is None:
                                    id_map = {}
                                    for r in records:
                                        if r.uid:
                                            id_map[r.uid] = r
                                uid = uuid.UUID(comps[2])
                                if uid:
                                    ref_id = utils.base64_url_encode(uid.bytes)
                                    rec = id_map.get(ref_id)
                            elif comps[1].upper() == 'T':
                                if title_map is None:
                                    title_map = {}
                                    for r in records:
                                        if r.title:
                                            title_map[r.title] = r
                                rec = title_map.get(comps[2])
                            if rec:
                                field_id = comps[0].upper()
                                if field_id == 'T':
                                    val = rec.title
                                elif field_id == 'U':
                                    val = rec.login
                                elif field_id == 'P':
                                    val = rec.password
                                elif field_id == 'A':
                                    val = rec.login_url
                                elif field_id == 'N':
                                    val = rec.notes
                        values.append(val or '')

                        idx = list(range(len(matches)))
                        idx.reverse()
                        for index in idx:
                            match = matches[index]
                            val = values[index] if index < len(values) else ''
                            text = text[:match.start()] + val + text[match.end():]
                        return text

                for record in records:
                    try:
                        record.login = resolve_references(record.login)
                        record.password = resolve_references(record.password)
                        record.login_url = resolve_references(record.login_url)
                        record.notes = resolve_references(record.notes)
                        for field in record.fields:
                            field.value = resolve_references(field.value)
                    except Exception as e:
                        logging.debug(e)
                    yield record
        except CredentialsError:
            utils.get_logger().warning('Invalid Keepass credentials')

    def extension(self):
        return 'kdbx'


class KeepassExporter(import_data.BaseExporter, XmlUtils):
    def __init__(self, filename: str, password: str):
        super().__init__()
        self.filename = filename
        self.password = password

    @staticmethod
    def to_keepass_value(keeper_value: Any) -> str:
        if not keeper_value:
            return ''
        if isinstance(keeper_value, list):
            return ','.join((KeepassExporter.to_keepass_value(x) for x in keeper_value))
        elif isinstance(keeper_value, dict):
            return ';\n'.join((f'{k}:{KeepassExporter.to_keepass_value(v)}' for k, v in keeper_value.items()))
        else:
            return str(keeper_value)

    def vault_export(self,
                     items: List[Union[import_data.Record, import_data.SharedFolder, import_data.Team]],
                     **kwargs) -> None:
        sfs: List[import_data.SharedFolder] = []
        rs: List[import_data.Record] = []
        for x in items:
            if isinstance(x, import_data.Record):
                rs.append(x)
            elif isinstance(x, import_data.SharedFolder):
                sfs.append(x)

        with create_database(self.filename, password=self.password) as kdb:
            root = kdb.root_group
            for r in rs:
                try:
                    node = root
                    if r.folders:
                        fol = r.folders[0]
                        for is_shared in [True, False]:
                            path = fol.domain if is_shared else fol.path
                            if path:
                                comps = list(vault_utils.parse_folder_path(path, path_delimiter=import_data.PathDelimiter))
                                for i in range(len(comps)):
                                    comp = comps[i]
                                    sub_node = next((x for x in node.subgroups if x.name == comp), None)
                                    if sub_node is None:
                                        sub_node = kdb.add_group(node, comp)
                                    node = sub_node
                    entry = None
                    entries = node.entries
                    for en in entries:
                        if en.title == r.title and en.username == r.login and en.password == r.password:
                            entry = en
                            break

                    if entry is None:
                        entry = kdb.add_entry(node, title=r.title or '', username=r.login or '',
                                              password=r.password or '', url=r.login_url or '',
                                              notes=r.notes or '')
                        if r.uid:
                            entry.UUID = uuid.UUID(bytes=utils.base64_url_decode(r.uid))
                    if r.type:
                        entry.set_custom_property('$type', r.type)
                    if r.fields:
                        custom_names: Dict[str, int] = {}
                        for cf in r.fields:
                            if not cf.value:
                                continue
                            if cf.type and cf.label:
                                title = f'${cf.type}:{cf.label}'
                            elif cf.type:
                                title = f'${cf.type}'
                            else:
                                cf.type = '$text'
                                title = cf.label or ''
                            if title in custom_names:
                                no = custom_names[title]
                                no += 1
                                custom_names[title] = no
                                title = f'{title}#{no}'
                            else:
                                custom_names[title] = 1
                            entry.set_custom_property(title, self.to_keepass_value(self.export_field(cf.type, cf.value)))

                    if r.attachments:
                        for atta in r.attachments:
                            if atta.size < self.max_size:
                                with atta.open() as ina, io.BytesIO() as outa:
                                    buffer = bytearray(10240)
                                    view = memoryview(buffer)
                                    while True:
                                        bytes_read = ina.readinto(view)
                                        if bytes_read == 0:
                                            break
                                        outa.write(view[0:bytes_read])
                                    del view
                                    del buffer
                                    outa.flush()
                                    binary = outa.getvalue()

                                if binary:
                                    binary_id = kdb.add_binary(binary, compressed=True, protected=False)
                                    entry.add_attachment(binary_id, atta.name)
                            else:
                                scale = ''
                                msize = self.max_size
                                if msize > 1024 ** 3:
                                    scale = 'G'
                                    msize //= 1024 ** 3
                                elif msize > 1024 ** 2:
                                    scale = 'M'
                                    msize //= 1024 ** 2
                                elif msize > 1024:
                                    scale = 'K'
                                    msize //= 1024
                                utils.get_logger().warning(
                                    'File \'{0}\' was skipped because it exceeds the {1}{2} file size limit.'.format(atta.name, msize, scale))
                except Exception as e:
                    logging.debug(e)

            kdb.save()

    def has_shared_folders(self):
        return True

    def has_attachments(self):
        return True

    def extension(self):
        return 'kdbx'

    def supports_v3_record(self):
        return False
