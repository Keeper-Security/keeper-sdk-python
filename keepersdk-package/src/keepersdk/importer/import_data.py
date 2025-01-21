import abc
import contextlib
import io
import json
import os
from typing import Optional, List, Any, Union, Iterable

from ..vault import record_types, typed_field_utils, attachment, vault_online, vault_record

PathDelimiter = '\\'
TWO_FACTOR_CODE = 'TFC:Keeper'
FIELD_TYPE_ONE_TIME_CODE = 'oneTimeCode'

STANDARD_RECORD_TYPES = {
    'login', 'bankAccount', 'address', 'bankCard', 'birthCertificate', 'contact', 'driverLicense', 'encryptedNotes', 'file',
    'healthInsurance', 'membership', 'passport', 'photo', 'serverCredentials', 'softwareLicense', 'ssnCard', 'general', 'sshKeys',
    'databaseCredentials', 'wifiCredentials'}


def check_if_bool(value):
    return value is None or isinstance(value, bool)


class Permission:
    def __init__(self) -> None:
        self.uid: Optional[str] = None
        self.name: Optional[str] = None
        self.manage_users: Optional[bool] = None
        self.manage_records: Optional[bool] = None


class SharedFolder:
    def __init__(self) -> None:
        self.uid: Optional[str] = None
        self.path: Optional[str] = None
        self.manage_users: Optional[bool] = None
        self.manage_records: Optional[bool] = None
        self.can_edit: Optional[bool] = None
        self.can_share: Optional[bool] = None
        self.permissions: Optional[List[Permission]] = None

class Team:
    def __init__(self) -> None:
        self.uid: Optional[str] = None
        self.name: Optional[str] = None
        self.members: Optional[List[str]] = None

    def validate(self):
        if not self.name:
            raise Exception('Team name cannot be empty')


class Attachment(abc.ABC):
    def __init__(self) -> None:
        self.file_uid: Optional[str] = None
        self.name: Optional[str] = None
        self.size: Optional[int] = None
        self.mime: Optional[str] = None

    @abc.abstractmethod
    def open(self) -> io.RawIOBase:
        pass

    def prepare(self) -> None:
        """ populate size if empty """
        pass


class Folder:
    def __init__(self) -> None:
        self.uid: Optional[str] = None
        self.domain: Optional[str] = None
        self.path: Optional[str] = None
        self.can_edit: Optional[bool] = None
        self.can_share: Optional[bool] = None

    def get_folder_path(self):
        path = self.domain or ''
        if self.path:
            if path:
                if path[0] == PathDelimiter:
                    path = path[1:]
                path += PathDelimiter
            path += self.path
        return path


class RecordField(record_types.ITypedField):
    def __init__(self) -> None:
        self.type: Optional[str] = None
        self.label: Optional[str] = None
        self.value: Any = None

    @classmethod
    def create(cls, field_type:Optional[str]=None, field_label:Optional[str]=None, value:Any=None) -> 'RecordField':
        rt = cls()
        rt.type = field_type
        rt.label = field_label
        rt.value = value
        return rt

    def field_type(self) -> str:
        return self.type or ''

    def field_label(self) -> str:
        return self.label or ''

    @staticmethod
    def hash_value(value: Any) -> str:
        if not value:
            return ''
        if isinstance(value, str):
            value = value.strip()
        elif isinstance(value, list):
            value = [RecordField.hash_value(x) for x in value]
            value = '|'.join((x for x in value if x))
        elif isinstance(value, dict):
            value = json.dumps(value, sort_keys=True, separators=(',', ':'))
        else:
            value = str(value)
        return value

    def hash_key(self) -> Optional[str]:
        value = RecordField.hash_value(self.value)
        if value:
            name = self.external_name()
            return f'{name}:{value}'


class RecordReferences:
    def __init__(self) -> None:
        self.type: str = ''
        self.uids: List[Any] = list()
        self.label: Optional[str] = None


class RecordSchemaField:
    def __init__(self) -> None:
        self.ref: str = ''
        self.label: str = ''
        self.required: Optional[bool] = None


class Record:
    def __init__(self) -> None:
        self.uid: Optional[Any] = None
        self.type: Optional[str] = None
        self.title: Optional[str] = None
        self.login: Optional[str] = None
        self.password: Optional[str] = None
        self.login_url: Optional[str] = None
        self.notes: Optional[str] = None
        self.last_modified: int = 0
        self.fields: List[RecordField] = list()
        self.folders: Optional[List[Folder]] = None
        self.attachments: Optional[List[Attachment]] = None
        self.references: Optional[List[RecordReferences]] = None
        self.schema: Optional[List[RecordSchemaField]] = None


class RecordTypeField:
    def __init__(self) -> None:
        self.type: str = ''
        self.label: str = ''
        self.required: Optional[bool] = None

    @classmethod
    def create(cls, field_type: str, field_label: str) -> 'RecordTypeField':
        f = cls()
        f.type = field_type
        f.label = field_label
        return f


class RecordType:
    def __init__(self) -> None:
        self.name: str = ''
        self.description: str = ''
        self.fields: List[RecordTypeField] = list()


class BytesAttachment(Attachment):
    def __init__(self, name: str, buffer: bytes) -> None:
        super().__init__()
        self.name = name
        self.data = buffer
        self.size = len(buffer)

    @contextlib.contextmanager
    def open(self):
        yield io.BytesIO(self.data)


class BaseImporter(typed_field_utils.TypedFieldMixin, abc.ABC):

    @abc.abstractmethod
    def vault_import(self, **kwargs) -> Iterable[Union[Record, SharedFolder]]:
        pass

    @abc.abstractmethod
    def description(self) -> str:
        pass

    def extension(self):
        return ''

    def support_folder_filter(self):
        return False

    def cleanup(self) -> None:
        return


class BaseFileImporter(BaseImporter, abc.ABC):
    def __init__(self, filename: str):
        super().__init__()
        path = os.path.expanduser(filename)
        if not os.path.isfile(path):
            ext = self.extension()
            if ext:
                path = path + '.' + ext
        if not os.path.isfile(path):
            raise Exception(f'File "{filename}" does not exist')

        self.filename = path


class BaseExporter(typed_field_utils.TypedFieldMixin, abc.ABC):
    def __init__(self):
        self.max_size = 10 * 1024 * 1024

    @abc.abstractmethod
    def vault_export(self, items: List[Union[Record, SharedFolder, Team]], **kwargs) -> None:
        pass

    def has_shared_folders(self):
        return False

    def has_attachments(self):
        return False

    def extension(self):
        return ''

    def supports_stdout(self):
        return False

    def supports_v3_record(self):
        return True

    @staticmethod
    def export_field(field_type: str, field_value: Any) -> Optional[str]:
        if not field_value:
            return ''

        if isinstance(field_value, str):
            return field_value
        if isinstance(field_value, list):
            values = []
            for value in field_value:
                v = BaseExporter.export_field(field_type, value)
                if v:
                    values.append(v)
            return '\n'.join((x.replace('\n', ' ') for x in values))
        if isinstance(field_value, dict):
            if field_type == 'host':
                return BaseExporter.export_host_field(field_value)
            if field_type == 'phone':
                return BaseExporter.export_phone_field(field_value)
            if field_type == 'name':
                return BaseExporter.export_name_field(field_value)
            if field_type == 'address':
                return BaseExporter.export_address_field(field_value)
            if field_type == 'securityQuestion':
                return BaseExporter.export_q_and_a_field(field_value)
            if field_type == 'paymentCard':
                return BaseExporter.export_card_field(field_value)
            if field_type == 'bankAccount':
                return BaseExporter.export_account_field(field_value)
            if field_type in ('keyPair', 'privateKey'):
                return BaseExporter.export_ssh_key_field(field_value)
            if field_type == 'schedule':
                return BaseExporter.export_schedule_field(field_value)
            return json.dumps(field_value)

        return str(field_value)


class AttachmentUploadTask(attachment.UploadTask):
    def __init__(self, atta: Attachment):
        super().__init__()
        self.attachment = atta

    def prepare(self) -> None:
        self.attachment.prepare()
        self.name = self.attachment.name or ''
        self.size = self.attachment.size or 0
        self.mime_type = self.attachment.mime or ''

    @contextlib.contextmanager
    def open(self):
        with self.attachment.open() as s:
            yield s


class BaseDownloadMembership(abc.ABC):
    @abc.abstractmethod
    def download_membership(self, *, folders_only: Optional[bool] = False, **kwargs) -> Iterable[Union[SharedFolder, Team]]:
        pass


class BaseDownloadRecordType(abc.ABC):
    @abc.abstractmethod
    def download_record_type(self, **kwargs) -> Iterable[RecordType]:
        pass


class KeeperAttachment(Attachment):
    def __init__(self, vault: vault_online.VaultOnline, record_uid: str, file_id: str):
        super().__init__()
        self.vault = vault
        self.file_id = file_id
        self.record_uid = record_uid

    @contextlib.contextmanager
    def open(self):
        da = next(attachment.prepare_attachment_download(self.vault, self.record_uid, self.file_id), None)
        if da is None:
            raise Exception(f'File attachment {self.file_id} does not exist in a record {self.record_uid}')
        with da.get_decrypted_stream() as plain:
            yield plain


class IImportLogger(abc.ABC):
    @abc.abstractmethod
    def added_record(self, import_record: Record, update_existing: bool,
                     keeper_record: Union[vault_record.PasswordRecord, vault_record.TypedRecord]) -> None:
        pass
    @abc.abstractmethod
    def failed_record(self, record_name: str, message: str) -> None:
        pass
    @abc.abstractmethod
    def confirm_import(self) -> bool:
        pass
