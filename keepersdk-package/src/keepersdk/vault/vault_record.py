from __future__ import annotations

import abc
import enum
import itertools
from typing import Optional, Dict, Any, List, Tuple, Iterable, Type
from dataclasses import dataclass

from . import vault_types, record_types


def sanitize_str_field_value(value: Any) -> str:
    if not value:
        return ''
    if not isinstance(value, str):
        value = str(value) if value else ''
    return value


def sanitize_int_field_value(value: Any, *, default:int=0) -> int:
    if not value:
        return default
    if not isinstance(value, int):
        try:
            value = int(value)
        except ValueError:
            if default is not None:
                if not isinstance(default, int):
                    default = 0
            value = default
    return value


def sanitize_bool_field_value(value: Any) -> bool:
    if not value:
        return False
    if not isinstance(value, bool):
        if isinstance(value, int):
            value = value != 0
        else:
            value = False
    return value


class RecordFlags(enum.IntFlag):
    IsOwner = 1 << 0
    IsShared = 1 << 1
    HasAttachments = 1 << 2
    HasPassword = 1 << 3
    HasUrl = 1 << 4


@dataclass(frozen=True)
class KeeperRecordInfo:
    record_uid: str
    version: int
    revision: int
    record_type: str
    title: str
    description: str
    flags: RecordFlags


class KeeperRecord(abc.ABC):
    def __init__(self):
        self.record_uid = ''
        self.title = ''
        self.client_time_modified = 0

    @abc.abstractmethod
    def version(self) -> int:
        pass

    @abc.abstractmethod
    def load_record_data(self, data: Dict[str, Any], extra: Optional[Dict[str, Any]]=None) -> None:
        pass

    def enumerate_fields(self) -> Iterable[Tuple[str, str, Any]]:
        yield 'title', '', self.title

    def extract_password(self) -> Optional[str]:
        if isinstance(self, PasswordRecord):
            return self.password
        if isinstance(self, TypedRecord):
            password_field = self.get_typed_field('password')
            if password_field:
                return password_field.get_default_value(str)

    def extract_url(self: KeeperRecord) -> Optional[str]:
        if isinstance(self, PasswordRecord):
            return self.link
        if isinstance(self, TypedRecord):
            url_field = self.get_typed_field('url')
            if url_field:
                return url_field.get_default_value(str)


class CustomField:
    def __init__(self):
        self.name = ''
        self.value = ''
        self.type = ''

    @classmethod
    def create_field(cls, name: str, value: str) -> 'CustomField':
        cf = cls()
        cf.name = name
        cf.value = value
        cf.type = 'text'
        return cf


class AttachmentFileThumb:
    def __init__(self):
        self.id = ''
        self.type = ''
        self.size = 0


class AttachmentFile:
    def __init__(self) -> None:
        self.id = ''
        self.key = ''
        self.name = ''
        self.title = ''
        self.mime_type = ''
        self.size = 0
        self.last_modified = 0
        self.thumbnails: List[AttachmentFileThumb] = []


class PasswordRecord(KeeperRecord):
    def __init__(self) -> None:
        super(PasswordRecord, self).__init__()
        self.login = ''
        self.password = ''
        self.link = ''
        self.notes = ''
        self.custom: List[CustomField] = []
        self.attachments: Optional[List[AttachmentFile]] = None
        self.totp = ''
        self.unparsed_extra: Optional[Dict[str, Any]] = None

    def version(self):
        return 2

    def load_record_data(self, data: Dict[str, Any], extra: Optional[Dict[str, Any]]=None) -> None:
        self.title = sanitize_str_field_value(data.get('title'))
        self.login = sanitize_str_field_value(data.get('secret1'))
        self.password = sanitize_str_field_value(data.get('secret2'))
        self.link = sanitize_str_field_value(data.get('link'))
        self.notes = sanitize_str_field_value(data.get('notes'))
        custom = data.get('custom')
        if isinstance(custom, list):
            for cf in custom:
                if isinstance(cf, dict):
                    custom_field = CustomField()
                    custom_field.name = sanitize_str_field_value(cf.get('name'))
                    custom_field.value = sanitize_str_field_value(cf.get('value'))
                    custom_field.type = sanitize_str_field_value(cf.get('type'))
                    self.custom.append(custom_field)

        if isinstance(extra, dict):
            extra_copy = extra.copy()
            files = extra_copy.pop('files', None)
            if isinstance(files, list):
                self.attachments = []
                for file in files:
                    if isinstance(file, dict):
                        af = AttachmentFile()
                        af.id = sanitize_str_field_value(file.get('id'))
                        af.key = sanitize_str_field_value(file.get('key'))
                        af.name = sanitize_str_field_value(file.get('name'))
                        af.title = sanitize_str_field_value(file.get('title'))
                        af.mime_type = sanitize_str_field_value(file.get('type'))
                        af.size = sanitize_int_field_value(file.get('size'), default=0)
                        af.last_modified = sanitize_int_field_value(file.get('lastModified'), default=0)
                        thumbs = file.get('thumbnails')
                        if isinstance(thumbs, list):
                            for thumb in thumbs:
                                aft = AttachmentFileThumb()
                                if isinstance(thumb, dict):
                                    aft.id = sanitize_str_field_value(thumb.get('id'))
                                    aft.type = sanitize_str_field_value(thumb.get('type'))
                                    aft.size = sanitize_int_field_value(thumb.get('size'), default=0)
                                thumbs.append(aft)

                        self.attachments.append(af)
            fields = extra_copy.get('fields', None)
            if isinstance(fields, list):
                totp_field = next((x for x in fields if isinstance(x, dict) and x.get('field_type') == 'totp'), None)
                if totp_field is not None:
                    if 'data' in totp_field:
                        self.totp = totp_field['data']
                        del totp_field['data']

            if len(extra_copy) >= 0:
                self.unparsed_extra = extra_copy

    def enumerate_fields(self) -> Iterable[Tuple[str, str, Any]]:
        for tup in super(PasswordRecord, self).enumerate_fields():
            yield tup

        yield 'login', '', self.login
        yield 'password', '', self.password
        yield 'url', '', self.link
        yield 'note', '', self.notes
        if self.totp:
            yield 'oneTimeCode', '', self.totp
        for cf in self.custom:
            yield '', cf.name, cf.value


class TypedField(record_types.ITypedField):
    def __init__(self):
        self.type = ''
        self.label = ''
        self.value = []
        self.required = False

    @classmethod
    def create_field(cls, field_type: str, field_label: Optional[str] = None, *,
                     required: bool = False) -> 'TypedField':
        field = cls()
        field.type = sanitize_str_field_value(field_type)
        if field_label:
            field.label = sanitize_str_field_value(field_label)
        if required is True:
            field.required = True
        return field

    @classmethod
    def create_schema_field(cls, record_field: vault_types.RecordTypeField) -> 'TypedField':
        field = cls()
        field.type = record_field.type
        field.label = record_field.label or ''
        field.required = record_field.required
        return field

    def get_default_value(self, value_type: Optional[Type]=None) -> Any:
        value = None
        if isinstance(self.value, list):
            if len(self.value) > 0:
                value = self.value[0]
        else:
            value = self.value
        if isinstance(value_type, type):
            if not isinstance(value, value_type):
                return None
        return value

    def get_external_value(self) -> Any:
        if isinstance(self.value, list):
            if len(self.value) == 0:
                return None
            if len(self.value) == 1:
                return self.value[0]
        return self.value

    def is_equal_to(self, other_type: str, other_label: Optional[str]=None) -> bool:
        if other_label and self.label:
            if other_label.casefold() != self.label.casefold():
                return False
        return self.type == other_type

    def field_type(self) -> str:
        return self.type

    def field_label(self) -> str:
        return self.label


class TypedRecord(KeeperRecord):
    def __init__(self) -> None:
        super(TypedRecord, self).__init__()
        self.record_type = ''
        self.notes = ''
        self.fields: List[TypedField] = []
        self.custom: List[TypedField] = []
        self.linked_keys: Optional[Dict[str, bytes]] = None

    def version(self):
        return 3

    def get_typed_field(self, field_type: str, field_label: Optional[str]=None) -> Optional[TypedField]:
        return next((x for x in itertools.chain(self.fields, self.custom)
                     if x.is_equal_to(field_type, field_label)), None)

    def load_record_data(self, data, extra=None):
        if isinstance(data, dict):
            self.record_type = sanitize_str_field_value(data.get('type'))
            self.title = sanitize_str_field_value(data.get('title'))
            self.notes = sanitize_str_field_value(data.get('notes'))
            self.fields.clear()
            for f_name in ('fields', 'custom'):
                f_src = data.get(f_name)
                if isinstance(f_src, list):
                    f_dst = self.fields if f_name == 'fields' else self.custom
                    for field in f_src:
                        if isinstance(field, dict):
                            f = TypedField()
                            f.type = sanitize_str_field_value(field.get('type'))
                            f.label = sanitize_str_field_value(field.get('label'))
                            value = field.get('value')
                            if not isinstance(value, list):
                                if value:
                                    value = [value]
                                else:
                                    value = []
                            f.value = value
                            f_dst.append(f)

    def enumerate_fields(self):
        yield 'record_type', '', self.record_type
        for tup in super(TypedRecord, self).enumerate_fields():
            yield tup
        if self.notes:
            yield 'note', '', self.notes
        for field in itertools.chain(self.fields, self.custom):
            value = field.get_external_value()
            if value:
                yield field.type, field.label or '', value


class FileRecord(KeeperRecord):
    def __init__(self) -> None:
        super(FileRecord, self).__init__()
        self.file_name = ''
        self.size: Optional[int] = None
        self.mime_type = ''
        self.storage_size: Optional[int] = None

    def version(self):
        return 4

    def load_record_data(self, data, extra=None):
        self.title = sanitize_str_field_value(data.get('title'))
        self.file_name = sanitize_str_field_value(data.get('name'))
        self.size = sanitize_int_field_value(data.get('size'))
        self.mime_type = sanitize_str_field_value(data.get('type'))

    def enumerate_fields(self):
        for tup in super(FileRecord, self).enumerate_fields():
            yield tup
        yield 'file_name', '', self.file_name
        yield 'mime_type', '', self.mime_type


class ApplicationRecord(KeeperRecord):
    def __init__(self) -> None:
        super(ApplicationRecord, self).__init__()
        self.app_type = ''

    def version(self):
        return 5

    def load_record_data(self, data, extra=None):
        self.title = sanitize_str_field_value(data.get('title'))
        self.app_type = sanitize_str_field_value(data.get('type'))
