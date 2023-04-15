#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper SDK
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import abc
import itertools
from typing import Optional, Dict, Any, List
from dataclasses import dataclass

from . import vault_types


@dataclass(frozen=True)
class KeeperRecordInfo:
    record_uid: str
    version: int
    record_type: str
    title: str
    description: str
    client_time_modified: int
    shared: bool
    has_attachments: bool


class KeeperRecord(abc.ABC):
    def __init__(self):
        self.record_uid = ''
        self.title = ''
        self.client_time_modified = 0

    @abc.abstractmethod
    def version(self):   # type: () -> int
        pass

    @abc.abstractmethod
    def load_record_data(self, data, extra=None):  # type: (Dict[str, Any], Optional[Dict[str, Any]]) -> None
        pass

    def enumerate_fields(self):
        yield 'title', '', self.title


class CustomField:
    def __init__(self):
        self.name = ''
        self.value = ''
        self.type = ''

    @classmethod
    def create_field(cls, name, value):   # type: (str, str) -> 'CustomField'
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
    def __init__(self):
        self.id = ''
        self.key = ''
        self.name = ''
        self.title = ''
        self.mime_type = ''
        self.size = 0
        self.last_modified = 0
        self.thumbnails = []        # type: List[AttachmentFileThumb]


class PasswordRecord(KeeperRecord):
    def __init__(self):
        super(PasswordRecord, self).__init__()
        self.login = ''
        self.password = ''
        self.link = ''
        self.notes = ''
        self.custom = []            # type: List[CustomField]
        self.attachments = None     # type: Optional[List[AttachmentFile]]
        self.totp = ''

    def version(self):
        return 2

    def load_record_data(self, data, extra=None):
        self.title = data.get('title', '')
        self.login = data.get('secret1', '')
        self.password = data.get('secret2', '')
        self.link = data.get('link', '')
        self.notes = data.get('notes', '')
        custom = data.get('custom')
        if isinstance(custom, list):
            for cf in custom:
                if isinstance(cf, dict):
                    custom_field = CustomField()
                    custom_field.name = cf.get('name') or ''
                    custom_field.value = cf.get('value') or ''
                    custom_field.type = cf.get('type') or ''
                    self.custom.append(custom_field)

        if isinstance(extra, dict):
            if 'files' in extra and isinstance(extra['files'], list):
                files = extra['files']
                self.attachments = []
                for file in files:
                    if isinstance(file, dict):
                        af = AttachmentFile()
                        af.id = file.get('id') or ''
                        af.key = file.get('key') or ''
                        af.name = file.get('name') or ''
                        af.title = file.get('title') or ''
                        af.mime_type = file.get('type') or ''
                        af.size = file.get('size') or 0
                        af.last_modified = file.get('lastModified') or 0
                        thumbs = file.get('thumbnails')
                        if isinstance(thumbs, list):
                            for thumb in thumbs:
                                aft = AttachmentFileThumb()
                                if isinstance(thumb, dict):
                                    aft.id = thumb.get('id') or ''
                                    aft.type = thumb.get('type') or ''
                                    aft.size = thumb.get('size') or 0
                                thumbs.append(aft)

                        self.attachments.append(af)

            if 'fields' in extra and isinstance(extra['fields'], list):
                self.totp = next((x.get('data', '') for x in extra['fields'] if x.get('field_type') == 'totp'), '')

    def enumerate_fields(self):
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


class TypedField(object):
    def __init__(self):
        self.type = ''
        self.label = ''
        self.value = []
        self.required = False

    @classmethod
    def create_field(cls, field_type, field_label=None):
        field = cls()
        field.type = field_type
        if field_label:
            field.label = field_label
        return field

    @classmethod
    def create_schema_field(cls, record_field):   # type: (vault_types.RecordTypeField) -> 'TypedField'
        field = cls()
        field.type = record_field.type
        field.label = record_field.label or ''
        field.required = record_field.required
        return field

    def get_default_value(self, value_type=None):
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

    def get_external_value(self):
        if isinstance(self.value, list):
            if len(self.value) == 0:
                return None
            if len(self.value) == 1:
                return self.value[0]
        return self.value

    def is_equal_to(self, other_type, other_label=None):
        if other_label and self.label:
            if other_label.casefold() != self.label.casefold():
                return False
        return self.type == other_type


class TypedRecord(KeeperRecord):
    def __init__(self):
        super(TypedRecord, self).__init__()
        self.record_type = ''    # type: str
        self.notes = ''          # type: str
        self.fields = []         # type: List[TypedField]
        self.custom = []         # type: List[TypedField]
        self.linked_keys = None  # type: Optional[Dict[str, bytes]]

    def version(self):
        return 3

    def get_typed_field(self, field_type, field_label=None):    # type: (str, Optional[str]) -> Optional[TypedField]
        return next((x for x in itertools.chain(self.fields, self.custom)
                     if x.is_equal_to(field_type, field_label)), None)

    def load_record_data(self, data, extra=None):
        if isinstance(data, dict):
            self.record_type = data.get('type') or ''
            self.title = data.get('title') or ''
            self.notes = data.get('notes') or ''
            self.fields.clear()
            for f_name in ('fields', 'custom'):
                f_src = data.get(f_name)
                if isinstance(f_src, list):
                    f_dst = self.fields if f_name == 'fields' else self.custom
                    for field in f_src:
                        if isinstance(field, dict):
                            f = TypedField()
                            f.type = field.get('type') or ''
                            f.label = field.get('label') or ''
                            f.value = field.get('value') or []
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
    def __init__(self):
        super(FileRecord, self).__init__()
        self.file_name = ''        # type: str
        self.size = None           # type: Optional[int]
        self.mime_type = ''        # type: str
        self.storage_size = None   # type: Optional[int]

    def version(self):
        return 4

    def load_record_data(self, data, extra=None):
        self.title = data.get('title', '')
        self.file_name = data.get('name', '')
        self.size = data.get('size')
        self.mime_type = data.get('type', '')

    def enumerate_fields(self):
        for tup in super(FileRecord, self).enumerate_fields():
            yield tup
        yield 'file_name', '', self.file_name
        yield 'mime_type', '', self.mime_type


class ApplicationRecord(KeeperRecord):
    def __init__(self):
        super(ApplicationRecord, self).__init__()
        self.app_type = ''

    def version(self):
        return 5

    def load_record_data(self, data, extra=None):
        self.title = data.get('title') or ''
        self.app_type = data.get('type') or ''
