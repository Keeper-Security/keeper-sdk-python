from typing import Optional, List, Any, Set, Iterable, Dict

from .storage import (StorageRecord, StorageSharedFolder, StorageTeam, StorageRecordKey, StorageSharedFolderPermission)
from .crypto import PrivateKey

class CustomField:
    name: str
    value: str
    type: str

class ExtraField:
    id: str
    field_type: str
    field_title: str
    custom: Dict[str, Any]

class AttachmentFileThumb:
    id: str
    type: str
    size: int

class AttachmentFile:
    id: str
    key: bytes
    name: str
    title: str
    type: str
    size: int
    last_modified: int
    thumbnails: List[AttachmentFileThumb]

class PasswordRecord:
    record_uid: str
    title: str
    login: str
    password: str
    link: str
    notes: str
    custom: List[CustomField]
    attachments: List[AttachmentFile]
    extra_fields: List[ExtraField]
    owner: bool
    shared: bool
    record_key: Optional[bytes]

    def get_field(self, name: str) -> Optional[CustomField]: ...
    def set_field(self, name: str, value: str) -> CustomField: ...
    def remove_field(self, name: str) -> None: ...
    def get_extra(self, type: str) -> Optional[ExtraField]: ...
    @staticmethod
    def load(store_record: StorageRecord, record_key: bytes) -> PasswordRecord: ...
    @staticmethod
    def dump(record: PasswordRecord, extra: Optional[Dict[str, Any]] = ..., udata: Optional[Dict[str, Any]] = ...) -> Dict[str, Any]: ...


class SharedFolderPermission:
    user_type: int
    user_id: str
    manage_records: bool
    manage_users: bool

class SharedFolderRecord:
    record_uid: str
    can_share: bool
    can_edit: bool

class SharedFolder:
    shared_folder_uid: str
    name: str
    default_manage_records: bool
    default_manage_users: bool
    default_can_edit: bool
    default_can_share: bool
    shared_folder_key: Optional[bytes]
    user_permissions: List[SharedFolderPermission]
    record_permissions: List[SharedFolderRecord]
    @staticmethod
    def load(store_sf: StorageSharedFolder,
             records: Iterable[StorageRecordKey],
             users: Iterable[StorageSharedFolderPermission],
             shared_folder_key: bytes) -> SharedFolder: ...

class EnterpriseTeam:
    team_uid: str
    name: str
    restrict_edit: bool
    restrict_share: bool
    restrict_view: bool
    team_key: Optional[bytes]
    private_key: Optional[PrivateKey]
    @staticmethod
    def load(store_team: StorageTeam, team_key: bytes) -> EnterpriseTeam: ...

class Folder:
    folder_uid: str
    folder_type: str
    name: str
    parent_uid: Optional[str]
    shared_folder_uid: Optional[str]
    subfolders: Set[str]
    records: Set[str]