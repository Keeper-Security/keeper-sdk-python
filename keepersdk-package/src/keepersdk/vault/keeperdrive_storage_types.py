from __future__ import annotations

from dataclasses import dataclass

from ..storage.storage_types import IUid, IUidLink


@dataclass
class KeeperDriveSettings:
    continuation_token: bytes = b''


@dataclass
class KDFolder(IUid):
    folder_uid: str = ''
    parent_uid: str = ''
    data: str = ''
    folder_type: int = 0
    inherit_user_permissions: int = 0
    folder_key: str = ''
    owner_account_uid: str = ''
    owner_username: str = ''
    date_created: int = 0
    last_modified: int = 0

    def uid(self) -> str:
        return self.folder_uid


@dataclass
class KDFolderKey(IUidLink[str, str]):
    folder_uid: str = ''
    parent_uid: str = ''
    folder_key: str = ''
    encrypted_by: int = 0

    def subject_uid(self) -> str:
        return self.folder_uid

    def object_uid(self) -> str:
        return self.parent_uid


@dataclass
class KDFolderAccess(IUidLink[str, str]):
    folder_uid: str = ''
    access_type_uid: str = ''
    access_type: int = 0
    access_role_type: int = 0
    folder_key_encrypted: str = ''
    folder_key_type: int = 0
    inherited: bool = False
    hidden: bool = False
    denied_access: bool = False
    permissions_json: str = ''
    tla_properties_json: str = ''
    date_created: int = 0
    last_modified: int = 0

    def subject_uid(self) -> str:
        return self.folder_uid

    def object_uid(self) -> str:
        return self.access_type_uid


@dataclass
class KDRecordData(IUid):
    record_uid: str = ''
    account_uid: str = ''
    username: str = ''
    data: str = ''

    def uid(self) -> str:
        return self.record_uid


@dataclass
class KDNonSharedData(IUid):
    record_uid: str = ''
    data: str = ''

    def uid(self) -> str:
        return self.record_uid


@dataclass
class KDRecordAccess(IUidLink[str, str]):
    record_uid: str = ''
    access_type_uid: str = ''
    access_type: int = 0
    access_role_type: int = 0
    owner: bool = False
    inherited: bool = False
    hidden: bool = False
    denied_access: bool = False
    can_view_title: bool = False
    can_edit: bool = False
    can_view: bool = False
    can_list_access: bool = False
    can_update_access: bool = False
    can_delete: bool = False
    can_change_ownership: bool = False
    can_request_access: bool = False
    can_approve_access: bool = False
    date_created: int = 0
    last_modified: int = 0
    tla_properties_json: str = ''

    def subject_uid(self) -> str:
        return self.record_uid

    def object_uid(self) -> str:
        return self.access_type_uid


@dataclass
class KDRecordLink(IUidLink[str, str]):
    parent_record_uid: str = ''
    child_record_uid: str = ''
    record_key: str = ''
    revision: int = 0

    def subject_uid(self) -> str:
        return self.parent_record_uid

    def object_uid(self) -> str:
        return self.child_record_uid


@dataclass
class KDBreachWatchRecord(IUid):
    record_uid: str = ''
    data: str = ''
    type: int = 0
    scanned_by: str = ''
    revision: int = 0
    scanned_by_account_uid: str = ''

    def uid(self) -> str:
        return self.record_uid


@dataclass
class KDSecurityScoreData(IUid):
    record_uid: str = ''
    data: str = ''
    revision: int = 0

    def uid(self) -> str:
        return self.record_uid


@dataclass
class KDBreachWatchSecurityData(IUid):
    record_uid: str = ''
    revision: int = 0
    removed: bool = False

    def uid(self) -> str:
        return self.record_uid


@dataclass
class KDFolderRecord(IUidLink[str, str]):
    folder_uid: str = ''
    record_uid: str = ''
    encrypted_record_key: str = ''
    encrypted_record_key_type: int = 0
    folder_key_encryption_type: int = 0
    tla_properties_json: str = ''

    def subject_uid(self) -> str:
        return self.folder_uid

    def object_uid(self) -> str:
        return self.record_uid


@dataclass
class KDRecordSummary(IUid):
    record_uid: str = ''
    revision: int = 0
    version: int = 0
    shared: bool = False
    client_modified_time: int = 0
    file_size: int = 0
    thumbnail_size: int = 0

    def uid(self) -> str:
        return self.record_uid


@dataclass
class KDListChunk(IUidLink[str, str]):
    chunk_group: str = ''
    chunk_key: str = ''
    payload_json: str = ''

    def subject_uid(self) -> str:
        return self.chunk_group

    def object_uid(self) -> str:
        return self.chunk_key
