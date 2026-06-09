from __future__ import annotations

from dataclasses import dataclass

from ..storage.storage_types import IUid, IUidLink


@dataclass
class NSFSettings:
    continuation_token: bytes = b''


@dataclass
class NSFFolder(IUid):
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
class NSFFolderKey(IUidLink[str, str]):
    folder_uid: str = ''
    parent_uid: str = ''
    folder_key: str = ''
    encrypted_by: int = 0

    def subject_uid(self) -> str:
        return self.folder_uid

    def object_uid(self) -> str:
        return self.parent_uid


@dataclass
class NSFRecord(IUid):
    record_uid: str = ''
    revision: int = 0
    version: int = 0
    shared: bool = False
    client_modified_time: int = 0
    file_size: int = 0
    thumbnail_size: int = 0
    data: str = ''

    def uid(self) -> str:
        return self.record_uid


@dataclass
class NSFRecordKey(IUidLink[str, str]):
    record_uid: str = ''
    folder_uid: str = ''
    record_key: str = ''
    record_key_type: int = 0
    folder_key_encryption_type: int = 0

    def subject_uid(self) -> str:
        return self.record_uid

    def object_uid(self) -> str:
        return self.folder_uid


@dataclass
class NSFFolderAccess(IUidLink[str, str]):
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
class NSFRecordAccess(IUidLink[str, str]):
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
class NSFRecordLink(IUidLink[str, str]):
    parent_record_uid: str = ''
    child_record_uid: str = ''
    record_key: str = ''
    revision: int = 0

    def subject_uid(self) -> str:
        return self.parent_record_uid

    def object_uid(self) -> str:
        return self.child_record_uid


@dataclass
class NSFFolderRecord(IUidLink[str, str]):
    folder_uid: str = ''
    record_uid: str = ''

    def subject_uid(self) -> str:
        return self.folder_uid

    def object_uid(self) -> str:
        return self.record_uid


@dataclass
class NSFFolderSharingState(IUid):
    folder_uid: str = ''
    shared: bool = False
    count: int = 0

    def uid(self) -> str:
        return self.folder_uid


@dataclass
class NSFRecordSharingState(IUid):
    record_uid: str = ''
    is_directly_shared: bool = False
    is_indirectly_shared: bool = False
    is_shared: bool = False

    def uid(self) -> str:
        return self.record_uid


@dataclass
class NSFNonSharedData(IUid):
    record_uid: str = ''
    data: str = ''

    def uid(self) -> str:
        return self.record_uid


@dataclass
class NSFBreachWatchRecord(IUid):
    record_uid: str = ''
    data: str = ''
    type: int = 0
    scanned_by: str = ''
    revision: int = 0
    scanned_by_account_uid: str = ''

    def uid(self) -> str:
        return self.record_uid


@dataclass
class NSFSecurityScoreData(IUid):
    record_uid: str = ''
    data: str = ''
    revision: int = 0

    def uid(self) -> str:
        return self.record_uid


@dataclass
class NSFBreachWatchSecurityData(IUid):
    record_uid: str = ''
    revision: int = 0
    removed: bool = False

    def uid(self) -> str:
        return self.record_uid


@dataclass
class NSFListChunk(IUidLink[str, str]):
    chunk_group: str = ''
    chunk_key: str = ''
    payload_json: str = ''

    def subject_uid(self) -> str:
        return self.chunk_group

    def object_uid(self) -> str:
        return self.chunk_key
