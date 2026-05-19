from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class KeeperDriveOwnerInfo:
    account_uid: str
    username: str


@dataclass
class KeeperDriveEncryptedKey:
    encrypted_key: str
    encrypted_key_type: int


@dataclass
class KeeperDriveFolderPermissions:
    can_add: bool
    can_remove: bool
    can_delete: bool
    can_list_access: bool
    can_update_access: bool
    can_change_ownership: bool
    can_edit_records: bool
    can_view_records: bool
    can_approve_access: bool
    can_request_access: bool
    can_update_setting: bool
    can_list_records: bool
    can_list_folders: bool


@dataclass
class KeeperDriveFolder:
    folder_uid: str
    parent_uid: str
    data: str
    type: int
    inherit_user_permissions: int
    folder_key: str
    owner_info: KeeperDriveOwnerInfo
    date_created: int
    last_modified: int


@dataclass
class KeeperDriveFolderKey:
    folder_uid: str
    parent_uid: str
    folder_key: str
    encrypted_by: int


@dataclass
class KeeperDriveFolderAccess:
    folder_uid: str
    access_type_uid: str
    access_type: int
    access_role_type: int
    folder_key: Optional[KeeperDriveEncryptedKey]
    inherited: bool
    hidden: bool
    permissions: Optional[KeeperDriveFolderPermissions]
    tla_properties: Optional[Any]
    date_created: int
    last_modified: int
    denied_access: bool


@dataclass
class KeeperDriveRecordUser:
    account_uid: str
    username: str


@dataclass
class KeeperDriveRecordData:
    user: KeeperDriveRecordUser
    data: str
    record_uid: str


@dataclass
class KeeperDriveRecordAccess:
    access_type_uid: str
    access_type: int
    record_uid: str
    access_role_type: int
    owner: bool
    inherited: bool
    hidden: bool
    denied_access: bool
    can_view_title: bool
    can_edit: bool
    can_view: bool
    can_list_access: bool
    can_update_access: bool
    can_delete: bool
    can_change_ownership: bool
    can_request_access: bool
    can_approve_access: bool
    date_created: int
    last_modified: int
    tla_properties: Optional[Any]


@dataclass
class KeeperDriveRecordLink:
    parent_record_uid: str
    child_record_uid: str
    record_key: str
    revision: int


@dataclass
class KeeperDriveBreachWatchRecord:
    record_uid: str
    data: str
    type: int
    scanned_by: str
    revision: int
    scanned_by_account_uid: str


@dataclass
class KeeperDriveSecurityScoreData:
    record_uid: str
    data: str
    revision: int


@dataclass
class KeeperDriveBreachWatchSecurityData:
    record_uid: str
    revision: int
    removed: bool


@dataclass
class KeeperDriveRecordMetadata:
    record_uid: str
    encrypted_record_key: str
    encrypted_record_key_type: int
    tla_properties: Optional[Any]


@dataclass
class KeeperDriveFolderRecord:
    folder_uid: str
    record_metadata: KeeperDriveRecordMetadata
    folder_key_encryption_type: int


@dataclass
class KeeperDriveRecordSummary:
    record_uid: str
    revision: int
    version: int
    shared: bool
    client_modified_time: int
    file_size: int
    thumbnail_size: int


@dataclass
class KeeperDriveData:
    folders: List[KeeperDriveFolder] = field(default_factory=list)
    folder_keys: List[KeeperDriveFolderKey] = field(default_factory=list)
    folder_accesses: List[KeeperDriveFolderAccess] = field(default_factory=list)
    record_data: List[KeeperDriveRecordData] = field(default_factory=list)
    non_shared_data: List[Dict[str, Any]] = field(default_factory=list)
    record_accesses: List[KeeperDriveRecordAccess] = field(default_factory=list)
    record_sharing_states: List[Any] = field(default_factory=list)
    record_links: List[KeeperDriveRecordLink] = field(default_factory=list)
    breach_watch_records: List[KeeperDriveBreachWatchRecord] = field(default_factory=list)
    security_score_data: List[KeeperDriveSecurityScoreData] = field(default_factory=list)
    breach_watch_security_data: List[KeeperDriveBreachWatchSecurityData] = field(default_factory=list)
    folder_records: List[KeeperDriveFolderRecord] = field(default_factory=list)
    record_rotation_data: List[Any] = field(default_factory=list)
    records: List[KeeperDriveRecordSummary] = field(default_factory=list)
    folder_sharing_state: List[Any] = field(default_factory=list)
    raw_dag_data: List[Any] = field(default_factory=list)
