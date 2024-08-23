from dataclasses import dataclass
from typing import List, Optional, Set, Literal

from cryptography.hazmat.primitives.asymmetric import rsa, ec

from . import record_types
from .storage_types import (    SharedFolderUserType, RecordTypeScope    )


@dataclass(frozen=True)
class RecordPath:
    folder_uid: str
    record_uid: str


@dataclass(frozen=True)
class SharedFolderInfo:
    shared_folder_uid: str
    name: str
    teams: int = 0
    users: int = 0
    records: int = 0


class SharedFolderRecord:
    def __init__(self) -> None:
        self.record_uid = ''
        self.can_edit = False
        self.can_share = False


class SharedFolderPermission:
    def __init__(self) -> None:
        self.user_type: int = SharedFolderUserType.User
        self.user_uid = ''
        self.manage_records = False
        self.manage_users = False
        self.name: Optional[str] = None


class SharedFolder:
    def __init__(self) -> None:
        self.shared_folder_uid = ''
        self.name = ''
        self.default_manage_records = False
        self.default_manage_users = False
        self.default_can_edit = False
        self.default_can_share = False
        self.user_permissions: List[SharedFolderPermission] = []
        self.record_permissions: List[SharedFolderRecord] = []


@dataclass(frozen=True)
class TeamInfo:
    team_uid: str
    name: str


@dataclass(frozen=True)
class UserInfo:
    account_uid: str
    username: str


@dataclass(frozen=True)
class BreachWatchInfo:
    record_uid: str
    status: int
    resolved: int
    total: int


class Team:
    def __init__(self) -> None:
        self.team_uid = ''
        self.name = ''
        self.restrict_edit = False
        self.restrict_share = False
        self.restrict_view = False
        self.rsa_private_key: Optional[rsa.RSAPrivateKey] = None
        self.ec_private_key: Optional[ec.EllipticCurvePrivateKey] = None


FolderTypes = Literal['user_folder', 'shared_folder', 'shared_folder_folder']
class Folder:
    def __init__(self) -> None:
        self.folder_uid = ''
        self.folder_type: FolderTypes = 'user_folder'
        self.folder_key = b''
        self.name = ''
        self.parent_uid: Optional[str] = None
        self.folder_scope_uid: Optional[str] = None
        self.subfolders: Set[str] = set()
        self.records: Set[str] = set()


class RecordTypeField(record_types.ITypedField):
    def __init__(self):
        self.type = ''
        self.label = ''
        self.required = False

    def field_type(self) -> str:
        return self.type

    def field_label(self) -> str:
        return self.label


class RecordType:
    def __init__(self) -> None:
        self.id = 0
        self.scope: int = RecordTypeScope.Standard
        self.name = ''
        self.description = ''
        self.fields: List[RecordTypeField] = []
