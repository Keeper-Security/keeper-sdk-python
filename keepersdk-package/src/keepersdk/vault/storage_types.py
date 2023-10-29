import abc
import enum
from dataclasses import dataclass
from typing import Iterable

from ..storage.types import IUid, IUidLink

@dataclass
class UserSettings:
    continuation_token: bytes = b''
    profile_data: bytes = b''
    profile_name: str = ''
    profile_url: str = ''


class KeyType:
    DataKey = 1             # AES GSM: user client key
    RsaPrivateKey = 2       # RSA: user RSA key
    EcPrivateKey = 3        # EC: user ECC key
    SharedFolderKey = 5     # AES GSM: shared folder key
    TeamKey = 5             # AES GSM: team key
    TeamRsaPrivateKey = 6   # RSA: team rsa private key
    RecordKey = 7           # AES GSM: record key


class StorageRecord(IUid):
    def __init__(self) -> None:
        self.record_uid = ''
        self.revision = 0
        self.version = 0
        self.client_modified_time = 0
        self.data = b''
        self.extra = b''
        self.udata = ''
        self.shared = False
        self.owner = False
        self.owner_account_id = b''

    def uid(self):
        return self.record_uid


class StorageNonSharedData(IUid):
    def __init__(self) -> None:
        self.record_uid = ''
        self.data = b''

    def uid(self):
        return self.record_uid


class StorageSharedFolder(IUid):
    def __init__(self) -> None:
        self.shared_folder_uid = ''
        self.revision = 0
        self.name = b''
        self.data = b''
        self.owner_account_uid = ''
        self.default_manage_records = False
        self.default_manage_users = False
        self.default_can_edit = False
        self.default_can_share = False

    def uid(self):
        return self.shared_folder_uid


class StorageFolder(IUid):
    def __init__(self) -> None:
        self.folder_uid = ''
        self.parent_uid = ''
        self.folder_type = ''
        self.folder_key = b''
        self.shared_folder_uid = ''
        self.revision = 0
        self.data = b''

    def uid(self):
        return self.folder_uid


@dataclass
class StorageUserEmail(IUidLink):
    account_uid: str = ''
    email: str = ''

    def subject_uid(self):
        return self.account_uid

    def object_uid(self):
        return self.email


@dataclass
class StorageTeam(IUid):
    team_uid = ''
    name = ''
    team_key = b''
    key_type = 0
    team_private_key = b''
    restrict_edit = False
    restrict_share = False
    restrict_view = False

    def uid(self):
        return self.team_uid


class StorageRecordKey(IUidLink):
    def __init__(self) -> None:
        self.record_uid = ''
        # TODO rename to owner UID
        self.shared_folder_uid = ''
        self.key_type = KeyType.DataKey
        self.record_key = b''
        self.can_share = False
        self.can_edit = False
        self.owner_account_uid = ''

    def subject_uid(self):
        return self.record_uid

    def object_uid(self):
        return self.shared_folder_uid


class StorageSharedFolderKey(IUidLink):
    def __init__(self) -> None:
        self.shared_folder_uid = ''
        self.team_uid = ''
        self.key_type = 0
        self.shared_folder_key = b''

    def subject_uid(self):
        return self.shared_folder_uid

    def object_uid(self):
        return self.team_uid


class SharedFolderUserType:
    User = 1
    Team = 2


class StorageSharedFolderPermission(IUidLink):
    def __init__(self) -> None:
        self.shared_folder_uid = ''
        self.user_uid = ''
        self.user_type = 0
        self.manage_records = False
        self.manage_users = False
        self.expiration = 0

    def subject_uid(self):
        return self.shared_folder_uid

    def object_uid(self):
        return self.user_uid


class StorageFolderRecordLink(IUidLink):
    def __init__(self) -> None:
        self.folder_uid = ''
        self.record_uid = ''

    def subject_uid(self):
        return self.folder_uid

    def object_uid(self):
        return self.record_uid


class BreachWatchRecord(IUid):
    def __init__(self) -> None:
        self.record_uid = ''
        self.data = b''
        self.type = 0
        self.revision = 0

    def uid(self):
        return self.record_uid


class RecordTypeScope:
    Standard = 0
    User = 1
    Enterprise = 2


class StorageRecordType(IUid):
    def __init__(self) -> None:
        self.id = 0
        self.scope: int = RecordTypeScope.Standard
        self.content = ''

    def uid(self):
        return self.id


class PendingShareAction(enum.Enum):
    ACCEPT = 1
    DENY = 2
    IGNORE = 3


class IPendingShares(abc.ABC):
    @abc.abstractmethod
    def pending_shares(self) -> Iterable[str]:
        pass

    @abc.abstractmethod
    def set_pending_shares(self, shares: Iterable[str]) -> None:
        pass

    @abc.abstractmethod
    def resolve_pending_shares(self, shares: Iterable[str], action: PendingShareAction) -> None:
        pass

