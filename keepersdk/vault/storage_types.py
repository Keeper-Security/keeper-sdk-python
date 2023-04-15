#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

from dataclasses import dataclass

from ..storage.types import IUid, IUidLink


class KeyType:
    DataKey = 1             # AES GSM: user client key
    RsaPrivateKey = 2       # RSA: user RSA key
    SharedFolderKey = 3     # AES GSM: shared folder key
    TeamKey = 4             # AES GSM: team key
    TeamRsaPrivateKey = 5   # RSA: team rsa private key
    RecordKey = 6           # AES GSM: record key
    EcPrivateKey = 7        # EC: user ECC key


class StorageRecord(IUid):
    def __init__(self):
        self.record_uid = ''
        self.revision = 0
        self.version = 0
        self.client_modified_time = 0
        self.data = b''
        self.extra = b''
        self.udata = ''
        self.shared = False
        self.owner = False

    def uid(self):
        return self.record_uid


class StorageNonSharedData(IUid):
    def __init__(self):
        self.record_uid = ''
        self.data = b''

    def uid(self):
        return self.record_uid


class StorageSharedFolder(IUid):
    def __init__(self):
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
    def __init__(self):
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
    def __init__(self):
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
    def __init__(self):
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
    def __init__(self):
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
    def __init__(self):
        self.folder_uid = ''
        self.record_uid = ''

    def subject_uid(self):
        return self.folder_uid

    def object_uid(self):
        return self.record_uid


class BreachWatchRecord(IUid):
    def __init__(self):
        self.record_uid = ''      # type: str
        self.data = b''           # type: bytes
        self.type = ''            # type: str
        self.revision = 0         # type: int

    def uid(self):
        return self.record_uid


class RecordTypeScope:
    Standard = 0
    User = 1
    Enterprise = 2


class StorageRecordType(IUid):
    def __init__(self):
        self.id = 0                            # type: int
        self.scope = RecordTypeScope.Standard  # type: int
        self.content = ''                      # type: str

    def uid(self):
        return self.id
