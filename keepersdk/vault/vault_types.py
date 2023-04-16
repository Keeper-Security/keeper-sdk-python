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

import json
from typing import List, Optional, Set, Iterable, Sequence, Literal
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import rsa

from .storage_types import (
    StorageSharedFolder, StorageRecordKey, StorageSharedFolderPermission, SharedFolderUserType, RecordTypeScope,
    StorageTeam, StorageRecordType)
from .. import crypto, utils


@dataclass(frozen=True)
class RecordPath:
    record_uid: str
    folder_uid: str


@dataclass(frozen=True)
class SharedFolderInfo:
    shared_folder_uid: str
    name: str
    teams: int = 0
    users: int = 0
    records: int = 0


class SharedFolderRecord:
    def __init__(self):              # type: () -> None
        self.record_uid = ''         # type: str
        self.can_edit = False        # type: bool
        self.can_share = False       # type: bool


class SharedFolderPermission:
    def __init__(self):                             # type: () -> None
        self.user_id = ''                           # type: str
        self.user_type = SharedFolderUserType.User  # type: int
        self.manage_records = False                 # type: bool
        self.manage_users = False                   # type: bool


class SharedFolder:
    def __init__(self):                        # type: () -> None
        self.shared_folder_uid = ''            # type: str
        self.name = ''                         # type: str
        self.default_manage_records = False    # type: bool
        self.default_manage_users = False      # type: bool
        self.default_can_edit = False          # type: bool
        self.default_can_share = False         # type: bool
        self.user_permissions = []             # type: List[SharedFolderPermission]
        self.record_permissions = []           # type: List[SharedFolderRecord]

    @staticmethod
    def load(store_sf,     # type: StorageSharedFolder
             records,      # type: Iterable[StorageRecordKey]
             users,        # type: Iterable[StorageSharedFolderPermission]
             shared_folder_key  # type: bytes
             ):            # type: (...) -> SharedFolder
        shared_folder_uid = store_sf.shared_folder_uid
        shared_folder = SharedFolder()
        shared_folder.shared_folder_uid = shared_folder_uid
        shared_folder.default_manage_records = store_sf.default_manage_records
        shared_folder.default_manage_users = store_sf.default_manage_users
        shared_folder.default_can_edit = store_sf.default_can_edit
        shared_folder.default_can_share = store_sf.default_can_share
        if store_sf.data:
            try:
                decrypted_data = crypto.decrypt_aes_v1(store_sf.data, shared_folder_key)
                data = json.loads(decrypted_data.decode())
                if 'name' in data:
                    shared_folder.name = data['name']
            except Exception as e:
                utils.get_logger().debug('Error decrypting Shared Folder %s data: %s', shared_folder_uid, e)
        if not shared_folder.name:
            try:
                dec_name = crypto.decrypt_aes_v1(store_sf.name, shared_folder_key)
                shared_folder.name = dec_name.decode('utf-8')
            except Exception as e:
                utils.get_logger().debug('Error decrypting Shared Folder %s name: %s', shared_folder_uid, e)
        if not shared_folder.name:
            shared_folder.name = shared_folder_uid
        for up in users:
            sf_p = SharedFolderPermission()
            sf_p.user_type = up.user_type
            sf_p.user_id = up.user_uid
            sf_p.manage_records = up.manage_records
            sf_p.manage_users = up.manage_users
            shared_folder.user_permissions.append(sf_p)

        for rp in records:
            sf_r = SharedFolderRecord()
            sf_r.record_uid = rp.record_uid
            sf_r.can_edit = rp.can_edit
            sf_r.can_share = rp.can_share
            shared_folder.record_permissions.append(sf_r)

        return shared_folder


@dataclass(frozen=True)
class TeamInfo:
    team_uid: str
    name: str


class Team:
    def __init__(self):               # type: () -> None
        self.team_uid = ''            # type: str
        self.name = ''                # type: str
        self.restrict_edit = False    # type: bool
        self.restrict_share = False   # type: bool
        self.restrict_view = False    # type: bool
        self.rsa_private_key = None   # type: Optional[rsa.RSAPrivateKey]

    @staticmethod
    def load(store_team, team_key):   # type: (StorageTeam, bytes) -> Team
        team = Team()
        team.team_uid = store_team.team_uid
        team.name = store_team.name
        team.restrict_edit = store_team.restrict_edit
        team.restrict_view = store_team.restrict_view
        team.restrict_share = store_team.restrict_share
        private_key = crypto.decrypt_aes_v1(store_team.team_private_key, team_key)
        team.rsa_private_key = crypto.load_rsa_private_key(private_key)
        return team


FolderType = Literal['user_folder', 'shared_folder', 'shared_folder_folder']


class Folder:
    def __init__(self):                   # type: () -> None
        self.folder_uid = ''              # type: str
        self.folder_type = 'user_folder'  # type: FolderType
        self.folder_key = b''             # type: bytes
        self.name = ''                    # type: str
        self.parent_uid = None            # type: Optional[str]
        self.folder_scope_uid = None      # type: Optional[str]
        self.subfolders = set()           # type: Set[str]
        self.records = set()              # type: Set[str]


class RecordTypeField:
    def __init__(self):
        self.type = ''
        self.label = ''
        self.required = False


class RecordType:
    def __init__(self):        # type: () -> None
        self.id = 0
        self.scope = RecordTypeScope.Standard
        self.name = ''
        self.description = ''
        self.fields = []       # type: Sequence[RecordTypeField]

    @classmethod
    def load(cls, store_record_type):   # type: (StorageRecordType) -> RecordType
        record_type = cls()
        record_type.id = store_record_type.id
        record_type.scope = store_record_type.scope
        content = json.loads(store_record_type.content)
        record_type.name = content.get('$id', '')
        record_type.description = content.get('description', '')
        fields = content.get('fields')
        if isinstance(fields, list):
            rfs = []                    # List[RecordTypeField]
            for field in fields:
                record_field = RecordTypeField()
                record_field.type = field.get('$ref', '')
                record_field.label = field.get('label', '')
                record_field.required = field.get('required', False)
                rfs.append(record_field)

            record_type.fields = rfs
        return record_type
