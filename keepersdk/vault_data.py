#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2019 Keeper Security Inc.
# Contact: ops@keepersecurity.coms
#
from typing import Dict, Optional, NoReturn, Iterable

import json
import logging

from .vault_types import PasswordRecord, SharedFolder, Team, Folder, RecordPermission
from .storage import KeeperStorage
from .vault_types import PersonalFolderUid
from . import crypto, utils


class VaultData:
    def __init__(self, storage):    # type: (KeeperStorage) -> NoReturn
        self.storage = storage      # type: KeeperStorage
        self.records = {}           # type: Dict[str, PasswordRecord]
        self.shared_folders = {}    # type: Dict[str, SharedFolder]
        self.teams = {}             # type: Dict[str, Team]
        self.folders = {}           # type: Dict[str, Folder]
        self.root_folder = None     # type: Optional[Folder]

    def get_record(self, record_uid):
        # type: (str) -> Optional[PasswordRecord]
        return self.records.get(record_uid) if record_uid else None

    def get_all_records(self):
        # type: () -> Iterable[PasswordRecord]
        for record in self.records.values():
            yield record

    def get_shared_folder(self, shared_folder_uid):
        # type: (str) -> Optional[SharedFolder]
        return self.shared_folders.get(shared_folder_uid) if shared_folder_uid else None

    def get_all_shared_folders(self):
        # type: () -> Iterable[SharedFolder]
        for shared_folder in self.shared_folders.values():
            yield shared_folder

    def get_team(self, team_uid):
        # type: (str) -> Optional[Team]
        return self.teams.get(team_uid) if team_uid else None

    def get_all_teams(self):
        # type: () -> Iterable[Team]
        for team in self.teams.values():
            yield team

    def get_folder(self, folder_uid):
        # type: (str) -> Optional[Folder]
        return self.folders.get(folder_uid) if folder_uid else None

    def get_all_folders(self):
        # type: () -> Iterable[Folder]
        for folder in self.folders.values():
            yield folder

    def get_root_folder(self):
        # type: () -> Optional[Folder]
        return self.root_folder

    def build_folders(self):
        self.folders.clear()
        self.root_folder = Folder(PersonalFolderUid)
        self.root_folder.name = 'My Vault'
        self.root_folder.folder_type = 'user_folder'
        self.folders[self.root_folder.folder_uid] = self.root_folder
        for folder_dict in self.storage.folders.get_all_folders():
            folder = Folder(folder_dict['folder_uid'])
            folder.parent_uid = folder_dict['parent_uid']
            folder.shared_folder_uid = folder_dict.get('shared_folder_uid')
            folder.folder_type = folder_dict['type']
            try:
                if folder.folder_type in {'user_folder', 'shared_folder_folder'}:
                    key = utils.base64_url_decode(folder_dict['folder_key'])
                    if folder.folder_type == 'user_folder':
                        encryption_key = self.storage.client_key
                    else:
                        encryption_key = self.shared_folders[folder.shared_folder_uid].shared_folder_key
                    key = crypto.decrypt_aes_v1(key, encryption_key)
                    data = utils.base64_url_decode(folder_dict['data'])
                    data = crypto.decrypt_aes_v1(data, key)
                    data_dict = json.loads(data.decode('utf-8'))
                    folder.name = data_dict.get('name') or folder.folder_uid
                elif folder.folder_type == 'shared_folder':
                    folder.name = self.shared_folders[folder.folder_uid].name
            except Exception as e:
                folder.name = folder.folder_uid
                logging.debug('Folder %s name decrypt error: %s', folder.folder_uid, e)

            self.folders[folder.folder_uid] = folder
        for (record_uid, folder_uid) in self.storage.folders.get_all_records():
            if folder_uid in self.folders:
                self.folders[folder_uid].records.add(record_uid)
        for folder in self.folders.values():
            if folder.parent_uid:
                if folder.parent_uid in self.folders:
                    self.folders[folder.parent_uid].subfolders.add(folder.folder_uid)

    def full_rebuild(self):
        self.records.clear()
        self.shared_folders.clear()
        self.teams.clear()
        for t in self.storage.teams.get_all():
            team_uid = None
            try:
                team_uid = t['team_uid']
                team_key = utils.base64_url_decode(t['team_key'])
                team_key = crypto.decrypt_aes_v1(team_key, self.storage.client_key)
                team = Team.parse(t, team_key)
                self.teams[team.team_uid] = team
            except Exception as e:
                logging.warning('Error loading Team UID %s: %s', team_uid, e)

        uids_to_delete = set()

        uids_to_delete.clear()
        for sf in self.storage.shared_folders.get_all():
            shared_folder_uid = None
            try:
                shared_folder_uid = sf['shared_folder_uid']
                shared_folder_key = None
                if 'shared_folder_key' in sf:
                    key = utils.base64_url_decode(sf['shared_folder_key'])
                    shared_folder_key = crypto.decrypt_aes_v1(key, self.storage.client_key)
                elif 'teams' in sf:
                    for sft in sf['teams']:
                        team_uid = sft['team_uid']
                        if team_uid in self.teams:
                            team = self.teams[team_uid]
                            if shared_folder_uid in team.shared_folder_keys:
                                shared_folder_key = team.shared_folder_keys[shared_folder_uid]
                                break
                if shared_folder_key:
                    shared_folder = SharedFolder.parse(sf, shared_folder_key)
                    self.shared_folders[shared_folder.shared_folder_uid] = shared_folder
                else:
                    uids_to_delete.add(shared_folder_uid)
            except Exception as e:
                logging.warning('Error loading Shared Folder UID %s: %s', shared_folder_uid, e)
        for shared_folder_uid in uids_to_delete:
            self.storage.shared_folders.delete(shared_folder_uid)

        uids_to_delete.clear()
        for r in self.storage.records.get_all():
            record_uid = None
            try:
                record_uid = r['record_uid']
                meta_data = self.storage.metadata.get(record_uid)
                record_key = None
                if meta_data:
                    key = utils.base64_url_decode(meta_data['record_key'])
                    record_key = crypto.decrypt_aes_v1(key, self.storage.client_key)
                else:
                    for shared_folder in self.shared_folders.values():
                        if record_uid in shared_folder.record_keys:
                            record_key = shared_folder.record_keys[record_uid]
                            break
                if record_key:
                    record = PasswordRecord.load(r, record_key)
                    if meta_data:
                        record.owner = meta_data['owner']
                        permission = RecordPermission()
                        permission.can_edit = meta_data['can_edit']
                        permission.can_share = meta_data['can_share']
                        record.permissions.append(permission)
                    self.records[record_uid] = record
                else:
                    uids_to_delete.add(record_uid)
            except Exception as e:
                logging.warning('Error loading Record UID %s: %s', record_uid, e)
        for record_uid in uids_to_delete:
            self.storage.records.delete(record_uid)

        # record's shared folder permissions
        for shared_folder in self.shared_folders.values():
            for record_uid in shared_folder.record_permissions:
                if record_uid in self.records:
                    record = self.records[record_uid]
                    record.permissions.append(shared_folder.record_permissions[record_uid])

