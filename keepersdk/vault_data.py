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

import json
import logging

from .vault_types import PasswordRecord, SharedFolder, EnterpriseTeam, Folder
from . import crypto, utils


class RebuildTask:
    def __init__(self, is_full_sync):
        self.is_full_sync = is_full_sync
        self.records = set()
        self.shared_folders = set()

    def add_record(self, record_uid):
        if not self.is_full_sync:
            self.records.add(record_uid)

    def add_shared_folder(self, shared_folder_uid):
        if not self.is_full_sync:
            self.shared_folders.add(shared_folder_uid)


class VaultData:
    def __init__(self, client_key, storage):
        self.storage = storage
        self.client_key = client_key
        self.records = {}
        self.shared_folders = {}
        self.teams = {}
        self.folders = {}
        self._root_folder = Folder()
        self._root_folder.name = 'My Vault'
        self._root_folder.folder_type = 'user_folder'

    def get_record(self, record_uid):
        return self.records.get(record_uid) if record_uid else None

    def get_all_records(self):
        for record in self.records.values():
            yield record

    @property
    def record_count(self):
        return len(self.records)

    def get_shared_folder(self, shared_folder_uid):
        return self.shared_folders.get(shared_folder_uid) if shared_folder_uid else None

    def get_all_shared_folders(self):
        for shared_folder in self.shared_folders.values():
            yield shared_folder

    @property
    def shared_folder_count(self):
        return len(self.shared_folders)

    def get_team(self, team_uid):
        return self.teams.get(team_uid) if team_uid else None

    def get_all_teams(self):
        for team in self.teams.values():
            yield team

    @property
    def team_count(self):
        return len(self.teams)

    def get_folder(self, folder_uid):
        return self.folders.get(folder_uid) if folder_uid else None

    def get_all_folders(self):
        for folder in self.folders.values():
            yield folder

    @property
    def root_folder(self):
        return self._root_folder

    def rebuild_data(self, changes):   # type: (RebuildTask) -> None
        full_rebuild = not changes or changes.is_full_sync

        self.teams.clear()
        for t in self.storage.teams.get_all():
            team_uid = None
            try:
                team_key = utils.base64_url_decode(t.team_key)
                team_key = crypto.decrypt_aes_v1(team_key, self.client_key)
                team = EnterpriseTeam.load(t, team_key)
                self.teams[team.team_uid] = team
            except Exception as e:
                logging.warning('Error loading Team UID %s: %s', team_uid, e)

        uids = set()
        if full_rebuild:
            self.shared_folders.clear()
        else:
            for shared_folder_uid in changes.shared_folders:
                if shared_folder_uid in self.shared_folders:
                    del self.shared_folders[shared_folder_uid]

        def shared_folder_changes():
            nonlocal full_rebuild
            if full_rebuild:
                for _sf in self.storage.shared_folders.get_all():
                    yield _sf
            else:
                for _sf_uid in changes.shared_folders:
                    _sf = self.storage.shared_folders.get(_sf_uid)
                    if _sf:
                        yield _sf

        uids.clear()
        for sf in shared_folder_changes():
            shared_folder_uid = sf.shared_folder_uid
            has_key = False
            for sk_key in self.storage.shared_folder_keys.get_links_for_subject(shared_folder_uid):
                has_key = True
                try:
                    key = utils.base64_url_decode(sk_key.shared_folder_key)
                    key_type = sk_key.key_type
                    shared_folder_key = None
                    if key_type == 1:
                        shared_folder_key = crypto.decrypt_aes_v1(key, self.client_key)
                    elif key_type == 4:
                        team = self.get_team(sk_key.team_uid)
                        if team:
                            shared_folder_key = crypto.decrypt_aes_v1(key, team.team_key)
                        else:
                            logging.warning('Shared Folder key: Team %s not found', sk_key.team_uid)
                    else:
                        logging.warning('Unsupported key type Shared Folder UID %s: %s', shared_folder_uid, key_type)

                    if shared_folder_key:
                        sf_rec = self.storage.record_keys.get_links_for_object(shared_folder_uid)
                        sf_per = self.storage.shared_folder_permissions.get_links_for_object(shared_folder_uid)
                        shared_folder = SharedFolder.load(sf, sf_rec, sf_per, shared_folder_key)
                        self.shared_folders[shared_folder.shared_folder_uid] = shared_folder
                    else:
                        uids.add(shared_folder_uid)
                except Exception as e:
                    logging.warning('Error loading Shared Folder UID %s: %s', shared_folder_uid, e)
            if not has_key:
                uids.add(shared_folder_uid)

        for shared_folder_uid in uids:
            self.storage.shared_folders.delete(shared_folder_uid)
            self.storage.record_keys.delete_object(shared_folder_uid)
            self.storage.shared_folder_keys.delete_subject(shared_folder_uid)
            self.storage.shared_folder_permissions.delete_subject(shared_folder_uid)

        if full_rebuild:
            self.records.clear()
        else:
            for record_uid in changes.records:
                if record_uid in self.records:
                    del self.records[record_uid]

        def record_changes():
            nonlocal full_rebuild
            if full_rebuild:
                for _r in self.storage.records.get_all():
                    yield _r
            else:
                for _r_uid in changes.records:
                    _r = self.storage.records.get(_r_uid)
                    if _r:
                        yield _r

        uids.clear()
        for record in record_changes():
            record_uid = record.record_uid
            has_key = False
            for r_key in self.storage.record_keys.get_links_for_subject(record_uid):
                has_key = True
                record_key = None
                key = utils.base64_url_decode(r_key.record_key)
                key_type = r_key.key_type
                try:
                    if key_type in {0, 1, 2}:
                        record_key = crypto.decrypt_aes_v1(key, self.client_key)
                    elif key_type == 3:
                        shared_folder_uid = r_key.shared_folder_uid
                        if shared_folder_uid in self.shared_folders:
                            sf = self.shared_folders[shared_folder_uid]
                            record_key = crypto.decrypt_aes_v1(key, sf.shared_folder_key)

                    if record_key:
                        rec = PasswordRecord.load(record, record_key)
                        self.records[rec.record_uid] = rec
                except Exception as e:
                    logging.warning('Error loading Record UID %s: %s', record_uid, e)
            if not has_key:
                uids.add(record_uid)

        for record_uid in uids:
            self.storage.records.delete(record_uid)

        self.build_folders()

    def build_folders(self):
        self.folders.clear()
        self.root_folder.records.clear()
        self.root_folder.subfolders.clear()

        self.folders[self.root_folder.folder_uid] = self.root_folder
        for fol in self.storage.folders.get_all():
            folder = Folder()
            folder.folder_uid = fol.folder_uid
            folder.parent_uid = fol.parent_uid
            folder.folder_type = fol.folder_type

            try:
                data = None
                key = utils.base64_url_decode(fol.folder_key)
                if folder.folder_type == 'user_folder':
                    key = crypto.decrypt_aes_v1(key, self.client_key)
                    data = crypto.decrypt_aes_v1(utils.base64_url_decode(fol.data), key)
                else:
                    folder.shared_folder_uid = fol.shared_folder_uid
                    shared_folder = self.get_shared_folder(folder.shared_folder_uid)
                    if shared_folder:
                        if folder.folder_type == 'shared_folder_folder':
                            key = crypto.decrypt_aes_v1(key, shared_folder.shared_folder_key)
                            data = crypto.decrypt_aes_v1(utils.base64_url_decode(fol.data), key)
                        else:
                            data = None
                            folder.name = shared_folder.name
                if data:
                    data_dict = json.loads(data.decode('utf-8'))
                    if 'name' in data_dict:
                        folder.name = data_dict['name']
            except Exception as e:
                logging.debug('Folder %s name decrypt error: %s', folder.folder_uid, e)

            if not folder.name:
                folder.name = folder.folder_uid
            self.folders[folder.folder_uid] = folder

        for folder_uid in self.folders:
            folder = self.folders[folder_uid]
            if folder.parent_uid:
                parent = self.folders[folder.parent_uid] if folder.parent_uid in self.folders else self.root_folder
                parent.subfolders.add(folder.folder_uid)

        for link in self.storage.folder_records.get_all_links():
            record_uid = link.record_uid
            if record_uid:
                folder_uid = link.folder_uid
                folder = self.folders[folder_uid] if folder_uid in self.folders else self.root_folder
                folder.records.add(record_uid)
