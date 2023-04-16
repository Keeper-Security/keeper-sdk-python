#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.coms
#

import itertools
import json
from typing import Iterable, Dict, Set, Optional, List, Tuple, Protocol, TypeVar

from cryptography.hazmat.primitives.asymmetric import rsa

from . import vault_types, vault_storage, vault_record, storage_types, vault_extensions
from .. import crypto, utils


class RebuildTask:
    def __init__(self, is_full_sync):      # type: (bool) -> None
        self.is_full_sync = is_full_sync   # type: bool
        self.records = set()               # type: Set[str]
        self.shared_folders = set()        # type: Set[str]

    def add_record(self, record_uid):      # type: (str) -> None
        if self.is_full_sync:
            return
        self.records.add(record_uid)

    def add_records(self, record_uids):    # type: (Iterable[str]) -> None
        if self.is_full_sync:
            return
        self.records.update(record_uids)

    def add_shared_folders(self, shared_folder_uids):  # type: (Iterable[str]) -> None
        if self.is_full_sync:
            return
        self.shared_folders.update(shared_folder_uids)


TInfo = TypeVar('TInfo')


class EntitySearch(Protocol[TInfo]):
    info: TInfo
    words: Optional[Tuple[str, ...]]


TSearch = TypeVar('TSearch', bound=EntitySearch)


class LoadedRecord(EntitySearch[vault_record.KeeperRecordInfo]):
    def __init__(self, key, info, words=None):
        # type: (bytes, vault_record.KeeperRecordInfo, Optional[Tuple[str, ...]]) -> None
        self.record_key = key            # type: bytes
        self.info = info                 # type: vault_record.KeeperRecordInfo
        self.words = words               # type: Optional[Tuple[str, ...]]


class LoadedSharedFolder(EntitySearch[vault_types.SharedFolderInfo]):
    def __init__(self, key, info, words=None):
        # type: (bytes, vault_types.SharedFolderInfo, Optional[Tuple[str, ...]]) -> None
        self.shared_folder_key = key    # type: bytes
        self.info = info                # type: vault_types.SharedFolderInfo
        self.words = words              # type: Optional[Tuple[str, ...]]


class LoadedTeam(EntitySearch[vault_types.TeamInfo]):
    def __init__(self, team_key, info, words=None, rsa_key=None):
        # type: (bytes, vault_types.TeamInfo, Optional[Tuple[str, ...]], Optional[rsa.RSAPrivateKey]) -> None
        self.team_key = team_key            # type: bytes
        self.info = info                    # type: vault_types.TeamInfo
        self.rsa_private_key = rsa_key      # type: Optional[rsa.RSAPrivateKey]
        self.words = words                  # type: Optional[Tuple[str, ...]]


class VaultData:
    def __init__(self, client_key, storage):    # type: (bytes, vault_storage.IVaultStorage) -> None
        self._storage = storage                  # type: vault_storage.IVaultStorage
        self._client_key = client_key           # type: bytes
        self._records = {}                      # type: Dict[str, LoadedRecord]
        self._shared_folders = {}               # type: Dict[str, LoadedSharedFolder]
        self._teams = {}                        # type: Dict[str, LoadedTeam]
        self._folders = {}                      # type: Dict[str, vault_types.Folder]
        self._keeper_record_types = {}          # type: Dict[str, vault_types.RecordType]
        self._custom_record_types = []          # type: List[vault_types.RecordType]
        self._root_folder = vault_types.Folder()  # type: vault_types.Folder
        self._root_folder.name = 'My Vault'
        self._logger = utils.get_logger()

        task = RebuildTask(True)
        self.rebuild_data(task)

    def close(self):
        if self._storage:
            self._storage.close()

    @property
    def storage(self):
        return self._storage

    @property
    def client_key(self):
        return self._client_key

    @staticmethod
    def _find_entities(entity_dict, criteria):
        # type: (Dict[str, TSearch], str) -> Iterable[TInfo]
        words = list(utils.tokenize_searchable_text(criteria))
        if words:
            found = False
            for entity in entity_dict.values():
                if entity.words is None:
                    continue
                for entity_word in entity.words:
                    for search_word in words:
                        if len(search_word) <= len(entity_word):
                            if search_word in entity_word:
                                found = True
                                break
                    if found:
                        break
                if found:
                    yield entity.info

    def get_record(self, record_uid):    # type: (str) -> Optional[vault_record.KeeperRecordInfo]
        rec = self._records.get(record_uid)
        if rec:
            return rec.info

    def records(self):   # type: () -> Iterable[vault_record.KeeperRecordInfo]
        return (x.info for x in self._records.values())

    @property
    def record_count(self):   # type: () -> int
        return len(self._records)

    def find_records(self, criteria):   # type: (str) -> Iterable[vault_record.KeeperRecordInfo]
        for e in self._find_entities(self._records, criteria):  # type: vault_record.KeeperRecordInfo
            yield e

    def load_record(self, record_uid):   # type: (str) -> Optional[vault_record.KeeperRecord]
        record_key = self.get_record_key(record_uid)
        if record_key:
            storage_record = self.storage.records.get_entity(record_uid)
            if storage_record:
                return vault_extensions.load_keeper_record(storage_record, record_key)

    def get_record_key(self, record_uid):   # type: (str) -> Optional[bytes]
        if record_uid in self._records:
            return self._records[record_uid].record_key

    def get_shared_folder(self, shared_folder_uid):  # type: (str) -> Optional[vault_types.SharedFolderInfo]
        sf = self._shared_folders.get(shared_folder_uid)
        if sf:
            return sf.info

    def shared_folders(self):   # type: () -> Iterable[vault_types.SharedFolderInfo]
        return (x.info for x in self._shared_folders.values())

    @property
    def shared_folder_count(self):    # type: () -> int
        return len(self._shared_folders)

    def find_shared_folders(self, criteria):   # type: (str) -> Iterable[vault_types.SharedFolderInfo]
        for e in self._find_entities(self._shared_folders, criteria):   # type: vault_types.SharedFolderInfo
            yield e

    def load_shared_folder(self, shared_folder_uid):    # type: (str) -> Optional[vault_types.SharedFolder]
        if shared_folder_uid in self._shared_folders:
            shared_folder_key = self._shared_folders[shared_folder_uid].shared_folder_key
            sf = self.storage.shared_folders.get_entity(shared_folder_uid)
            if sf:
                return vault_types.SharedFolder.load(
                    sf, self.storage.record_keys.get_links_for_object(sf.shared_folder_uid),
                    self.storage.shared_folder_permissions.get_links_for_subject(sf.shared_folder_uid),
                    shared_folder_key)

    def get_shared_folder_key(self, shared_folder_uid):   # type: (str) -> Optional[bytes]
        if shared_folder_uid in self._shared_folders:
            return self._shared_folders[shared_folder_uid].shared_folder_key

    def get_team(self, team_uid):     # type: (str) -> Optional[vault_types.TeamInfo]
        t = self._teams.get(team_uid)
        if t:
            return t.info

    def teams(self):      # type: () -> Iterable[vault_types.TeamInfo]
        return (x.info for x in self._teams.values())

    @property
    def team_count(self):     # type: () -> int
        return len(self._teams)

    def find_teams(self, criteria):   # type: (str) -> Iterable[vault_types.TeamInfo]
        for e in self._find_entities(self._teams, criteria):  # type: vault_types.TeamInfo
            yield e

    def load_team(self, team_uid):   # type: (str) -> Optional[vault_types.Team]
        if team_uid in self._teams:
            team_key = self._teams[team_uid].team_key
            storage_team = self.storage.teams.get_entity(team_uid)
            if storage_team:
                return vault_types.Team.load(storage_team, team_key)

    def get_folder(self, folder_uid):   # type: (str) -> Optional[vault_types.Folder]
        return self._folders.get(folder_uid) if folder_uid else None

    def folders(self):  # type: () -> Iterable[vault_types.Folder]
        for folder in self._folders.values():
            yield folder

    def get_record_types(self):   # type: () -> Iterable[vault_types.RecordType]
        return itertools.chain(self._keeper_record_types.values(), self._custom_record_types)

    def get_record_type_by_name(self, name):    # type: (str) -> Optional[vault_types.RecordType]
        rt = self._keeper_record_types.get(name.lower())
        if not rt:
            lname = name.lower()
            rt = next((x for x in self._custom_record_types if x.name.lower() == lname), None)
        return rt

    @property
    def root_folder(self):  # type: () -> vault_types.Folder
        return self._root_folder

    def _decrypt_shared_folder_key(self, sf_key):   # type: (storage_types.StorageSharedFolderKey) -> Optional[bytes]
        try:
            key_bytes = sf_key.shared_folder_key
            if sf_key.key_type == storage_types.KeyType.DataKey:
                return crypto.decrypt_aes_v2(key_bytes, self.client_key)

            if sf_key.key_type in {storage_types.KeyType.TeamKey, storage_types.KeyType.TeamRsaPrivateKey}:
                team = self._teams.get(sf_key.team_uid)
                if team is not None:
                    if sf_key.key_type == storage_types.KeyType.TeamKey:
                        if len(key_bytes) < 100:
                            if len(key_bytes) == 60:
                                return crypto.decrypt_aes_v2(key_bytes, team.team_key)
                            else:
                                return crypto.decrypt_aes_v1(key_bytes, team.team_key)
                        elif team.rsa_private_key is not None:
                            return crypto.decrypt_rsa(key_bytes, team.rsa_private_key)
                    if sf_key.key_type == storage_types.KeyType.TeamRsaPrivateKey and team.rsa_private_key is not None:
                        return crypto.decrypt_rsa(key_bytes, team.rsa_private_key)
                else:
                    self._logger.warning('Decrypt shared folder \"%s\" key: Team \"%s\" not found',
                                         sf_key.shared_folder_uid, sf_key.team_uid)
            else:
                self._logger.warning('Decrypt shared folder \"%s\" key: Decryption algorithm is not found',
                                     sf_key.shared_folder_uid)
        except Exception as e:
            self._logger.error('Decrypt shared folder \"%s\" key error: %s', sf_key.shared_folder_uid, e)

    def decrypt_record_key(self, record_key):   # type: (storage_types.StorageRecordKey) -> Optional[bytes]
        try:
            key_bytes = record_key.record_key
            if record_key.key_type == storage_types.KeyType.DataKey:
                return crypto.decrypt_aes_v2(key_bytes, self.client_key)

            if record_key.key_type == storage_types.KeyType.SharedFolderKey:
                shared_folder = self._shared_folders.get(record_key.shared_folder_uid)
                if shared_folder:
                    if len(key_bytes) == 60:
                        return crypto.decrypt_aes_v2(key_bytes, shared_folder.shared_folder_key)
                    else:
                        return crypto.decrypt_aes_v1(key_bytes, shared_folder.shared_folder_key)
                else:
                    self._logger.warning('Decrypt record \"%s\" key: Shared folder \"%s\" not found',
                                         record_key.record_uid, record_key.shared_folder_uid)
            else:
                self._logger.warning('Decrypt record \"%s\" key: Decryption algorithm is not found',
                                     record_key.record_uid)
        except Exception as e:
            self._logger.error('Decrypt record \"%s\" key error: %s', record_key.record_uid, e)

    def rebuild_data(self, changes):   # type: (RebuildTask) -> None
        full_rebuild = changes.is_full_sync

        self._teams.clear()
        for t in self.storage.teams.get_all():
            team_uid = None
            try:
                team_key = crypto.decrypt_aes_v2(t.team_key, self.client_key)
                team = vault_types.Team.load(t, team_key)
                team_info = vault_types.TeamInfo(team_uid=team.team_uid, name=team.name)
                words = set(utils.tokenize_searchable_text(team.name))
                self._teams[team_info.team_uid] = LoadedTeam(
                    team_key=team_key, info=team_info, words=tuple(words), rsa_key=team.rsa_private_key)
            except Exception as e:
                self._logger.warning('Error loading Team UID %s: %s', team_uid, e)

        if not full_rebuild and len(self._shared_folders) > 20:
            if len(changes.shared_folders) * 4 > len(self._shared_folders):
                full_rebuild = True

        entity_keys = {}   # type: Dict[str, bytes]

        if full_rebuild:
            self._shared_folders.clear()
        else:
            for shared_folder_uid in changes.shared_folders:
                if shared_folder_uid in self._shared_folders:
                    changes.add_records(
                        (x.record_uid for x in self.storage.record_keys.get_links_for_object(shared_folder_uid)))
                    del self._shared_folders[shared_folder_uid]

        entity_keys.clear()
        if full_rebuild:
            for sf_key in self.storage.shared_folder_keys.get_all_links():
                if sf_key.shared_folder_uid in entity_keys:
                    continue
                key = self._decrypt_shared_folder_key(sf_key)
                if key:
                    entity_keys[sf_key.shared_folder_uid] = key
        else:
            for shared_folder_uid in changes.shared_folders:
                if shared_folder_uid in entity_keys:
                    continue
                for sf_key in self.storage.shared_folder_keys.get_links_for_subject(shared_folder_uid):
                    key = self._decrypt_shared_folder_key(sf_key)
                    if key:
                        entity_keys[sf_key.shared_folder_uid] = key
                        break

        def shared_folders_to_load():  # type: () -> Iterable[storage_types.StorageSharedFolder]
            nonlocal full_rebuild
            if full_rebuild:
                for _sf in self.storage.shared_folders.get_all():
                    yield _sf
            else:
                for _sf_uid in changes.shared_folders:
                    _osf = self.storage.shared_folders.get_entity(_sf_uid)
                    if _osf:
                        yield _osf

        uid_to_remove = set()    # type: Set[str]
        for sf in shared_folders_to_load():
            if sf.shared_folder_uid in entity_keys:
                sf_key = entity_keys[sf.shared_folder_uid]
                shared_folder = vault_types.SharedFolder.load(
                    sf, self.storage.record_keys.get_links_for_object(sf.shared_folder_uid),
                    self.storage.shared_folder_permissions.get_links_for_subject(sf.shared_folder_uid),
                    sf_key)

                sf_info = vault_types.SharedFolderInfo(
                    shared_folder_uid=shared_folder.shared_folder_uid,
                    name=shared_folder.name,
                    teams=sum((1 for x in shared_folder.user_permissions
                               if x.user_type == storage_types.SharedFolderUserType.Team)),
                    users=sum((1 for x in shared_folder.user_permissions
                               if x.user_type == storage_types.SharedFolderUserType.User)),
                    records=sum((1 for _ in shared_folder.record_permissions)),
                )
                sf_words = set()    # type: Set[str]
                sf_words.update(utils.tokenize_searchable_text(shared_folder.name))
                sf_words.update((x.user_id.lower() for x in shared_folder.user_permissions))

                self._shared_folders[sf_info.shared_folder_uid] = \
                    LoadedSharedFolder(key=sf_key, info=sf_info, words=tuple(sf_words))
            else:
                uid_to_remove.add(sf.shared_folder_uid)

        if len(uid_to_remove) > 0:
            self.storage.shared_folders.delete_uids(uid_to_remove)
            self.storage.record_keys.delete_links_for_objects(uid_to_remove)
            self.storage.shared_folder_keys.delete_links_for_subjects(uid_to_remove)
            self.storage.shared_folder_permissions.delete_links_for_subjects(uid_to_remove)

        if full_rebuild:
            self._records.clear()
        else:
            for record_uid in changes.records:
                if record_uid in self._records:
                    del self._records[record_uid]

        entity_keys.clear()
        record_key_encrypted = []   # type: List[storage_types.StorageRecordKey]

        def record_keys_to_decrypt():   # type: () -> Iterable[storage_types.StorageRecordKey]
            if full_rebuild:
                for srk in self.storage.record_keys.get_all_links():
                    yield srk
            else:
                for r_uid in changes.records:
                    for srk in self.storage.record_keys.get_links_for_subject(r_uid):
                        yield srk

        for record_key in record_keys_to_decrypt():
            if record_key.record_uid in entity_keys:
                continue
            if record_key.key_type == storage_types.KeyType.RecordKey:
                record_key_encrypted.append(record_key)
            else:
                key = self.decrypt_record_key(record_key)
                if key:
                    entity_keys[record_key.record_uid] = key

        for record_key in record_key_encrypted:
            if record_key.record_uid in entity_keys:
                continue
            host_record_key = None
            if record_key.shared_folder_uid in entity_keys:
                host_record_key = entity_keys[record_key.shared_folder_uid]
            elif record_key.shared_folder_uid in self._records:
                host_record_key = self._records[record_key.shared_folder_uid].record_key
            if host_record_key:
                try:
                    key_bytes = record_key.record_key
                    if len(key_bytes) == 60:
                        key = crypto.decrypt_aes_v2(key_bytes, host_record_key)
                    else:
                        key = crypto.decrypt_aes_v1(key_bytes, host_record_key)
                    entity_keys[record_key.record_uid] = key
                except Exception as e:
                    self._logger.warning('Decrypt record \"%s\" key error: %s', record_key.record_uid, e)
            else:
                self._logger.error('Decrypt record \"%s\" key: Parent record \"%s\" not found',
                                   record_key.record_uid, record_key.shared_folder_uid)

        def records_to_load():     # type: () -> Iterable[storage_types.StorageRecord]
            nonlocal full_rebuild
            if full_rebuild:
                for _r in self.storage.records.get_all():
                    yield _r
            else:
                for _r_uid in changes.records:
                    _or = self.storage.records.get_entity(_r_uid)
                    if _or:
                        yield _or

        uid_to_remove.clear()
        for record in records_to_load():
            record_uid = record.record_uid
            if record_uid in entity_keys:
                try:
                    key_bytes = entity_keys[record_uid]
                    kr = vault_extensions.load_keeper_record(record, key_bytes)
                    if kr:
                        record_type = kr.record_type if isinstance(kr, vault_record.TypedRecord) else ''
                        description = vault_extensions.get_record_description(kr)
                        has_attachments = False
                        if isinstance(kr, vault_record.TypedRecord):
                            file_field = kr.get_typed_field('fileRef')
                            if isinstance(file_field, vault_record.TypedField):
                                attachments = file_field.get_external_value()
                                if attachments:
                                    has_attachments = True
                        elif isinstance(kr, vault_record.PasswordRecord):
                            if kr.attachments and len(kr.attachments) > 0:
                                has_attachments = True
                        info = vault_record.KeeperRecordInfo(
                            record_uid=record.record_uid, version=record.version, record_type=record_type,
                            title=kr.title, description=description, client_time_modified=record.client_modified_time,
                            shared=record.shared, has_attachments=has_attachments)

                        words = set(vault_extensions.get_record_words(kr))
                        self._records[record_uid] = LoadedRecord(key=key_bytes, info=info, words=tuple(words))
                except Exception as e:
                    raise e
                    # self._logger.warning('Load record \"%s\" error: %s', record_uid, e)
            else:
                uid_to_remove.add(record_uid)

        if len(uid_to_remove) > 0:
            self.storage.record_keys.delete_links_for_subjects(uid_to_remove)
            self.storage.records.delete_uids(uid_to_remove)

        self.build_folders()

    def build_folders(self):
        self._folders.clear()

        self._root_folder.records.clear()
        self._root_folder.subfolders.clear()

        self._folders[self.root_folder.folder_uid] = self._root_folder
        for fol in self.storage.folders.get_all():
            folder = vault_types.Folder()
            folder.folder_uid = fol.folder_uid
            folder.parent_uid = fol.parent_uid
            folder.folder_type = fol.folder_type

            try:
                data = None
                if folder.folder_type == 'user_folder':
                    folder.folder_key = crypto.decrypt_aes_v2(fol.folder_key, self.client_key)
                    data = crypto.decrypt_aes_v1(fol.data, folder.folder_key)
                else:
                    folder.folder_scope_uid = fol.shared_folder_uid
                    shared_folder = self._shared_folders.get(fol.shared_folder_uid)
                    if shared_folder:
                        if folder.folder_type == 'shared_folder_folder':
                            folder.folder_key = crypto.decrypt_aes_v1(fol.folder_key, shared_folder.shared_folder_key)
                            data = crypto.decrypt_aes_v1(utils.base64_url_decode(fol.data), folder.folder_key)
                        else:
                            folder.folder_key = shared_folder.shared_folder_key
                            if fol.data:
                                data = crypto.decrypt_aes_v1(utils.base64_url_decode(fol.data), folder.folder_key)
                            else:
                                folder.name = shared_folder.info.name
                if data:
                    data_dict = json.loads(data.decode('utf-8'))
                    if 'name' in data_dict:
                        folder.name = data_dict['name']
            except Exception as e:
                self._logger.debug('Folder %s name decrypt error: %s', folder.folder_uid, e)

            if not folder.name:
                folder.name = folder.folder_uid
            self._folders[folder.folder_uid] = folder

        for folder_uid in self._folders:
            folder = self._folders[folder_uid]
            if folder.parent_uid:
                parent = self._folders[folder.parent_uid] if folder.parent_uid in self._folders else self._root_folder
                parent.subfolders.add(folder.folder_uid)

        for link in self.storage.folder_records.get_all_links():
            record_uid = link.record_uid
            if record_uid:
                folder_uid = link.folder_uid
                folder = self._folders[folder_uid] if folder_uid in self._folders else self._root_folder
                folder.records.add(record_uid)
