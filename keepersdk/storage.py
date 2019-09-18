#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2019 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import abc
import collections

from typing import Iterable, Dict, Optional, NoReturn, Set


class StorageItem(abc.ABC):
    @abc.abstractmethod
    def put(self, uid, data):  # type: (str, dict) -> NoReturn
        pass

    @abc.abstractmethod
    def delete(self, uid):  # type: (str) -> NoReturn
        pass

    @abc.abstractmethod
    def get_all(self):   # type: () -> Iterable[dict]
        pass

    @abc.abstractmethod
    def clear(self):   # type: () -> NoReturn
        pass


class StorageItemLookup(StorageItem):
    @abc.abstractmethod
    def get(self, uid):  # type: (str) -> Optional[dict]
        pass


FolderRecordLink = collections.namedtuple('FolderRecordLink', 'record_uid, folder_uid')


class StorageFolder(abc.ABC):
    @abc.abstractmethod
    def get_all_folders(self):      # type: () -> Iterable[dict]
        pass

    def get_all_records(self):      # type: () -> Iterable[FolderRecordLink]
        pass

    @abc.abstractmethod
    def delete_record(self, record_uid, key_scope_uid=None, folder_uid=None):
        # type: (str, Optional[str], Optional[str]) -> NoReturn
        pass

    @abc.abstractmethod
    def delete_folder(self, folder_uid):   # type: (str) -> NoReturn
        pass

    @abc.abstractmethod
    def put_folder(self, folder_uid, data):  # type: (str, dict) -> NoReturn
        pass

    @abc.abstractmethod
    def put_record(self, record_uid, folder_uid):           # type: (str, str) -> NoReturn
        pass

    @abc.abstractmethod
    def clear(self):   # type: () -> NoReturn
        pass


class KeeperStorage(abc.ABC):
    @abc.abstractmethod
    def clear(self):  # type: () -> NoReturn
        pass

    @property
    @abc.abstractmethod
    def client_key(self):  # type: () -> bytes
        pass

    @property
    @abc.abstractmethod
    def revision(self):  # type: () -> int
        pass

    @revision.setter
    @abc.abstractmethod
    def revision(self, value):  # type: (int) -> NoReturn
        pass

    @property
    @abc.abstractmethod
    def metadata(self):    # type: () -> StorageItemLookup
        pass

    @property
    @abc.abstractmethod
    def records(self):    # type: () -> StorageItemLookup
        pass

    @property
    @abc.abstractmethod
    def shared_folders(self):    # type: () -> StorageItemLookup
        pass

    @property
    @abc.abstractmethod
    def teams(self):    # type: () -> StorageItemLookup
        pass

    @property
    @abc.abstractmethod
    def non_shared_data(self):    # type: () -> StorageItemLookup
        pass

    @property
    @abc.abstractmethod
    def folders(self):    # type: () -> StorageFolder
        pass


class InMemoryStorageItem(StorageItem):
    def __init__(self):
        self._items = {}     # type: Dict[str, dict]

    def get(self, uid):  # type: (str) -> Optional[dict]
        return self._items.get(uid)

    def put(self, uid, data):  # type: (str, dict) -> NoReturn
        self._items[uid] = data

    def delete(self, uid):  # type: (str) -> NoReturn
        if uid in self._items:
            del self._items[uid]

    def get_all(self):   # type: () -> Iterable[dict]
        for item in self._items.values():
            yield item

    def clear(self):  # type: () -> NoReturn
        self._items.clear()


class InMemoryStorageFolder(StorageFolder):
    def __init__(self):
        self._folders = {}      # type: Dict[str, dict]
        self._records = {}     # type: Dict[str, Set[str]]

    def clear(self):  # type: () -> NoReturn
        self._folders.clear()
        self._records.clear()

    def get_all_folders(self):  # type: () -> Iterable[dict]
        for data in self._folders.values():
            yield data

    def get_all_records(self):  # type: () -> Iterable[FolderRecordLink]
        for folder_uid in self._records:
            records = self._records[folder_uid]
            for record_uid in records:
                yield FolderRecordLink(record_uid, folder_uid)

    def delete_folder(self, folder_uid):   # type: (str) -> NoReturn
        if folder_uid in self._folders:
            del self._folders[folder_uid]
        if folder_uid in self._records:
            del self._records[folder_uid]

    def delete_record(self, record_uid, key_scope_uid=None, folder_uid=None):
        # type: (str, Optional[str], Optional[str]) -> NoReturn
        if folder_uid:
            if folder_uid in self._records:
                folder = self._records[folder_uid]
                if record_uid in folder:
                    folder.remove(record_uid)

        elif key_scope_uid:
            for folder in self._folders.values():
                if 'key_scope_uid' in folder:
                    if folder['key_scope_uid'] == key_scope_uid:
                        folder_uid = folder['folder_uid']
                        if folder_uid in self._records:
                            folder = self._records[folder_uid]
                            if record_uid in folder:
                                folder.remove(record_uid)
        else:
            for records in self._records.values():
                if record_uid in records:
                    records.remove(record_uid)

    def put_folder(self, folder_uid, data):         # type: (str, dict) -> NoReturn
        self._folders[folder_uid] = data

    def put_record(self, record_uid, folder_uid):  # type: (str, str) -> NoReturn
        if folder_uid not in self._records:
            self._records[folder_uid] = set()
        self._records[folder_uid].add(record_uid)


class InMemoryVaultStorage(KeeperStorage):
    def __init__(self, client_key):
        self._revision = 0
        self._client_key = client_key
        self._metadata = InMemoryStorageItem()
        self._records = InMemoryStorageItem()
        self._shared_folders = InMemoryStorageItem()
        self._teams = InMemoryStorageItem()
        self._non_shared_data = InMemoryStorageItem()
        self._folders = InMemoryStorageFolder()

    def clear(self):
        self.revision = 0
        self._metadata.clear()
        self._records.clear()
        self._shared_folders.clear()
        self._teams.clear()
        self._non_shared_data.clear()

    @property
    def client_key(self):
        return self._client_key

    @property
    def revision(self):
        return self._revision

    @revision.setter
    def revision(self, value):
        self._revision = value

    @property
    def metadata(self):
        return self._metadata

    @property
    def records(self):
        return self._records

    @property
    def shared_folders(self):
        return self._shared_folders

    @property
    def teams(self):
        return self._teams

    @property
    def non_shared_data(self):
        return self._non_shared_data

    @property
    def folders(self):
        return self._folders
