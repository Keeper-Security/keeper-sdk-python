from __future__ import annotations

from . import keeperdrive_storage_types as kd
from .keeperdrive_vault_storage import IKeeperDriveStorage
from ..storage.in_memory import InMemoryEntityStorage, InMemoryLinkStorage, InMemoryRecordStorage


class InMemoryKeeperDriveStorage(IKeeperDriveStorage):
    def __init__(self) -> None:
        self._settings = InMemoryRecordStorage[kd.KeeperDriveSettings]()
        self._folders = InMemoryEntityStorage[kd.KDFolder, str]()
        self._folder_keys = InMemoryLinkStorage[kd.KDFolderKey, str, str]()
        self._records = InMemoryEntityStorage[kd.KDRecord, str]()
        self._record_keys = InMemoryLinkStorage[kd.KDRecordKey, str, str]()
        self._folder_accesses = InMemoryLinkStorage[kd.KDFolderAccess, str, str]()
        self._record_accesses = InMemoryLinkStorage[kd.KDRecordAccess, str, str]()
        self._record_links = InMemoryLinkStorage[kd.KDRecordLink, str, str]()
        self._folder_records = InMemoryLinkStorage[kd.KDFolderRecord, str, str]()
        self._folder_sharing_states = InMemoryEntityStorage[kd.KDFolderSharingState, str]()
        self._record_sharing_states = InMemoryEntityStorage[kd.KDRecordSharingState, str]()
        self._non_shared_data = InMemoryEntityStorage[kd.KDNonSharedData, str]()
        self._breach_watch_records = InMemoryEntityStorage[kd.KDBreachWatchRecord, str]()
        self._security_score_data = InMemoryEntityStorage[kd.KDSecurityScoreData, str]()
        self._breach_watch_security_data = InMemoryEntityStorage[kd.KDBreachWatchSecurityData, str]()
        self._list_chunks = InMemoryLinkStorage[kd.KDListChunk, str, str]()

    @property
    def settings(self):
        return self._settings

    @property
    def folders(self):
        return self._folders

    @property
    def folder_keys(self):
        return self._folder_keys

    @property
    def records(self):
        return self._records

    @property
    def record_keys(self):
        return self._record_keys

    @property
    def folder_accesses(self):
        return self._folder_accesses

    @property
    def record_accesses(self):
        return self._record_accesses

    @property
    def record_links(self):
        return self._record_links

    @property
    def folder_records(self):
        return self._folder_records

    @property
    def folder_sharing_states(self):
        return self._folder_sharing_states

    @property
    def record_sharing_states(self):
        return self._record_sharing_states

    @property
    def non_shared_data(self):
        return self._non_shared_data

    @property
    def breach_watch_records(self):
        return self._breach_watch_records

    @property
    def security_score_data(self):
        return self._security_score_data

    @property
    def breach_watch_security_data(self):
        return self._breach_watch_security_data

    @property
    def list_chunks(self):
        return self._list_chunks

    def clear_all(self) -> None:
        self._settings.delete()
        self._folders.clear()
        self._folder_keys.clear()
        self._records.clear()
        self._record_keys.clear()
        self._folder_accesses.clear()
        self._record_accesses.clear()
        self._record_links.clear()
        self._folder_records.clear()
        self._folder_sharing_states.clear()
        self._record_sharing_states.clear()
        self._non_shared_data.clear()
        self._breach_watch_records.clear()
        self._security_score_data.clear()
        self._breach_watch_security_data.clear()
        self._list_chunks.clear()

    def close(self) -> None:
        pass
