from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, Optional, Set

from . import keeperdrive_storage_types as kd
from .keeperdrive_vault_storage import IKeeperDriveStorage


class KeeperDriveRebuildTask:
    def __init__(self, is_full_sync: bool) -> None:
        self.is_full_sync = is_full_sync
        self.folder_uids: Set[str] = set()
        self.record_uids: Set[str] = set()

    def add_folder(self, folder_uid: str) -> None:
        if self.is_full_sync or not folder_uid:
            return
        self.folder_uids.add(folder_uid)

    def add_folders(self, folder_uids: Iterable[str]) -> None:
        if self.is_full_sync:
            return
        self.folder_uids.update((x for x in folder_uids if x))

    def add_record(self, record_uid: str) -> None:
        if self.is_full_sync or not record_uid:
            return
        self.record_uids.add(record_uid)

    def add_records(self, record_uids: Iterable[str]) -> None:
        if self.is_full_sync:
            return
        self.record_uids.update((x for x in record_uids if x))


@dataclass(frozen=True)
class KeeperDriveFolderInfo:
    folder_uid: str
    parent_uid: str
    folder_type: int
    owner_username: str
    date_created: int
    last_modified: int


@dataclass(frozen=True)
class KeeperDriveRecordInfo:
    record_uid: str
    revision: int
    version: int
    shared: bool
    client_modified_time: int
    file_size: int
    thumbnail_size: int


class KeeperDriveData:
    def __init__(self, storage: IKeeperDriveStorage) -> None:
        self._storage = storage
        self._folders: Dict[str, KeeperDriveFolderInfo] = {}
        self._records: Dict[str, KeeperDriveRecordInfo] = {}
        self.rebuild_data(KeeperDriveRebuildTask(True))

    @property
    def storage(self) -> IKeeperDriveStorage:
        return self._storage

    def folders(self) -> Iterable[KeeperDriveFolderInfo]:
        return self._folders.values()

    def records(self) -> Iterable[KeeperDriveRecordInfo]:
        return self._records.values()

    def get_folder(self, folder_uid: str) -> Optional[KeeperDriveFolderInfo]:
        return self._folders.get(folder_uid)

    def get_record(self, record_uid: str) -> Optional[KeeperDriveRecordInfo]:
        return self._records.get(record_uid)

    @property
    def folder_count(self) -> int:
        return len(self._folders)

    @property
    def record_count(self) -> int:
        return len(self._records)

    def rebuild_data(self, changes: KeeperDriveRebuildTask) -> None:
        if changes.is_full_sync:
            self._folders.clear()
            self._records.clear()
            self._load_all_folders()
            self._load_all_records()
            return

        for folder_uid in changes.folder_uids:
            if folder_uid in self._folders:
                del self._folders[folder_uid]
            row = self._storage.folders.get_entity(folder_uid)
            if row:
                self._folders[folder_uid] = self._folder_info(row)

        for record_uid in changes.record_uids:
            if record_uid in self._records:
                del self._records[record_uid]
            row = self._storage.record_summaries.get_entity(record_uid)
            if row:
                self._records[record_uid] = self._record_info(row)

    def _load_all_folders(self) -> None:
        for row in self._storage.folders.get_all_entities():
            self._folders[row.folder_uid] = self._folder_info(row)

    def _load_all_records(self) -> None:
        for row in self._storage.record_summaries.get_all_entities():
            self._records[row.record_uid] = self._record_info(row)

    @staticmethod
    def _folder_info(row: kd.KDFolder) -> KeeperDriveFolderInfo:
        return KeeperDriveFolderInfo(
            folder_uid=row.folder_uid,
            parent_uid=row.parent_uid,
            folder_type=row.folder_type,
            owner_username=row.owner_username,
            date_created=row.date_created,
            last_modified=row.last_modified,
        )

    @staticmethod
    def _record_info(row: kd.KDRecordSummary) -> KeeperDriveRecordInfo:
        return KeeperDriveRecordInfo(
            record_uid=row.record_uid,
            revision=row.revision,
            version=row.version,
            shared=row.shared,
            client_modified_time=row.client_modified_time,
            file_size=row.file_size,
            thumbnail_size=row.thumbnail_size,
        )
