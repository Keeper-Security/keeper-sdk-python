from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set

from ..authentication import keeper_auth
from . import keeperdrive_crypto, keeperdrive_storage_types as kd
from .keeperdrive_vault_storage import IKeeperDriveStorage


class KeeperDriveRebuildTask:
    """Tracks UIDs touched during incremental sync-down."""

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


@dataclass
class KeeperDriveFolderNode:
    folder_uid: str
    parent_uid: Optional[str] = None
    name: Optional[str] = None
    folder_key: Optional[bytes] = None
    subfolder_uids: List[str] = field(default_factory=list)
    record_uids: List[str] = field(default_factory=list)


@dataclass
class KeeperDriveRecordEntry:
    record_uid: str
    revision: int = 0
    version: int = 0
    shared: bool = False
    client_modified_time: int = 0
    file_size: int = 0
    thumbnail_size: int = 0
    record_key: Optional[bytes] = None
    decrypted_data: Optional[str] = None


class KeeperDriveData:
    """In-memory decrypted Keeper Drive view, rebuilt from encrypted storage after sync-down."""

    def __init__(
            self,
            storage: IKeeperDriveStorage,
            auth_context: Optional[keeper_auth.AuthContext] = None) -> None:
        self._storage = storage
        self._auth_context = auth_context
        self._folders: Dict[str, KeeperDriveFolderNode] = {}
        self._records: Dict[str, KeeperDriveRecordEntry] = {}
        if auth_context is not None:
            self.rebuild_keeper_drive(auth_context)

    @property
    def storage(self) -> IKeeperDriveStorage:
        return self._storage

    def folders(self) -> Iterable[KeeperDriveFolderNode]:
        return self._folders.values()

    def records(self) -> Iterable[KeeperDriveRecordEntry]:
        return self._records.values()

    def get_folder(self, folder_uid: str) -> Optional[KeeperDriveFolderNode]:
        return self._folders.get(folder_uid)

    def get_record(self, record_uid: str) -> Optional[KeeperDriveRecordEntry]:
        return self._records.get(record_uid)

    @property
    def folder_count(self) -> int:
        return len(self._folders)

    @property
    def record_count(self) -> int:
        return len(self._records)

    def rebuild_data(self, changes: Optional[KeeperDriveRebuildTask] = None) -> None:
        """Rebuild in-memory views (always full decrypt rebuild."""
        del changes
        self.rebuild_keeper_drive(self._auth_context)

    def rebuild_keeper_drive(self, auth_context: Optional[keeper_auth.AuthContext]) -> None:
        self._folders.clear()
        self._records.clear()
        if auth_context is None:
            return

        decrypted_folder_keys = keeperdrive_crypto.decrypt_folder_keys(self._storage, auth_context)
        decrypted_record_keys = keeperdrive_crypto.decrypt_record_keys(
            self._storage, decrypted_folder_keys, auth_context)

        for row in self._storage.folders.get_all_entities():
            folder_key = decrypted_folder_keys.get(row.folder_uid)
            name = None
            if folder_key is not None:
                name = keeperdrive_crypto.decrypt_folder_name(row.data, folder_key)
            node = KeeperDriveFolderNode(
                folder_uid=row.folder_uid,
                parent_uid=row.parent_uid or None,
                name=name or '(Keeper Drive Folder)',
                folder_key=folder_key,
            )
            self._folders[row.folder_uid] = node

        for node in self._folders.values():
            if node.parent_uid and node.parent_uid in self._folders:
                self._folders[node.parent_uid].subfolder_uids.append(node.folder_uid)

        for link in self._storage.folder_records.get_all_links():
            folder = self._folders.get(link.folder_uid)
            if folder is not None:
                folder.record_uids.append(link.record_uid)

        for row in self._storage.records.get_all_entities():
            record_key = decrypted_record_keys.get(row.record_uid)
            if record_key is None:
                continue
            decrypted = keeperdrive_crypto.decrypt_record_data(row.data, record_key)
            self._records[row.record_uid] = KeeperDriveRecordEntry(
                record_uid=row.record_uid,
                revision=row.revision,
                version=row.version,
                shared=row.shared,
                client_modified_time=row.client_modified_time,
                file_size=row.file_size,
                thumbnail_size=row.thumbnail_size,
                record_key=record_key,
                decrypted_data=decrypted,
            )

        self._purge_orphaned_records()

    def _purge_orphaned_records(self) -> None:
        linked: Set[str] = set()
        for fr in self._storage.folder_records.get_all_links():
            linked.add(fr.record_uid)
        for uid in list(self._records):
            if uid not in linked:
                del self._records[uid]
