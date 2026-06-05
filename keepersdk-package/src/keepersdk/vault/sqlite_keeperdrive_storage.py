from __future__ import annotations

import sqlite3
from typing import Callable, Tuple, Type

from . import keeperdrive_storage_types as kd
from .keeperdrive_vault_storage import IKeeperDriveStorage
from .. import sqlite_dao, utils
from ..storage import sqlite


def keeper_drive_table_schemas(owner_column: str, owner_type: Type[sqlite_dao.KeyTypes]
                               ) -> Tuple[sqlite_dao.TableSchema, ...]:

    settings_schema = sqlite_dao.TableSchema.load_schema(
        kd.KeeperDriveSettings, [], owner_column=owner_column, owner_type=owner_type)
    folder_schema = sqlite_dao.TableSchema.load_schema(
        kd.KDFolder, 'folder_uid', owner_column=owner_column, owner_type=owner_type)
    folder_key_schema = sqlite_dao.TableSchema.load_schema(
        kd.KDFolderKey, ['folder_uid', 'parent_uid'],
        indexes={'ParentUid': ['parent_uid']}, owner_column=owner_column, owner_type=owner_type)
    record_schema = sqlite_dao.TableSchema.load_schema(
        kd.KDRecord, 'record_uid', owner_column=owner_column, owner_type=owner_type)
    record_key_schema = sqlite_dao.TableSchema.load_schema(
        kd.KDRecordKey, ['record_uid', 'folder_uid'],
        indexes={'FolderUid': ['folder_uid']}, owner_column=owner_column, owner_type=owner_type)
    folder_access_schema = sqlite_dao.TableSchema.load_schema(
        kd.KDFolderAccess, ['folder_uid', 'access_type_uid'],
        indexes={'AccessTypeUid': ['access_type_uid']}, owner_column=owner_column, owner_type=owner_type)
    record_access_schema = sqlite_dao.TableSchema.load_schema(
        kd.KDRecordAccess, ['record_uid', 'access_type_uid'],
        indexes={'AccessTypeUid': ['access_type_uid']}, owner_column=owner_column, owner_type=owner_type)
    record_link_schema = sqlite_dao.TableSchema.load_schema(
        kd.KDRecordLink, ['parent_record_uid', 'child_record_uid'],
        indexes={'ChildRecordUid': ['child_record_uid']}, owner_column=owner_column, owner_type=owner_type)
    folder_record_schema = sqlite_dao.TableSchema.load_schema(
        kd.KDFolderRecord, ['folder_uid', 'record_uid'],
        indexes={'RecordUid': ['record_uid']}, owner_column=owner_column, owner_type=owner_type)
    folder_sharing_schema = sqlite_dao.TableSchema.load_schema(
        kd.KDFolderSharingState, 'folder_uid', owner_column=owner_column, owner_type=owner_type)
    record_sharing_schema = sqlite_dao.TableSchema.load_schema(
        kd.KDRecordSharingState, 'record_uid', owner_column=owner_column, owner_type=owner_type)
    non_shared_schema = sqlite_dao.TableSchema.load_schema(
        kd.KDNonSharedData, 'record_uid', owner_column=owner_column, owner_type=owner_type)
    bw_record_schema = sqlite_dao.TableSchema.load_schema(
        kd.KDBreachWatchRecord, 'record_uid', owner_column=owner_column, owner_type=owner_type)
    security_score_schema = sqlite_dao.TableSchema.load_schema(
        kd.KDSecurityScoreData, 'record_uid', owner_column=owner_column, owner_type=owner_type)
    bw_sec_schema = sqlite_dao.TableSchema.load_schema(
        kd.KDBreachWatchSecurityData, 'record_uid', owner_column=owner_column, owner_type=owner_type)
    list_chunk_schema = sqlite_dao.TableSchema.load_schema(
        kd.KDListChunk, ['chunk_group', 'chunk_key'],
        indexes={'ChunkKey': ['chunk_key']}, owner_column=owner_column, owner_type=owner_type)
    return (settings_schema, folder_schema, folder_key_schema, record_schema, record_key_schema,
            folder_access_schema, record_access_schema, record_link_schema, folder_record_schema,
            folder_sharing_schema, record_sharing_schema, non_shared_schema, bw_record_schema,
            security_score_schema, bw_sec_schema, list_chunk_schema)


class SqliteKeeperDriveStorage(IKeeperDriveStorage):
    def __init__(self, get_connection: Callable[[], sqlite3.Connection], vault_owner: bytes, *,
                 verify: bool = True) -> None:
        self.get_connection = get_connection
        self.vault_owner = vault_owner
        self.owner_column = 'owner_uid'

        schemas = keeper_drive_table_schemas(self.owner_column, bytes)
        if verify:
            sqlite_dao.verify_database(self.get_connection(), schemas)

        (settings_schema, folder_schema, folder_key_schema, record_schema, record_key_schema,
         folder_access_schema, record_access_schema, record_link_schema, folder_record_schema,
         folder_sharing_schema, record_sharing_schema, non_shared_schema, bw_record_schema,
         security_score_schema, bw_sec_schema, list_chunk_schema) = schemas

        self._settings = sqlite.SqliteRecordStorage(
            self.get_connection, settings_schema, owner=self.vault_owner)
        self._folders = sqlite.SqliteEntityStorage(
            self.get_connection, folder_schema, owner=self.vault_owner)
        self._folder_keys = sqlite.SqliteLinkStorage(
            self.get_connection, folder_key_schema, owner=self.vault_owner)
        self._records = sqlite.SqliteEntityStorage(
            self.get_connection, record_schema, owner=self.vault_owner)
        self._record_keys = sqlite.SqliteLinkStorage(
            self.get_connection, record_key_schema, owner=self.vault_owner)
        self._folder_accesses = sqlite.SqliteLinkStorage(
            self.get_connection, folder_access_schema, owner=self.vault_owner)
        self._record_accesses = sqlite.SqliteLinkStorage(
            self.get_connection, record_access_schema, owner=self.vault_owner)
        self._record_links = sqlite.SqliteLinkStorage(
            self.get_connection, record_link_schema, owner=self.vault_owner)
        self._folder_records = sqlite.SqliteLinkStorage(
            self.get_connection, folder_record_schema, owner=self.vault_owner)
        self._folder_sharing_states = sqlite.SqliteEntityStorage(
            self.get_connection, folder_sharing_schema, owner=self.vault_owner)
        self._record_sharing_states = sqlite.SqliteEntityStorage(
            self.get_connection, record_sharing_schema, owner=self.vault_owner)
        self._non_shared_data = sqlite.SqliteEntityStorage(
            self.get_connection, non_shared_schema, owner=self.vault_owner)
        self._breach_watch_records = sqlite.SqliteEntityStorage(
            self.get_connection, bw_record_schema, owner=self.vault_owner)
        self._security_score_data = sqlite.SqliteEntityStorage(
            self.get_connection, security_score_schema, owner=self.vault_owner)
        self._breach_watch_security_data = sqlite.SqliteEntityStorage(
            self.get_connection, bw_sec_schema, owner=self.vault_owner)
        self._list_chunks = sqlite.SqliteLinkStorage(
            self.get_connection, list_chunk_schema, owner=self.vault_owner)

    @property
    def personal_scope_uid(self) -> str:
        return utils.base64_url_encode(self.vault_owner)

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
        self._settings.delete_all()
        self._folders.delete_all()
        self._folder_keys.delete_all()
        self._records.delete_all()
        self._record_keys.delete_all()
        self._folder_accesses.delete_all()
        self._record_accesses.delete_all()
        self._record_links.delete_all()
        self._folder_records.delete_all()
        self._folder_sharing_states.delete_all()
        self._record_sharing_states.delete_all()
        self._non_shared_data.delete_all()
        self._breach_watch_records.delete_all()
        self._security_score_data.delete_all()
        self._breach_watch_security_data.delete_all()
        self._list_chunks.delete_all()

    def close(self) -> None:
        pass
