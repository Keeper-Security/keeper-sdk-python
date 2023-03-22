import sqlite3
from typing import Optional

from . import vault_storage, storage_types
from .. import sqlite_dao
from ..storage import sqlite


class UserSettings:
    def __init__(self):
        self.revision = 0


class SqliteVaultStorage(vault_storage.IVaultStorage):
    def __init__(self, file_name, vault_owner):   # type: (str, str) -> None
        self._file_name = file_name or ':memory:'
        self._connection = None              # type: Optional[sqlite3.Connection]
        self.vault_owner = vault_owner
        self.owner_column = 'account_uid'
        settings_schema = sqlite_dao.TableSchema.load_schema(UserSettings, [], owner_column=self.owner_column)
        record_schema = sqlite_dao.TableSchema.load_schema(
            storage_types.StorageRecord, 'record_uid', owner_column=self.owner_column)
        record_type_schema = sqlite_dao.TableSchema.load_schema(
            storage_types.StorageRecordType, 'id', owner_column=self.owner_column)
        shared_folder_schema = sqlite_dao.TableSchema.load_schema(
            storage_types.StorageSharedFolder, 'shared_folder_uid', owner_column=self.owner_column)
        team_schema = sqlite_dao.TableSchema.load_schema(
            storage_types.StorageTeam, 'team_uid', owner_column=self.owner_column)
        non_shared_data_schema = sqlite_dao.TableSchema.load_schema(
            storage_types.StorageNonSharedData, 'record_uid', owner_column=self.owner_column)
        record_key_schema = sqlite_dao.TableSchema.load_schema(
            storage_types.StorageRecordKey, ['record_uid', 'shared_folder_uid'],
            indexes={'SharedFolderUID': ['shared_folder_uid']}, owner_column=self.owner_column)
        shared_folder_key_schema = sqlite_dao.TableSchema.load_schema(
            storage_types.StorageSharedFolderKey, ['shared_folder_uid', 'team_uid'],
            indexes={'TeamUID': ['team_uid']}, owner_column=self.owner_column)
        shared_folder_permission_schema = sqlite_dao.TableSchema.load_schema(
            storage_types.StorageSharedFolderPermission, ['shared_folder_uid', 'user_uid'],
            indexes={'UserUID': ['user_uid']}, owner_column=self.owner_column)
        folder_schema = sqlite_dao.TableSchema.load_schema(
            storage_types.StorageFolder, 'folder_uid', owner_column=self.owner_column)
        folder_record_schema = sqlite_dao.TableSchema.load_schema(
            storage_types.StorageFolderRecordLink, ['folder_uid', 'record_uid'],
            indexes={'RecordUID': ['record_uid']}, owner_column=self.owner_column)
        breach_watch_record_schema = sqlite_dao.TableSchema.load_schema(
            storage_types.BreachWatchRecord, 'record_uid', owner_column=self.owner_column)

        sqlite_dao.verify_database(self.get_connection(),
                                   (settings_schema, record_schema, record_type_schema, shared_folder_schema,
                                    team_schema, non_shared_data_schema, record_key_schema, shared_folder_key_schema,
                                    shared_folder_permission_schema, folder_schema, folder_record_schema,
                                    breach_watch_record_schema))

        self._settings_storage = sqlite.SqliteRecordStorage(
            self.get_connection, settings_schema, owner=self.vault_owner)

        self._records = sqlite.SqliteEntityStorage(
            self.get_connection, record_schema, owner=self.vault_owner)
        self._record_types = sqlite.SqliteEntityStorage(
            self.get_connection, record_type_schema, owner=self.vault_owner)

        self._shared_folders = sqlite.SqliteEntityStorage(
            self.get_connection, shared_folder_schema, owner=self.vault_owner)
        self._teams = sqlite.SqliteEntityStorage(
            self.get_connection, team_schema, owner=self.vault_owner)
        self._non_shared_data = sqlite.SqliteEntityStorage(
            self.get_connection, non_shared_data_schema, owner=self.vault_owner)

        self._record_keys = sqlite.SqliteLinkStorage(
            self.get_connection, record_key_schema, owner=self.vault_owner)
        self._shared_folder_keys = sqlite.SqliteLinkStorage(
            self.get_connection, shared_folder_key_schema, owner=self.vault_owner)
        self._shared_folder_permissions = sqlite.SqliteLinkStorage(
            self.get_connection, shared_folder_permission_schema, owner=self.vault_owner)

        self._folders = sqlite.SqliteEntityStorage(
            self.get_connection, folder_schema, owner=self.vault_owner)
        self._folder_records = sqlite.SqliteLinkStorage(
            self.get_connection, folder_record_schema, owner=self.vault_owner)

        self._breach_watch_records = sqlite.SqliteEntityStorage(
            self.get_connection, breach_watch_record_schema, owner=self.vault_owner)

    def get_connection(self):   # type: () -> sqlite3.Connection
        if self._connection is None:
            self._connection = sqlite3.Connection(self._file_name)
        return self._connection

    def get_revision(self):
        setting = self._settings_storage.load()
        return setting.revision if setting and isinstance(setting.revision, int) else 0

    def set_revision(self, value):
        setting = self._settings_storage.load()
        if setting is None:
            setting = UserSettings()
        setting.revision = value
        self._settings_storage.store(setting)

    def get_personal_scope_uid(self):
        return self.vault_owner

    def get_records(self):
        return self._records

    def get_record_types(self):
        return self._record_types

    def get_shared_folders(self):
        return self._shared_folders

    def get_teams(self):
        return self._teams

    def get_non_shared_data(self):
        return self._non_shared_data

    def get_record_keys(self):
        return self._record_keys

    def get_shared_folder_keys(self):
        return self._shared_folder_keys

    def get_shared_folder_permissions(self):
        return self._shared_folder_permissions

    def get_folders(self):
        return self._folders

    def get_folder_records(self):
        return self._folder_records

    def get_breach_watch_records(self):
        return self._breach_watch_records

    def clear(self):
        self._settings_storage.delete_all()
        self._records.delete_all()
        self._record_types.delete_all()
        self._shared_folders.delete_all()
        self._teams.delete_all()
        self._non_shared_data.delete_all()
        self._record_keys.delete_all()
        self._shared_folder_keys.delete_all()
        self._shared_folder_permissions.delete_all()
        self._folders.delete_all()
        self._folder_records.delete_all()
        self._breach_watch_records.delete_all()

    def close(self):  # type: () -> None
        if self._connection:
            self._connection.close()
            self._connection = None
