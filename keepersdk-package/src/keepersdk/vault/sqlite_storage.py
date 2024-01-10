import sqlite3
from typing import Callable

from . import vault_storage, storage_types
from .. import sqlite_dao, utils
from ..storage import sqlite


class SqliteVaultStorage(vault_storage.IVaultStorage):
    def __init__(self, get_connection: Callable[[], sqlite3.Connection], vault_owner: bytes) -> None:
        self.get_connection: Callable[[], sqlite3.Connection] = get_connection
        self.vault_owner: bytes = vault_owner
        self._personal_scope_uid = utils.base64_url_encode(vault_owner)
        self.owner_column = 'owner_uid'
        settings_schema = sqlite_dao.TableSchema.load_schema(
            storage_types.UserSettings, [], owner_column=self.owner_column, owner_type=bytes)
        record_schema = sqlite_dao.TableSchema.load_schema(
            storage_types.StorageRecord, 'record_uid', owner_column=self.owner_column, owner_type=bytes)
        shared_folder_schema = sqlite_dao.TableSchema.load_schema(
            storage_types.StorageSharedFolder, 'shared_folder_uid', owner_column=self.owner_column, owner_type=bytes)
        team_schema = sqlite_dao.TableSchema.load_schema(
            storage_types.StorageTeam, 'team_uid', owner_column=self.owner_column, owner_type=bytes)
        non_shared_data_schema = sqlite_dao.TableSchema.load_schema(
            storage_types.StorageNonSharedData, 'record_uid', owner_column=self.owner_column, owner_type=bytes)
        record_key_schema = sqlite_dao.TableSchema.load_schema(
            storage_types.StorageRecordKey, ['record_uid', 'shared_folder_uid'],
            indexes={'SharedFolderUID': ['shared_folder_uid']}, owner_column=self.owner_column, owner_type=bytes)
        shared_folder_key_schema = sqlite_dao.TableSchema.load_schema(
            storage_types.StorageSharedFolderKey, ['shared_folder_uid', 'team_uid'],
            indexes={'TeamUID': ['team_uid']}, owner_column=self.owner_column, owner_type=bytes)
        shared_folder_permission_schema = sqlite_dao.TableSchema.load_schema(
            storage_types.StorageSharedFolderPermission, ['shared_folder_uid', 'user_uid'],
            indexes={'UserUID': ['user_uid']}, owner_column=self.owner_column, owner_type=bytes)
        user_email_schema = sqlite_dao.TableSchema.load_schema(
            storage_types.StorageUserEmail, ['account_uid', 'email'], indexes={'Email': ['email']},
            owner_column=self.owner_column, owner_type=bytes)
        folder_schema = sqlite_dao.TableSchema.load_schema(
            storage_types.StorageFolder, 'folder_uid', owner_column=self.owner_column, owner_type=bytes)
        folder_record_schema = sqlite_dao.TableSchema.load_schema(
            storage_types.StorageFolderRecord, ['folder_uid', 'record_uid'],
            indexes={'RecordUID': ['record_uid']}, owner_column=self.owner_column, owner_type=bytes)
        breach_watch_record_schema = sqlite_dao.TableSchema.load_schema(
            storage_types.BreachWatchRecord, 'record_uid', owner_column=self.owner_column, owner_type=bytes)
        breach_watch_security_data_schema = sqlite_dao.TableSchema.load_schema(
            storage_types.BreachWatchSecurityData, 'record_uid', owner_column=self.owner_column, owner_type=bytes)

        record_type_schema = sqlite_dao.TableSchema.load_schema(
            storage_types.StorageRecordType, 'id', owner_column=self.owner_column, owner_type=bytes)

        sqlite_dao.verify_database(self.get_connection(),
                                   (settings_schema, team_schema, record_schema, shared_folder_schema,
                                    non_shared_data_schema, record_key_schema, shared_folder_key_schema,
                                    shared_folder_permission_schema, user_email_schema, folder_schema,
                                    folder_record_schema, breach_watch_record_schema, breach_watch_security_data_schema,
                                    record_type_schema))

        self._settings_storage = sqlite.SqliteRecordStorage(
            self.get_connection, settings_schema, owner=self.vault_owner)

        self._records = sqlite.SqliteEntityStorage(
            self.get_connection, record_schema, owner=self.vault_owner)
        self._record_types = sqlite.SqliteEntityStorage(
            self.get_connection, record_type_schema, owner=self.vault_owner)

        self._shared_folders = sqlite.SqliteEntityStorage(
            self.get_connection, shared_folder_schema, owner=self.vault_owner)
        self._user_emails = sqlite.SqliteLinkStorage(
            self.get_connection, user_email_schema, owner=self.vault_owner)
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

        self._breach_watch_security_data = sqlite.SqliteEntityStorage(
            self.get_connection, breach_watch_security_data_schema, owner=self.vault_owner)

    @property
    def user_settings(self):
        return self._settings_storage

    @property
    def personal_scope_uid(self):
        return self._personal_scope_uid

    @property
    def records(self):
        return self._records

    @property
    def record_types(self):
        return self._record_types

    @property
    def shared_folders(self):
        return self._shared_folders

    @property
    def user_emails(self):
        return self._user_emails

    @property
    def teams(self):
        return self._teams

    @property
    def non_shared_data(self):
        return self._non_shared_data

    @property
    def record_keys(self):
        return self._record_keys

    @property
    def shared_folder_keys(self):
        return self._shared_folder_keys

    @property
    def shared_folder_permissions(self):
        return self._shared_folder_permissions

    @property
    def folders(self):
        return self._folders

    @property
    def folder_records(self):
        return self._folder_records

    @property
    def breach_watch_records(self):
        return self._breach_watch_records

    @property
    def breach_watch_security_data(self):
        return self._breach_watch_security_data

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
        self._breach_watch_security_data.delete_all()
        self._user_emails.delete_all()

    def close(self) -> None:
        pass
