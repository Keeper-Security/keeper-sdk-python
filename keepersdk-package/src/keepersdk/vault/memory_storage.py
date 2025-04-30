from .vault_storage import IVaultStorage
from ..storage.in_memory import InMemoryLinkStorage, InMemoryEntityStorage, InMemoryRecordStorage
from . import storage_types

class InMemoryVaultStorage(IVaultStorage):
    def __init__(self):
        self._personal_scope = 'PersonalScopeUid'

        self._user_settings = InMemoryRecordStorage[storage_types.UserSettings]()
        self._records = InMemoryEntityStorage[storage_types.StorageRecord, str]()
        self._record_types = InMemoryEntityStorage[storage_types.StorageRecordType, int]()
        self._shared_folders = InMemoryEntityStorage[storage_types.StorageSharedFolder, str]()
        self._user_emails = InMemoryLinkStorage[storage_types.StorageUserEmail, str, str]()
        self._teams = InMemoryEntityStorage[storage_types.StorageTeam, str]()
        self._non_shared_data = InMemoryEntityStorage[storage_types.StorageNonSharedData, str]()

        self._record_keys = InMemoryLinkStorage[storage_types.StorageRecordKey, str, str]()
        self._shared_folder_keys = InMemoryLinkStorage[storage_types.StorageSharedFolderKey, str, str]()
        self._shared_folder_permissions = InMemoryLinkStorage[storage_types.StorageSharedFolderPermission, str, str]()

        self._folders = InMemoryEntityStorage[storage_types.StorageFolder, str]()
        self._folder_records = InMemoryLinkStorage[storage_types.StorageFolderRecord, str, str]()

        self._breach_watch_records = InMemoryEntityStorage[storage_types.BreachWatchRecord, str]()
        self._breach_watch_security_data = InMemoryEntityStorage[storage_types.BreachWatchSecurityData, str]()

        self._notifications = InMemoryEntityStorage[storage_types.StorageNotification, str]()

    @property
    def user_settings(self):
        return self._user_settings

    @property
    def personal_scope_uid(self):
        return self._personal_scope

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
    def user_emails(self):
        return self._user_emails

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

    @property
    def notifications(self):
        return self._notifications

    def clear(self):
        self._user_settings.delete()
        self._records.clear()
        self._record_types.clear()

        self._shared_folders.clear()
        self._teams.clear()
        self._non_shared_data.clear()

        self._record_keys.clear()
        self._shared_folder_keys.clear()
        self._shared_folder_permissions.clear()

        self._folders.clear()
        self._folder_records.clear()

        self._breach_watch_records.clear()
        self._breach_watch_security_data.clear()

        self._notifications.clear()
