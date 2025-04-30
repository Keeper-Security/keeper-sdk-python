import abc

from ..storage.storage_types import IEntityStorage, ILinkStorage, IRecordStorage
from . import storage_types


class IVaultStorage(abc.ABC):
    @property
    @abc.abstractmethod
    def user_settings(self) -> IRecordStorage[storage_types.UserSettings]:
        pass

    @property
    @abc.abstractmethod
    def personal_scope_uid(self) -> str:
        pass

    @property
    @abc.abstractmethod
    def records(self) -> IEntityStorage[storage_types.StorageRecord, str]:
        pass

    @property
    @abc.abstractmethod
    def record_types(self) -> IEntityStorage[storage_types.StorageRecordType, int]:
        pass

    @property
    @abc.abstractmethod
    def shared_folders(self) -> IEntityStorage[storage_types.StorageSharedFolder, str]:
        pass

    @property
    @abc.abstractmethod
    def user_emails(self) -> ILinkStorage[storage_types.StorageUserEmail, str, str]:
        pass

    @property
    @abc.abstractmethod
    def teams(self) -> IEntityStorage[storage_types.StorageTeam, str]:
        pass

    @property
    @abc.abstractmethod
    def non_shared_data(self) -> IEntityStorage[storage_types.StorageNonSharedData, str]:
        pass

    @property
    @abc.abstractmethod
    def record_keys(self) -> ILinkStorage[storage_types.StorageRecordKey, str, str]:
        pass

    @property
    @abc.abstractmethod
    def shared_folder_keys(self) -> ILinkStorage[storage_types.StorageSharedFolderKey, str, str]:
        pass

    @property
    @abc.abstractmethod
    def shared_folder_permissions(self) -> ILinkStorage[storage_types.StorageSharedFolderPermission, str, str]:
        pass

    @property
    @abc.abstractmethod
    def folders(self) -> IEntityStorage[storage_types.StorageFolder, str]:
        pass

    @property
    @abc.abstractmethod
    def folder_records(self) -> ILinkStorage[storage_types.StorageFolderRecord, str, str]:
        pass

    @property
    @abc.abstractmethod
    def breach_watch_records(self) -> IEntityStorage[storage_types.BreachWatchRecord, str]:
        pass

    @property
    @abc.abstractmethod
    def breach_watch_security_data(self) -> IEntityStorage[storage_types.BreachWatchSecurityData, str]:
        pass

    @property
    @abc.abstractmethod
    def notifications(self) -> IEntityStorage[storage_types.StorageNotification, str]:
        pass

    @abc.abstractmethod
    def clear(self) -> None:
        pass

    def close(self) -> None:
        pass
