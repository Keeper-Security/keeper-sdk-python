import abc

from ..storage.storage_types import IEntityReaderStorage, ILinkReaderStorage, IRecordStorage
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
    def records(self) -> IEntityReaderStorage[storage_types.StorageRecord, str]:
        pass

    @property
    @abc.abstractmethod
    def record_types(self) -> IEntityReaderStorage[storage_types.StorageRecordType, int]:
        pass

    @property
    @abc.abstractmethod
    def shared_folders(self) -> IEntityReaderStorage[storage_types.StorageSharedFolder, str]:
        pass

    @property
    @abc.abstractmethod
    def user_emails(self) -> ILinkReaderStorage[storage_types.StorageUserEmail, str, str]:
        pass

    @property
    @abc.abstractmethod
    def teams(self) -> IEntityReaderStorage[storage_types.StorageTeam, str]:
        pass

    @property
    @abc.abstractmethod
    def non_shared_data(self) -> IEntityReaderStorage[storage_types.StorageNonSharedData, str]:
        pass

    @property
    @abc.abstractmethod
    def record_keys(self) -> ILinkReaderStorage[storage_types.StorageRecordKey, str, str]:
        pass

    @property
    @abc.abstractmethod
    def shared_folder_keys(self) -> ILinkReaderStorage[storage_types.StorageSharedFolderKey, str, str]:
        pass

    @property
    @abc.abstractmethod
    def shared_folder_permissions(self) -> ILinkReaderStorage[storage_types.StorageSharedFolderPermission, str, str]:
        pass

    @property
    @abc.abstractmethod
    def folders(self) -> IEntityReaderStorage[storage_types.StorageFolder, str]:
        pass

    @property
    @abc.abstractmethod
    def folder_records(self) -> ILinkReaderStorage[storage_types.StorageFolderRecord, str, str]:
        pass

    @property
    @abc.abstractmethod
    def breach_watch_records(self) -> IEntityReaderStorage[storage_types.BreachWatchRecord, str]:
        pass

    @property
    @abc.abstractmethod
    def breach_watch_security_data(self) -> IEntityReaderStorage[storage_types.BreachWatchSecurityData, str]:
        pass

    @property
    @abc.abstractmethod
    def notifications(self) -> IEntityReaderStorage[storage_types.StorageNotification, str]:
        pass

    @abc.abstractmethod
    def clear(self) -> None:
        pass

    def close(self) -> None:
        pass
