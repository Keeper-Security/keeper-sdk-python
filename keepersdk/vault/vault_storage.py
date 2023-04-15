#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import abc

from ..storage.types import IEntityStorage, ILinkStorage
from . import storage_types


class IVaultStorage(abc.ABC):
    @property
    @abc.abstractmethod
    def continuation_token(self) -> bytes:
        pass

    @continuation_token.setter
    @abc.abstractmethod
    def continuation_token(self, value: bytes):
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
    def record_types(self) -> IEntityStorage[storage_types.StorageRecordType, str]:
        pass

    @property
    @abc.abstractmethod
    def shared_folders(self) -> IEntityStorage[storage_types.StorageSharedFolder, str]:
        pass

    @property
    @abc.abstractmethod
    def teams(self) -> IEntityStorage[storage_types.StorageTeam, str]:
        pass

    @property
    @abc.abstractmethod
    def user_emails(self):    # type: () -> ILinkStorage[storage_types.StorageUserEmail, str]
        pass

    @property
    @abc.abstractmethod
    def non_shared_data(self) -> IEntityStorage[storage_types.StorageNonSharedData, str]:
        pass

    @property
    @abc.abstractmethod
    def record_keys(self):      # type: () -> ILinkStorage[storage_types.StorageRecordKey, str, str]
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
    def folder_records(self) -> ILinkStorage[storage_types.StorageFolderRecordLink, str, str]:
        pass

    @property
    @abc.abstractmethod
    def breach_watch_records(self) -> IEntityStorage[storage_types.BreachWatchRecord, str]:
        pass

    @abc.abstractmethod
    def clear(self) -> None:
        pass

    def close(self) -> None:
        pass
