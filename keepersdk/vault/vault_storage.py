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
    @abc.abstractmethod
    def get_revision(self):                  # type: () -> int
        pass

    @abc.abstractmethod
    def set_revision(self, value):           # type: (int) -> None
        pass

    def get_revision_property(self):         # type: () -> int
        return self.get_revision()

    def set_revision_property(self, value):  # type: (int) -> None
        self.set_revision(value)

    revision = property(fget=get_revision_property, fset=set_revision_property)

    @abc.abstractmethod
    def get_personal_scope_uid(self):  # type: () -> str
        pass

    @property
    def personal_scope_uid(self):      # type: () -> str
        return self.get_personal_scope_uid()

    @abc.abstractmethod
    def get_records(self):   # type: () -> IEntityStorage[storage_types.StorageRecord, str]
        pass

    @property
    def records(self):
        return self.get_records()

    @abc.abstractmethod
    def get_record_types(self):   # type: () -> IEntityStorage[storage_types.StorageRecordType, str]
        pass

    @property
    def record_types(self):
        return self.get_record_types()

    @abc.abstractmethod
    def get_shared_folders(self):   # type: () -> IEntityStorage[storage_types.StorageSharedFolder, str]
        pass

    @property
    def shared_folders(self):
        return self.get_shared_folders()

    @abc.abstractmethod
    def get_teams(self):    # type: () -> IEntityStorage[storage_types.StorageTeam, str]
        pass

    @property
    def teams(self):
        return self.get_teams()

    @abc.abstractmethod
    def get_non_shared_data(self):   # type: () -> IEntityStorage[storage_types.StorageNonSharedData, str]
        pass

    @property
    def non_shared_data(self):
        return self.get_non_shared_data()

    @abc.abstractmethod
    def get_record_keys(self):      # type: () -> ILinkStorage[storage_types.StorageRecordKey, str, str]
        pass

    @property
    def record_keys(self):
        return self.get_record_keys()

    @abc.abstractmethod
    def get_shared_folder_keys(self):
        # type: () -> ILinkStorage[storage_types.StorageSharedFolderKey, str, str]
        pass

    @property
    def shared_folder_keys(self):
        return self.get_shared_folder_keys()

    @abc.abstractmethod
    def get_shared_folder_permissions(self):
        # type: () -> ILinkStorage[storage_types.StorageSharedFolderPermission, str, str]
        pass

    @property
    def shared_folder_permissions(self):
        return self.get_shared_folder_permissions()

    @abc.abstractmethod
    def get_folders(self):    # type: () -> IEntityStorage[storage_types.StorageFolder, str]
        pass

    @property
    def folders(self):
        return self.get_folders()

    @abc.abstractmethod
    def get_folder_records(self):    # type: () -> ILinkStorage[storage_types.StorageFolderRecordLink, str, str]
        pass

    @property
    def folder_records(self):
        return self.get_folder_records()

    @abc.abstractmethod
    def get_breach_watch_records(self):    # type: () -> IEntityStorage[storage_types.BreachWatchRecord, str]
        pass

    @property
    def breach_watch_records(self):
        return self.get_breach_watch_records()

    @abc.abstractmethod
    def clear(self):   # type: () -> None
        pass

    def close(self):  # type: () -> None
        pass
