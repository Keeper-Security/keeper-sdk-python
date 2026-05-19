from __future__ import annotations

import abc

from ..storage.storage_types import IEntityReaderStorage, ILinkReaderStorage, IRecordStorage
from . import keeperdrive_storage_types as kd


class IKeeperDriveStorage(abc.ABC):

    @property
    @abc.abstractmethod
    def settings(self) -> IRecordStorage[kd.KeeperDriveSettings]:
        pass

    @property
    @abc.abstractmethod
    def folders(self) -> IEntityReaderStorage[kd.KDFolder, str]:
        pass

    @property
    @abc.abstractmethod
    def folder_keys(self) -> ILinkReaderStorage[kd.KDFolderKey, str, str]:
        pass

    @property
    @abc.abstractmethod
    def folder_accesses(self) -> ILinkReaderStorage[kd.KDFolderAccess, str, str]:
        pass

    @property
    @abc.abstractmethod
    def record_data(self) -> IEntityReaderStorage[kd.KDRecordData, str]:
        pass

    @property
    @abc.abstractmethod
    def non_shared_data(self) -> IEntityReaderStorage[kd.KDNonSharedData, str]:
        pass

    @property
    @abc.abstractmethod
    def record_accesses(self) -> ILinkReaderStorage[kd.KDRecordAccess, str, str]:
        pass

    @property
    @abc.abstractmethod
    def record_links(self) -> ILinkReaderStorage[kd.KDRecordLink, str, str]:
        pass

    @property
    @abc.abstractmethod
    def breach_watch_records(self) -> IEntityReaderStorage[kd.KDBreachWatchRecord, str]:
        pass

    @property
    @abc.abstractmethod
    def security_score_data(self) -> IEntityReaderStorage[kd.KDSecurityScoreData, str]:
        pass

    @property
    @abc.abstractmethod
    def breach_watch_security_data(self) -> IEntityReaderStorage[kd.KDBreachWatchSecurityData, str]:
        pass

    @property
    @abc.abstractmethod
    def folder_records(self) -> ILinkReaderStorage[kd.KDFolderRecord, str, str]:
        pass

    @property
    @abc.abstractmethod
    def record_summaries(self) -> IEntityReaderStorage[kd.KDRecordSummary, str]:
        pass

    @property
    @abc.abstractmethod
    def list_chunks(self) -> ILinkReaderStorage[kd.KDListChunk, str, str]:
        pass

    @abc.abstractmethod
    def clear_all(self) -> None:
        pass

    def close(self) -> None:
        pass
