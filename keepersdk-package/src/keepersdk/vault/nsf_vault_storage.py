from __future__ import annotations

import abc

from ..storage.storage_types import IEntityReaderStorage, ILinkReaderStorage, IRecordStorage
from . import nsf_storage_types as nsf


class INSFStorage(abc.ABC):

    @property
    @abc.abstractmethod
    def settings(self) -> IRecordStorage[nsf.NSFSettings]:
        pass

    @property
    @abc.abstractmethod
    def folders(self) -> IEntityReaderStorage[nsf.NSFFolder, str]:
        pass

    @property
    @abc.abstractmethod
    def folder_keys(self) -> ILinkReaderStorage[nsf.NSFFolderKey, str, str]:
        pass

    @property
    @abc.abstractmethod
    def records(self) -> IEntityReaderStorage[nsf.NSFRecord, str]:
        pass

    @property
    @abc.abstractmethod
    def record_keys(self) -> ILinkReaderStorage[nsf.NSFRecordKey, str, str]:
        pass

    @property
    @abc.abstractmethod
    def folder_accesses(self) -> ILinkReaderStorage[nsf.NSFFolderAccess, str, str]:
        pass

    @property
    @abc.abstractmethod
    def record_accesses(self) -> ILinkReaderStorage[nsf.NSFRecordAccess, str, str]:
        pass

    @property
    @abc.abstractmethod
    def record_links(self) -> ILinkReaderStorage[nsf.NSFRecordLink, str, str]:
        pass

    @property
    @abc.abstractmethod
    def folder_records(self) -> ILinkReaderStorage[nsf.NSFFolderRecord, str, str]:
        pass

    @property
    @abc.abstractmethod
    def folder_sharing_states(self) -> IEntityReaderStorage[nsf.NSFFolderSharingState, str]:
        pass

    @property
    @abc.abstractmethod
    def record_sharing_states(self) -> IEntityReaderStorage[nsf.NSFRecordSharingState, str]:
        pass

    @property
    @abc.abstractmethod
    def non_shared_data(self) -> IEntityReaderStorage[nsf.NSFNonSharedData, str]:
        pass

    @property
    @abc.abstractmethod
    def breach_watch_records(self) -> IEntityReaderStorage[nsf.NSFBreachWatchRecord, str]:
        pass

    @property
    @abc.abstractmethod
    def security_score_data(self) -> IEntityReaderStorage[nsf.NSFSecurityScoreData, str]:
        pass

    @property
    @abc.abstractmethod
    def breach_watch_security_data(self) -> IEntityReaderStorage[nsf.NSFBreachWatchSecurityData, str]:
        pass

    @property
    @abc.abstractmethod
    def list_chunks(self) -> ILinkReaderStorage[nsf.NSFListChunk, str, str]:
        pass

    @abc.abstractmethod
    def clear_all(self) -> None:
        pass

    def close(self) -> None:
        pass
