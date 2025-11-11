import abc
import attrs

from typing import TypeVar, Generic, Optional, Union, Tuple, Iterable

K = TypeVar('K', int, str, bytes)
class IUid(Generic[K], abc.ABC):
    @abc.abstractmethod
    def uid(self) -> K:
        pass


KS = TypeVar('KS', int, str, bytes)
KO = TypeVar('KO', int, str, bytes)
class IUidLink(Generic[KS, KO], abc.ABC):
    @abc.abstractmethod
    def subject_uid(self) -> KS:
        pass

    @abc.abstractmethod
    def object_uid(self) -> KO:
        pass


@attrs.define(frozen=True, order=True)
class Uid(IUid[str]):
    _uid: str

    def uid(self) -> str:
        return self._uid

@attrs.define(frozen=True, order=True)
class UidLink(IUidLink[KS, KO]):
    _subject_uid: KS
    _object_uid: KO

    def subject_uid(self) -> KS:
        return self._subject_uid

    def object_uid(self) -> KO:
        return self._object_uid


T = TypeVar('T')
class IRecordStorage(Generic[T], abc.ABC):
    @abc.abstractmethod
    def load(self) -> Optional[T]:
        pass

    @abc.abstractmethod
    def store(self, record: T):
        pass

    @abc.abstractmethod
    def delete(self):
        pass


class IEntityReader(Generic[T, K], abc.ABC):
    @abc.abstractmethod
    def get_all_entities(self) -> Iterable[T]:
        pass

    @abc.abstractmethod
    def get_entity(self, key: K) -> Optional[T]:
        pass


class ILinkReader(Generic[T, KS, KO], abc.ABC):
    @abc.abstractmethod
    def get_link(self, subject_id: KS, object_id: KO) -> Optional[T]:
        pass

    @abc.abstractmethod
    def get_links_by_subject(self, subject_id: KS) -> Iterable[T]:
        pass

    @abc.abstractmethod
    def get_links_by_object(self, object_id: KO) -> Iterable[T]:
        pass

    @abc.abstractmethod
    def get_all_links(self) -> Iterable[T]:
        pass


class IEntityReaderStorage(IEntityReader[T, K]):
    @abc.abstractmethod
    def put_entities(self, entities: Iterable[T]) -> None:
        pass

    @abc.abstractmethod
    def delete_uids(self, uids: Iterable[K]) -> None:
        pass


class ILinkReaderStorage(Generic[T, KS, KO], ILinkReader[T, KS, KO]):
    @abc.abstractmethod
    def put_links(self, links: Iterable[T]):
        pass

    @abc.abstractmethod
    def delete_links(self, links: Iterable[Union[Tuple[KS, KO], IUidLink[KS, KO]]]):
        pass

    @abc.abstractmethod
    def delete_links_by_subjects(self, subject_uids: Iterable[KS]):
        pass

    @abc.abstractmethod
    def delete_links_by_objects(self, object_uids: Iterable[KO]):
        pass
