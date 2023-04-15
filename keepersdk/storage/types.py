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

from dataclasses import dataclass
from typing import TypeVar, Generic, Optional, Union, Tuple, Iterable, Iterator

K = TypeVar('K', int, str, bytes)


class IUid(Generic[K], abc.ABC):
    @abc.abstractmethod
    def uid(self) -> K:
        pass


@dataclass(frozen=True)
class Uid(IUid[str]):
    _uid: str

    def uid(self) -> str:
        return self._uid


KS = TypeVar('KS', int, str, bytes)
KO = TypeVar('KO', int, str, bytes)


class IUidLink(Generic[KS, KO], abc.ABC):
    @abc.abstractmethod
    def subject_uid(self) -> KS:
        pass

    @abc.abstractmethod
    def object_uid(self) -> KO:
        pass


@dataclass(frozen=True)
class UidLink(IUidLink[str, str]):
    _subject_uid: str
    _object_uid: str

    def subject_uid(self) -> str:
        return self._subject_uid

    def object_uid(self) -> str:
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


class IEntityStorage(Generic[T, K], abc.ABC):
    @abc.abstractmethod
    def get_entity(self, uid: K) -> Optional[T]:
        pass

    @abc.abstractmethod
    def get_all(self) -> Iterator[T]:
        pass

    @abc.abstractmethod
    def put_entities(self, entities: Iterable[T]):
        pass

    @abc.abstractmethod
    def delete_uids(self, uids: Iterable[K]):
        pass


class ILinkStorage(Generic[T, KS, KO], abc.ABC):
    @abc.abstractmethod
    def put_links(self, links: Iterable[T]):
        pass

    @abc.abstractmethod
    def delete_links(self, links: Iterable[Union[Tuple[KS, KO], IUidLink[KS, KO]]]):
        pass

    @abc.abstractmethod
    def delete_links_for_subjects(self, subject_uids: Iterable[KS]):
        pass

    @abc.abstractmethod
    def delete_links_for_objects(self, object_uids: Iterable[KS]):
        pass

    @abc.abstractmethod
    def get_links_for_subject(self, subject_uid) -> Iterator[T]:
        pass

    @abc.abstractmethod
    def get_links_for_object(self, object_uid) -> Iterator[T]:
        pass

    @abc.abstractmethod
    def get_all_links(self) -> Iterator[T]:
        pass
