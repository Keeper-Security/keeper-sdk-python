import abc
import sqlite3
from typing import Callable

import attrs

from ... import sqlite_dao
from ...storage import storage_types, sqlite, in_memory
from ...storage.storage_types import K, KS, KO


@attrs.define(kw_only=True)
class PedmStreamSettings(storage_types.IUid[str]):
    stream_uid: str = ''
    sync_point: int = 0
    def uid(self) -> str:
        return self.stream_uid


@attrs.define(kw_only=True)
class PedmEntityData(storage_types.IUid[str]):
    entity_uid: str = ''
    entity_type: int = 0
    data: bytes = b''
    def uid(self) -> str:
        return self.entity_uid

@attrs.define(kw_only=True)
class PedmLinkData(storage_types.IUidLink[str, str]):
    entity_uid: str = ''
    parent_uid: str = ''
    link_type: int = 0
    data: bytes = b''
    def subject_uid(self) -> str:
        return self.entity_uid
    def object_uid(self) -> str:
        return self.parent_uid


class IPedmStorage(abc.ABC):
    @property
    @abc.abstractmethod
    def settings(self) -> storage_types.IEntityStorage[PedmStreamSettings, str]:
        pass

    @property
    @abc.abstractmethod
    def entities(self) -> storage_types.IEntityStorage[PedmEntityData, str]:
        pass

    @property
    @abc.abstractmethod
    def links(self) -> storage_types.ILinkStorage[PedmLinkData, str, str]:
        pass

    @abc.abstractmethod
    def reset(self):
        pass


class MemoryPedmStorage(IPedmStorage):
    def __init__(self):
        self._settings = in_memory.InMemoryEntityStorage[PedmStreamSettings, str]()
        self._entity_data = in_memory.InMemoryEntityStorage[PedmEntityData, str]()
        self._link_data = in_memory.InMemoryLinkStorage[PedmLinkData, str, str]()

    @property
    def settings(self) -> storage_types.IEntityStorage[PedmStreamSettings, str]:
        return self._settings

    @property
    def entities(self) -> storage_types.IEntityStorage[PedmEntityData, str]:
        return self._entity_data

    @property
    def links(self) -> storage_types.ILinkStorage[PedmLinkData, str, str]:
        return self._link_data

    def reset(self):
        self._settings.delete()
        self._entity_data.clear()
        self._link_data.clear()


class SqlitePedmStorage(IPedmStorage):
    def __init__(self, get_connection: Callable[[], sqlite3.Connection], enterprise_id: int):
        self.get_connection = get_connection
        self.enterprise_id = enterprise_id
        self.owner_column = 'enterprise_id'
        setting_schema = sqlite_dao.TableSchema.load_schema(
            PedmStreamSettings, 'stream_uid', owner_column=self.owner_column, owner_type=int)
        entity_schema = sqlite_dao.TableSchema.load_schema(
            PedmEntityData, primary_key='entity_uid', owner_column=self.owner_column, owner_type=int)
        link_schema = sqlite_dao.TableSchema.load_schema(
            PedmLinkData, primary_key=['entity_uid', 'parent_uid'], indexes={'PARENT_UID': 'parent_uid'},
            owner_column=self.owner_column, owner_type=int)

        sqlite_dao.verify_database(self.get_connection(), (setting_schema, entity_schema, link_schema))

        self._settings = sqlite.SqliteEntityStorage(self.get_connection, setting_schema, owner=self.enterprise_id)
        self._entities = sqlite.SqliteEntityStorage(self.get_connection, entity_schema, owner=self.enterprise_id)
        self._links = sqlite.SqliteLinkStorage(self.get_connection, link_schema, owner=self.enterprise_id)

    @property
    def settings(self) -> storage_types.IEntityStorage[PedmStreamSettings, str]:
        return self._settings

    @property
    def entities(self) -> storage_types.IEntityStorage[PedmEntityData, str]:
        return self._entities

    @property
    def links(self) -> storage_types.ILinkStorage[PedmLinkData, str, str]:
        return self._links

    def reset(self):
        self._settings.delete_all()
        self._entities.delete_all()
        self._links.delete_all()
