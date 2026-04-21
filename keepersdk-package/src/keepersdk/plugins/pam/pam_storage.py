import abc
import sqlite3
from typing import Callable

import attrs

from ... import sqlite_dao
from ...proto import enterprise_pb2
from ...storage import in_memory, sqlite, storage_types


@attrs.define(kw_only=True)
class PamStorageController(storage_types.IUid[str]):
    controller_uid: str = ''
    controller_name: str = ''
    device_token: str = ''
    device_name: str = ''
    node_id: int = 0
    created: int = 0
    last_modified: int = 0
    application_uid: str = ''
    app_client_type: enterprise_pb2.AppClientType = enterprise_pb2.NOT_USED
    is_initialized: bool = False

    def uid(self) -> str:
        return self.controller_uid


class IPamStorage(abc.ABC):
    @property
    @abc.abstractmethod
    def controllers(self) -> storage_types.IEntityReaderStorage[PamStorageController, str]:
        pass

    @abc.abstractmethod
    def reset(self):
        pass


class MemoryPamStorage(IPamStorage):
    def __init__(self):
        self._controllers = in_memory.InMemoryEntityStorage[PamStorageController, str]()

    @property
    def controllers(self) -> storage_types.IEntityReaderStorage[PamStorageController, str]:
        return self._controllers

    def reset(self):
        self._controllers.clear()


class SqlitePamStorage(IPamStorage):
    def __init__(self, get_connection: Callable[[], sqlite3.Connection], enterprise_id: int) -> None:
        self.get_connection = get_connection
        self.enterprise_id = enterprise_id
        self.owner_column = 'enterprise_id'
        controller_schema = sqlite_dao.TableSchema.load_schema(
            PamStorageController, 'controller_uid', owner_column=self.owner_column, owner_type=int)
        sqlite_dao.verify_database(self.get_connection(), (controller_schema,))
        self._controllers = sqlite.SqliteEntityStorage(
            self.get_connection, controller_schema, owner=enterprise_id)

    @property
    def controllers(self) -> storage_types.IEntityReaderStorage[PamStorageController, str]:
        return self._controllers

    def reset(self):
        self._controllers.delete_all()
