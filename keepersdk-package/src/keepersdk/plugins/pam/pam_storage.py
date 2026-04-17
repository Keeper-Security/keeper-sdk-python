import sqlite3
import attrs
import abc
from typing import Callable

from ...storage.storage_types import IEntityReaderStorage, IUid
from ...storage.in_memory import InMemoryEntityStorage
from ...storage.sqlite import sqlite_dao, SqliteEntityStorage
from ...proto import enterprise_pb2

@attrs.define(kw_only=True)
class PamStorageController(IUid[str]):
    controller_uid: str
    controller_name: str
    device_token: str
    device_name: str
    node_id: int
    created: int
    last_modified: int
    application_uid: str
    app_client_type: enterprise_pb2.AppClientType
    is_initialized: bool
    def uid(self) -> str:
        return self.controller_uid
    

class IPAMStorage(abc.ABC):
    @property
    @abc.abstractmethod
    def controller_storage(self) -> IEntityReaderStorage[PamStorageController, bytes]:
        pass

    @abc.abstractmethod
    def reset(self):
        pass


class MemoryPamStorage(IPAMStorage):
    def __init__(self):
        self._controller_storage = InMemoryEntityStorage[PamStorageController, str]()

    @property
    def controller_storage(self) -> IEntityReaderStorage[PamStorageController, str]:
        return self._controller_storage

    def reset(self):
        self._controller_storage.clear()


class SqlitePamStorage(IPAMStorage):
    def __init__(self, get_connection: Callable[[], sqlite3.Connection], enterprise_id: int) -> None:
        self.get_connection = get_connection
        self.enterprise_id = enterprise_id
        self.owner_column = 'enterprise_id'
        controller_schema = sqlite_dao.TableSchema.load_schema(
            PamStorageController, 'controller_uid', owner_column=self.owner_column, owner_type=int)
        sqlite_dao.verify_database(self.get_connection(),(controller_schema,))
        self._controller_storage = SqliteEntityStorage(self.get_connection, controller_schema, owner=enterprise_id)

    @property
    def controller_storage(self) -> IEntityReaderStorage[PamStorageController, str]:
        return self._controller_storage

    def reset(self):
        self._controller_storage.delete_all()