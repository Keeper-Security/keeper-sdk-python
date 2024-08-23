import abc
import sqlite3
from typing import Optional, Callable, Dict, Any

import attrs

from ...storage import storage_types, sqlite, in_memory
from ... import sqlite_dao
from ...storage.storage_types import K


@attrs.define(kw_only=True, frozen=True)
class PolicyInformation(storage_types.IUid[str]):
    policy_uid: str
    name: str
    data: Dict[str, Any]
    def uid(self) -> str:
        return self.policy_uid

@attrs.define(kw_only=True)
class PedmAgentSettings:
    sync_point: int = 0


@attrs.define(kw_only=True)
class PedmAgentPolicy(storage_types.IUid[str]):
    policy_uid: str = ''
    key: bytes = b''
    data: bytes = b''
    def uid(self) -> str:
        return self.policy_uid


class IPedmAgentStorage(abc.ABC):
    @property
    @abc.abstractmethod
    def settings(self) -> storage_types.IRecordStorage[PedmAgentSettings]:
        pass

    @property
    @abc.abstractmethod
    def policies(self) -> storage_types.IEntityStorage[PedmAgentPolicy, str]:
        pass

    @abc.abstractmethod
    def reset(self):
        pass


class MemoryPedmAgentStorage(IPedmAgentStorage):
    def __init__(self):
        self._settings = in_memory.InMemoryRecordStorage[PedmAgentSettings]()
        self._policies = in_memory.InMemoryEntityStorage[PedmAgentPolicy, str]()

    @property
    def settings(self) -> storage_types.IRecordStorage[PedmAgentSettings]:
        return self._settings

    @property
    def policies(self) -> storage_types.IEntityStorage[PedmAgentPolicy, str]:
        return self._policies

    def reset(self):
        self._settings.delete()
        self._policies.clear()


class SqlitePedmAgentStorage(IPedmAgentStorage):
    def __init__(self, get_connection: Callable[[], sqlite3.Connection], agent_uid: str):
        self.get_connection = get_connection
        self.agent_uid = agent_uid
        self.owner_column = 'agent_uid'
        setting_schema = sqlite_dao.TableSchema.load_schema(
            PedmAgentSettings, [], owner_column=self.owner_column, owner_type=str)
        policy_schema = sqlite_dao.TableSchema.load_schema(
            PedmAgentPolicy, primary_key='policy_uid', owner_column=self.owner_column, owner_type=str)

        sqlite_dao.verify_database(self.get_connection(), (setting_schema, policy_schema))
        self._settings = sqlite.SqliteRecordStorage(self.get_connection, setting_schema, owner=self.agent_uid)
        self._policies = sqlite.SqliteEntityStorage(self.get_connection, policy_schema, owner=self.agent_uid)

    @property
    def settings(self) -> storage_types.IRecordStorage[PedmAgentSettings]:
        return self._settings

    @property
    def policies(self) -> storage_types.IEntityStorage[PedmAgentPolicy, str]:
        return self._policies

    def reset(self):
        self._settings.delete_all()
        self._policies.delete_all()
