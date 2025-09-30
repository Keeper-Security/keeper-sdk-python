import abc
import sqlite3
from typing import Callable

import attrs

from ... import sqlite_dao
from ...storage import storage_types, sqlite, in_memory


@attrs.define(kw_only=True)
class PedmAgentSettings:
    token: bytes = b''


@attrs.define(kw_only=True)
class PedmAgentPolicy(storage_types.IUid[str]):
    policy_uid: str = ''
    key: bytes = b''
    data: bytes = b''
    disabled: bool = False
    def uid(self) -> str:
        return self.policy_uid

@attrs.define(kw_only=True)
class PedmAgentApproval(storage_types.IUid[str]):
    approval_uid: str = ''
    approval_type: int = 0
    account_info: bytes = b''
    application_info: bytes = b''
    justification: bytes = b''
    expire_in: int = 0
    created: int = 0
    def uid(self) -> str:
        return self.approval_uid

@attrs.define(kw_only=True)
class PedmAgentApprovalStatus(storage_types.IUid[str]):
    approval_uid: str = ''
    approval_status: int = 0
    modified: int = 0
    def uid(self) -> str:
        return self.approval_uid

@attrs.define(kw_only=True)
class PedmAgentCollection(storage_types.IUid[str]):
    collection_uid: str = ''
    collection_type: int = 0
    data: bytes = b''
    def uid(self) -> str:
        return self.collection_uid

class IPedmAgentStorage(abc.ABC):
    @property
    @abc.abstractmethod
    def settings(self) -> storage_types.IRecordStorage[PedmAgentSettings]:
        pass

    @property
    @abc.abstractmethod
    def policies(self) -> storage_types.IEntityStorage[PedmAgentPolicy, str]:
        pass

    @property
    @abc.abstractmethod
    def collections(self) -> storage_types.IEntityStorage[PedmAgentCollection, str]:
        pass

    @property
    @abc.abstractmethod
    def approvals(self) -> storage_types.IEntityStorage[PedmAgentApproval, str]:
        pass

    @property
    @abc.abstractmethod
    def approval_status(self) -> storage_types.IEntityStorage[PedmAgentApprovalStatus, str]:
        pass

    @abc.abstractmethod
    def reset(self):
        pass


class MemoryPedmAgentStorage(IPedmAgentStorage):
    def __init__(self):
        self._settings = in_memory.InMemoryRecordStorage[PedmAgentSettings]()
        self._policies = in_memory.InMemoryEntityStorage[PedmAgentPolicy, str]()
        self._collections = in_memory.InMemoryEntityStorage[PedmAgentCollection, str]()
        self._approvals = in_memory.InMemoryEntityStorage[PedmAgentApproval, str]()
        self._approval_status = in_memory.InMemoryEntityStorage[PedmAgentApprovalStatus, str]()

    @property
    def settings(self) -> storage_types.IRecordStorage[PedmAgentSettings]:
        return self._settings

    @property
    def policies(self) -> storage_types.IEntityStorage[PedmAgentPolicy, str]:
        return self._policies

    @property
    def collections(self) -> storage_types.IEntityStorage[PedmAgentCollection, str]:
        return self._collections

    @property
    def approvals(self) -> storage_types.IEntityStorage[PedmAgentApproval, str]:
        return self._approvals

    @property
    def approval_status(self) -> storage_types.IEntityStorage[PedmAgentApprovalStatus, str]:
        return self._approval_status

    def reset(self):
        self._settings.delete()
        self._policies.clear()
        self._collections.clear()
        self._approval_status.clear()


class SqlitePedmAgentStorage(IPedmAgentStorage):
    def __init__(self, get_connection: Callable[[], sqlite3.Connection], agent_uid: str):
        self.get_connection = get_connection
        self.agent_uid = agent_uid
        self.owner_column = 'agent_uid'
        setting_schema = sqlite_dao.TableSchema.load_schema(
            PedmAgentSettings, [], owner_column=self.owner_column, owner_type=str)
        policy_schema = sqlite_dao.TableSchema.load_schema(
            PedmAgentPolicy, primary_key='policy_uid', owner_column=self.owner_column, owner_type=str)
        collection_schema = sqlite_dao.TableSchema.load_schema(
            PedmAgentCollection, primary_key='collection_uid', owner_column=self.owner_column, owner_type=str)
        approval_status = sqlite_dao.TableSchema.load_schema(
            PedmAgentApproval, primary_key='approval_uid', owner_column=self.owner_column, owner_type=str)
        approval_status_schema = sqlite_dao.TableSchema.load_schema(
            PedmAgentApprovalStatus, primary_key='approval_uid', owner_column=self.owner_column, owner_type=str)

        sqlite_dao.verify_database(
            self.get_connection(),(setting_schema, policy_schema, collection_schema,
                                   approval_status, approval_status_schema))

        self._settings = sqlite.SqliteRecordStorage(self.get_connection, setting_schema, owner=self.agent_uid)
        self._policies = sqlite.SqliteEntityStorage(self.get_connection, policy_schema, owner=self.agent_uid)
        self._collections = sqlite.SqliteEntityStorage(self.get_connection, collection_schema, owner=self.agent_uid)
        self._approvals = sqlite.SqliteEntityStorage(self.get_connection, approval_status, owner=self.agent_uid)
        self._approval_status = sqlite.SqliteEntityStorage(self.get_connection, approval_status_schema, owner=self.agent_uid)

    @property
    def settings(self) -> storage_types.IRecordStorage[PedmAgentSettings]:
        return self._settings

    @property
    def policies(self) -> storage_types.IEntityStorage[PedmAgentPolicy, str]:
        return self._policies

    @property
    def collections(self) -> storage_types.IEntityStorage[PedmAgentCollection, str]:
        return self._collections

    # @property
    # def collection_links(self) -> storage_types.ILinkStorage[PedmAgentCollectionLink, str, str]:
    #     return self._collection_links

    @property
    def approvals(self) -> storage_types.IEntityStorage[PedmAgentApproval, str]:
        return self._approvals

    @property
    def approval_status(self) -> storage_types.IEntityStorage[PedmAgentApprovalStatus, str]:
        return self._approval_status

    def reset(self):
        self._settings.delete_all()
        self._policies.delete_all()
        self._collections.delete_all()
        # self._collection_links.delete_all()
        self._approvals.delete_all()
        self._approval_status.delete_all()
