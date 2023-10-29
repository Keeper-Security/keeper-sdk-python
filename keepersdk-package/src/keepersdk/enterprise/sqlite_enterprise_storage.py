import abc
import sqlite3
from dataclasses import dataclass
from typing import Callable, Any, Dict, Sequence, Tuple, Optional, Set, Iterable

from .enterprise_types import EnterpriseEntityMap, EnterpriseStorage
from .. import utils, sqlite_dao
from ..proto import enterprise_pb2
from ..storage import sqlite, types as storage_types


@dataclass
class EnterpriseSettings:
    continuation_token: bytes = b''


@dataclass
class EnterpriseEntityData:
    type: int = 0
    key: str = ''
    data: bytes = b''


class _DataType(abc.ABC):
    @abc.abstractmethod
    def get_proto_entity_key(self, entity) -> str:
        pass


class _MergeDataType(_DataType, abc.ABC):
    @abc.abstractmethod
    def merge(self, existing: Optional[Any], new, is_delete: bool) -> Tuple[Any, bool]:
        pass


class _SimpleDataType(_DataType):
    def __init__(self, keys: Sequence[str]) -> None:
        self.keys = keys

    def get_proto_entity_key(self, entity: Any) -> str:
        values = []
        for key in self.keys:
            value = getattr(entity, key)
            if isinstance(value, str):
                pass
            elif isinstance(value, bytes):
                value = utils.base64_url_encode(value)
            elif isinstance(value, int):
                value = str(value)
            values.append(value)
        return ':'.join(values)


class _QueuedTeamUserDataType(_MergeDataType):
    def get_proto_entity_key(self, entity):
        return utils.base64_url_encode(entity.teamUid)

    def merge(self, existing, new, is_delete):
        users = {x for x in new.users}
        if existing is not None:
            if is_delete:
                users.difference_update(existing.users)
            else:
                users.update(existing.users)
        new.users.clear()
        if len(users) > 0:
            new.users.extend(users)
        return new, len(users) > 0


@dataclass(frozen=True)
class _EntityKey:
    type: enterprise_pb2.EnterpriseDataEntity
    key: str


class _EnterpriseEntityStorage(sqlite_dao.SqliteStorage):
    def __init__(self, get_connection: Callable[[], sqlite3.Connection], schema: sqlite_dao.TableSchema,
                 owner: Optional[sqlite_dao.KeyTypes]=None) -> None:
        super(_EnterpriseEntityStorage, self).__init__(get_connection, schema, owner)
        if len(self.schema.primary_key) != 2:
            raise ValueError(f'SqliteEntityStorage: Primary key to have two column.')

    def get_all(self):
        for entity in self.select_all():
            yield entity

    def get_entity(self, entity_type, key):
        return next(self.select_by_filter(self.schema.primary_key, [entity_type, key]), None)

    def delete_entities(self, keys: Iterable[_EntityKey]) -> None:
        self.delete_by_filter(
            self.schema.primary_key, ((x.type, x.key) for x in keys), multiple_criteria=True)


class SqliteEnterpriseStorage(EnterpriseStorage):
    def __init__(self, get_connection: Callable[[], sqlite3.Connection], enterprise_id: int) -> None:
        self.get_connection = get_connection
        self.enterprise_id = enterprise_id
        self.owner_column = 'enterprise_id'
        self._put_cache: Dict[_EntityKey, EnterpriseEntityData] = {}
        self._delete_cache: Set[_EntityKey] = set()

        settings_schema = sqlite_dao.TableSchema.load_schema(
            EnterpriseSettings, [], owner_column=self.owner_column, owner_type=int)
        data_schema = sqlite_dao.TableSchema.load_schema(
            EnterpriseEntityData, ['type', 'key'], owner_column=self.owner_column, owner_type=int)

        sqlite_dao.verify_database(self.get_connection(), (settings_schema, data_schema))
        self._settings_storage: storage_types.IRecordStorage[EnterpriseSettings] = sqlite.SqliteRecordStorage(
            self.get_connection, settings_schema, owner=self.enterprise_id)
        self._data_storage = _EnterpriseEntityStorage(self.get_connection, data_schema, owner=self.enterprise_id)

        self._data_types: Dict[int, _DataType] = {
            enterprise_pb2.NODES: _SimpleDataType(['nodeId']),
            enterprise_pb2.USERS: _SimpleDataType(['enterpriseUserId']),
            enterprise_pb2.TEAMS: _SimpleDataType(['teamUid']),
            enterprise_pb2.ROLES: _SimpleDataType(['roleId']),
            enterprise_pb2.LICENSES: _SimpleDataType(['enterpriseLicenseId']),
            enterprise_pb2.QUEUED_TEAMS: _SimpleDataType(['teamUid']),
            enterprise_pb2.SCIMS: _SimpleDataType(['scimId']),
            enterprise_pb2.SSO_SERVICES: _SimpleDataType(['nodeId']),
            enterprise_pb2.BRIDGES: _SimpleDataType(['bridgeId']),
            enterprise_pb2.EMAIL_PROVISION: _SimpleDataType(['id']),
            enterprise_pb2.TEAM_USERS: _SimpleDataType(['teamUid', 'enterpriseUserId']),
            enterprise_pb2.QUEUED_TEAM_USERS: _QueuedTeamUserDataType(),
            enterprise_pb2.ROLE_USERS: _SimpleDataType(['roleId', 'enterpriseUserId']),
            enterprise_pb2.ROLE_TEAMS: _SimpleDataType(['roleId', 'teamUid']),
            enterprise_pb2.MANAGED_NODES: _SimpleDataType(['roleId', 'managedNodeId']),
            enterprise_pb2.ROLE_PRIVILEGES: _SimpleDataType(['roleId', 'managedNodeId', 'privilegeType']),
            enterprise_pb2.ROLE_ENFORCEMENTS: _SimpleDataType(['roleId', 'enforcementType']),
            enterprise_pb2.MANAGED_COMPANIES: _SimpleDataType(['mcEnterpriseId']),
            enterprise_pb2.DEVICES_REQUEST_FOR_ADMIN_APPROVAL: _SimpleDataType(['enterprise_user_id', 'device_id']),
            enterprise_pb2.USER_ALIASES: _SimpleDataType(['username']),
        }

    def get_continuation_token(self) -> bytes:
        setting = self._settings_storage.load()
        if setting is None:
            setting = EnterpriseSettings()
        return setting.continuation_token

    def set_continuation_token(self, token: bytes) -> None:
        setting = self._settings_storage.load()
        if setting is None:
            setting = EnterpriseSettings()
        setting.continuation_token = token
        self._settings_storage.store(setting)

    def store_entity(self, entity_type: enterprise_pb2.EnterpriseDataEntity, data: bytes, is_delete: bool) -> None:
        if entity_type in EnterpriseEntityMap and entity_type in self._data_types:
            entity = EnterpriseEntityMap[entity_type]()
            entity.SerializeToString()
            entity.ParseFromString(data)
            proc = self._data_types[entity_type]
            entity_key = proc.get_proto_entity_key(entity)
            if isinstance(proc, _MergeDataType):
                ee: Optional[EnterpriseEntityData] = self._data_storage.get_entity(entity_type, entity_key)
                existing = None
                if ee:
                    existing = EnterpriseEntityMap[entity_type]()
                    existing.ParseFromString(ee.data)
                entity, is_delete = proc.merge(existing, entity, is_delete)
                data = entity.SerializeToString()

            key = _EntityKey(entity_type, entity_key)
            if is_delete:
                if key in self._put_cache:
                    del self._put_cache[key]
                self._delete_cache.add(key)
            else:
                if key in self._delete_cache:
                    self._delete_cache.remove(key)
                eed = EnterpriseEntityData()
                eed.type = entity_type
                eed.key = entity_key
                eed.data = data
                self._put_cache[key] = eed
        if len(self._put_cache) > 1000 or len(self._delete_cache) > 1000:
            self.flush()

    def get_all(self):
        for ed in self._data_storage.get_all():
            yield ed.type, ed.data

    def put_entity(self, entity_type, data):
        self.store_entity(entity_type, data, False)

    def delete_entity(self, entity_type, data):
        self.store_entity(entity_type, data, True)

    def flush(self):
        if len(self._delete_cache) > 0:
            self._data_storage.delete_entities(self._delete_cache)
            self._delete_cache.clear()
        if len(self._put_cache) > 0:
            self._data_storage.put(self._put_cache.values())
            self._put_cache.clear()

    def clear(self):
        self._data_storage.delete_all()
