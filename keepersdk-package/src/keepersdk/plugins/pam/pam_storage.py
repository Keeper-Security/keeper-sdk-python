import abc
import sqlite3
from typing import Callable

import attrs

from ... import sqlite_dao
from ...proto import enterprise_pb2
from ...storage import in_memory, sqlite, storage_types
from ... import utils
from ...proto import SyncDown_pb2


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

@attrs.define(kw_only=True)
class PamRecordRotation(storage_types.IUid[str]):
    """Mirrors ``Vault.RecordRotation``; UIDs are URL-safe base64 strings."""

    record_uid: str = ''
    revision: int = 0
    configuration_uid: str = ''
    schedule: str = ''
    pwd_complexity: bytes = b''
    disabled: bool = False
    resource_uid: str = ''
    last_rotation: int = 0
    last_rotation_status: int = 0

    def uid(self) -> str:
        return self.record_uid


def pam_record_rotation_from_proto(rr: SyncDown_pb2.RecordRotation) -> PamRecordRotation:
    return PamRecordRotation(
        record_uid=utils.base64_url_encode(rr.recordUid) if rr.recordUid else '',
        revision=int(rr.revision),
        configuration_uid=utils.base64_url_encode(rr.configurationUid) if rr.configurationUid else '',
        schedule=rr.schedule or '',
        pwd_complexity=rr.pwdComplexity or b'',
        disabled=bool(rr.disabled),
        resource_uid=utils.base64_url_encode(rr.resourceUid) if rr.resourceUid else '',
        last_rotation=int(rr.lastRotation),
        last_rotation_status=int(rr.lastRotationStatus),
    )


class IPamStorage(abc.ABC):
    @property
    @abc.abstractmethod
    def controllers(self) -> storage_types.IEntityReaderStorage[PamStorageController, str]:
        pass

    @property
    @abc.abstractmethod
    def record_rotations(self) -> storage_types.IEntityReaderStorage[PamRecordRotation, str]:
        pass

    @abc.abstractmethod
    def reset(self):
        pass


class MemoryPamStorage(IPamStorage):
    def __init__(self):
        self._controllers = in_memory.InMemoryEntityStorage[PamStorageController, str]()
        self._record_rotations = in_memory.InMemoryEntityStorage[PamRecordRotation, str]()

    @property
    def controllers(self) -> storage_types.IEntityReaderStorage[PamStorageController, str]:
        return self._controllers

    @property
    def record_rotations(self) -> storage_types.IEntityReaderStorage[PamRecordRotation, str]:
        return self._record_rotations

    def reset(self):
        self._controllers.clear()
        self._record_rotations.clear()


class SqlitePamStorage(IPamStorage):
    def __init__(self, get_connection: Callable[[], sqlite3.Connection], enterprise_id: int) -> None:
        self.get_connection = get_connection
        self.enterprise_id = enterprise_id
        self.owner_column = 'enterprise_id'
        controller_schema = sqlite_dao.TableSchema.load_schema(
            PamStorageController, 'controller_uid', owner_column=self.owner_column, owner_type=int)
        rotation_schema = sqlite_dao.TableSchema.load_schema(
            PamRecordRotation,
            'record_uid',
            owner_column=self.owner_column,
            owner_type=int,
            indexes={'configuration_uid': ['configuration_uid']},
        )
        sqlite_dao.verify_database(self.get_connection(), (controller_schema, rotation_schema))
        self._controllers = sqlite.SqliteEntityStorage(
            self.get_connection, controller_schema, owner=enterprise_id)
        self._record_rotations = sqlite.SqliteEntityStorage(
            self.get_connection, rotation_schema, owner=enterprise_id)

    @property
    def controllers(self) -> storage_types.IEntityReaderStorage[PamStorageController, str]:
        return self._controllers

    @property
    def record_rotations(self) -> storage_types.IEntityReaderStorage[PamRecordRotation, str]:
        return self._record_rotations

    def reset(self):
        self._controllers.delete_all()
        self._record_rotations.delete_all()

