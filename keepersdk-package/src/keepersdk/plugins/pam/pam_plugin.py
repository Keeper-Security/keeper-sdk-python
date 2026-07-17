from __future__ import annotations

import abc
from typing import Iterable, List, Tuple

from . import pam_storage, pam_types
from ... import utils
from ...authentication.keeper_auth import KeeperAuth
from ...enterprise import enterprise_loader, sqlite_enterprise_storage
from ...proto import pam_pb2
from ...storage import in_memory, storage_types


def _pam_rows_from_proto(c: pam_pb2.PAMController) -> Tuple[pam_storage.PamStorageController, pam_types.PamController]:
    kwargs = dict(
        controller_uid=utils.base64_url_encode(c.controllerUid) if c.controllerUid else '',
        controller_name=c.controllerName or '',
        device_token=c.deviceToken or '',
        device_name=c.deviceName or '',
        node_id=c.nodeId,
        created=c.created,
        last_modified=c.lastModified,
        application_uid=utils.base64_url_encode(c.applicationUid) if c.applicationUid else '',
        app_client_type=c.appClientType,
        is_initialized=c.isInitialized,
    )
    return pam_storage.PamStorageController(**kwargs), pam_types.PamController(**kwargs)


def _pam_rotation_to_domain(row: pam_storage.PamRecordRotation) -> pam_types.PamRecordRotationInfo:
    return pam_types.PamRecordRotationInfo(
        record_uid=row.record_uid,
        revision=row.revision,
        configuration_uid=row.configuration_uid,
        schedule=row.schedule,
        pwd_complexity=row.pwd_complexity,
        disabled=row.disabled,
        resource_uid=row.resource_uid,
        last_rotation=row.last_rotation,
        last_rotation_status=row.last_rotation_status,
    )


class IPamPlugin(abc.ABC):
    @abc.abstractmethod
    def sync_down(self, *, reload: bool = False) -> None:
        pass

    @abc.abstractmethod
    def sync_record_rotations_from_vault(self) -> None:
        pass

    @abc.abstractmethod
    def merge_record_rotations(
            self, rows: Iterable[pam_storage.PamRecordRotation], *,
            replace_all: bool = False) -> None:
        pass

    @property
    @abc.abstractmethod
    def controllers(self) -> storage_types.IEntityReader[pam_types.PamController, str]:
        pass

    @property
    @abc.abstractmethod
    def record_rotations(self) -> storage_types.IEntityReader[pam_types.PamRecordRotationInfo, str]:
        pass


class PamPlugin(IPamPlugin):
    def __init__(self, loader: enterprise_loader.EnterpriseLoader):
        assert loader.keeper_auth.auth_context.enterprise_id
        assert loader.keeper_auth.auth_context.is_enterprise_admin
        self._enterprise_id = loader.keeper_auth.auth_context.enterprise_id
        self.enterprise_uid: str = utils.base64_url_encode(self._enterprise_id.to_bytes(16, byteorder='big'))
        loader_storage = loader.storage
        self.storage: pam_storage.IPamStorage
        if isinstance(loader_storage, sqlite_enterprise_storage.SqliteEnterpriseStorage):
            self.storage = pam_storage.SqlitePamStorage(loader_storage.get_connection, self._enterprise_id)
        else:
            self.storage = pam_storage.MemoryPamStorage()
        self.loader = loader
        self._controllers = in_memory.InMemoryEntityStorage[pam_types.PamController, str]()
        self._record_rotations = in_memory.InMemoryEntityStorage[pam_types.PamRecordRotationInfo, str]()
        self.logger = utils.get_logger()
        # Load any rotations already persisted from a prior vault sync.
        self.sync_record_rotations_from_vault()

    @property
    def controllers(self) -> storage_types.IEntityReader[pam_types.PamController, str]:
        return self._controllers

    @property
    def record_rotations(self) -> storage_types.IEntityReader[pam_types.PamRecordRotationInfo, str]:
        return self._record_rotations

    def _get_all_gateways(self, auth: KeeperAuth) -> List[pam_pb2.PAMController]:
        rs = auth.execute_auth_rest(
            'pam/get_controllers',
            None,
            response_type=pam_pb2.PAMControllersResponse,
        )
        if rs:
            return list(rs.controllers)
        return []

    def sync_record_rotations_from_vault(self) -> None:
        """Reload rotations from PAM sqlite into memory (no vault/sync_down)."""
        self._record_rotations.clear()
        rows = list(self.storage.record_rotations.get_all_entities())
        if rows:
            self._record_rotations.put_entities(_pam_rotation_to_domain(r) for r in rows)

    def merge_record_rotations(
            self, rows: Iterable[pam_storage.PamRecordRotation], *,
            replace_all: bool = False) -> None:
        """Upsert rotation rows into PAM sqlite + memory (from normal vault sync)."""
        row_list = [r for r in rows if r and r.record_uid]
        if replace_all:
            existing = [r.uid() for r in self.storage.record_rotations.get_all_entities()]
            if existing:
                self.storage.record_rotations.delete_uids(existing)
            self._record_rotations.clear()
        if not row_list:
            return
        self.storage.record_rotations.put_entities(row_list)
        self._record_rotations.put_entities(_pam_rotation_to_domain(r) for r in row_list)

    def sync_down(self, *, reload: bool = False) -> None:
        """Refresh controllers from PAM API; reload rotations from local sqlite only."""
        _ = reload
        existing = [c.uid() for c in self.storage.controllers.get_all_entities()]
        if existing:
            self.storage.controllers.delete_uids(existing)
        self._controllers.clear()

        auth = self.loader.keeper_auth
        all_controllers = self._get_all_gateways(auth)
        storage_rows = []
        domain_rows = []
        for c in all_controllers:
            s_row, d_row = _pam_rows_from_proto(c)
            storage_rows.append(s_row)
            domain_rows.append(d_row)
        if storage_rows:
            self.storage.controllers.put_entities(storage_rows)
        if domain_rows:
            self._controllers.put_entities(domain_rows)

        self.sync_record_rotations_from_vault()