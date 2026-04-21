from __future__ import annotations

import abc
from typing import List, Tuple

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


class IPamPlugin(abc.ABC):
    @abc.abstractmethod
    def sync_down(self, *, reload: bool = False) -> None:
        pass

    @property
    @abc.abstractmethod
    def controllers(self) -> storage_types.IEntityReader[pam_types.PamController, str]:
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
        self.logger = utils.get_logger()

    @property
    def controllers(self) -> storage_types.IEntityReader[pam_types.PamController, str]:
        return self._controllers

    def _get_all_gateways(self, auth: KeeperAuth) -> List[pam_pb2.PAMController]:
        rs = auth.execute_auth_rest(
            'pam/get_controllers',
            None,
            response_type=pam_pb2.PAMControllersResponse,
        )
        if rs:
            return list(rs.controllers)
        return []

    def sync_down(self, *, reload: bool = False) -> None:
        _ = reload
        self.storage.reset()
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
