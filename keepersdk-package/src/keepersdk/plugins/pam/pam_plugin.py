import abc
from typing import Dict, Iterable, List, Optional, Set

from keepersdk import utils
from keepersdk.authentication.keeper_auth import KeeperAuth
from keepersdk.proto import pam_pb2

from ...storage.storage_types import IEntityReader
from ...plugins.pam.pam_storage import IPAMStorage, MemoryPamStorage, PamStorageController, SqlitePamStorage
from ...enterprise.enterprise_loader import EnterpriseLoader
from ...enterprise.sqlite_enterprise_storage import SqliteEnterpriseStorage


class IPAMPlugin(abc.ABC):
    @abc.abstractmethod
    def sync_down(self, *, reload: bool = False) -> None:
        pass

    @property
    @abc.abstractmethod
    def controllers(self) -> IEntityReader[PamStorageController, str]:
        pass


class PamPlugin(IPAMPlugin):
    def __init__(self, loader: EnterpriseLoader):
        assert loader.keeper_auth.auth_context.enterprise_id
        assert loader.keeper_auth.auth_context.is_enterprise_admin
        self._enterprise_id = loader.keeper_auth.auth_context.enterprise_id
        self.enterprise_uid: str = utils.base64_url_encode(self._enterprise_id.to_bytes(16, byteorder='big'))
        loader_storage = loader.storage
        self.storage: IPAMStorage
        if isinstance(loader_storage, SqliteEnterpriseStorage):
            self.storage = SqlitePamStorage(loader_storage.get_connection, self._enterprise_id)
        else:
            self.storage = MemoryPamStorage()
        self.loader = loader
        self.logger = utils.get_logger()

    @property
    def controllers(self) -> IEntityReader[PamStorageController, str]:
        return self.storage.controller_storage
    
    def _get_all_gateways(self,auth: KeeperAuth) -> List[pam_pb2.PAMController]:
        """Retrieve all PAM gateways from the vault."""
        rs = auth.execute_auth_rest(
            'pam/get_controllers', 
            None, 
            response_type=pam_pb2.PAMControllersResponse
        )
        if rs:
            return list(rs.controllers)
        return []

    def sync_down(self) -> None:
        """Sync down the PAM data from the vault."""
        self.storage.reset()

        auth = self.loader.keeper_auth

        controllers: List[pam_pb2.PAMController] = []
    
        all_controllers = self._get_all_gateways(auth)

        controllers.extend(all_controllers)

        self.storage.controller_storage.put_entities(controllers)

