import concurrent.futures
import threading
from typing import Optional, Any, Dict

from . import sync_down, vault_plugins
from . import vault_data, vault_storage
from .. import utils
from ..authentication import keeper_auth


class VaultOnline(vault_plugins.IVaultData, keeper_auth.IKeeperAuth):
    def __init__(self, auth: keeper_auth.KeeperAuth, storage: vault_storage.IVaultStorage) -> None:
        super(VaultOnline, self).__init__()
        self._vault_data = vault_data.VaultData(auth.auth_context.client_key, storage)
        self._keeper_auth = auth
        self._auto_sync = False
        self._lock = threading.Lock()
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        self._background_future: Optional[concurrent.futures.Future] = None
        self._sync_record_types = True
        self.sync_requested = False
        self.auto_sync = True    # call setter

    @property
    def vault_data(self)-> vault_data.VaultData:
        return self._vault_data

    @property
    def keeper_auth(self) -> keeper_auth.KeeperAuth:
        return self._keeper_auth

    @property
    def lock(self)-> threading.Lock:
        return self._lock

    def close(self):
        self.auto_sync = False
        self._executor.shutdown(wait=False, cancel_futures=True)
        self._vault_data.close()

    def pending_share_plugin(self) -> Optional[vault_plugins.IPendingSharePlugin]:
        if isinstance(self, vault_plugins.IPendingSharePlugin):
            return self

    def breach_watch_plugin(self) -> Optional[vault_plugins.IBreachWatchPlugin]:
        keeper_licence = self._keeper_auth.auth_context.license
        if not keeper_licence:
            return None
        if not keeper_licence.get('breachWatchEnabled'):
            return None
        if keeper_licence.get('breachWatchFeatureDisable') is True:
            return None
        if isinstance(self, vault_plugins.IBreachWatchPlugin):
            return self

    def client_audit_event_plugin(self) -> Optional[vault_plugins.IClientAuditEventPlugin]:
        if isinstance(self, vault_plugins.IClientAuditEventPlugin):
            return self

    def audit_data_plugin(self) -> Optional[vault_plugins.IAuditDataPlugin]:
        if isinstance(self, vault_plugins.IAuditDataPlugin):
            return self

    def security_audit_plugin(self) -> Optional[vault_plugins.ISecurityAuditPlugin]:
        if isinstance(self, vault_plugins.ISecurityAuditPlugin):
            return self


    def request_sync(self)-> None:
        self.sync_requested = True

    @property
    def auto_sync(self) -> bool:
        return self._auto_sync

    @auto_sync.setter
    def auto_sync(self, value: bool) -> None:
        if value != self._auto_sync:
            self._auto_sync = value
            if self._keeper_auth.push_notifications:
                self._keeper_auth.push_notifications.remove_callback(self.on_notification_received)
                if value:
                    self._keeper_auth.push_notifications.register_callback(self.on_notification_received)

    def on_notification_received(self, event: Dict[str, Any]) -> Optional[bool]:
        if isinstance(event, dict):
            if event.get('event', '') == 'sync':
                if event.get('sync', False):
                    with self._lock:
                        self.sync_requested = True
            return False

    def sync_down(self, force=False):
        if force:
            self._vault_data.storage.clear()

        changes = sync_down.sync_down_request(self._keeper_auth, self._vault_data.storage,
                                              sync_record_types=self._sync_record_types,
                                              pending_shares=self.pending_share_plugin(),
                                              audit_data=self.audit_data_plugin())
        self.sync_requested = False
        self._sync_record_types = False
        self._vault_data.rebuild_data(changes)

    def _background_task(self):
        if self._keeper_auth.auth_context.enterprise_ec_public_key:
            logger = utils.get_logger()
            audit_event_plugin = self.client_audit_event_plugin()
            if audit_event_plugin is not None:
                try:
                    audit_event_plugin.send_client_audit_events()
                except Exception as e:
                    logger.debug('Client Audit Event Plugin Error: %s', e)

            audit_data_plugin = self.audit_data_plugin()
            if audit_data_plugin is not None:
                try:
                    audit_data_plugin.send_audit_data()
                except Exception as e:
                    logger.debug('Audit Data Plugin Error: %s', e)

            security_audit_plugin = self.security_audit_plugin()
            if security_audit_plugin is not None:
                try:
                    security_audit_plugin.send_security_audit_data()
                except Exception as e:
                    logger.debug('Security Audit Plugin Error: %s', e)

    def run_pending_jobs(self):
        if self.sync_requested:
            self.sync_down()
        if self._background_future is not None and self._background_future.running():
            return
        self._background_future = self._executor.submit(self._background_task)


class PersonalVault(VaultOnline, vault_plugins.PendingSharePlugin, vault_plugins.BreachWatchPlugin):
    def __init__(self, auth: keeper_auth.KeeperAuth, storage: vault_storage.IVaultStorage) -> None:
        super(PersonalVault, self).__init__(auth, storage)

class EnterpriseVault(PersonalVault, vault_plugins.AuditDataPlugin, vault_plugins.ClientAuditEventPlugin,
                      vault_plugins.SecurityAuditPlugin):
    def __init__(self, auth: keeper_auth.KeeperAuth, storage: vault_storage.IVaultStorage) -> None:
        super(EnterpriseVault, self).__init__(auth, storage)

def get_vault_online(auth: keeper_auth.KeeperAuth, storage: vault_storage.IVaultStorage) -> VaultOnline:
    vault_online: VaultOnline
    if auth.auth_context.enterprise_ec_public_key is not None:
        vault_online = EnterpriseVault(auth, storage)
    else:
        vault_online = PersonalVault(auth, storage)
    return vault_online
