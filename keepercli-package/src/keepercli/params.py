import json
import os
import sqlite3
import threading
from typing import Dict, Optional, Any, Type

from keepersdk import utils as keepersdk_utils
from keepersdk.authentication import configuration, endpoint, keeper_auth
from keepersdk.enterprise import sqlite_enterprise_storage, enterprise_types, enterprise_loader
from keepersdk.vault import vault_online, sqlite_storage
from keepersdk.plugins.pedm import admin_plugin
from keepersdk.plugins.pam import pam_plugin, pam_types


class KeeperConfig(configuration.IConfigurationStorage):
    def __init__(self, *,
                 config_filename: Optional[str] = None,
                 config: Optional[Dict] = None) -> None:
        self.config_filename: Optional[str] = config_filename
        self.config: Dict[str, Any] = config or {}
        self.shadow_config: Dict[str, Any] = {}
        self.thread_local = threading.local()

    def getter(self, name: str, value_type: Optional[Type] = None) -> Any:
        value = self.shadow_config.get(name) if name in self.shadow_config else self.config.get(name)
        if value is not None:
            if value_type is not None:
                if not isinstance(value, value_type):
                    return None
            return value
        return None

    def setter(self, name: str, value: Any, value_type: Optional[Type] = None) -> None:
        if value is None:
            if name in self.shadow_config:
                del self.shadow_config[name]
        else:
            if value_type is not None and not isinstance(value, value_type):
                return None
            if name in self.config:
                if self.config[name] == value:
                    if name in self.shadow_config:
                        del self.shadow_config[name]
                    return None
            self.shadow_config[name] = value
        return None

    def get(self) -> configuration.JsonKeeperConfiguration:
        return configuration.JsonKeeperConfiguration(self.config)

    def put(self, keeper_configuration: configuration.IKeeperConfiguration) -> None:
        if self.config_filename:
            jc = configuration.JsonKeeperConfiguration(self.config)
            jc.assign(keeper_configuration)
            self.config = json.loads(json.dumps(jc))

            with open(self.config_filename, 'w') as fd:
                json.dump(self.config, fd, ensure_ascii=False, indent=2)

    @property
    def batch_mode(self) -> bool:
        return self.getter('batch_mode', bool)

    @batch_mode.setter
    def batch_mode(self, value: bool):
        self.setter('batch_mode', value, bool)

    @property
    def debug(self) -> bool:
        return self.getter('debug', bool)

    @debug.setter
    def debug(self, value: bool):
        self.setter('debug', value, bool)

    @property
    def unmask_all(self) -> str:
        return self.getter('unmask_all', str)

    @unmask_all.setter
    def unmask_all(self, value: str):
        self.setter('unmask_all', value, str)

    @property
    def fail_on_throttle(self) -> bool:
        return self.getter('fail_on_throttle', bool)

    @fail_on_throttle.setter
    def fail_on_throttle(self, value: bool):
        self.setter('fail_on_throttle', value, bool)

    @property
    def skip_vault(self) -> bool:
        return self.getter('skip_vault', bool)

    @skip_vault.setter
    def skip_vault(self, value: bool):
        self.setter('skip_vault', value, bool)

    @property
    def skip_enterprise(self) -> bool:
        return self.getter('skip_enterprise', bool)

    @skip_enterprise.setter
    def skip_enterprise(self, value: bool):
        self.setter('skip_enterprise', value, bool)

    @property
    def server(self) -> Optional[str]:
        return self.getter('last_server', str) or endpoint.DEFAULT_KEEPER_SERVER

    @server.setter
    def server(self, value: Optional[str]):
        self.setter('last_server', value, str)

    @property
    def username(self) -> Optional[str]:
        return self.getter('last_login', str)

    @username.setter
    def username(self, value: Optional[str]):
        self.setter('last_login', value, str)

    @property
    def password(self) -> Optional[str]:
        return self.shadow_config.get('password')

    @password.setter
    def password(self, value: Optional[str]):
        if value:
            self.shadow_config['password'] = value
        else:
            if 'password' in self.shadow_config:
                del self.shadow_config['password']

    def get_connection(self) -> sqlite3.Connection:
        if not hasattr(self.thread_local, 'sqlite_connection'):
            if self.config_filename:
                file_path = os.path.abspath(self.config_filename)
                file_path = os.path.dirname(file_path)
                file_path = os.path.join(file_path, 'keeper_db.sqlite')
            else:
                file_path = ':memory:'
            self.thread_local.sqlite_connection = sqlite3.Connection(file_path)
        return self.thread_local.sqlite_connection


# TODO Make vault, enterprise, and plugins Mixins
class KeeperParams:
    def __init__(self, keeper_config: KeeperConfig):
        self._keeper_config = keeper_config
        cert_check = self.certificate_check
        if isinstance(cert_check, bool):
            endpoint.set_certificate_check(cert_check)

        self._environment_variables: Dict[str, Any] = {}

        self._auth: Optional[keeper_auth.KeeperAuth] = None

        self.current_folder: Optional[str] = None
        self._vault: Optional[vault_online.VaultOnline] = None

        self._enterprise_loader: Optional[enterprise_loader.EnterpriseLoader] = None

        self._pedm_plugin: Optional[admin_plugin.PedmPlugin] = None

        self._pam_plugin: Optional[pam_plugin.PamPlugin] = None

    @property
    def keeper_config(self) -> KeeperConfig:
        return self._keeper_config

    @property
    def environment_variables(self) -> Dict[str, Any]:
        return self._environment_variables

    @property
    def certificate_check(self) -> bool:
        return self._keeper_config.getter('certificate_check', bool)

    def clear_session(self) -> None:
        self.current_folder = None

        if self._pedm_plugin:
            self._pedm_plugin.close()
            self._pedm_plugin = None

        if self._pam_plugin:
            self._pam_plugin = None

        if self._enterprise_loader:
            self._enterprise_loader = None

        if self._vault:
            self._vault.close()
            self._vault = None

        if self._auth:
            self._auth.close()
            self._auth = None

    @property
    def auth(self) -> Optional[keeper_auth.KeeperAuth]:
        return self._auth

    def set_auth(self, value: keeper_auth.KeeperAuth, *,
                 tree_key: Optional[bytes] = None,
                 skip_vault: Optional[bool] = None,
                 skip_enterprise: Optional[bool] = None,
                 ):
        self.clear_session()
        if value:
            self._auth = value
            if skip_vault is None:
                skip_vault = self.keeper_config.skip_vault
            if not skip_vault:
                storage = sqlite_storage.SqliteVaultStorage(self._keeper_config.get_connection, self._auth.auth_context.account_uid)
                self._vault = vault_online.get_vault_online(self._auth, storage)
                self.vault_down()

            if skip_enterprise is None:
                skip_enterprise = self.keeper_config.skip_enterprise
            if not skip_enterprise and self._auth.auth_context.is_enterprise_admin:
                enterprise_id = self._auth.auth_context.enterprise_id
                assert isinstance(enterprise_id, int)
                enterprise_storage = sqlite_enterprise_storage.SqliteEnterpriseStorage(
                    self._keeper_config.get_connection, enterprise_id)
                self._enterprise_loader = enterprise_loader.EnterpriseLoader(self._auth, enterprise_storage, tree_key=tree_key)
                self.enterprise_down()
                # Persist rotations from the vault sync into PAM sqlite now that the plugin exists.
                self.refresh_record_rotations()

    @property
    def enterprise_loader(self) -> enterprise_types.IEnterpriseLoader:
        assert self._enterprise_loader is not None
        return self._enterprise_loader

    @property
    def pedm_plugin(self) -> admin_plugin.PedmPlugin:
        assert self._enterprise_loader is not None
        if not self._pedm_plugin:
            self._pedm_plugin = admin_plugin.PedmPlugin(self._enterprise_loader)

        if self._pedm_plugin.need_sync:
            self._pedm_plugin.sync_down()
        return self._pedm_plugin

    @property
    def pam_plugin(self) -> pam_plugin.PamPlugin:
        assert self._enterprise_loader is not None
        if not self._pam_plugin:
            self._pam_plugin = pam_plugin.PamPlugin(self._enterprise_loader)
        return self._pam_plugin

    def vault_down(self):
        if self._vault:
            self._vault.sync_down()
        self.refresh_record_rotations()

    def refresh_record_rotations(self) -> None:
        """Copy rotations from the last vault sync into :attr:`pam_plugin` sqlite (no extra sync_down)."""
        if not self._auth:
            return
        try:
            if self._vault is not None:
                self._merge_nsf_rotation_chunks_into_vault_cache()
            if (not self._auth.auth_context.is_enterprise_admin
                    or self._enterprise_loader is None):
                return
            replace_all = False
            rows = []
            if self._vault is not None:
                replace_all = self._vault.consume_rotations_cleared()
                from keepersdk.plugins.pam import pam_storage as pam_stor
                rows = [
                    pam_stor.PamRecordRotation(
                        record_uid=info.record_uid,
                        revision=info.revision,
                        configuration_uid=info.configuration_uid,
                        schedule=info.schedule,
                        pwd_complexity=info.pwd_complexity,
                        disabled=info.disabled,
                        resource_uid=info.resource_uid,
                        last_rotation=info.last_rotation,
                        last_rotation_status=info.last_rotation_status,
                    )
                    for info in self._vault.record_rotation_cache.values()
                ]
            self.pam_plugin.merge_record_rotations(rows, replace_all=replace_all)
        except Exception as e:
            keepersdk_utils.get_logger().warning('refresh_record_rotations failed: %s', e)

    def _merge_nsf_rotation_chunks_into_vault_cache(self) -> None:
        """Secondary source: NSF list_chunks for recordRotationData (already written by sync)."""
        if not self._vault:
            return
        try:
            nsf_storage = self._vault.nsf
        except Exception:
            return
        if nsf_storage is None:
            return
        from keepersdk.vault import nsf_sync
        from keepersdk.plugins.pam import pam_storage as pam_stor

        for item in nsf_sync.load_list_chunks(nsf_storage, nsf_sync.CHUNK_RECORD_ROTATION):
            if not isinstance(item, dict):
                continue
            row = pam_stor.pam_record_rotation_from_nsf_dict(item)
            if not row or not row.record_uid:
                continue
            if row.record_uid in self._vault.record_rotation_cache:
                continue
            self._vault.record_rotation_cache[row.record_uid] = pam_types.PamRecordRotationInfo(
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

    def get_record_rotation(self, record_uid: str) -> Optional[pam_types.PamRecordRotationInfo]:
        """Rotation metadata for ``record_uid`` from vault sync cache / PAM sqlite (or ``None``)."""
        if not self._auth or not record_uid:
            return None
        if self._vault is not None:
            info = self._vault.get_record_rotation(record_uid)
            if info is not None:
                return info
        if (not self._auth.auth_context.is_enterprise_admin
                or self._enterprise_loader is None):
            return None
        return self.pam_plugin.record_rotations.get_entity(record_uid)

    def enterprise_down(self):
        if self._auth and self._enterprise_loader:
            _ = self._enterprise_loader.load()

    @property
    def vault(self) -> Optional[vault_online.VaultOnline]:
        return self._vault

    @property
    def enterprise_data(self) -> Optional[enterprise_types.IEnterpriseData]:
        if self._enterprise_loader is not None:
            return self._enterprise_loader.enterprise_data
        return None
