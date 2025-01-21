import json
import os
import sqlite3
from typing import Dict, Optional, Any, Type

from keepersdk.authentication import configuration, endpoint, keeper_auth
from keepersdk.enterprise import sqlite_enterprise_storage, enterprise_types, enterprise_loader
from keepersdk.vault import vault_online, sqlite_storage


class ParamsConfig:
    def __init__(self, config_filename: str, config: Optional[Dict] = None) -> None:
        self.config_filename: str = config_filename
        self.config: Dict[str, Any] = config or {}
        self.shadow_config: Dict[str, Any] = {}

    def _getter(self, name: str, value_type: Optional[Type] = None) -> Any:
        value = self.shadow_config.get(name) if name in self.shadow_config else self.config.get(name)
        if value is not None:
            if value_type is not None:
                if not isinstance(value, value_type):
                    return
            return value

    def _setter(self, name: str, value: Any, value_type: Optional[Type] = None) -> None:
        if value is None:
            if name in self.shadow_config:
                del self.shadow_config[name]
        else:
            if value_type is not None and not isinstance(value, value_type):
                return
            if name in self.config:
                if self.config[name] == value:
                    if name in self.shadow_config:
                        del self.shadow_config[name]
                    return
            self.shadow_config[name] = value

    @property
    def batch_mode(self) -> bool:
        return self._getter('batch_mode', bool)

    @batch_mode.setter
    def batch_mode(self, value: bool):
        self._setter('batch_mode', value, bool)

    @property
    def debug(self) -> bool:
        return self._getter('debug', bool)

    @debug.setter
    def debug(self, value: bool):
        self._setter('debug', value, bool)

    @property
    def unmask_all(self) -> str:
        return self._getter('unmask_all', str)

    @unmask_all.setter
    def unmask_all(self, value: str):
        self._setter('unmask_all', value, str)

    @property
    def certificate_check(self) -> bool:
        return self._getter('certificate_check', bool)

    @property
    def fail_on_throttle(self) -> bool:
        return self._getter('fail_on_throttle', bool)

    @fail_on_throttle.setter
    def fail_on_throttle(self, value: str):
        self._setter('fail_on_throttle', value, str)

    @property
    def mfa_duration(self) -> str:
        return self._getter('mfa_duration', str)

    @property
    def server(self) -> Optional[str]:
        return self._getter('last_server', str) or endpoint.DEFAULT_KEEPER_SERVER

    @server.setter
    def server(self, value: Optional[str]):
        self._setter('last_server', value, str)

    @property
    def username(self) -> Optional[str]:
        return self._getter('last_login', str)

    @username.setter
    def username(self, value: Optional[str]):
        self._setter('last_login', value, str)

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


class KeeperParams(ParamsConfig, configuration.IConfigurationStorage):
    def __init__(self, config_filename: str, config: Optional[Dict]):
        super().__init__(config_filename, config)
        self.current_folder: Optional[str] = None
        self._auth: Optional[keeper_auth.KeeperAuth] = None
        self._vault: Optional[vault_online.VaultOnline] = None
        self._enterprise_loader: Optional[enterprise_loader.EnterpriseLoader] = None
        self._sqlite_connection: Optional[sqlite3.Connection] = None
        self._environment_variables: Dict[str, Any] = {}
        cert_check = self.certificate_check
        if isinstance(cert_check, bool):
            endpoint.set_certificate_check(cert_check)

    def clear_session(self) -> None:
        self.shadow_config.clear()
        self.current_folder = None
        self._pedm_plugin = None
        self._enterprise_loader = None
        if self._vault:
            self._vault.close()
        self._vault = None
        if self._sqlite_connection:
            self._sqlite_connection.close()
            self._sqlite_connection = None
        if self._auth:
            self._auth.close()
            self._auth = None

    @property
    def auth(self) -> Optional[keeper_auth.KeeperAuth]:
        return self._auth

    @auth.setter
    def auth(self, value: keeper_auth.KeeperAuth):
        self.clear_session()
        if value:
            self._auth = value
            storage = sqlite_storage.SqliteVaultStorage(self.get_connection, self._auth.auth_context.account_uid)
            self._vault = vault_online.get_vault_online(self._auth, storage)
            self.vault_down()
            if self._auth.auth_context.is_enterprise_admin:
                enterprise_id = self._auth.auth_context.license.get('enterpriseId')
                assert isinstance(enterprise_id, int)
                enterprise_storage = sqlite_enterprise_storage.SqliteEnterpriseStorage(
                    self.get_connection, enterprise_id)
                self._enterprise_loader = enterprise_loader.EnterpriseLoader(self._auth, enterprise_storage)
                self.enterprise_down()

    @property
    def enterprise_loader(self) -> enterprise_types.IEnterpriseLoader:
        assert self._enterprise_loader is not None
        return self._enterprise_loader

    def vault_down(self):
        if self._vault:
            self._vault.sync_down()

    def enterprise_down(self):
        if self._auth and self._enterprise_loader:
            _ = self._enterprise_loader.load()

    def get_connection(self) -> sqlite3.Connection:
        if self._sqlite_connection is None:
            file_path = os.path.abspath(self.config_filename)
            file_path = os.path.dirname(file_path)
            file_path = os.path.join(file_path, 'keeper_db.sqlite')
            self._sqlite_connection = sqlite3.Connection(file_path)
        return self._sqlite_connection

    @property
    def vault(self) -> Optional[vault_online.VaultOnline]:
        return self._vault

    @property
    def enterprise_data(self) -> Optional[enterprise_types.IEnterpriseData]:
        if self._enterprise_loader is not None:
            return self._enterprise_loader.enterprise_data

    def get(self) -> configuration.JsonKeeperConfiguration:
        return configuration.JsonKeeperConfiguration(self.config)

    def put(self, keeper_configuration: configuration.IKeeperConfiguration) -> None:
        jc = configuration.JsonKeeperConfiguration(self.config)
        jc.assign(keeper_configuration)
        self.config = json.loads(json.dumps(jc))

        with open(self.config_filename, 'w') as fd:
            json.dump(self.config, fd, ensure_ascii=False, indent=2)

    @property
    def environment_variables(self) -> Dict[str, Any]:
        return self._environment_variables
