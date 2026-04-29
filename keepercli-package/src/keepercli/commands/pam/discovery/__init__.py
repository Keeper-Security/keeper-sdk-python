
import base64
import json
import os
import re
from typing import Any, Callable, Dict, List, Optional, Tuple, Union


from .... import api
from ....commands import base
from ....helpers import router_utils
from ....helpers.gateway_utils import get_all_gateways
from ..pam_config import PAM_CONFIG_RECORD_TYPES

from keepersdk.vault import ksm_management, vault_record, vault_online
from keepersdk.helpers.pam_config_facade import PamConfigurationRecordFacade
from keepersdk.helpers.keeper_dag.constants import PAM_USER, PAM_MACHINE, PAM_DATABASE, PAM_DIRECTORY
from keepersdk.proto import pam_pb2, APIRequest_pb2
from keepersdk import utils
from keepersdk.crypto import decrypt_aes_v2, encrypt_aes_v2
from keepersdk.helpers.keeper_dag import dag_utils

logger = api.get_logger()


class MultiConfigurationException(Exception):
    """
    If the gateway has multiple configuration
    """
    def __init__(self, items: List[Dict]):
        super().__init__()
        self.items = items

    def print_items(self):
        for item in self.items:
            record = item["configuration_record"]
            logger.info(f" * {record.record_uid} - {record.title}")


class GatewayContext:

    """
    Context for a gateway and a configuration.

    In the configuration record, the gateway is selected.
    This means multiple configuration can use the same gateway.
    Commander is gateway centric, we need to treat gateway and configuration as a `primary key`
    """

    def __init__(self, configuration: vault_record.KeeperRecord, facade: PamConfigurationRecordFacade,
                 gateway: pam_pb2.PAMController, application: vault_record.ApplicationRecord,
                 vault: vault_online.VaultOnline):
        self.configuration = configuration
        self.facade = facade
        self.gateway = gateway
        self.application = application
        self._vault = vault
        self._shared_folders = None

    @staticmethod
    def all_gateways(vault: vault_online.VaultOnline):
        return get_all_gateways(vault)

    @staticmethod
    def find_gateway(vault: vault_online.VaultOnline, find_func: Callable, gateways: Optional[List] = None) \
            -> Tuple[Optional["GatewayContext"], Any]:
        """
        Populate the context from matching using the function passed in.
        The function needs to return a non-None value to be considered a positive match.
        """
        if gateways is None:
            gateways = GatewayContext.all_gateways(vault)

        configuration_records = list(vault.vault_data.find_records(
                criteria=None, record_type=PAM_CONFIG_RECORD_TYPES, record_version=6))
        for configuration_record in configuration_records:
            payload = find_func(
                configuration_record=configuration_record
            )
            if payload is not None:
                return GatewayContext.from_configuration_uid(
                    vault=vault,
                    configuration_uid=configuration_record.record_uid,
                    gateways=gateways
                ), payload

        return None, None

    @staticmethod
    def from_configuration_uid(vault: vault_online.VaultOnline, configuration_uid: str, gateways: Optional[List] = None) \
            -> Optional["GatewayContext"]:
        """
        Populate context using the configuration UID.
        From the configuration record, get the gateway from the settings.
        """

        if gateways is None:
            gateways = GatewayContext.all_gateways(vault)

        configuration_record = vault.vault_data.load_record(configuration_uid)
        if not isinstance(configuration_record, vault_record.TypedRecord):
            logger.error(f'PAM Configuration [{configuration_uid}] is not available.')
            return None

        configuration_facade = PamConfigurationRecordFacade()
        configuration_facade.record = configuration_record

        gateway_uid = configuration_facade.controller_uid
        gateway = next((x for x in gateways
                        if utils.base64_url_encode(x.controllerUid) == gateway_uid),
                       None)

        if gateway is None:
            return None

        application_id = utils.base64_url_encode(gateway.applicationUid)
        application = vault.vault_data.load_record(application_id)

        return GatewayContext(
            configuration=configuration_record,
            facade=configuration_facade,
            gateway=gateway,
            application=application,
            vault=vault
        )

    @staticmethod
    def from_gateway(vault: vault_online.VaultOnline, gateway: str, configuration_uid: Optional[str] = None) \
            -> Optional["GatewayContext"]:
        """
        Populate context use the gateway, and optional configuration UID.

        This will scan all configuration to find which ones use this gateway.
        If there are multiple ones, a MultiConfigurationException is thrown.
        If there is only one gateway, then that gateway is used.
        """
        configuration_records = list(vault.vault_data.find_records(
            criteria=None, record_type=PAM_CONFIG_RECORD_TYPES, record_version=6))

        if configuration_uid:
            logger.debug(f"find the gateway with configuration record {configuration_uid}")

        if len(configuration_records) == 0:
            logger.error(f"Cannot find any PAM configuration records in the Vault")
            return None

        all_gateways = get_all_gateways(vault)
        found_items = []
        for configuration_record in configuration_records:

            logger.debug(f"checking configuration record {configuration_record.title}")

            # Load the configuration record and get the gateway_uid from the facade.
            configuration_record = vault.vault_data.load_record(configuration_record.record_uid)
            configuration_facade = PamConfigurationRecordFacade()
            configuration_facade.record = configuration_record

            configuration_gateway_uid = configuration_facade.controller_uid
            if configuration_gateway_uid is None:
                logger.debug(f" * configuration {configuration_record.title} does not have a gateway set, skipping.")
                continue

            # Get the gateway for this configuration
            found_gateway = next((x for x in all_gateways if utils.base64_url_encode(x.controllerUid) ==
                                  configuration_gateway_uid), None)
            if found_gateway is None:
                logger.debug(f" * configuration does not use desired gateway")
                continue

            if configuration_uid is not None and configuration_uid == configuration_record.record_uid:
                logger.debug(f" * configuration record uses this gateway and matches desire configuration, "
                              "skipping the rest")
                found_items = [{
                    "configuration_facade": configuration_facade,
                    "configuration_record": configuration_record,
                    "gateway": found_gateway
                }]
                break

            if (utils.base64_url_encode(found_gateway.controllerUid) == gateway or
                    found_gateway.controllerName.lower() == gateway.lower()):
                logger.debug(f" * configuration record uses this gateway")
                found_items.append({
                    "configuration_facade": configuration_facade,
                    "configuration_record": configuration_record,
                    "gateway": found_gateway
                })

            if len(found_items) > 1:
                logger.debug(f"found {len(found_items)} configurations using this gateway")
                raise MultiConfigurationException(
                    items=found_items
                )

        if len(found_items) == 1:
            found_gateway = found_items[0]["gateway"]
            configuration_record = found_items[0]["configuration_record"]
            configuration_facade = found_items[0]["configuration_facade"]

            application_id = utils.base64_url_encode(found_gateway.applicationUid)
            application = vault.vault_data.load_record(application_id)
            if application is None:
                logger.debug(f"cannot find application for gateway {gateway}, skipping.")

            if (utils.base64_url_encode(found_gateway.controllerUid) == gateway or
                    found_gateway.controllerName.lower() == gateway.lower()):
                return GatewayContext(
                    configuration=configuration_record,
                    facade=configuration_facade,
                    gateway=found_gateway,
                    application=application,
                    vault=vault
                )

        return None

    @property
    def gateway_uid(self) -> str:
        return utils.base64_url_encode(self.gateway.controllerUid)

    @property
    def configuration_uid(self) -> str:
        return self.configuration.record_uid

    @property
    def gateway_name(self) -> str:
        return self.gateway.controllerName

    @property
    def default_shared_folder_uid(self) -> str:
        return self.facade.folder_uid

    def is_gateway(self, request_gateway: str) -> bool:
        if request_gateway is None or self.gateway_name is None:
            return False
        return (request_gateway == utils.base64_url_encode(self.gateway.controllerUid) or
                request_gateway.lower() == self.gateway_name.lower())

    def get_shared_folders(self, vault: vault_online.VaultOnline) -> List[dict]:
        if self._shared_folders is None:
            self._shared_folders = []
            application_uid = utils.base64_url_encode(self.gateway.applicationUid)
            app_infos = ksm_management.get_app_info(vault, application_uid)
            if not app_infos:
                return self._shared_folders
            for shared in getattr(app_infos[0], 'shares', None) or []:
                if APIRequest_pb2.ApplicationShareType.Name(shared.shareType) != 'SHARE_TYPE_FOLDER':
                    continue
                uid_str = utils.base64_url_encode(shared.secretUid)
                sf_info = vault.vault_data.get_shared_folder(uid_str)
                if sf_info is None:
                    continue
                full_sf = vault.vault_data.load_shared_folder(uid_str)
                records: List[Dict[str, str]] = []
                if full_sf is not None:
                    records = [{"record_uid": rp.record_uid} for rp in full_sf.record_permissions]
                self._shared_folders.append({
                    "uid": uid_str,
                    "name": sf_info.name,
                    "folder": {"records": records},
                })
        return self._shared_folders

    def _configuration_record_key(self) -> bytes:
        key = self._vault.vault_data.get_record_key(self.configuration.record_uid)
        if not key:
            raise RuntimeError(
                f'No record key for PAM configuration {self.configuration.record_uid!r}; '
                f'ensure the vault is unlocked and records are synced.'
            )
        return key

    def decrypt(self, cipher_base64: bytes) -> dict:
        ciphertext = base64.b64decode(cipher_base64.decode())
        return json.loads(decrypt_aes_v2(ciphertext, self._configuration_record_key()))

    def encrypt(self, data: dict) -> str:
        json_data = json.dumps(data)
        ciphertext = encrypt_aes_v2(json_data.encode(), self._configuration_record_key())
        return base64.b64encode(ciphertext).decode()

    def encrypt_str(self, data: Union[bytes, str]) -> str:
        if isinstance(data, str):
            data = data.encode()
        ciphertext = encrypt_aes_v2(data, self._configuration_record_key())
        return base64.b64encode(ciphertext).decode()

    @staticmethod
    def get_configuration_records(vault: vault_online.VaultOnline) -> List[vault_record.KeeperRecord]:

        """
        Get PAM configuration records.

        The default it to find all the record version 6 records.
        If the environment variable `PAM_RECORD_TYPE_MATCH` is set to a true value, the search will use both record
          versions 3 and 6, and then check the record type.
        """

        configuration_list = []
        if dag_utils.value_to_boolean(os.environ.get("PAM_RECORD_TYPE_MATCH")):
            for record in list(vault.vault_data.find_records(record_version=iter([3, 6]), record_type=None)):
                if re.search(r"pam.+Configuration", record.record_type):
                    configuration_list.append(record)
        else:
            configuration_list = list(vault.vault_data.find_records(record_version=6, record_type=None))
        return configuration_list


class PAMGatewayActionDiscoverCommandBase(base.ArgparseCommand):
    """
    The discover command base.
    Contains static methods to get the configuration record, get and update the discovery store. These are methods
    used by multiple discover actions.
    """

    # If the discovery data field does not exist, or the field contains no values, use the template to init the
    # field.

    STORE_LABEL = "discoveryKey"
    FIELD_MAPPING = {
        "pamHostname": {
            "type": "dict",
            "field_input": [
                {"key": "hostName", "prompt": "Hostname"},
                {"key": "port", "prompt": "Port"}
            ],
            "field_format": [
                {"key": "hostName", "label": "Hostname"},
                {"key": "port", "label": "Port"},
            ]
        },
        "alternativeIPs": {
            "type": "csv",
        },
        "privatePEMKey": {
            "type": "multiline",
        },
        "operatingSystem": {
            "type": "choice",
            "values": ["linux", "macos", "windows", "cisco_ios_xe"]
        }
    }

    type_name_map = {
        PAM_USER: "PAM Users",
        PAM_MACHINE: "PAM Machines",
        PAM_DATABASE: "PAM Databases",
        PAM_DIRECTORY: "PAM Directories",
    }

    @staticmethod
    def get_response_data(router_response: dict) -> Optional[dict]:

        if router_response is None:
            return None

        response = router_response.get("response")
        logger.debug(f"Router Response: {response}")
        payload = router_utils.get_response_payload(router_response)
        return payload.get("data")

    @staticmethod
    def _p(msg):
        return msg

    @staticmethod
    def _n(record_type):
        return PAMGatewayActionDiscoverCommandBase.type_name_map.get(record_type, "PAM Configuration")


def multi_conf_msg(gateway: str, err: MultiConfigurationException):
    logger.info(f"Found multiple configuration records for gateway {gateway}.")
    logger.info("Please use the --configuration-uid parameter to select the configuration.")
    logger.info("Available configurations are: ")
    err.print_items()