import argparse
import json
import re
import requests
from datetime import datetime

from .. import base
from ... import api
from ...helpers import report_utils, router_utils, gateway_utils, folder_utils
from ...params import KeeperParams
from ..record_edit import RecordEditMixin


from keepersdk import utils
from keepersdk.proto import pam_pb2, record_pb2
from keepersdk.helpers import router_utils, gateway_utils, config_utils
from keepersdk.vault import ksm_management, vault_online, vault_utils, vault_record, record_management
from keepersdk.helpers.pam_config_facade import PamConfigurationRecordFacade
from keepersdk.helpers.tunnel.tunnel_graph import TunnelDAG, tunnel_utils
from .. import record_edit


logger = api.get_logger()


# Constants
DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S'
MILLISECONDS_TO_SECONDS = 1000
VERSION_SEPARATOR = ';'

DEFAULT_TOKEN_EXPIRATION_MIN = 60
MAX_TOKEN_EXPIRATION_MIN = 1440
MIN_INSTANCES = 1

ERROR_VAULT_NOT_INITIALIZED = "Vault is not initialized, login to initialize the vault."
ERROR_ROUTER_DOWN_MESSAGE_TEMPLATE = "Looks like router is down. Use '-f' flag to retrieve list of all available routers associated with your enterprise.\n\nRouter URL [{}]"
ERROR_ROUTER_DOWN_INFO_TEMPLATE = "Looks like router is down. Router URL [{}]"
ERROR_UNHANDLED_GATEWAY_RETRIEVAL = "Unhandled error during retrieval of the connected gateways."
MESSAGE_NO_GATEWAYS = "This Enterprise does not have Gateways yet. To create new Gateway, use command `pam gateway new`\n\nNOTE: If you have added new Gateway, you might still need to initialize it before it is listed."
MESSAGE_NO_GATEWAYS_JSON = "This Enterprise does not have Gateways yet."

# Header field names
HEADER_KSM_APP_NAME_UID = 'ksm_app_name_uid'
HEADER_GATEWAY_NAME = 'gateway_name'
HEADER_GATEWAY_UID = 'gateway_uid'
HEADER_GATEWAY_VERSION = 'gateway_version'
HEADER_DEVICE_NAME = 'device_name'
HEADER_DEVICE_TOKEN = 'device_token'
HEADER_CREATED_ON = 'created_on'
HEADER_LAST_MODIFIED = 'last_modified'
HEADER_NODE_ID = 'node_id'
HEADER_OS_RELEASE = 'os_release'
HEADER_MACHINE_TYPE = 'machine_type'
HEADER_OS_VERSION = 'os_version'

# Display headers
DISPLAY_HEADER_KSM_APP_NAME_UID = 'KSM Application Name (UID)'
DISPLAY_HEADER_GATEWAY_NAME = 'Gateway Name'
DISPLAY_HEADER_GATEWAY_UID = 'Gateway UID'
DISPLAY_HEADER_GATEWAY_VERSION = 'Gateway Version'
DISPLAY_HEADER_DEVICE_NAME = 'Device Name'
DISPLAY_HEADER_DEVICE_TOKEN = 'Device Token'
DISPLAY_HEADER_CREATED_ON = 'Created On'
DISPLAY_HEADER_LAST_MODIFIED = 'Last Modified'
DISPLAY_HEADER_NODE_ID = 'Node ID'
DISPLAY_HEADER_OS_RELEASE = 'OS Release'
DISPLAY_HEADER_MACHINE_TYPE = 'Machine Type'
DISPLAY_HEADER_OS_VERSION = 'OS Version'

APP_NOT_ACCESSIBLE_FORMAT = '[APP NOT ACCESSIBLE OR DELETED] ({})'
INSTANCE_PREFIX = '  |- Instance {} (connected: {})'
TOKEN_SEPARATOR = '-----------------------------------------------'


class PAMControllerCommand(base.GroupCommand):

    def __init__(self):
        super().__init__('PAM Controller')
        self.register_command(PAMGatewayCommand(), 'gateway', 'g')
        self.register_command(PAMConfigCommand(), 'config', 'c')


class PAMGatewayCommand(base.GroupCommand):
    
    def __init__(self):
        super().__init__('PAM Gateway')
        self.register_command(PAMGatewayListCommand(), 'list', 'l')
        self.register_command(PAMGatewayNewCommand(), 'new', 'n')
        self.register_command(PAMGatewayRemoveCommand(), 'remove', 'rm')
        self.register_command(PAMGatewaySetMaxInstancesCommand(), 'set-max-instances', 'smi')
        self.default_verb = 'list'


class PAMConfigCommand(base.GroupCommand):

    def __init__(self):
        super().__init__('PAM Configurations')
        self.register_command(PAMConfigListCommand(), 'list', 'l')
        self.register_command(PAMConfigNewCommand(), 'new', 'n')
        self.register_command(PAMConfigEditCommand(), 'edit', 'e')
        self.register_command(PAMConfigRemoveCommand(), 'remove', 'rm')
        self.default_verb = 'list'


class PAMGatewayListCommand(base.ArgparseCommand):

    def __init__(self):
        parser = argparse.ArgumentParser(prog='dr-gateway')
        PAMGatewayListCommand.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('--force', '-f', required=False, default=False, dest='is_force', action='store_true',
                            help='Force retrieval of gateways')
        parser.add_argument('--verbose', '-v', required=False, default=False, dest='is_verbose', action='store_true',
                            help='Verbose output')
        parser.add_argument('--format', dest='format', action='store', choices=['table', 'json'], default='table',
                            help='Output format (table, json)')

    def execute(self, context: KeeperParams, **kwargs):
        self._validate_vault_and_permissions(context)
        vault = context.vault

        is_force = kwargs.get('is_force')
        is_verbose = kwargs.get('is_verbose')
        format_type = kwargs.get('format', 'table')

        enterprise_controllers_connected, is_router_down = self._fetch_connected_gateways(vault, is_force)
        enterprise_controllers_all = gateway_utils.get_all_gateways(vault)

        if not enterprise_controllers_all:
            return self._handle_no_gateways(format_type)

        headers = self._build_headers(format_type, is_verbose)
        connected_controllers_dict = self._build_connected_controllers_dict(enterprise_controllers_connected)

        table, gateways_data = self._process_gateways(
            vault, enterprise_controllers_all, connected_controllers_dict,
            is_router_down, format_type, is_verbose
        )

        return self._format_output(vault, table, gateways_data, headers, format_type, is_verbose)

    def _validate_vault_and_permissions(self, context: KeeperParams):
        """Validates that vault is initialized and user has enterprise admin permissions."""
        if not context.vault:
            raise ValueError(ERROR_VAULT_NOT_INITIALIZED)
        base.require_enterprise_admin(context)

    def _fetch_connected_gateways(self, vault, is_force):
        """Fetches connected gateways and handles router connection errors."""
        is_router_down = False
        krouter_url = f"https://{vault.keeper_auth.keeper_endpoint.get_router_server()}"
        enterprise_controllers_connected = None

        try:
            enterprise_controllers_connected = router_utils.router_get_connected_gateways(vault)
        except requests.exceptions.ConnectionError:
            is_router_down = True
            if not is_force:
                logger.warning(ERROR_ROUTER_DOWN_MESSAGE_TEMPLATE.format(krouter_url))
                return None, is_router_down
            else:
                logger.info(ERROR_ROUTER_DOWN_INFO_TEMPLATE.format(krouter_url))
        except Exception as e:
            logger.warning(ERROR_UNHANDLED_GATEWAY_RETRIEVAL)
            raise e

        return enterprise_controllers_connected, is_router_down

    def _handle_no_gateways(self, format_type):
        """Handles the case when no gateways are found."""
        if format_type == 'json':
            return json.dumps({"gateways": [], "message": MESSAGE_NO_GATEWAYS_JSON})
        else:
            logger.info(MESSAGE_NO_GATEWAYS)
            return None

    def _build_headers(self, format_type, is_verbose):
        """Builds headers for output based on format type and verbosity."""
        if format_type == 'json':
            headers = [HEADER_KSM_APP_NAME_UID, HEADER_GATEWAY_NAME, HEADER_GATEWAY_UID,
                      'status', HEADER_GATEWAY_VERSION]
            if is_verbose:
                headers.extend([HEADER_DEVICE_NAME, HEADER_DEVICE_TOKEN, HEADER_CREATED_ON,
                              HEADER_LAST_MODIFIED, HEADER_NODE_ID, 'os', HEADER_OS_RELEASE,
                              HEADER_MACHINE_TYPE, HEADER_OS_VERSION])
        else:
            headers = [DISPLAY_HEADER_KSM_APP_NAME_UID, DISPLAY_HEADER_GATEWAY_NAME,
                      DISPLAY_HEADER_GATEWAY_UID, 'Status', DISPLAY_HEADER_GATEWAY_VERSION]
            if is_verbose:
                headers.extend([DISPLAY_HEADER_DEVICE_NAME, DISPLAY_HEADER_DEVICE_TOKEN,
                              DISPLAY_HEADER_CREATED_ON, DISPLAY_HEADER_LAST_MODIFIED, DISPLAY_HEADER_NODE_ID,
                              'OS', DISPLAY_HEADER_OS_RELEASE, DISPLAY_HEADER_MACHINE_TYPE,
                              DISPLAY_HEADER_OS_VERSION])
        return headers

    def _build_connected_controllers_dict(self, enterprise_controllers_connected):
        """Builds a dictionary mapping controller UIDs to their connected instances."""
        connected_controllers_dict = {}
        if enterprise_controllers_connected:
            for controller in list(enterprise_controllers_connected.controllers):
                if controller.controllerUid not in connected_controllers_dict:
                    connected_controllers_dict[controller.controllerUid] = []
                connected_controllers_dict[controller.controllerUid].append(controller)
        return connected_controllers_dict

    def _process_gateways(self, vault, enterprise_controllers_all, connected_controllers_dict,
                          is_router_down, format_type, is_verbose):
        """Processes all gateways and builds table and JSON data structures."""
        table = []
        gateways_data = []

        for controller in enterprise_controllers_all:
            gateway_uid_bytes = controller.controllerUid
            gateway_uid_str = utils.base64_url_encode(controller.controllerUid)
            connected_instances = connected_controllers_dict.get(gateway_uid_bytes, [])

            ksm_app_info = self._get_ksm_app_info(vault, controller)
            overall_status = self._determine_gateway_status(connected_instances, is_router_down)
            is_pool = len(connected_instances) > 1

            if not is_pool:
                self._process_single_gateway(
                    controller, gateway_uid_str, connected_instances, ksm_app_info,
                    overall_status, format_type, is_verbose, table, gateways_data
                )
            else:
                self._process_pool_gateway(
                    controller, gateway_uid_str, connected_instances, ksm_app_info,
                    overall_status, format_type, is_verbose, table, gateways_data
                )

        return table, gateways_data

    def _get_ksm_app_info(self, vault, controller):
        """Retrieves KSM application information for a controller."""
        ksm_app_uid_str = utils.base64_url_encode(controller.applicationUid)
        ksm_app = vault.vault_data.load_record(ksm_app_uid_str)

        if ksm_app:
            ksm_app_title = ksm_app.title
            ksm_app_info_plain = f'{ksm_app_title} ({ksm_app_uid_str})'
            ksm_app_name = ksm_app_title
            ksm_app_accessible = True
        else:
            ksm_app_info_plain = APP_NOT_ACCESSIBLE_FORMAT.format(ksm_app_uid_str)
            ksm_app_name = None
            ksm_app_accessible = False

        return {
            'ksm_app_uid_str': ksm_app_uid_str,
            'ksm_app_info_plain': ksm_app_info_plain,
            'ksm_app_name': ksm_app_name,
            'ksm_app_accessible': ksm_app_accessible
        }

    def _determine_gateway_status(self, connected_instances, is_router_down):
        """Determines the overall status of a gateway."""
        if is_router_down:
            return 'UNKNOWN'
        elif len(connected_instances) > 0:
            is_pool = len(connected_instances) > 1
            return f"ONLINE ({len(connected_instances)} instances)" if is_pool else 'ONLINE'
        else:
            return 'OFFLINE'

    def _parse_version(self, version_string):
        """Parses version string and returns version and parts."""
        if not version_string:
            return "", []
        version_parts = version_string.split(VERSION_SEPARATOR)
        version = version_parts[0] if version_parts else version_string
        return version, version_parts

    def _format_timestamp(self, timestamp_ms):
        """Formats timestamp from milliseconds to datetime string."""
        return datetime.fromtimestamp(timestamp_ms / MILLISECONDS_TO_SECONDS).strftime(DATETIME_FORMAT)

    def _extract_version_info(self, version_parts):
        """Extracts OS information from version parts."""
        os_name = version_parts[1] if len(version_parts) > 1 else ""
        os_release = version_parts[2] if len(version_parts) > 2 else ""
        machine_type = version_parts[3] if len(version_parts) > 3 else ""
        os_version = version_parts[4] if len(version_parts) > 4 else ""
        return os_name, os_release, machine_type, os_version

    def _process_single_gateway(self, controller, gateway_uid_str, connected_instances,
                                ksm_app_info, overall_status, format_type, is_verbose,
                                table, gateways_data):
        """Processes a single gateway (non-pool) instance."""
        connected_controller = connected_instances[0] if connected_instances else None
        version, version_parts = self._parse_version(
            connected_controller.version if connected_controller and hasattr(connected_controller, 'version') else None
        )

        gateway_data = {
            "ksm_app_name": ksm_app_info['ksm_app_name'],
            "ksm_app_uid": ksm_app_info['ksm_app_uid_str'],
            "ksm_app_accessible": ksm_app_info['ksm_app_accessible'],
            "gateway_name": controller.controllerName,
            "gateway_uid": gateway_uid_str,
            "status": overall_status,
            "gateway_version": version
        }

        if is_verbose:
            os_name, os_release, machine_type, os_version = self._extract_version_info(version_parts)
            gateway_data.update({
                "device_name": controller.deviceName,
                "device_token": controller.deviceToken,
                "created_on": self._format_timestamp(controller.created),
                "last_modified": self._format_timestamp(controller.lastModified),
                "node_id": controller.nodeId,
                "os": os_name,
                "os_release": os_release,
                "machine_type": machine_type,
                "os_version": os_version
            })

        gateways_data.append(gateway_data)

        if format_type == 'table':
            row = self._build_single_gateway_table_row(
                controller, gateway_uid_str, ksm_app_info, overall_status, version, is_verbose, version_parts
            )
            table.append(row)

    def _build_single_gateway_table_row(self, controller, gateway_uid_str, ksm_app_info,
                                        overall_status, version, is_verbose, version_parts):
        """Builds a table row for a single gateway."""
        row = [
            ksm_app_info['ksm_app_info_plain'],
            controller.controllerName,
            gateway_uid_str,
            overall_status,
            version
        ]

        if is_verbose:
            os_name, os_release, machine_type, os_version = self._extract_version_info(version_parts)
            row.extend([
                controller.deviceName,
                controller.deviceToken,
                datetime.fromtimestamp(controller.created / MILLISECONDS_TO_SECONDS),
                datetime.fromtimestamp(controller.lastModified / MILLISECONDS_TO_SECONDS),
                controller.nodeId,
                os_name,
                os_release,
                machine_type,
                os_version
            ])

        return row

    def _process_pool_gateway(self, controller, gateway_uid_str, connected_instances,
                             ksm_app_info, overall_status, format_type, is_verbose,
                             table, gateways_data):
        """Processes a pool gateway with multiple instances."""
        if format_type == 'json':
            instances_data = self._build_pool_instances_json(connected_instances, is_verbose)
            gateway_data = {
                "ksm_app_name": ksm_app_info['ksm_app_name'],
                "ksm_app_uid": ksm_app_info['ksm_app_uid_str'],
                "ksm_app_accessible": ksm_app_info['ksm_app_accessible'],
                "gateway_name": controller.controllerName,
                "gateway_uid": gateway_uid_str,
                "status": overall_status,
                "instances": instances_data
            }

            if is_verbose:
                gateway_data.update({
                    "device_name": controller.deviceName,
                    "device_token": controller.deviceToken,
                    "created_on": self._format_timestamp(controller.created),
                    "last_modified": self._format_timestamp(controller.lastModified),
                    "node_id": controller.nodeId
                })

            gateways_data.append(gateway_data)
        else:
            row = self._build_pool_gateway_table_row(
                controller, gateway_uid_str, ksm_app_info, overall_status, is_verbose
            )
            table.append(row)

            for idx, instance in enumerate(connected_instances, 1):
                instance_row = self._build_pool_instance_table_row(instance, idx, is_verbose)
                table.append(instance_row)

    def _build_pool_instances_json(self, connected_instances, is_verbose):
        """Builds JSON data for pool gateway instances."""
        instances_data = []
        for idx, instance in enumerate(connected_instances, 1):
            version, version_parts = self._parse_version(
                instance.version if hasattr(instance, 'version') else None
            )

            instance_data = {
                "instance_number": idx,
                "status": 'ONLINE',
                "gateway_version": version,
                "ip_address": instance.ipAddress if hasattr(instance, 'ipAddress') else "",
                "connected_on": instance.connectedOn
            }

            if is_verbose:
                os_name, os_release, machine_type, os_version = self._extract_version_info(version_parts)
                instance_data.update({
                    "os": os_name,
                    "os_release": os_release,
                    "machine_type": machine_type,
                    "os_version": os_version
                })

            instances_data.append(instance_data)

        return instances_data

    def _build_pool_gateway_table_row(self, controller, gateway_uid_str, ksm_app_info,
                                     overall_status, is_verbose):
        """Builds a table row for a pool gateway header."""
        row = [
            ksm_app_info['ksm_app_info_plain'],
            controller.controllerName,
            gateway_uid_str,
            overall_status,
            ''
        ]

        if is_verbose:
            row.extend([
                controller.deviceName,
                controller.deviceToken,
                datetime.fromtimestamp(controller.created / MILLISECONDS_TO_SECONDS),
                datetime.fromtimestamp(controller.lastModified / MILLISECONDS_TO_SECONDS),
                controller.nodeId,
                '', '', '', ''
            ])

        return row

    def _build_pool_instance_table_row(self, instance, idx, is_verbose):
        """Builds a table row for a pool gateway instance."""
        version, version_parts = self._parse_version(
            instance.version if hasattr(instance, 'version') else None
        )

        ip_address = instance.ipAddress if hasattr(instance, 'ipAddress') else ""
        connected_on = self._format_timestamp(instance.connectedOn) if hasattr(instance, 'connectedOn') else ""

        instance_row = [
            '',
            INSTANCE_PREFIX.format(idx, connected_on),
            ip_address,
            'ONLINE',
            version
        ]

        if is_verbose:
            os_name, os_release, machine_type, os_version = self._extract_version_info(version_parts)
            instance_row.extend([
                '', '',
                datetime.fromtimestamp(instance.connectedOn / MILLISECONDS_TO_SECONDS) if hasattr(instance, 'connectedOn') else "",
                '', '',
                os_name, os_release, machine_type, os_version
            ])

        return instance_row

    def _format_output(self, vault, table, gateways_data, headers, format_type, is_verbose):
        """Formats and returns the final output."""
        if format_type == 'json':
            return self._format_json_output(vault, gateways_data, is_verbose)
        else:
            return self._format_table_output(vault, table, headers, is_verbose)

    def _format_json_output(self, vault, gateways_data, is_verbose):
        """Formats output as JSON."""
        gateways_data.sort(key=lambda x: (x['status'], (x['ksm_app_name'] or '').lower()))

        result = {"gateways": gateways_data}
        if is_verbose:
            krouter_host = f"https://{vault.keeper_auth.keeper_endpoint.get_router_server()}"
            result["router_host"] = krouter_host

        return json.dumps(result, indent=2)

    def _format_table_output(self, vault, table, headers, is_verbose):
        """Formats output as table."""
        sorted_groups = []
        current_group = []

        for row in table:
            if row[0]:
                if current_group:
                    sorted_groups.append(current_group)
                current_group = [row]
            else:
                current_group.append(row)

        if current_group:
            sorted_groups.append(current_group)

        sorted_groups.sort(key=lambda group: (group[0][3] or '', group[0][0].lower()))

        table = []
        for group in sorted_groups:
            table.extend(group)

        if is_verbose:
            krouter_host = f"https://{vault.keeper_auth.keeper_endpoint.get_router_server()}"
            logger.info(f"\nRouter Host: {krouter_host}\n")

        report_utils.dump_report_data(table, headers, fmt='table', filename="",
                                      row_number=False, column_width=None)


class PAMGatewayNewCommand(base.ArgparseCommand):

    def __init__(self):
        parser = argparse.ArgumentParser(prog='dr-create-gateway')
        PAMGatewayNewCommand.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('--name', '-n', required=True, dest='gateway_name',
                             help='Name of the Gateway',
                             action='store')
        parser.add_argument('--application', '-a', required=True, dest='ksm_app',
                             help='KSM Application name or UID. Use command `sm app list` to view '
                                  'available KSM Applications.', action='store')
        parser.add_argument('--token-expires-in-min', '-e', type=int, dest='token_expire_in_min',
                             action='store',
                             help=f'Time for the one time token to expire. Maximum {MAX_TOKEN_EXPIRATION_MIN} minutes (24 hrs). Default: {DEFAULT_TOKEN_EXPIRATION_MIN}',
                             default=DEFAULT_TOKEN_EXPIRATION_MIN)
        parser.add_argument('--return_value', '-r', dest='return_value', action='store_true',
                             help='Return value from the command for automation purposes')

    def execute(self, context: KeeperParams, **kwargs):
        self._validate_vault_and_permissions(context)
        vault = context.vault

        gateway_name = kwargs.get('gateway_name')
        ksm_app = kwargs.get('ksm_app')
        is_return_value = kwargs.get('return_value')
        token_expire_in_min = kwargs.get('token_expire_in_min')

        self._log_gateway_creation_params(gateway_name, ksm_app, token_expire_in_min)
        ksm_app_info = ksm_management.get_secrets_manager_app(vault, ksm_app)
        one_time_token = gateway_utils.create_gateway(vault, gateway_name, ksm_app_info.uid, token_expire_in_min)

        if is_return_value:
            return one_time_token
        else:
            self._display_token_info(ksm_app, gateway_name, token_expire_in_min, one_time_token)

    def _validate_vault_and_permissions(self, context: KeeperParams):
        """Validates that vault is initialized and user has enterprise admin permissions."""
        if not context.vault:
            raise ValueError(ERROR_VAULT_NOT_INITIALIZED)
        base.require_enterprise_admin(context)

    def _log_gateway_creation_params(self, gateway_name, ksm_app, token_expire_in_min):
        """Logs gateway creation parameters for debugging."""
        logger.debug(f'gateway_name =[{gateway_name}]')
        logger.debug(f'ksm_app =[{ksm_app}]')
        logger.debug(f'ott_expire_in_min =[{token_expire_in_min}]')

    def _display_token_info(self, ksm_app, gateway_name, token_expire_in_min, one_time_token):
        """Displays one-time token information to the user."""
        logger.info(f'The one time token has been created in application [{ksm_app}].\n\n'
                  f'The new Gateway named {gateway_name} will show up in a list '
                  f'of gateways once it is initialized.\n\n')
        logger.info(f'Following one time token will expire in {token_expire_in_min} minutes.')
        logger.info(TOKEN_SEPARATOR)
        logger.info(one_time_token)
        logger.info(TOKEN_SEPARATOR)


class PAMGatewayRemoveCommand(base.ArgparseCommand):

    def __init__(self):
        parser = argparse.ArgumentParser(prog='dr-remove-gateway')
        PAMGatewayRemoveCommand.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('--gateway', '-g', required=True, dest='gateway',
                             help='UID of the Gateway', action='store')

    def execute(self, context: KeeperParams, **kwargs):
        self._validate_vault_and_permissions(context)
        vault = context.vault

        gateway_uid = kwargs.get('gateway')
        gateway = self._find_gateway(vault, gateway_uid)

        if gateway:
            gateway_utils.remove_gateway(vault, gateway.controllerUid)
            logger.info('Gateway %s has been removed.', gateway.controllerName)
        else:
            logger.warning('Gateway %s not found', gateway_uid)

    def _validate_vault_and_permissions(self, context: KeeperParams):
        """Validates that vault is initialized and user has enterprise admin permissions."""
        if not context.vault:
            raise ValueError(ERROR_VAULT_NOT_INITIALIZED)
        base.require_enterprise_admin(context)

    def _find_gateway(self, vault, gateway_uid):
        """Finds a gateway by UID or name."""
        gateways = gateway_utils.get_all_gateways(vault)
        return next((x for x in gateways
                    if utils.base64_url_encode(x.controllerUid) == gateway_uid
                    or x.controllerName.lower() == gateway_uid.lower()), None)


class PAMGatewaySetMaxInstancesCommand(base.ArgparseCommand):

    def __init__(self):
        parser = argparse.ArgumentParser(prog='pam gateway set-max-instances')
        PAMGatewaySetMaxInstancesCommand.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('--gateway', '-g', required=True, dest='gateway',
                            help='Gateway UID or Name', action='store')
        parser.add_argument('--max-instances', '-m', required=True, dest='max_instances', type=int,
                            help='Maximum number of gateway instances (must be >= 1)', action='store')

    def execute(self, context: KeeperParams, **kwargs):
        self._validate_vault_and_permissions(context)
        vault = context.vault

        gateway_uid = kwargs.get('gateway')
        max_instances = kwargs.get('max_instances')

        self._validate_max_instances(max_instances)
        gateway = self._find_gateway(vault, gateway_uid)

        if not gateway:
            raise base.CommandError(f'Gateway "{gateway_uid}" not found')

        self._set_max_instances(vault, gateway, max_instances)

    def _validate_vault_and_permissions(self, context: KeeperParams):
        """Validates that vault is initialized and user has enterprise admin permissions."""
        if not context.vault:
            raise ValueError(ERROR_VAULT_NOT_INITIALIZED)
        base.require_enterprise_admin(context)

    def _validate_max_instances(self, max_instances):
        """Validates that max_instances is at least the minimum required."""
        if max_instances < MIN_INSTANCES:
            raise base.CommandError(f'pam gateway set-max-instances: --max-instances must be at least {MIN_INSTANCES}')

    def _find_gateway(self, vault, gateway_uid):
        """Finds a gateway by UID or name."""
        gateways = gateway_utils.get_all_gateways(vault)
        return next((x for x in gateways
                    if utils.base64_url_encode(x.controllerUid) == gateway_uid
                    or x.controllerName.lower() == gateway_uid.lower()), None)

    def _set_max_instances(self, vault, gateway, max_instances):
        """Sets the maximum number of instances for a gateway."""
        try:
            gateway_utils.set_gateway_max_instances(vault, gateway.controllerUid, max_instances)
            logger.info('%s: max instance count set to %d', gateway.controllerName, max_instances)
        except Exception as e:
            raise base.CommandError(f'Error setting max instances: {e}')


class PAMConfigListCommand(base.ArgparseCommand):

    def __init__(self):
        parser = argparse.ArgumentParser(prog='pam config list')
        PAMConfigListCommand.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('--config', '-c', required=False, dest='pam_configuration', action='store',
                            help='Specific PAM Configuration UID')
        parser.add_argument('--verbose', '-v', required=False, dest='verbose', action='store_true', help='Verbose')
        parser.add_argument('--format', dest='format', action='store', choices=['table', 'json'], default='table',
                            help='Output format (table, json)')

    def execute(self, context: KeeperParams, **kwargs):
        if not context.vault:
            raise ValueError("Vault is not initialized, login to initialize the vault.")
        
        base.require_enterprise_admin(context)
        
        vault = context.vault

        pam_configuration_uid = kwargs.get('pam_configuration')
        is_verbose = kwargs.get('verbose')
        format_type = kwargs.get('format', 'table')

        if not pam_configuration_uid:  # Print ALL root level configs
            result = PAMConfigListCommand.print_root_rotation_setting(vault, is_verbose, format_type)
            if format_type == 'json' and result:
                return result
        else:  # Print element configs (config that is not a root)
            result = PAMConfigListCommand.print_pam_configuration_details(vault, pam_configuration_uid, is_verbose, format_type)
            if format_type == 'json' and result:
                return result

            if format_type == 'table':  # Only print tunneling config for table format
                encrypted_session_token, encrypted_transmission_key, transmission_key = gateway_utils.get_keeper_tokens(vault)
                tmp_dag = TunnelDAG(vault, encrypted_session_token, encrypted_transmission_key, pam_configuration_uid,
                                    is_config=True)
                tmp_dag.print_tunneling_config(pam_configuration_uid, None)

    @staticmethod
    def print_pam_configuration_details(vault: vault_online.VaultOnline, config_uid: str, is_verbose: bool = False, format_type: str = 'table'):
        configuration = vault.vault_data.load_record(config_uid)
        if not configuration:
            if format_type == 'json':
                return json.dumps({"error": f'Configuration {config_uid} not found'})
            else:
                raise Exception(f'Configuration {config_uid} not found')
        if configuration.version != 6:
            if format_type == 'json':
                return json.dumps({"error": f'{config_uid} is not PAM Configuration'})
            else:
                raise Exception(f'{config_uid} is not PAM Configuration')
        if not isinstance(configuration, vault_record.TypedRecord):
            if format_type == 'json':
                return json.dumps({"error": f'{config_uid} is not PAM Configuration'})
            else:
                raise Exception(f'{config_uid} is not PAM Configuration')

        facade = PamConfigurationRecordFacade()
        facade.record = configuration
        
        folder_uid = facade.folder_uid
        sf = None
        if folder_uid in vault.vault_data._shared_folders:
            sf = vault.vault_data.load_shared_folder(folder_uid)
        
        if format_type == 'json':
            config_data = {
                "uid": configuration.record_uid,
                "name": configuration.title,
                "config_type": configuration.record_type,
                "shared_folder": {
                    "name": sf.name if sf else None,
                    "uid": sf.shared_folder_uid if sf else None
                } if sf else None,
                "gateway_uid": facade.controller_uid,
                "resource_record_uids": facade.resource_ref,
                "fields": {}
            }
            
            for field in configuration.fields:
                if field.type in ('pamResources', 'fileRef'):
                    continue
                values = list(field.get_external_value())
                if not values:
                    continue
                field_name = field.external_name()
                if field.type == 'schedule':
                    field_name = 'Default Schedule'
                
                config_data["fields"][field_name] = values
            
            return json.dumps(config_data, indent=2)
        else:
            table = []
            header = ['name', 'value']
            table.append(['UID', configuration.record_uid])
            table.append(['Name', configuration.title])
            table.append(['Config Type', configuration.record_type])
            table.append(['Shared Folder', f'{sf.name} ({sf.shared_folder_uid})' if sf else ''])
            table.append(['Gateway UID', facade.controller_uid])
            table.append(['Resource Record UIDs', facade.resource_ref])

            for field in configuration.fields:
                if field.type in ('pamResources', 'fileRef'):
                    continue
                values = list(field.get_external_value())
                if not values:
                    continue
                
                field_name = field.external_name()
                
                if field.type == 'schedule':
                    field_name = 'Default Schedule'

                table.append([field_name, values])
            report_utils.dump_report_data(table, header, no_header=True, right_align=(0,))

    @staticmethod
    def print_root_rotation_setting(vault: vault_online.VaultOnline, is_verbose: bool = False, format_type: str = 'table'):
        facade = PamConfigurationRecordFacade()
        
        configs_data = []
        table = []
        
        if format_type == 'json':
            headers = ['uid', 'config_name', 'config_type', 'shared_folder', 'gateway_uid', 'resource_record_uids']
            if is_verbose:
                headers.append('fields')
        else:
            headers = ['UID', 'Config Name', 'Config Type', 'Shared Folder', 'Gateway UID', 'Resource Record UIDs']
            if is_verbose:
                headers.append('Fields')

        for c in vault.vault_data.find_records(criteria='', record_type=None, record_version=6):
            if c.record_type in ('pamAwsConfiguration', 'pamAzureConfiguration', 'pamGcpConfiguration', 'pamDomainConfiguration', 'pamNetworkConfiguration', 'pamOciConfiguration'):
                facade.record = c
                shared_folder_parents = vault_utils.get_folders_for_record(vault.vault_data, c.record_uid)
                if shared_folder_parents:
                    sf = shared_folder_parents[0]
                    
                    record = vault.vault_data.load_record(c.record_uid)
                    if format_type == 'json':
                        config_data = {
                            "uid": c.record_uid,
                            "config_name": c.title,
                            "config_type": c.record_type,
                            "shared_folder": {
                                "name": sf.name,
                                "uid": sf.folder_uid
                            },
                            "gateway_uid": facade.controller_uid,
                            "resource_record_uids": facade.resource_ref
                        }

                        if is_verbose:
                            fields = {}
                            for field in record.fields:
                                if field.type in ('pamResources', 'fileRef'):
                                    continue
                                value = ', '.join(field.get_external_value())
                                if value:
                                    fields[field.external_name()] = value
                            config_data["fields"] = fields

                        configs_data.append(config_data)
                    else:
                        row = [c.record_uid, c.title, c.record_type, f'{sf.name} ({sf.folder_uid})',
                               facade.controller_uid, facade.resource_ref]

                        if is_verbose:
                            fields = []
                            for field in record.fields:
                                if field.type in ('pamResources', 'fileRef'):
                                    continue
                                value = ', '.join(field.get_external_value())
                                if value:
                                    fields.append(f'{field.external_name()}: {value}')
                            row.append(fields)

                        table.append(row)
                else:
                    logger.warning(f'Following configuration is not in the shared folder: UID: %s, Title: %s',
                                    c.record_uid, c.title)
            else:
                logger.warning(f'Following configuration has unsupported type: UID: %s, Title: %s', c.record_uid,
                                c.title)

        if format_type == 'json':
            configs_data.sort(key=lambda x: x['config_name'] or '')
            return json.dumps({"configurations": configs_data}, indent=2)
        else:
            table.sort(key=lambda x: (x[1] or ''))
            report_utils.dump_report_data(table, headers, fmt='table', filename="", row_number=False, column_width=None)


class PamConfigurationEditMixin(record_edit.RecordEditMixin):
    pam_record_types = None

    def __init__(self):
        super().__init__()

    @staticmethod
    def get_pam_record_types(vault: vault_online.VaultOnline):
        if PamConfigurationEditMixin.pam_record_types is None:
            rts = [x for x in vault.vault_data._custom_record_types if x.scope // 1000000 == record_pb2.RT_PAM]
            PamConfigurationEditMixin.pam_record_types = []
            for rt in rts:
                PamConfigurationEditMixin.pam_record_types.append(rt.id)
        return PamConfigurationEditMixin.pam_record_types

    def parse_pam_configuration(self, vault: vault_online.VaultOnline, record: vault_record.TypedRecord, **kwargs):
        field = record.get_typed_field('pamResources')
        if not field:
            value = {}
            field = vault_record.TypedField.new_field('pamResources', value)
            record.fields.append(field)

        if len(field.value) == 0:
            field.value.append({})
        value = field.value[0]

        gateway_uid = None
        gateway = kwargs.get('gateway_uid')
        if gateway:
            gateways = gateway_utils.get_all_gateways(vault)
            gateway_uid = next((utils.base64_url_encode(x.controllerUid) for x in gateways
                                if utils.base64_url_encode(x.controllerUid) == gateway
                                or x.controllerName.casefold() == gateway.casefold()), None)
        if gateway_uid:
            value['controllerUid'] = gateway_uid

        shared_folder_uid = None
        folder_name = kwargs.get('shared_folder_uid')
        if folder_name:
            shared_folder_cache = vault.vault_data._shared_folders
            if folder_name in shared_folder_cache:
                shared_folder_uid = folder_name
            else:
                for sf_uid in shared_folder_cache:
                    sf = vault.vault_data.load_shared_folder(sf_uid)
                    if sf and sf.name.casefold() == folder_name.casefold():
                        shared_folder_uid = sf_uid
                        break
        if shared_folder_uid:
            value['folderUid'] = shared_folder_uid
        else:
            for f in record.fields:
                if f.type == 'pamResources' and f.value and len(f.value) > 0 and 'folderUid' in f.value[0]:
                    shared_folder_uid = f.value[0]['folderUid']
                    break
            if not shared_folder_uid:
                raise base.CommandError('Shared Folder not found')

        rrr = kwargs.get('remove_records')
        if rrr:
            pam_record_lookup = {}
            rti = PamConfigurationEditMixin.get_pam_record_types(vault)
            records = vault.vault_data.records()
            for r in records:
                if r.record_type in rti:
                    pam_record_lookup[r.record_uid] = r.record_uid
                    pam_record_lookup[r.title.lower()] = r.record_uid

            record_uids = set()
            if 'resourceRef' in value:
                record_uids.update(value['resourceRef'])
            if isinstance(rrr, list):
                for r in rrr:
                    if r in pam_record_lookup:
                        record_uids.remove(r)
                        continue
                    r_l = r.lower()
                    if r_l in pam_record_lookup:
                        record_uids.remove(r_l)
                        continue
                    logger.warning(f'Failed to find PAM record: {r}')

            value['resourceRef'] = list(record_uids)

    @staticmethod
    def resolve_single_record(vault: vault_online.VaultOnline, record_name: str, rec_type: str = ''):
        records = vault.vault_data.records()
        for r in records:
            if r.title == record_name and (not rec_type or rec_type == r.record_type):
                return r
        return None

    def parse_properties(self, vault: vault_online.VaultOnline, record: vault_record.TypedRecord, **kwargs):
        extra_properties = []
        self.parse_pam_configuration(vault, record, **kwargs)
        port_mapping = kwargs.get('port_mapping')
        if isinstance(port_mapping, list) and len(port_mapping) > 0:
            pm = "\n".join(port_mapping)
            extra_properties.append(f'multiline.portMapping={pm}')
        schedule = kwargs.get('default_schedule')  # Default Schedule: Use CRON syntax
        if schedule:
            valid, err = validate_cron_expression(schedule, for_rotation=True)
            if not valid:
                raise base.CommandError(f'Invalid CRON "{schedule}" Error: {err}')
        if schedule:
            extra_properties.append(f'schedule.defaultRotationSchedule=$JSON:{{"type": "CRON", "cron": "{schedule}", "tz": "Etc/UTC"}}')
        else:
            extra_properties.append('schedule.defaultRotationSchedule=On-Demand')

        if record.record_type == 'pamNetworkConfiguration':
            network_id = kwargs.get('network_id')
            if network_id:
                extra_properties.append(f'text.networkId={network_id}')
            network_cidr = kwargs.get('network_cidr')
            if network_cidr:
                extra_properties.append(f'text.networkCIDR={network_cidr}')
        elif record.record_type == 'pamAwsConfiguration':
            aws_id = kwargs.get('aws_id')
            if aws_id:
                extra_properties.append(f'text.awsId={aws_id}')
            access_key_id = kwargs.get('access_key_id')
            if access_key_id:
                extra_properties.append(f'secret.accessKeyId={access_key_id}')
            access_secret_key = kwargs.get('access_secret_key')
            if access_secret_key:
                extra_properties.append(f'secret.accessSecretKey={access_secret_key}')
            region_names = kwargs.get('region_names')
            if region_names:
                regions = '\n'.join(region_names)
                extra_properties.append(f'multiline.regionNames={regions}')
        elif record.record_type == 'pamGcpConfiguration':
            gcp_id = kwargs.get('gcp_id')
            if gcp_id:
                extra_properties.append(f'text.pamGcpId={gcp_id}')
            service_account_key = kwargs.get('service_account_key')
            if service_account_key:
                extra_properties.append(f'json.pamServiceAccountKey={service_account_key}')
            google_admin_email = kwargs.get('google_admin_email')
            if google_admin_email:
                extra_properties.append(f'email.pamGoogleAdminEmail={google_admin_email}')
            gcp_region = kwargs.get('region_names')
            if gcp_region:
                regions = '\n'.join(gcp_region)
                extra_properties.append(f'multiline.pamGcpRegionName={regions}')
        elif record.record_type == 'pamAzureConfiguration':
            azure_id = kwargs.get('azure_id')
            if azure_id:
                extra_properties.append(f'text.azureId={azure_id}')
            client_id = kwargs.get('client_id')
            if client_id:
                extra_properties.append(f'secret.clientId={client_id}')
            client_secret = kwargs.get('client_secret')
            if client_secret:
                extra_properties.append(f'secret.clientSecret={client_secret}')
            subscription_id = kwargs.get('subscription_id')
            if subscription_id:
                extra_properties.append(f'secret.subscriptionId={subscription_id}')
            tenant_id = kwargs.get('tenant_id')
            if tenant_id:
                extra_properties.append(f'secret.tenantId={tenant_id}')
            resource_groups = kwargs.get('resource_groups')
            if isinstance(resource_groups, list) and len(resource_groups) > 0:
                rg = '\n'.join(resource_groups)
                extra_properties.append(f'multiline.resourceGroups={rg}')
        elif record.record_type == 'pamDomainConfiguration':
            domain_id = kwargs.get('domain_id')
            if domain_id:
                extra_properties.append(f'text.pamDomainId={domain_id}')
            host = str(kwargs.get('domain_hostname') or '').strip()
            port = str(kwargs.get('domain_port') or '').strip()
            if host or port:
                val = json.dumps({"hostName": host, "port": port})
                extra_properties.append(f"f.pamHostname=$JSON:{val}")
            domain_use_ssl = utils.value_to_boolean(kwargs.get('domain_use_ssl'))
            if domain_use_ssl is not None:
                val = 'true' if domain_use_ssl else 'false'
                extra_properties.append(f'checkbox.useSSL={val}')
            domain_scan_dc_cidr = utils.value_to_boolean(kwargs.get('domain_scan_dc_cidr'))
            if domain_scan_dc_cidr is not None:
                val = 'true' if domain_scan_dc_cidr else 'false'
                extra_properties.append(f'checkbox.scanDCCIDR={val}')
            domain_network_cidr = kwargs.get('domain_network_cidr')
            if domain_network_cidr:
                extra_properties.append(f'text.networkCIDR={domain_network_cidr}')
            domain_administrative_credential = kwargs.get('domain_administrative_credential')
            dac = str(domain_administrative_credential or '')
            if dac:
                # pam import will link it later (once admin pamUser is created)
                if kwargs.get('force_domain_admin', False) is True:
                    if bool(re.search('^[A-Za-z0-9-_]{22}$', dac)) is not True:
                        logger.warning(f'Invalid Domain Admin User UID: "{dac}" (skipped)')
                        dac = ''
                else:
                    adm_rec = PamConfigurationEditMixin.resolve_single_record(vault, dac, 'pamUser')
                    if adm_rec and isinstance(adm_rec, vault_record.TypedRecord) and adm_rec.record_type == 'pamUser':
                        dac = adm_rec.record_uid
                    else:
                        logger.warning(f'Domain Admin User UID: "{dac}" not found (skipped).')
                        dac = ''
            if dac:
                prf = record.get_typed_field('pamResources')
                prf.value = prf.value or [{}]
                prf.value[0]["adminCredentialRef"] = dac
        elif record.record_type == 'pamOciConfiguration':
            oci_id = kwargs.get('oci_id')
            if oci_id:
                extra_properties.append(f'text.pamOciId={oci_id}')
            oci_admin_id = kwargs.get('oci_admin_id')
            if oci_admin_id:
                extra_properties.append(f'secret.adminOcid={oci_admin_id}')
            oci_admin_public_key = kwargs.get('oci_admin_public_key')
            if oci_admin_public_key:
                extra_properties.append(f'secret.adminPublicKey={oci_admin_public_key}')
            oci_admin_private_key = kwargs.get('oci_admin_private_key')
            if oci_admin_private_key:
                extra_properties.append(f'secret.adminPrivateKey={oci_admin_private_key}')
            oci_tenancy = kwargs.get('oci_tenancy')
            if oci_tenancy:
                extra_properties.append(f'text.tenancyOci={oci_tenancy}')
            oci_region = kwargs.get('oci_region')
            if oci_region:
                extra_properties.append(f'text.regionOci={oci_region}')
        if extra_properties:
            self.assign_typed_fields(record, [record_edit.RecordEditMixin.parse_field(x) for x in extra_properties])

    def verify_required(self, record: vault_record.TypedRecord):
        for field in record.fields:
            if field.required:
                if len(field.value) == 0:
                    if field.type == 'schedule':
                        field.value = [{
                            'type': 'ON_DEMAND'
                        }]
                    else:
                        self.warnings.append(f'Empty required field: "{field.external_name()}"')
        for custom in record.custom:
            if custom.required:
                custom.required = False


class PAMConfigNewCommand(base.ArgparseCommand, PamConfigurationEditMixin):

    def __init__(self):
        self.choices = ['on', 'off', 'default']
        parser = argparse.ArgumentParser(prog='pam config new')
        PAMConfigNewCommand.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        choices = ['on', 'off', 'default']
        parser.add_argument('--config-type', '-ct', dest='config_type', action='store',
                                choices=['network', 'aws', 'azure'], help='PAM Configuration Type', )
        parser.add_argument('--title', '-t', dest='title', action='store', help='Title of the PAM Configuration')
        parser.add_argument('--gateway', '-g', dest='gateway', action='store', help='Gateway UID or Name')
        parser.add_argument('--shared-folder', '-sf', dest='shared_folder', action='store',
                                help='Share Folder where this PAM Configuration is stored. Should be one of the folders to '
                                        'which the gateway has access to.')
        parser.add_argument('--resource-record', '-rr', dest='resource_records', action='append',
                                help='Resource Record UID')
        parser.add_argument('--schedule', '-sc', dest='default_schedule', action='store', help='Default Schedule: Use CRON syntax')
        parser.add_argument('--port-mapping', '-pm', dest='port_mapping', action='append', help='Port Mapping')
        network_group = parser.add_argument_group('network', 'Local network configuration')
        network_group.add_argument('--network-id', dest='network_id', action='store', help='Network ID')
        network_group.add_argument('--network-cidr', dest='network_cidr', action='store', help='Network CIDR')
        aws_group = parser.add_argument_group('aws', 'AWS configuration')
        aws_group.add_argument('--aws-id', dest='aws_id', action='store', help='AWS ID')
        aws_group.add_argument('--access-key-id', dest='access_key_id', action='store', help='Access Key Id')
        aws_group.add_argument('--access-secret-key', dest='access_secret_key', action='store', help='Access Secret Key')
        aws_group.add_argument('--region-name', dest='region_names', action='append', help='Region Names')
        azure_group = parser.add_argument_group('azure', 'Azure configuration')
        azure_group.add_argument('--azure-id', dest='azure_id', action='store', help='Azure Id')
        azure_group.add_argument('--client-id', dest='client_id', action='store', help='Client Id')
        azure_group.add_argument('--client-secret', dest='client_secret', action='store', help='Client Secret')
        azure_group.add_argument('--subscription_id', dest='subscription_id', action='store',
                                help='Subscription Id')
        azure_group.add_argument('--tenant-id', dest='tenant_id', action='store', help='Tenant Id')
        azure_group.add_argument('--resource-group', dest='resource_group', action='append', help='Resource Group')

    def execute(self, context: KeeperParams, **kwargs):
        self.warnings.clear()

        if not context.vault:
            raise base.CommandError('Vault is not initialized. Login to initialize the vault.')
        
        vault = context.vault

        config_type = kwargs.get('config_type')
        if not config_type:
            raise base.CommandError('--environment parameter is required')
        if config_type == 'aws':
            record_type = 'pamAwsConfiguration'
        elif config_type == 'azure':
            record_type = 'pamAzureConfiguration'
        elif config_type == 'local':
            record_type = 'pamNetworkConfiguration'
        elif config_type == 'gcp':
            record_type = 'pamGcpConfiguration'
        elif config_type == 'domain':
            record_type = 'pamDomainConfiguration'
        elif config_type == 'oci':
            record_type = 'pamOciConfiguration'
        else:
            raise base.CommandError(f'--environment {config_type} is not supported'
                               ' - supported options: local, aws, azure, gcp, domain, oci')

        title = kwargs.get('title')
        if not title:
            raise base.CommandError('--title parameter is required')

        record = vault_record.TypedRecord(version=6)
        record.type_name = record_type
        record.title = title

        record_type = vault.vault_data.get_record_type_by_name(record_type)

        if record_type:
            fields = record_type.fields
            RecordEditMixin.adjust_typed_record_fields(record, fields)

        # resolve folder path to UID
        sf_name = kwargs.get('shared_folder_uid', '')
        if sf_name:
            fpath = folder_utils.try_resolve_path(context, sf_name)
            if fpath and len(fpath) >= 2 and fpath[-1] == '':
                sfuid = fpath[-2].uid
                if sfuid: kwargs['shared_folder_uid'] = sfuid

        self.parse_properties(vault, record, **kwargs)

        field = record.get_typed_field('pamResources')
        if not field:
            raise base.CommandError('PAM configuration record does not contain resource field')

        gateway_uid = None
        shared_folder_uid = None
        admin_cred_ref = None
        value = field.get_default_value(dict)
        if value:
            gateway_uid = value.get('controllerUid')
            shared_folder_uid = value.get('folderUid')
            if record.record_type == 'pamDomainConfiguration' and not kwargs.get('force_domain_admin', False) is True:
                # pamUser must exist or "403 Insufficient PAM access to perform this operation"
                admin_cred_ref = value.get('adminCredentialRef')

        if not shared_folder_uid:
            raise base.CommandError('--shared-folder parameter is required to create a PAM configuration')
        gw_name = kwargs.get('gateway_uid') or ''
        if not gateway_uid:
            logger.warning(f'Gateway "{gw_name}" not found.')

        self.verify_required(record)

        config_utils.pam_configuration_create_record_v6(vault, record, shared_folder_uid)

        encrypted_session_token, encrypted_transmission_key, _ = tunnel_utils.get_keeper_tokens(vault)
        # Add DAG for configuration
        tmp_dag = TunnelDAG(vault, encrypted_session_token, encrypted_transmission_key, record_uid=record.record_uid,
                            is_config=True)
        tmp_dag.edit_tunneling_config(
            kwargs.get('connections'),
            kwargs.get('tunneling'),
            kwargs.get('rotation'),
            kwargs.get('recording'),
            kwargs.get('typescriptrecording'),
            kwargs.get('remotebrowserisolation')
        )
        if admin_cred_ref:
            tmp_dag.link_user_to_config_with_options(admin_cred_ref, is_admin='on')
        tmp_dag.print_tunneling_config(record.record_uid, None)

        # Moving v6 record into the folder
        vault.sync_down()
        
        record_management.move_vault_objects(vault, [record.record_uid], shared_folder_uid)

        vault.sync_down()

        if gateway_uid:
            pcc = pam_pb2.PAMConfigurationController()
            pcc.configurationUid = utils.base64_url_decode(record.record_uid)
            pcc.controllerUid = utils.base64_url_decode(gateway_uid)
            vault.keeper_auth.execute_auth_rest('pam/set_configuration_controller', pcc)

        for w in self.warnings:
            logger.warning(w)

        return record.record_uid


class PAMConfigEditCommand(base.ArgparseCommand, PamConfigurationEditMixin):

    def __init__(self):
        parser = argparse.ArgumentParser(prog='pam config edit')
        PAMConfigEditCommand.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        choices = ['on', 'off', 'default']
        parser.add_argument('--config-type', '-ct', dest='config_type', action='store',
                                choices=['network', 'aws', 'azure'], help='PAM Configuration Type', )
        parser.add_argument('--title', '-t', dest='title', action='store', help='Title of the PAM Configuration')
        parser.add_argument('--gateway', '-g', dest='gateway', action='store', help='Gateway UID or Name')
        parser.add_argument('--shared-folder', '-sf', dest='shared_folder', action='store',
                                help='Share Folder where this PAM Configuration is stored. Should be one of the folders to '
                                        'which the gateway has access to.')
        parser.add_argument('--resource-record', '-rr', dest='resource_records', action='append',
                                help='Resource Record UID')
        parser.add_argument('--schedule', '-sc', dest='default_schedule', action='store', help='Default Schedule: Use CRON syntax')
        parser.add_argument('--port-mapping', '-pm', dest='port_mapping', action='append', help='Port Mapping')
        network_group = parser.add_argument_group('network', 'Local network configuration')
        network_group.add_argument('--network-id', dest='network_id', action='store', help='Network ID')
        network_group.add_argument('--network-cidr', dest='network_cidr', action='store', help='Network CIDR')
        aws_group = parser.add_argument_group('aws', 'AWS configuration')
        aws_group.add_argument('--aws-id', dest='aws_id', action='store', help='AWS ID')
        aws_group.add_argument('--access-key-id', dest='access_key_id', action='store', help='Access Key Id')
        aws_group.add_argument('--access-secret-key', dest='access_secret_key', action='store', help='Access Secret Key')
        aws_group.add_argument('--region-name', dest='region_names', action='append', help='Region Names')
        azure_group = parser.add_argument_group('azure', 'Azure configuration')
        azure_group.add_argument('--azure-id', dest='azure_id', action='store', help='Azure Id')
        azure_group.add_argument('--client-id', dest='client_id', action='store', help='Client Id')
        azure_group.add_argument('--client-secret', dest='client_secret', action='store', help='Client Secret')
        azure_group.add_argument('--subscription_id', dest='subscription_id', action='store',
                                help='Subscription Id')
        azure_group.add_argument('--tenant-id', dest='tenant_id', action='store', help='Tenant Id')
        azure_group.add_argument('--resource-group', dest='resource_group', action='append', help='Resource Group')
    
    def execute(self, context: KeeperParams, **kwargs):
        self.warnings.clear()

        if not context.vault:
            raise base.CommandError('Vault is not initialized. Login to initialize the vault.')
        
        vault = context.vault

        configuration = None
        config_name = kwargs.get('config')
        if config_name in vault.vault_data._records:
            configuration = vault.vault_data.load_record(config_name)
        else:
            l_name = config_name.casefold()
            for c in vault.vault_data.find_records(record_type=None, record_version=6):
                if c.title.casefold() == l_name:
                    configuration = c
                    break
        if not configuration:
            raise base.CommandError(f'PAM configuration "{config_name}" not found')
        if not isinstance(configuration, vault.TypedRecord) or configuration.version != 6:
            raise base.CommandError(f'PAM configuration "{config_name}" not found')

        config_type = kwargs.get('config_type')
        if config_type:
            if not config_type:
                raise base.CommandError('--config-type parameter is required')
            if config_type == 'aws':
                record_type = 'pamAwsConfiguration'
            elif config_type == 'azure':
                record_type = 'pamAzureConfiguration'
            elif config_type == 'network':
                record_type = 'pamNetworkConfiguration'
            else:
                record_type = configuration.record_type

            if record_type != configuration.record_type:
                configuration.type_name = record_type
                record_type = vault.vault_data.get_record_type_by_name(record_type)
                fields = record_type.fields
                if fields:
                    RecordEditMixin.adjust_typed_record_fields(configuration, fields)

        title = kwargs.get('title')
        if title:
            configuration.title = title

        field = configuration.get_typed_field('pamResources')
        if not field:
            raise base.CommandError('PAM configuration record does not contain resource field')

        orig_gateway_uid = ''
        orig_shared_folder_uid = ''
        value = field.get_default_value(dict)
        if value:
            orig_gateway_uid = value.get('controllerUid') or ''
            orig_shared_folder_uid = value.get('folderUid') or ''

        self.parse_properties(vault, configuration, **kwargs)
        self.verify_required(configuration)

        record_management.update_record(vault, configuration)

        value = field.get_default_value(dict)
        if value:
            gateway_uid = value.get('controllerUid') or ''
            if gateway_uid != orig_gateway_uid:
                pcc = pam_pb2.PAMConfigurationController()
                pcc.configurationUid = utils.base64_url_decode(configuration.record_uid)
                pcc.controllerUid = utils.base64_url_decode(gateway_uid)
                vault.keeper_auth.execute_auth_rest('pam/set_configuration_controller', pcc)
            shared_folder_uid = value.get('folderUid') or ''
            if shared_folder_uid != orig_shared_folder_uid:
                record_management.move_vault_objects(vault, [configuration.record_uid], shared_folder_uid)

        for w in self.warnings:
            logger.warning(w)
        vault.sync_down()


class PAMConfigRemoveCommand(base.ArgparseCommand):

    def __init__(self):
        parser = argparse.ArgumentParser(prog='pam config remove')
        PAMConfigRemoveCommand.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('--config', '-c', required=True, dest='pam_config', action='store', 
            help='PAM Configuration UID. To view all rotation settings with their UIDs, use command `pam config list`')
    
    def execute(self, context: KeeperParams, **kwargs):
        if not context.vault:
            raise base.CommandError('Vault is not initialized. Login to initialize the vault.')
        
        vault = context.vault
        pam_config_name = kwargs.get('pam_config')
        pam_config_uid = None
        for config in vault.vault_data.find_records(record_type=None, record_version=6):
            if config.record_uid == pam_config_name:
                pam_config_uid = config.record_uid
                break
            if config.title.casefold() == pam_config_name.casefold():
                pass
        if not pam_config_name:
            raise Exception(f'Configuration "{pam_config_name}" not found')

        record_management.delete_vault_objects(vault, [pam_config_uid])
        vault.sync_down()


def validate_cron_field(field: str, min_val: int, max_val: int) -> bool:
    # Accept *, single number, range, step, list, and L suffix for last day/week
    pattern = r'^(\*|\d+L?|L[W]?|\d+-\d+|\*/\d+|\d+(,\d+)*|\d+-\d+/\d+)$'
    if not re.match(pattern, field):
        return False

    def is_valid_number(n: str) -> bool:
        # Strip L and W suffix if present (for last day/week expressions)
        n_stripped = n.rstrip('LW')
        return n_stripped and n_stripped.isdigit() and min_val <= int(n_stripped) <= max_val

    parts = re.split(r'[,\-/]', field)
    return all(part == '*' or part in ('L', 'LW') or is_valid_number(part) for part in parts if part != '*')


def validate_cron_expression(expr: str, for_rotation: bool = False) -> tuple[bool, str]:
    parts = expr.strip().split()

    # All internal docs, MRD etc. specify that rotation schedule is using CRON format
    # but actually back-end don't accept all valid standard CRON and uses unspecified custom CRON format
    if for_rotation is True:
        if len(parts) != 6:
            return False, f"CRON: Rotation schedules require all 6 parts incl. seconds - ex. Daily at 04:00:00 cron: 0 0 4 * * ? got {len(parts)} parts"
        if not(parts[3] == '?' or parts[5] == "?"):
            logger.warning("CRON: Rotation schedule CRON format - must use ? character in one of these fields: day-of-week, day-of-month")
        parts[3] = '*' if parts[3] == '?' else parts[3]
        parts[5] = '*' if parts[5] == '?' else parts[5]
        logger.debug("WARNING! Validating CRON expression for rotation - if you get 500 type errors make sure to validate your CRON using web vault UI")

    if len(parts) not in [5, 6]:
        return False, f"CRON: Expected 5 or 6 fields, got {len(parts)}"

    if len(parts) == 6:
        seconds, minute, hour, dom, month, dow = parts
        if not validate_cron_field(seconds, 0, 59):
            return False, "CRON: Invalid seconds field"
    else:
        minute, hour, dom, month, dow = parts

    validators = [
        (minute, 0, 59, "minute"),
        (hour, 0, 23, "hour"),
        (dom, 1, 31, "day of month"),
        (month, 1, 12, "month"),
        (dow, 0, 7, "day of week")
    ]

    for field, min_val, max_val, name in validators:
        if not validate_cron_field(field, min_val, max_val):
            return False, f"CRON: Invalid {name} field"

    return True, "Valid cron expression"

