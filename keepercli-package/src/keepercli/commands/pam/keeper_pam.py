import argparse
import json
import requests
from datetime import datetime

from .. import base
from ... import api
from ...helpers import report_utils, router_utils, gateway_utils
from ...params import KeeperParams

from keepersdk import utils


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


class PAMGatewayCommand(base.GroupCommand):
    
    def __init__(self):
        super().__init__('PAM Gateway')
        self.register_command(PAMGatewayListCommand(), 'list', 'l')
        self.register_command(PAMGatewayNewCommand(), 'new', 'n')
        self.register_command(PAMGatewayRemoveCommand(), 'remove', 'rm')
        self.register_command(PAMGatewaySetMaxInstancesCommand(), 'set-max-instances', 'smi')
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
        one_time_token = gateway_utils.create_gateway(vault, gateway_name, ksm_app, token_expire_in_min)

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

