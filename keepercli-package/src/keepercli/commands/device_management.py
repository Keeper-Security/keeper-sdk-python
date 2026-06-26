import argparse
import shlex
from datetime import datetime
from typing import Callable, Dict, List, Optional

from keepersdk.authentication import device_management

from . import base
from .. import api
from ..helpers import report_utils
from ..params import KeeperParams


logger = api.get_logger()

ADMIN_DEVICE_TABLE_HEADERS = [
    'ID', 'Enterprise User ID', 'Device Name', 'UI Category',
    'Device Status', 'Login Status', 'Last Accessed',
]


def _format_timestamp(dt: Optional[datetime]) -> str:
    if not dt:
        return 'N/A'
    return dt.strftime('%Y-%m-%d %H:%M:%S')


def _sdk_error(exc: Exception) -> base.CommandError:
    return base.CommandError(str(exc))


def _display_admin_devices(
    context: KeeperParams,
    enterprise_user_ids: List[int],
) -> None:
    """Fetch and print the admin device list table for the given enterprise user IDs."""
    try:
        devices = device_management.list_admin_devices(context.auth, enterprise_user_ids)
    except ValueError as e:
        raise _sdk_error(e) from e

    if not devices:
        logger.info('No devices found.')
        return

    rows: List[List] = []
    for d in devices:
        rows.append([
            d.list_index,
            d.enterprise_user_id,
            d.name,
            d.ui_category,
            d.device_status,
            d.login_status,
            _format_timestamp(d.last_accessed),
        ])

    title = f'Admin Device List ({len(rows)} devices found)'
    report_utils.dump_report_data(rows, ADMIN_DEVICE_TABLE_HEADERS, fmt='table', title=title)


DEVICE_ADMIN_ACTION_DEFINITIONS: Dict[str, Dict] = {
    'logout': {
        'description': 'Logout the user from the device',
        'handler': device_management.logout_admin_user_devices,
        'action_verb': 'logged out',
    },
    'remove': {
        'description': 'Logout & Remove the user from that device',
        'handler': device_management.remove_admin_user_devices,
        'action_verb': 'removed',
    },
}

DEVICE_ADMIN_ACTION_CHOICES = list(DEVICE_ADMIN_ACTION_DEFINITIONS.keys())

_device_admin_action_parsers: Dict[str, argparse.ArgumentParser] = {}
for _action, _config in DEVICE_ADMIN_ACTION_DEFINITIONS.items():
    _parser = argparse.ArgumentParser(
        prog=f'device-admin-action {_action}',
        description=_config['description'],
    )
    _parser.add_argument(
        'enterprise_user_id',
        type=int,
        help='Enterprise User ID whose devices to act on',
    )
    _parser.add_argument(
        'devices',
        nargs='+',
        help='Device IDs (1, 2, 3...) or device names',
    )
    _device_admin_action_parsers[_action] = _parser


class DeviceListCommand(base.ArgparseCommand):
    """List all active devices for the current user."""

    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='device-list',
            description='List all active devices for the current user',
            parents=[base.json_output_parser]
            )
        DeviceListCommand.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.error = base.ArgparseCommand.raise_parse_exception
        parser.exit = base.ArgparseCommand.suppress_exit

    def execute(self, context: KeeperParams, **kwargs):
        """Display user devices in table or JSON format."""
        base.require_login(context)
        try:
            devices = device_management.list_user_devices(context.auth)
        except ValueError as e:
            raise _sdk_error(e) from e

        if not devices:
            logger.info('No devices found.')
            return

        fmt = kwargs.get('format') or 'table'
        output = kwargs.get('output')

        headers = ['id', 'name', 'client_type', 'login_status', 'last_accessed']
        rows: List[List] = []
        for d in devices:
            rows.append([
                d.list_index,
                d.name,
                d.client_type,
                d.login_status,
                _format_timestamp(d.last_accessed),
            ])

        return report_utils.dump_report_data(
            rows, headers, fmt=fmt, filename=output, title=f'User Devices ({len(rows)} found)'
        )


class DeviceRenameCommand(base.ArgparseCommand):
    """Rename a device for the current user."""

    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='device-rename',
            description='Rename a device for the current user',
        )
        DeviceRenameCommand.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('device', help='Device ID (from device-list) or device name substring')
        parser.add_argument('new_name', help='New name for the device')
        parser.error = base.ArgparseCommand.raise_parse_exception
        parser.exit = base.ArgparseCommand.suppress_exit

    def execute(self, context: KeeperParams, **kwargs):
        """Rename the specified device and log the old and new names."""
        base.require_login(context)
        device_identifier = (kwargs.get('device') or '').strip()
        new_name = (kwargs.get('new_name') or '').strip()

        try:
            old_name, updated_name = device_management.rename_user_device(
                context.auth, device_identifier, new_name
            )
            logger.info("Device name updated from '%s' to '%s'", old_name, updated_name)
        except ValueError as e:
            raise _sdk_error(e) from e


class DeviceRemoveCommand(base.ArgparseCommand):
    """Log out and remove the current user from one or more devices."""

    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='device-remove',
            description='Logout and remove the current user from one or more devices',
        )
        DeviceRemoveCommand.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('devices', nargs='+', help='Device ID (from device-list) or device name substring')
        parser.error = base.ArgparseCommand.raise_parse_exception
        parser.exit = base.ArgparseCommand.suppress_exit

    def execute(self, context: KeeperParams, **kwargs):
        """Remove the current user from each specified device."""
        base.require_login(context)
        device_identifiers = kwargs.get('devices') or []
        try:
            for name in device_management.remove_user_devices(context.auth, device_identifiers):
                logger.info("Device '%s' successfully removed", name)
        except ValueError as e:
            raise _sdk_error(e) from e


class DeviceLogoutCommand(base.ArgparseCommand):
    """Log out the current user from one or more devices."""

    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='device-logout',
            description='Logout the current user from one or more devices',
        )
        DeviceLogoutCommand.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('devices', nargs='+', help='Device ID (from device-list) or device name substring')
        parser.error = base.ArgparseCommand.raise_parse_exception
        parser.exit = base.ArgparseCommand.suppress_exit

    def execute(self, context: KeeperParams, **kwargs):
        """Log out the current user from each specified device."""
        base.require_login(context)
        device_identifiers = kwargs.get('devices') or []
        try:
            for name in device_management.logout_user_devices(context.auth, device_identifiers):
                logger.info("Device '%s' successfully logged out", name)
        except ValueError as e:
            raise _sdk_error(e) from e


class DeviceAdminListCommand(base.ArgparseCommand):
    """List devices across enterprise users that the admin can manage."""

    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='device-admin-list',
            description='List all devices across users that the Admin has control of',
            parents=[base.json_output_parser],
        )
        DeviceAdminListCommand.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument(
            'enterprise_user_ids',
            nargs='+',
            type=int,
            help='List of Enterprise User IDs (required). You can get enterprise user IDs by running "ei --users" command',
        )
        parser.error = base.ArgparseCommand.raise_parse_exception
        parser.exit = base.ArgparseCommand.suppress_exit

    def execute(self, context: KeeperParams, **kwargs):
        """Display admin device list in table or JSON format for the given enterprise user IDs."""
        base.require_enterprise_admin(context)
        enterprise_user_ids = kwargs.get('enterprise_user_ids') or []

        try:
            devices = device_management.list_admin_devices(context.auth, enterprise_user_ids)
        except ValueError as e:
            raise _sdk_error(e) from e

        if not devices:
            logger.info('No devices found.')
            return

        fmt = kwargs.get('format') or 'table'
        output = kwargs.get('output')

        rows: List[List] = []
        for d in devices:
            rows.append([
                d.list_index,
                d.enterprise_user_id,
                d.name,
                d.ui_category,
                d.device_status,
                d.login_status,
                _format_timestamp(d.last_accessed),
            ])

        return report_utils.dump_report_data(
            rows, ADMIN_DEVICE_TABLE_HEADERS, fmt=fmt, filename=output,
            title=f'Admin Device List ({len(rows)} devices found)',
        )


class DeviceAdminActionCommand(base.ArgparseCommand):
    """Perform admin actions (logout, remove) on devices for an enterprise user."""

    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='device-admin-action',
            description='Perform various action on one or more devices that the Admin has control of.',
        )
        DeviceAdminActionCommand.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument(
            'action',
            choices=DEVICE_ADMIN_ACTION_CHOICES,
            help='Action to perform on devices',
        )
        parser.add_argument(
            'enterprise_user_id',
            type=int,
            help='Enterprise User ID whose devices to act on',
        )
        parser.add_argument(
            'devices',
            nargs='+',
            help='Device IDs or devicenames',
        )
        parser.error = base.ArgparseCommand.raise_parse_exception
        parser.exit = base.ArgparseCommand.suppress_exit

    def execute_args(self, context: KeeperParams, args, **kwargs):
        """Route per-action --help to the action-specific parser when requested."""
        args = '' if args is None else args
        args = base.expand_cmd_args(args, context.environment_variables)
        args = base.normalize_output_param(args)
        try:
            parsed_args = shlex.split(args)
            if len(parsed_args) >= 2 and parsed_args[1] in ('--help', '-h'):
                action_parser = _device_admin_action_parsers.get(parsed_args[0])
                if action_parser:
                    action_parser.print_help()
                    return
            if len(parsed_args) >= 3 and parsed_args[2] in ('--help', '-h'):
                action_parser = _device_admin_action_parsers.get(parsed_args[0])
                if action_parser:
                    action_parser.print_help()
                    return
        except base.ParseError as e:
            logger.warning(str(e))
            return
        return super().execute_args(context, args, **kwargs)

    def execute(self, context: KeeperParams, **kwargs):
        """Run the requested admin device action and refresh the device list."""
        base.require_enterprise_admin(context)
        action = kwargs.get('action')
        enterprise_user_id = kwargs.get('enterprise_user_id')
        devices = kwargs.get('devices') or []
        config = DEVICE_ADMIN_ACTION_DEFINITIONS.get(action or '')
        if not config:
            raise _sdk_error(ValueError(f"Invalid action: '{action}'"))

        if not devices:
            raise _sdk_error(ValueError('At least one device must be specified'))

        handler: Callable = config['handler']
        action_verb: str = config['action_verb']
        try:
            names = handler(context.auth, enterprise_user_id, devices)
            for name in names:
                logger.info(
                    "Device action successfully completed: '%s' %s for user %s",
                    name, action_verb, enterprise_user_id,
                )
        except ValueError as e:
            raise _sdk_error(e) from e

        logger.info('Updated device list for user %s:', enterprise_user_id)
        _display_admin_devices(context, [enterprise_user_id])
