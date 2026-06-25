import argparse
import json
import shlex
from datetime import datetime
from typing import Callable, Dict, List, Optional

from keepersdk.authentication import device_management

from . import base
from .. import api
from ..helpers import report_utils
from ..params import KeeperParams


logger = api.get_logger()

DEVICE_LIST_TABLE_HEADERS = [
    'ID', 'Device Name', 'Client Type', 'Login Status', 'Last Accessed',
]

ADMIN_DEVICE_TABLE_HEADERS = [
    'ID', 'Enterprise User ID', 'Device Name', 'UI Category',
    'Device Status', 'Login Status', 'Last Accessed',
]
DEVICE_IDENTIFIER_HELP = (
    'Device ID (from device-list) or exact device name (case-insensitive match)'
)


def _format_timestamp(dt: Optional[datetime]) -> str:
    if not dt:
        return 'N/A'
    return dt.strftime('%Y-%m-%d %H:%M:%S')


def _sdk_error(exc: Exception) -> base.CommandError:
    return base.CommandError(str(exc))


def _run_device_action_command(
    context: KeeperParams,
    device_identifiers: List[str],
    action_fn: Callable,
    success_message: str,
) -> None:
    base.require_login(context)
    try:
        for name in action_fn(context.auth, device_identifiers):
            logger.info(success_message, name)
    except ValueError as e:
        raise _sdk_error(e) from e


def _display_user_devices(context: KeeperParams, title_prefix: str = '') -> None:
    devices = device_management.list_user_devices(context.auth)
    if not devices:
        logger.info('No devices found.')
        return

    headers = DEVICE_LIST_TABLE_HEADERS
    rows: List[List] = []
    for d in devices:
        rows.append([
            d.list_index,
            d.name,
            d.client_type,
            d.login_status,
            _format_timestamp(d.last_accessed),
        ])

    title = f'{title_prefix}User Devices ({len(rows)} found)'.strip()
    report_utils.dump_report_data(rows, headers, fmt='table', title=title)


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


DEVICE_ACTION_DEFINITIONS: Dict[str, Dict] = {
    'logout': {
        'description': 'Logout the user from the device',
        'min_devices': 1,
        'handler': device_management.logout_user_devices,
        'success_message': "Device '%s' successfully logged out",
    },
    'remove': {
        'description': 'Logout and remove the user from that device',
        'min_devices': 1,
        'handler': device_management.remove_user_devices,
        'success_message': "Device '%s' successfully removed",
    },
    'lock': {
        'description': (
            'Lock the device for all users on the devices and linked devices; '
            'logout all users from the device'
        ),
        'min_devices': 1,
        'handler': device_management.lock_user_devices,
        'success_message': "Device '%s' successfully locked",
    },
    'unlock': {
        'description': 'Unlock the devices and linked devices for the calling user',
        'min_devices': 1,
        'handler': device_management.unlock_user_devices,
        'success_message': "Device '%s' successfully unlocked",
    },
    'account-lock': {
        'description': (
            'Lock the device for the calling user only; '
            'if logged in, logout the calling user'
        ),
        'min_devices': 1,
        'handler': device_management.account_lock_user_devices,
        'success_message': "Device '%s' successfully account locked",
    },
    'account-unlock': {
        'description': 'Unlock the device for the calling user',
        'min_devices': 1,
        'handler': device_management.account_unlock_user_devices,
        'success_message': "Device '%s' successfully account unlocked",
    },
    'link': {
        'description': 'Link devices for the calling user (requires persistent login)',
        'min_devices': 2,
        'handler': device_management.link_user_devices,
        'success_message': "Device '%s' successfully linked",
    },
    'unlink': {
        'description': 'Unlink devices for the calling user',
        'min_devices': 2,
        'handler': device_management.unlink_user_devices,
        'success_message': "Device '%s' successfully unlinked",
    },
}

DEVICE_ACTION_CHOICES = list(DEVICE_ACTION_DEFINITIONS.keys())

_device_action_parsers: Dict[str, argparse.ArgumentParser] = {}
for _action, _config in DEVICE_ACTION_DEFINITIONS.items():
    _parser = argparse.ArgumentParser(
        prog=f'device-action {_action}',
        description=_config['description'],
    )
    _parser.add_argument(
        'devices',
        nargs='+',
        help=DEVICE_IDENTIFIER_HELP,
    )
    _device_action_parsers[_action] = _parser


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

        if fmt == 'json':
            device_list = [{
                'id': d.list_index,
                'deviceName': d.name,
                'clientType': d.client_type,
                'loginStatus': d.login_status,
                'lastAccessedTimestamp': _format_timestamp(d.last_accessed),
            } for d in devices]
            report = json.dumps({'devices': device_list}, indent=2)
            if output:
                with open(output, 'w', encoding='utf-8') as fd:
                    fd.write(report)
            return report

        headers = DEVICE_LIST_TABLE_HEADERS
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
        parser.add_argument('device', help=DEVICE_IDENTIFIER_HELP)
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
            logger.info('')
            _display_user_devices(context, title_prefix='Updated ')
        except ValueError as e:
            raise _sdk_error(e) from e


class DeviceActionCommand(base.ArgparseCommand):
    """Perform actions on user devices (logout, remove, lock, unlock, link, unlink, etc.)."""

    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='device-action',
            description='Perform actions on user devices',
        )
        DeviceActionCommand.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument(
            'action',
            choices=DEVICE_ACTION_CHOICES,
            help='Action to perform on devices',
        )
        parser.add_argument(
            'devices',
            nargs='+',
            help=DEVICE_IDENTIFIER_HELP,
        )
        parser.error = base.ArgparseCommand.raise_parse_exception
        parser.exit = base.ArgparseCommand.suppress_exit

    def execute_args(self, context: KeeperParams, args, **kwargs):
        args = '' if args is None else args
        args = base.expand_cmd_args(args, context.environment_variables)
        args = base.normalize_output_param(args)
        try:
            parsed_args = shlex.split(args)
            if len(parsed_args) >= 2 and parsed_args[1] in ('--help', '-h'):
                action_parser = _device_action_parsers.get(parsed_args[0])
                if action_parser:
                    action_parser.print_help()
                    return
        except base.ParseError as e:
            logger.warning(str(e))
            return
        return super().execute_args(context, args, **kwargs)

    def execute(self, context: KeeperParams, **kwargs):
        action = kwargs.get('action')
        devices = kwargs.get('devices') or []
        config = DEVICE_ACTION_DEFINITIONS.get(action or '')
        if not config:
            raise _sdk_error(ValueError(f"Invalid action: '{action}'"))

        min_devices = config['min_devices']
        if len(devices) < min_devices:
            if min_devices == 1:
                raise _sdk_error(ValueError('At least one device must be specified'))
            raise _sdk_error(ValueError(
                f'{action} action requires at least {min_devices} devices'
            ))

        _run_device_action_command(
            context,
            devices,
            config['handler'],
            config['success_message'],
        )
        logger.info('')
        _display_user_devices(context, title_prefix='Updated ')


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
