import argparse
from datetime import datetime
from typing import Callable, List, Optional

from keepersdk.authentication import device_management

from . import base
from .. import api
from ..helpers import report_utils
from ..params import KeeperParams


logger = api.get_logger()


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


class DeviceListCommand(base.ArgparseCommand):
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
        _run_device_action_command(
            context,
            kwargs.get('devices') or [],
            device_management.remove_user_devices,
            "Device '%s' successfully removed",
        )


class DeviceLogoutCommand(base.ArgparseCommand):
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
        _run_device_action_command(
            context,
            kwargs.get('devices') or [],
            device_management.logout_user_devices,
            "Device '%s' successfully logged out",
        )


class DeviceLockCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='device-lock',
            description='Lock one or more devices for all users (logs out all users on those devices)',
        )
        DeviceLockCommand.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('devices', nargs='+', help='Device ID (from device-list) or device name substring')
        parser.error = base.ArgparseCommand.raise_parse_exception
        parser.exit = base.ArgparseCommand.suppress_exit

    def execute(self, context: KeeperParams, **kwargs):
        _run_device_action_command(
            context,
            kwargs.get('devices') or [],
            device_management.lock_user_devices,
            "Device '%s' successfully locked",
        )


class DeviceUnlockCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='device-unlock',
            description='Unlock one or more devices for the current user',
        )
        DeviceUnlockCommand.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('devices', nargs='+', help='Device ID (from device-list) or device name substring')
        parser.error = base.ArgparseCommand.raise_parse_exception
        parser.exit = base.ArgparseCommand.suppress_exit

    def execute(self, context: KeeperParams, **kwargs):
        _run_device_action_command(
            context,
            kwargs.get('devices') or [],
            device_management.unlock_user_devices,
            "Device '%s' successfully unlocked",
        )


class DeviceAccountLockCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='device-account-lock',
            description='Lock one or more devices for the current user only (logs out if logged in)',
        )
        DeviceAccountLockCommand.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('devices', nargs='+', help='Device ID (from device-list) or device name substring')
        parser.error = base.ArgparseCommand.raise_parse_exception
        parser.exit = base.ArgparseCommand.suppress_exit

    def execute(self, context: KeeperParams, **kwargs):
        _run_device_action_command(
            context,
            kwargs.get('devices') or [],
            device_management.account_lock_user_devices,
            "Device '%s' successfully account locked",
        )


class DeviceAccountUnlockCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='device-account-unlock',
            description='Unlock one or more devices for the current user',
        )
        DeviceAccountUnlockCommand.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('devices', nargs='+', help='Device ID (from device-list) or device name substring')
        parser.error = base.ArgparseCommand.raise_parse_exception
        parser.exit = base.ArgparseCommand.suppress_exit

    def execute(self, context: KeeperParams, **kwargs):
        _run_device_action_command(
            context,
            kwargs.get('devices') or [],
            device_management.account_unlock_user_devices,
            "Device '%s' successfully account unlocked",
        )
