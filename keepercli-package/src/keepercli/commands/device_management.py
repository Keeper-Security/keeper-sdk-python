import argparse
from datetime import datetime
from typing import List, Optional

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


class DeviceListCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='device-list',
            description='List all active devices for the current user',
            parents=[base.json_output_parser]
        )
        parser.error = base.ArgparseCommand.raise_parse_exception
        parser.exit = base.ArgparseCommand.suppress_exit
        super().__init__(parser)

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
        parser.add_argument('device', help='Device ID (from device-list) or device name substring')
        parser.add_argument('new_name', help='New name for the device')
        parser.error = base.ArgparseCommand.raise_parse_exception
        parser.exit = base.ArgparseCommand.suppress_exit
        super().__init__(parser)

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
        parser.add_argument(
            'devices',
            nargs='+',
            help='Device ID (from device-list) or device name substring',
        )
        parser.error = base.ArgparseCommand.raise_parse_exception
        parser.exit = base.ArgparseCommand.suppress_exit
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs):
        base.require_login(context)
        device_identifiers = kwargs.get('devices') or []
        try:
            for name in device_management.remove_user_devices(context.auth, device_identifiers):
                logger.info("Device '%s' successfully removed", name)
        except ValueError as e:
            raise _sdk_error(e) from e


class DeviceLogoutCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='device-logout',
            description='Logout the current user from one or more devices',
        )
        parser.add_argument(
            'devices',
            nargs='+',
            help='Device ID (from device-list) or device name substring',
        )
        parser.error = base.ArgparseCommand.raise_parse_exception
        parser.exit = base.ArgparseCommand.suppress_exit
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs):
        base.require_login(context)
        device_identifiers = kwargs.get('devices') or []
        try:
            for name in device_management.logout_user_devices(context.auth, device_identifiers):
                logger.info("Device '%s' successfully logged out", name)
        except ValueError as e:
            raise _sdk_error(e) from e
