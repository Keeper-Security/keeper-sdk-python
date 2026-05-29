import argparse
import re
from datetime import datetime
from typing import List, Optional, Tuple

from keepersdk.proto import APIRequest_pb2, DeviceManagement_pb2

from . import base
from .. import api
from ..helpers import report_utils
from ..params import KeeperParams


logger = api.get_logger()


def _format_timestamp(timestamp: Optional[int]) -> str:
    if not timestamp:
        return 'N/A'
    try:
        if timestamp > 10000000000:
            timestamp = int(timestamp / 1000)
        dt = datetime.fromtimestamp(timestamp)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return f'Invalid timestamp: {timestamp}'


def _login_state_to_str(login_state: int) -> str:
    try:
        return APIRequest_pb2.LoginState.Name(login_state)
    except Exception:
        return f'UNKNOWN_STATE_{login_state}'


def _client_type_to_str(client_type: int) -> str:
    try:
        return DeviceManagement_pb2.ClientType.Name(client_type)
    except Exception:
        return f'UNKNOWN_{client_type}'


def _extract_devices(rs: DeviceManagement_pb2.DeviceUserResponse) -> List[DeviceManagement_pb2.Device]:
    devices: List[DeviceManagement_pb2.Device] = []
    for group in rs.deviceGroups:
        devices.extend(list(group.devices))
    return devices


def _resolve_device_identifier(
    devices: List[DeviceManagement_pb2.Device], identifier: str
) -> Optional[Tuple[bytes, DeviceManagement_pb2.Device]]:
    """
    Resolve device identifier.
    - If identifier is a number N: treat as 1-based index in the displayed list.
    - Else: match by substring against deviceName (case-insensitive). If multiple matches, return None.
    """
    if not identifier:
        return None

    ident = identifier.strip()
    if ident.isdigit():
        idx = int(ident)
        if 1 <= idx <= len(devices):
            d = devices[idx - 1]
            return d.encryptedDeviceToken, d
        return None

    # Simple name match (Commander also supports token decoding; we keep this minimal).
    ident_l = ident.lower()
    matches = [d for d in devices if (d.deviceName or '').lower().find(ident_l) >= 0]
    if len(matches) == 1:
        d = matches[0]
        return d.encryptedDeviceToken, d
    return None


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
        rs = context.auth.execute_auth_rest(
            rest_endpoint='dm/device_user_list',
            request=None,
            response_type=DeviceManagement_pb2.DeviceUserResponse
        )
        if not rs:
            logger.info('No devices found.')
            return

        devices = _extract_devices(rs)
        if not devices:
            logger.info('No devices found.')
            return

        # stable sort by last access desc (match Commander UX)
        devices.sort(key=lambda d: d.lastModifiedTime or 0, reverse=True)

        fmt = kwargs.get('format') or 'table'
        output = kwargs.get('output')

        headers = ['id', 'name', 'client_type', 'login_status', 'last_accessed']
        rows: List[List] = []
        for i, d in enumerate(devices, start=1):
            rows.append([
                i,
                d.deviceName or 'N/A',
                _client_type_to_str(d.clientType),
                _login_state_to_str(d.loginState),
                _format_timestamp(d.lastModifiedTime),
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

        if not device_identifier:
            raise base.CommandError('Device identifier is required')
        if not new_name:
            raise base.CommandError('New device name is required')

        if re.search(r'[<>"\'\x00-\x1f\x7f-\x9f]', device_identifier):
            raise base.CommandError('Invalid device identifier')
        sanitized_name = re.sub(r'[<>"\'\x00-\x1f\x7f-\x9f]', '', new_name).strip()
        if not sanitized_name:
            raise base.CommandError('Device name contains only invalid characters')

        devices_rs = context.auth.execute_auth_rest(
            rest_endpoint='dm/device_user_list',
            request=None,
            response_type=DeviceManagement_pb2.DeviceUserResponse
        )
        if not devices_rs:
            raise base.CommandError('No devices found')

        devices = _extract_devices(devices_rs)
        devices.sort(key=lambda d: d.lastModifiedTime or 0, reverse=True)

        resolved = _resolve_device_identifier(devices, device_identifier)
        if not resolved:
            raise base.CommandError('No matching device found (or ambiguous device name)')
        device_token, device = resolved
        old_name = device.deviceName or 'N/A'

        rq = DeviceManagement_pb2.DeviceRenameRequest()
        dr = rq.deviceRename.add()
        dr.encryptedDeviceToken = device_token
        dr.deviceNewName = sanitized_name

        rs = context.auth.execute_auth_rest(
            rest_endpoint='dm/device_user_rename',
            request=rq,
            response_type=DeviceManagement_pb2.DeviceRenameResponse
        )
        if not rs or not rs.deviceRenameResult:
            raise base.CommandError('No response returned from device rename')

        # show concise result
        for r in rs.deviceRenameResult:
            if r.deviceActionStatus == DeviceManagement_pb2.SUCCESS:
                logger.info("Device name updated from '%s' to '%s'", old_name, sanitized_name)
            else:
                status_name = DeviceManagement_pb2.DeviceActionStatus.Name(r.deviceActionStatus)
                raise base.CommandError(f'Device rename failed: {status_name}')

