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


def _fetch_user_devices(context: KeeperParams) -> List[DeviceManagement_pb2.Device]:
    """Load and sort devices for the current user (newest last access first)."""
    devices_rs = context.auth.execute_auth_rest(
        rest_endpoint='dm/device_user_list',
        request=None,
        response_type=DeviceManagement_pb2.DeviceUserResponse,
    )
    if not devices_rs:
        return []
    devices = _extract_devices(devices_rs)
    devices.sort(key=lambda d: d.lastModifiedTime or 0, reverse=True)
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


def _resolve_device_identifiers(
    devices: List[DeviceManagement_pb2.Device], identifiers: List[str]
) -> List[Tuple[bytes, DeviceManagement_pb2.Device]]:
    resolved: List[Tuple[bytes, DeviceManagement_pb2.Device]] = []
    for identifier in identifiers:
        match = _resolve_device_identifier(devices, identifier)
        if not match:
            raise base.CommandError(
                f'No matching device found for "{identifier}" (or ambiguous device name)'
            )
        resolved.append(match)
    return resolved


def _execute_device_user_action(
    context: KeeperParams,
    device_identifiers: List[str],
    action_type: int,
    action_past_tense: str,
) -> None:
    """Perform logout or remove on one or more devices via dm/device_user_action."""
    if not device_identifiers:
        raise base.CommandError('At least one device identifier is required')

    for identifier in device_identifiers:
        if not identifier or not identifier.strip():
            raise base.CommandError('Device identifier cannot be empty')
        if re.search(r'[<>"\'\x00-\x1f\x7f-\x9f]', identifier):
            raise base.CommandError(f'Invalid device identifier: {identifier}')

    devices = _fetch_user_devices(context)
    if not devices:
        raise base.CommandError('No devices found')

    resolved = _resolve_device_identifiers(devices, device_identifiers)
    token_to_device = {token: device for token, device in resolved}

    rq = DeviceManagement_pb2.DeviceActionRequest()
    device_action = rq.deviceAction.add()
    device_action.deviceActionType = action_type
    device_action.encryptedDeviceToken.extend(list(token_to_device.keys()))

    rs = context.auth.execute_auth_rest(
        rest_endpoint='dm/device_user_action',
        request=rq,
        response_type=DeviceManagement_pb2.DeviceActionResponse,
    )
    if not rs or not rs.deviceActionResult:
        raise base.CommandError('No response returned from device action')

    for result in rs.deviceActionResult:
        for token in result.encryptedDeviceToken:
            device = token_to_device.get(token)
            device_name = (device.deviceName if device else None) or 'Unknown Device'
            if result.deviceActionStatus == DeviceManagement_pb2.SUCCESS:
                logger.info("Device '%s' successfully %s", device_name, action_past_tense)
            else:
                status_name = DeviceManagement_pb2.DeviceActionStatus.Name(
                    result.deviceActionStatus
                )
                if result.deviceActionStatus == DeviceManagement_pb2.NOT_ALLOWED:
                    msg = 'Operation not allowed'
                else:
                    msg = f'Action failed ({status_name})'
                raise base.CommandError(f"Device '{device_name}': {msg}")


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
        devices = _fetch_user_devices(context)
        if not devices:
            logger.info('No devices found.')
            return

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

        devices = _fetch_user_devices(context)
        if not devices:
            raise base.CommandError('No devices found')

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
        _execute_device_user_action(
            context,
            device_identifiers,
            DeviceManagement_pb2.DA_REMOVE,
            'removed',
        )


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
        _execute_device_user_action(
            context,
            device_identifiers,
            DeviceManagement_pb2.DA_LOGOUT,
            'logged out',
        )

