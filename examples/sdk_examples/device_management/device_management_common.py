#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper SDK for Python — shared helpers for device management examples.
#

import importlib.util
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

from keepersdk.authentication import keeper_auth
from keepersdk.proto import APIRequest_pb2, DeviceManagement_pb2


def run_login():
    """
    Run the standard SDK login flow from examples/sdk_examples/auth/login.py.

    Returns:
        (KeeperAuth, KeeperEndpoint) or (None, None) on failure.
    """
    login_path = Path(__file__).resolve().parent.parent / 'auth' / 'login.py'
    spec = importlib.util.spec_from_file_location('sdk_auth_login', login_path)
    if spec is None or spec.loader is None:
        raise ImportError(f'Cannot load login module from {login_path}')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.login()


def _format_timestamp(timestamp: Optional[int]) -> str:
    if not timestamp:
        return 'N/A'
    try:
        if timestamp > 10000000000:
            timestamp = int(timestamp / 1000)
        return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return f'Invalid timestamp: {timestamp}'


def _login_state_name(login_state: int) -> str:
    try:
        return APIRequest_pb2.LoginState.Name(login_state)
    except Exception:
        return f'UNKNOWN_STATE_{login_state}'


def _client_type_name(client_type: int) -> str:
    try:
        return DeviceManagement_pb2.ClientType.Name(client_type)
    except Exception:
        return f'UNKNOWN_{client_type}'


def fetch_user_devices(auth: keeper_auth.KeeperAuth) -> List[DeviceManagement_pb2.Device]:
    """Call dm/device_user_list and return a flat list of devices."""
    rs = auth.execute_auth_rest(
        rest_endpoint='dm/device_user_list',
        request=None,
        response_type=DeviceManagement_pb2.DeviceUserResponse,
    )
    if not rs:
        return []
    devices: List[DeviceManagement_pb2.Device] = []
    for group in rs.deviceGroups:
        devices.extend(list(group.devices))
    devices.sort(key=lambda d: d.lastModifiedTime or 0, reverse=True)
    return devices


def print_devices_table(devices: List[DeviceManagement_pb2.Device]) -> None:
    if not devices:
        print('\nNo devices found.')
        return
    print(f'\nUser Devices ({len(devices)} found)')
    print('=' * 100)
    print(f"{'ID':<4} {'Name':<24} {'Client Type':<14} {'Login Status':<14} {'Last Accessed':<20}")
    print('-' * 100)
    for i, d in enumerate(devices, start=1):
        print(
            f"{i:<4} {(d.deviceName or 'N/A')[:23]:<24} "
            f"{_client_type_name(d.clientType)[:13]:<14} "
            f"{_login_state_name(d.loginState)[:13]:<14} "
            f"{_format_timestamp(d.lastModifiedTime):<20}"
        )
    print('-' * 100)


def resolve_device(
    devices: List[DeviceManagement_pb2.Device], identifier: str
) -> Optional[Tuple[bytes, DeviceManagement_pb2.Device]]:
    ident = (identifier or '').strip()
    if not ident:
        return None
    if ident.isdigit():
        idx = int(ident)
        if 1 <= idx <= len(devices):
            d = devices[idx - 1]
            return d.encryptedDeviceToken, d
        return None
    ident_l = ident.lower()
    matches = [d for d in devices if (d.deviceName or '').lower().find(ident_l) >= 0]
    if len(matches) == 1:
        d = matches[0]
        return d.encryptedDeviceToken, d
    return None


def rename_user_device(
    auth: keeper_auth.KeeperAuth,
    device_identifier: str,
    new_name: str,
) -> None:
    """Rename a device via dm/device_user_rename (resolves identifier via device list)."""
    import re

    devices = fetch_user_devices(auth)
    if not devices:
        raise ValueError('No devices found')

    resolved = resolve_device(devices, device_identifier)
    if not resolved:
        raise ValueError('No matching device found (or ambiguous device name)')

    device_token, device = resolved
    old_name = device.deviceName or 'N/A'
    sanitized = re.sub(r'[<>"\'\x00-\x1f\x7f-\x9f]', '', new_name).strip()
    if not sanitized:
        raise ValueError('Device name contains only invalid characters')

    rq = DeviceManagement_pb2.DeviceRenameRequest()
    dr = rq.deviceRename.add()
    dr.encryptedDeviceToken = device_token
    dr.deviceNewName = sanitized

    rs = auth.execute_auth_rest(
        rest_endpoint='dm/device_user_rename',
        request=rq,
        response_type=DeviceManagement_pb2.DeviceRenameResponse,
    )
    if not rs or not rs.deviceRenameResult:
        raise ValueError('No response returned from device rename')

    for r in rs.deviceRenameResult:
        if r.deviceActionStatus == DeviceManagement_pb2.SUCCESS:
            print(f"Device name updated from '{old_name}' to '{sanitized}'")
            return
        status = DeviceManagement_pb2.DeviceActionStatus.Name(r.deviceActionStatus)
        raise ValueError(f'Device rename failed: {status}')
