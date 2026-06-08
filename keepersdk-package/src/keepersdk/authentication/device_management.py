#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper SDK for Python — user device management (list, rename, logout, remove).
#

import re
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Tuple

from ..proto import APIRequest_pb2, DeviceManagement_pb2
from . import keeper_auth

URL_DEVICE_USER_LIST = 'dm/device_user_list'
URL_DEVICE_USER_RENAME = 'dm/device_user_rename'
URL_DEVICE_USER_ACTION = 'dm/device_user_action'


@dataclass(frozen=True)
class UserDeviceInfo:
    """A device registered to the logged-in user (sorted by last access, newest first)."""

    list_index: int
    name: str
    client_type: str
    login_status: str
    last_accessed: Optional[datetime]


def list_user_devices(auth: keeper_auth.KeeperAuth) -> List[UserDeviceInfo]:
    """Return all devices for the current user, sorted by last access (newest first)."""
    devices = _fetch_devices(auth)
    return [_to_user_device_info(i, d) for i, d in enumerate(devices, start=1)]


def rename_user_device(
    auth: keeper_auth.KeeperAuth,
    device_identifier: str,
    new_name: str,
) -> Tuple[str, str]:
    """
    Rename a device by list index (from list_user_devices) or unique name substring.

    Returns:
        (old_name, new_name) on success.

    Raises:
        ValueError: validation, not found, or API failure.
    """
    _validate_identifier(device_identifier)
    sanitized = _sanitize_device_name(new_name)
    if not sanitized:
        raise ValueError('Device name contains only invalid characters')

    devices = _fetch_devices(auth)
    if not devices:
        raise ValueError('No devices found')

    resolved = _resolve_device(devices, device_identifier)
    if not resolved:
        raise ValueError('No matching device found (or ambiguous device name)')

    device_token, device = resolved
    old_name = device.deviceName or 'N/A'

    rq = DeviceManagement_pb2.DeviceRenameRequest()
    dr = rq.deviceRename.add()
    dr.encryptedDeviceToken = device_token
    dr.deviceNewName = sanitized

    rs = auth.execute_auth_rest(
        rest_endpoint=URL_DEVICE_USER_RENAME,
        request=rq,
        response_type=DeviceManagement_pb2.DeviceRenameResponse,
    )
    if not rs or not rs.deviceRenameResult:
        raise ValueError('No response returned from device rename')

    for r in rs.deviceRenameResult:
        if r.deviceActionStatus == DeviceManagement_pb2.SUCCESS:
            return old_name, sanitized
        status = DeviceManagement_pb2.DeviceActionStatus.Name(r.deviceActionStatus)
        raise ValueError(f'Device rename failed: {status}')

    raise ValueError('No response returned from device rename')


def logout_user_devices(
    auth: keeper_auth.KeeperAuth,
    device_identifiers: List[str],
) -> List[str]:
    """
    Log out the current user from one or more devices.

    Args:
        device_identifiers: List index strings ('1', '2', ...) or unique name substrings.

    Returns:
        Names of devices successfully logged out.

    Raises:
        ValueError: validation, not found, or API failure.
    """
    return _execute_device_action(auth, device_identifiers, DeviceManagement_pb2.DA_LOGOUT)


def remove_user_devices(
    auth: keeper_auth.KeeperAuth,
    device_identifiers: List[str],
) -> List[str]:
    """
    Log out and remove the current user from one or more devices.

    Returns:
        Names of devices successfully removed.

    Raises:
        ValueError: validation, not found, or API failure.
    """
    return _execute_device_action(auth, device_identifiers, DeviceManagement_pb2.DA_REMOVE)


def _fetch_devices(auth: keeper_auth.KeeperAuth) -> List[DeviceManagement_pb2.Device]:
    rs = auth.execute_auth_rest(
        rest_endpoint=URL_DEVICE_USER_LIST,
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


def _to_user_device_info(index: int, device: DeviceManagement_pb2.Device) -> UserDeviceInfo:
    return UserDeviceInfo(
        list_index=index,
        name=device.deviceName or 'N/A',
        client_type=_client_type_name(device.clientType),
        login_status=_login_state_name(device.loginState),
        last_accessed=_timestamp_to_datetime(device.lastModifiedTime),
    )


def _validate_identifier(identifier: str) -> None:
    if not identifier or not identifier.strip():
        raise ValueError('Device identifier cannot be empty')
    if re.search(r'[<>"\'\x00-\x1f\x7f-\x9f]', identifier):
        raise ValueError(f'Invalid device identifier: {identifier}')


def _sanitize_device_name(name: str) -> str:
    return re.sub(r'[<>"\'\x00-\x1f\x7f-\x9f]', '', name).strip()


def _resolve_device(
    devices: List[DeviceManagement_pb2.Device], identifier: str
) -> Optional[Tuple[bytes, DeviceManagement_pb2.Device]]:
    ident = identifier.strip()
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


def _resolve_devices(
    devices: List[DeviceManagement_pb2.Device], identifiers: List[str]
) -> List[Tuple[bytes, DeviceManagement_pb2.Device]]:
    if not identifiers:
        raise ValueError('At least one device identifier is required')
    resolved: List[Tuple[bytes, DeviceManagement_pb2.Device]] = []
    for identifier in identifiers:
        _validate_identifier(identifier)
        match = _resolve_device(devices, identifier)
        if not match:
            raise ValueError(
                f'No matching device found for "{identifier}" (or ambiguous device name)'
            )
        resolved.append(match)
    return resolved


def _execute_device_action(
    auth: keeper_auth.KeeperAuth,
    device_identifiers: List[str],
    action_type: int,
) -> List[str]:
    devices = _fetch_devices(auth)
    if not devices:
        raise ValueError('No devices found')

    resolved = _resolve_devices(devices, device_identifiers)
    token_to_device = {token: device for token, device in resolved}

    rq = DeviceManagement_pb2.DeviceActionRequest()
    device_action = rq.deviceAction.add()
    device_action.deviceActionType = action_type
    device_action.encryptedDeviceToken.extend(list(token_to_device.keys()))

    rs = auth.execute_auth_rest(
        rest_endpoint=URL_DEVICE_USER_ACTION,
        request=rq,
        response_type=DeviceManagement_pb2.DeviceActionResponse,
    )
    if not rs or not rs.deviceActionResult:
        raise ValueError('No response returned from device action')

    succeeded: List[str] = []
    for result in rs.deviceActionResult:
        for token in result.encryptedDeviceToken:
            device = token_to_device.get(token)
            device_name = (device.deviceName if device else None) or 'Unknown Device'
            if result.deviceActionStatus == DeviceManagement_pb2.SUCCESS:
                succeeded.append(device_name)
            else:
                status_name = DeviceManagement_pb2.DeviceActionStatus.Name(
                    result.deviceActionStatus
                )
                if result.deviceActionStatus == DeviceManagement_pb2.NOT_ALLOWED:
                    msg = 'Operation not allowed'
                else:
                    msg = f'Action failed ({status_name})'
                raise ValueError(f"Device '{device_name}': {msg}")
    return succeeded


def _timestamp_to_datetime(timestamp: Optional[int]) -> Optional[datetime]:
    if not timestamp:
        return None
    try:
        if timestamp > 10000000000:
            timestamp = int(timestamp / 1000)
        return datetime.fromtimestamp(timestamp)
    except (ValueError, OSError, TypeError):
        return None


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
