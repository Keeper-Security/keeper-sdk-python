#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper SDK for Python — user and admin device management.
#

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, List, Optional, Tuple

from .. import utils
from ..proto import APIRequest_pb2, DeviceManagement_pb2
from . import keeper_auth

logger = utils.get_logger()

URL_DEVICE_USER_LIST = 'dm/device_user_list'
URL_DEVICE_USER_RENAME = 'dm/device_user_rename'
URL_DEVICE_USER_ACTION = 'dm/device_user_action'
URL_DEVICE_ADMIN_LIST = 'dm/device_admin_list'
URL_DEVICE_ADMIN_ACTION = 'dm/device_admin_action'


@dataclass(frozen=True)
class UserDeviceInfo:
    """A device registered to the logged-in user (sorted by last access, newest first)."""

    list_index: int
    name: str
    client_type: str
    login_status: str
    last_accessed: Optional[datetime]


@dataclass(frozen=True)
class AdminDeviceInfo:
    """A device for an enterprise user (sorted by last access, newest first)."""

    list_index: int
    enterprise_user_id: int
    name: str
    ui_category: str
    device_status: str
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
    Rename a device by list index (from list_user_devices) or device name.
    All-digit identifiers (e.g. '01') are treated as list indices, not names.

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

    resolved_device = _resolve_single_device(devices, device_identifier)
    if not resolved_device:
        raise ValueError('No matching devices found.')

    device_token = resolved_device.encryptedDeviceToken
    device = resolved_device
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


def logout_user_devices(
    auth: keeper_auth.KeeperAuth,
    device_identifiers: List[str],
) -> List[str]:
    """
    Log out the current user from one or more devices.

    Args:
        device_identifiers: List index strings ('1', '2', ...) or device names.
            All-digit values (including '01') are list indices, not names.

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


def list_admin_devices(
    auth: keeper_auth.KeeperAuth,
    enterprise_user_ids: List[int],
) -> List[AdminDeviceInfo]:
    """
    List devices for one or more enterprise users (enterprise admin).

    Args:
        enterprise_user_ids: Enterprise user IDs to query.

    Returns:
        Devices sorted by last access (newest first), with list indices assigned after sort.

    Raises:
        ValueError: validation or empty result when IDs are invalid.
    """
    if not enterprise_user_ids:
        raise ValueError(
            'Enterprise User ID is required. You can get enterprise user IDs by running: ei --users'
        )
    for user_id in enterprise_user_ids:
        _validate_enterprise_user_id(user_id)

    entries = _fetch_admin_device_entries(auth, enterprise_user_ids)
    entries.sort(key=lambda e: e[1].lastModifiedTime or 0, reverse=True)
    return [
        _to_admin_device_info(i, enterprise_user_id, device)
        for i, (enterprise_user_id, device) in enumerate(entries, start=1)
    ]


def logout_admin_user_devices(
    auth: keeper_auth.KeeperAuth,
    enterprise_user_id: int,
    device_identifiers: List[str],
) -> List[str]:
    """Log out an enterprise user from one or more devices (enterprise admin)."""
    return _execute_admin_device_action(
        auth, enterprise_user_id, device_identifiers, DeviceManagement_pb2.DA_LOGOUT
    )


def remove_admin_user_devices(
    auth: keeper_auth.KeeperAuth,
    enterprise_user_id: int,
    device_identifiers: List[str],
) -> List[str]:
    """Log out and remove an enterprise user from one or more devices (enterprise admin)."""
    return _execute_admin_device_action(
        auth, enterprise_user_id, device_identifiers, DeviceManagement_pb2.DA_REMOVE
    )


def lock_user_devices(
    auth: keeper_auth.KeeperAuth,
    device_identifiers: List[str],
) -> List[str]:
    """
    Lock one or more devices for all users (and linked devices). Logs out all users.

    Returns:
        Names of devices successfully locked.

    Raises:
        ValueError: validation, not found, or API failure.
    """
    return _execute_device_action(auth, device_identifiers, DeviceManagement_pb2.DA_LOCK)


def unlock_user_devices(
    auth: keeper_auth.KeeperAuth,
    device_identifiers: List[str],
) -> List[str]:
    """
    Unlock one or more devices (and linked devices) for the calling user.

    Returns:
        Names of devices successfully unlocked.

    Raises:
        ValueError: validation, not found, or API failure.
    """
    return _execute_device_action(auth, device_identifiers, DeviceManagement_pb2.DA_UNLOCK)


def account_lock_user_devices(
    auth: keeper_auth.KeeperAuth,
    device_identifiers: List[str],
) -> List[str]:
    """
    Lock one or more devices for the current user only (logs out if logged in).

    Returns:
        Names of devices successfully account-locked.

    Raises:
        ValueError: validation, not found, or API failure.
    """
    return _execute_device_action(
        auth, device_identifiers, DeviceManagement_pb2.DA_DEVICE_ACCOUNT_LOCK
    )


def account_unlock_user_devices(
    auth: keeper_auth.KeeperAuth,
    device_identifiers: List[str],
) -> List[str]:
    """
    Unlock one or more devices for the current user.

    Returns:
        Names of devices successfully account-unlocked.

    Raises:
        ValueError: validation, not found, or API failure.
    """
    return _execute_device_action(
        auth, device_identifiers, DeviceManagement_pb2.DA_DEVICE_ACCOUNT_UNLOCK
    )


def link_user_devices(
    auth: keeper_auth.KeeperAuth,
    device_identifiers: List[str],
) -> List[str]:
    """
    Link two or more devices so logging into one can resume sessions on the others
    when persistent login is enabled.

    Returns:
        Names of devices successfully linked.

    Raises:
        ValueError: validation, not found, or API failure.
    """
    _validate_link_unlink_identifiers(device_identifiers)
    return _execute_device_action(auth, device_identifiers, DeviceManagement_pb2.DA_LINK)


def unlink_user_devices(
    auth: keeper_auth.KeeperAuth,
    device_identifiers: List[str],
) -> List[str]:
    """
    Unlink two or more previously linked devices for the current user.

    Returns:
        Names of devices successfully unlinked.

    Raises:
        ValueError: validation, not found, or API failure.
    """
    _validate_link_unlink_identifiers(device_identifiers)
    return _execute_device_action(auth, device_identifiers, DeviceManagement_pb2.DA_UNLINK)


def _validate_link_unlink_identifiers(device_identifiers: List[str]) -> None:
    if len(device_identifiers) < 2:
        raise ValueError('At least two device identifiers are required for link/unlink')


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


def _to_admin_device_info(
    index: int,
    enterprise_user_id: int,
    device: DeviceManagement_pb2.Device,
) -> AdminDeviceInfo:
    return AdminDeviceInfo(
        list_index=index,
        enterprise_user_id=enterprise_user_id,
        name=device.deviceName or 'N/A',
        ui_category=_ui_category_name(device),
        device_status=_device_status_name(device.deviceStatus),
        login_status=_login_state_name(device.loginState),
        last_accessed=_timestamp_to_datetime(device.lastModifiedTime),
    )


def _fetch_admin_device_entries(
    auth: keeper_auth.KeeperAuth,
    enterprise_user_ids: List[int],
) -> List[Tuple[int, DeviceManagement_pb2.Device]]:
    rq = DeviceManagement_pb2.DeviceAdminRequest()
    rq.enterpriseUserIds.extend(enterprise_user_ids)
    rs = auth.execute_auth_rest(
        rest_endpoint=URL_DEVICE_ADMIN_LIST,
        request=rq,
        response_type=DeviceManagement_pb2.DeviceAdminResponse,
    )
    if not rs:
        return []
    entries: List[Tuple[int, DeviceManagement_pb2.Device]] = []
    for device_user_group in rs.deviceUserList:
        enterprise_user_id = device_user_group.enterpriseUserId
        for device_group in device_user_group.deviceGroups:
            for device in device_group.devices:
                entries.append((enterprise_user_id, device))
    return entries


def _fetch_admin_devices_for_user(
    auth: keeper_auth.KeeperAuth,
    enterprise_user_id: int,
) -> List[DeviceManagement_pb2.Device]:
    entries = _fetch_admin_device_entries(auth, [enterprise_user_id])
    devices = [device for user_id, device in entries if user_id == enterprise_user_id]
    devices.sort(key=lambda d: d.lastModifiedTime or 0, reverse=True)
    return devices


def _validate_enterprise_user_id(user_id: int) -> None:
    if type(user_id) is not int:
        raise ValueError(f'Invalid enterprise user ID: {user_id}')
    if user_id < 1:
        raise ValueError(f'Invalid enterprise user ID: {user_id}')


def _validate_identifier(identifier: str) -> None:
    if not identifier or not identifier.strip():
        raise ValueError('Device identifier cannot be empty')
    if re.search(r'[<>"\'\x00-\x1f\x7f-\x9f]', identifier):
        raise ValueError(f'Invalid device identifier: {identifier}')


def _sanitize_device_name(name: str) -> str:
    return re.sub(r'[<>"\'\x00-\x1f\x7f-\x9f]', '', name).strip()


def _device_list_index(
    devices: List[DeviceManagement_pb2.Device], device: DeviceManagement_pb2.Device
) -> int:
    for index, candidate in enumerate(devices, start=1):
        if candidate.encryptedDeviceToken == device.encryptedDeviceToken:
            return index
    return 0


def _find_matching_devices(
    devices: List[DeviceManagement_pb2.Device], identifier: str
) -> Optional[Tuple[bytes, DeviceManagement_pb2.Device]]:
    """
    Resolve a device identifier to its token and device record.

    Resolution order:
    1. If the identifier contains only digits (``str.isdigit()``), it is treated as a
       1-based list index from ``list_user_devices`` / ``device-list`` (``int`` is applied,
       so ``"01"`` resolves to the first device, not a device named ``"01"``).
    2. Otherwise, match by case-insensitive device name (exact or substring per caller).
    """
    ident = identifier.strip()
    # All-digit strings are list IDs, not names ("01" -> index 1 via int(), not name "01").
    if ident.isdigit():
        idx = int(ident)
        if 1 <= idx <= len(devices):
            return [devices[idx - 1]]
        return []

    ident_l = ident.lower()
    return [d for d in devices if (d.deviceName or '').lower() == ident_l]


def _report_multiple_matches(
    devices: List[DeviceManagement_pb2.Device],
    identifier: str,
    matched_devices: List[DeviceManagement_pb2.Device],
) -> None:
    logger.warning("Warning: Multiple devices found matching '%s':", identifier)
    for device in matched_devices:
        device_id = _device_list_index(devices, device)
        logger.info('  - ID %s: %s', device_id, device.deviceName or 'N/A')
    logger.info(
        'Mutiple device with same name found, please use device ID instead'
    )


def _resolve_single_device(
    devices: List[DeviceManagement_pb2.Device],
    identifier: str,
    *,
    allow_multiple: bool = False,
) -> Optional[DeviceManagement_pb2.Device]:
    matched_devices = _find_matching_devices(devices, identifier)
    if not matched_devices:
        logger.warning("Warning: No device found matching '%s'", identifier)
        return None
    if len(matched_devices) > 1 and not allow_multiple:
        _report_multiple_matches(devices, identifier, matched_devices)
        return None
    if len(matched_devices) > 1:
        logger.warning(
            "Warning: Multiple devices found matching '%s'. Using first match.",
            identifier,
        )
    return matched_devices[0]


def _resolve_devices(
    devices: List[DeviceManagement_pb2.Device], identifiers: List[str]
) -> List[Tuple[bytes, DeviceManagement_pb2.Device]]:
    if not identifiers:
        raise ValueError('At least one device identifier is required')
    resolved: List[Tuple[bytes, DeviceManagement_pb2.Device]] = []
    seen_tokens: set[bytes] = set()
    for identifier in identifiers:
        _validate_identifier(identifier)
        match = _resolve_single_device(devices, identifier)
        if not match:
            raise ValueError(
                f'No matching device found for "{identifier}" (or ambiguous device name)'
            )
        token, device = match
        if token in seen_tokens:
            raise ValueError(
                f'Duplicate device specified: "{identifier}" resolves to a device '
                'already included'
            )
        seen_tokens.add(token)
        resolved.append((token, device))
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
    if action_type in (DeviceManagement_pb2.DA_LINK, DeviceManagement_pb2.DA_UNLINK):
        tokens = [token for token, _ in resolved]
        if len(set(tokens)) < 2:
            raise ValueError('Link/unlink requires at least two different devices')
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


def _execute_admin_device_action(
    auth: keeper_auth.KeeperAuth,
    enterprise_user_id: int,
    device_identifiers: List[str],
    action_type: int,
) -> List[str]:
    _validate_enterprise_user_id(enterprise_user_id)
    if not device_identifiers:
        raise ValueError('At least one device must be specified')

    devices = _fetch_admin_devices_for_user(auth, enterprise_user_id)
    if not devices:
        raise ValueError('No devices found')

    resolved = _resolve_devices(devices, device_identifiers)
    token_to_device = {token: device for token, device in resolved}

    rq = DeviceManagement_pb2.DeviceAdminActionRequest()
    admin_action = rq.deviceAdminAction.add()
    admin_action.deviceActionType = action_type
    admin_action.enterpriseUserId = enterprise_user_id
    admin_action.encryptedDeviceToken.extend(list(token_to_device.keys()))

    rs = auth.execute_auth_rest(
        rest_endpoint=URL_DEVICE_ADMIN_ACTION,
        request=rq,
        response_type=DeviceManagement_pb2.DeviceAdminActionResponse,
    )
    if not rs or not rs.deviceAdminActionResults:
        raise ValueError('No response returned from device admin action')

    succeeded: List[str] = []
    for result in rs.deviceAdminActionResults:
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


_UI_CATEGORY_RULES: List[Tuple[Callable[[DeviceManagement_pb2.Device], bool], str]] = [
    (lambda d: d.clientTypeCategory == DeviceManagement_pb2.CAT_EXTENSION, 'Browser Extension'),
    (lambda d: d.clientTypeCategory == DeviceManagement_pb2.CAT_DESKTOP, 'Desktop'),
    (lambda d: d.clientTypeCategory == DeviceManagement_pb2.CAT_WEB_VAULT, 'Web Vault'),
    (
        lambda d: (
            d.clientType == DeviceManagement_pb2.ENTERPRISE_MANAGEMENT_CONSOLE
            and d.clientTypeCategory == DeviceManagement_pb2.CAT_ADMIN
        ),
        'Admin Console',
    ),
    (
        lambda d: (
            d.clientType == DeviceManagement_pb2.COMMANDER
            and d.clientTypeCategory == DeviceManagement_pb2.CAT_ADMIN
        ),
        'Commander CLI',
    ),
    (
        lambda d: (
            d.clientType == DeviceManagement_pb2.IOS
            and d.clientTypeCategory == DeviceManagement_pb2.CAT_MOBILE
        ),
        'iOS App',
    ),
    (
        lambda d: (
            d.clientType == DeviceManagement_pb2.ANDROID
            and d.clientTypeCategory == DeviceManagement_pb2.CAT_MOBILE
        ),
        'Android App',
    ),
    (
        lambda d: (
            d.clientTypeCategory == DeviceManagement_pb2.CAT_MOBILE
            and d.clientFormFactor == APIRequest_pb2.FF_PHONE
        ),
        'Mobile',
    ),
    (
        lambda d: (
            d.clientTypeCategory == DeviceManagement_pb2.CAT_MOBILE
            and d.clientFormFactor == APIRequest_pb2.FF_TABLET
        ),
        'Tablet',
    ),
    (
        lambda d: (
            d.clientTypeCategory == DeviceManagement_pb2.CAT_MOBILE
            and d.clientFormFactor == APIRequest_pb2.FF_WATCH
        ),
        'Wear OS',
    ),
]

_DEVICE_STATUS_NAMES = {
    APIRequest_pb2.DEVICE_NEEDS_APPROVAL: 'NEEDS_APPROVAL',
    APIRequest_pb2.DEVICE_OK: 'OK',
    APIRequest_pb2.DEVICE_DISABLED_BY_USER: 'DISABLED_BY_USER',
    APIRequest_pb2.DEVICE_LOCKED_BY_ADMIN: 'LOCKED_BY_ADMIN',
}


def _ui_category_name(device: DeviceManagement_pb2.Device) -> str:
    try:
        for rule_check, category_name in _UI_CATEGORY_RULES:
            if rule_check(device):
                return category_name
        return 'Unknown Device'
    except (AttributeError, TypeError):
        return 'Unknown Device'


def _device_status_name(device_status: int) -> str:
    return _DEVICE_STATUS_NAMES.get(device_status, f'UNKNOWN_STATUS_{device_status}')


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
