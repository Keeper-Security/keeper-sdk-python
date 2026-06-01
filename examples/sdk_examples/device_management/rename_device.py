#!/usr/bin/env python3
#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper SDK for Python
# Copyright 2025 Keeper Security Inc.
#
# Example: rename a device for the logged-in user using the Keeper SDK.
# Equivalent to the device-rename CLI command.
#
# Uses:
#   - dm/device_user_list (resolve device)
#   - dm/device_user_rename (DeviceRenameRequest / DeviceRenameResponse)
#

from device_management_common import fetch_user_devices, print_devices_table, rename_user_device, run_login

# Set before running: device ID from list_devices.py output, or a unique name substring
DEVICE_IDENTIFIER = '1'
NEW_DEVICE_NAME = 'My Device Renamed'


def main() -> None:
    keeper_auth_context, _ = run_login()
    if not keeper_auth_context:
        print('Login failed.')
        return

    try:
        print(f"Renaming device '{DEVICE_IDENTIFIER}' to '{NEW_DEVICE_NAME}'...")
        rename_user_device(keeper_auth_context, DEVICE_IDENTIFIER, NEW_DEVICE_NAME)
        print('\nUpdated device list:')
        print_devices_table(fetch_user_devices(keeper_auth_context))
    except Exception as e:
        print(f'Error renaming device: {e}')
    finally:
        keeper_auth_context.close()


if __name__ == '__main__':
    main()
