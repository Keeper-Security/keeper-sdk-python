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
# Example: list active devices for the logged-in user using the Keeper SDK.
# Equivalent to the device-list CLI command.
#
# Uses:
#   - keepersdk.authentication.keeper_auth.KeeperAuth.execute_auth_rest
#   - keepersdk.proto.DeviceManagement_pb2.DeviceUserResponse
#

from device_management_common import fetch_user_devices, print_devices_table, run_login


def main() -> None:
    keeper_auth_context, _ = run_login()
    if not keeper_auth_context:
        print('Login failed.')
        return

    try:
        devices = fetch_user_devices(keeper_auth_context)
        print_devices_table(devices)
    except Exception as e:
        print(f'Error listing devices: {e}')
    finally:
        keeper_auth_context.close()


if __name__ == '__main__':
    main()
