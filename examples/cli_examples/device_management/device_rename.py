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
# Example: rename a device (device-rename command).
# Set DEVICE_ID and NEW_NAME below before running.
#

import argparse
import json
import os
import sys

from keepercli.commands.device_management import DeviceRenameCommand
from keepercli.params import KeeperConfig, KeeperParams
from keepercli.login import LoginFlow


def get_default_config_path() -> str:
    file_name = 'config.json'
    if os.path.isfile(file_name):
        return os.path.abspath(file_name)
    keeper_dir = os.path.join(os.path.expanduser('~'), '.keeper')
    os.makedirs(keeper_dir, exist_ok=True)
    return os.path.join(keeper_dir, file_name)


def login_to_keeper_with_config(filename: str) -> KeeperParams:
    if not os.path.exists(filename):
        raise FileNotFoundError(f'Config file {filename} not found')
    with open(filename, 'r') as f:
        config_data = json.load(f)

    keeper_config = KeeperConfig(config_filename=filename, config=config_data)
    auth = LoginFlow.login(keeper_config)
    if not auth:
        raise Exception('Failed to authenticate with Keeper')

    context = KeeperParams(keeper_config=keeper_config)
    context.set_auth(auth)
    return context


def rename_device(context: KeeperParams, device_id: str, new_name: str):
    cmd = DeviceRenameCommand()
    cmd.execute(context, device=device_id, new_name=new_name)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Rename a Keeper device (device-rename)')
    default_config = get_default_config_path()
    parser.add_argument('-c', '--config', default=default_config, help='Keeper config file')
    parser.add_argument('device', nargs='?', help='Device ID from device-list or name substring')
    parser.add_argument('new_name', nargs='?', help='New device name')
    args = parser.parse_args()

    # Defaults — run device_list.py first to pick an ID
    device_id = args.device or '1'
    new_name = args.new_name or 'My Device Renamed'

    print(f"Note: will rename device '{device_id}' to '{new_name}'")

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
        rename_device(context, device_id, new_name)
    except Exception as e:
        print(f'Error: {e}', file=sys.stderr)
        sys.exit(1)
    finally:
        if context:
            context.clear_session()
