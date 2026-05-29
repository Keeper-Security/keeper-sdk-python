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
# Example: list devices for the logged-in user (device-list command).
#

import argparse
import json
import os
import sys

from keepercli.commands.device_management import DeviceListCommand
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


def list_devices(context: KeeperParams, output_format: str = 'table', output_file: str = None):
    cmd = DeviceListCommand()
    cmd.execute(context, format=output_format, output=output_file)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='List Keeper devices (device-list)')
    default_config = get_default_config_path()
    parser.add_argument('-c', '--config', default=default_config, help='Keeper config file')
    parser.add_argument('--format', choices=['table', 'json'], default='table')
    parser.add_argument('--output', help='Output file (json format only)')
    args = parser.parse_args()

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
        list_devices(context, output_format=args.format, output_file=args.output)
    except Exception as e:
        print(f'Error: {e}', file=sys.stderr)
        sys.exit(1)
    finally:
        if context:
            context.clear_session()
