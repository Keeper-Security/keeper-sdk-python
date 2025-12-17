#!/usr/bin/env python3
#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper CLI for Python
# Copyright 2025 Keeper Security Inc.
# Contact: commander@keepersecurity.com
#
# Example showing how to create a one-time share URL for a record
# using the Keeper CLI architecture.
#

import argparse
import json
import logging
import os
import sys

from keepercli.commands.share_management import OneTimeShareCreateCommand
from keepercli.params import KeeperParams, KeeperConfig
from keepercli.login import LoginFlow


logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)


def get_default_config_path() -> str:
    """
    Get the default config file path following the same logic as JsonFileLoader.
    
    First checks if 'config.json' exists in the current directory.
    If not, uses ~/.keeper/config.json.
    """
    file_name = 'config.json'
    if os.path.isfile(file_name):
        return os.path.abspath(file_name)
    else:
        keeper_dir = os.path.join(os.path.expanduser('~'), '.keeper')
        if not os.path.exists(keeper_dir):
            os.mkdir(keeper_dir)
        return os.path.join(keeper_dir, file_name)
        

def login_to_keeper_with_config(filename: str) -> KeeperParams:
    """
    Login to Keeper with a configuration file.
    
    This function logs in to Keeper using the provided configuration file.
    It reads the configuration file, extracts the username,
    and returns a Authenticated KeeperParams Context object.
    """
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


def execute_one_time_share_create(context: KeeperParams, **kwargs):
    """
    Execute one-time share create command.
    
    This function creates a one-time share URL for a record
    using the Keeper CLI command infrastructure.
    """
    one_time_share_create_command = OneTimeShareCreateCommand()
    
    try:
        one_time_share_create_command.execute(context=context, **kwargs)
    except Exception as e:
        raise Exception(f'Error: {str(e)}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Create a one-time share URL for a record using Keeper SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python create_one_time_share.py
        '''
    )
    
    default_config_path = get_default_config_path()
    parser.add_argument(
        '-c', '--config',
        default=default_config_path,
        help=f'Configuration file (default: {default_config_path})'
    )

    args = parser.parse_args()

    if not os.path.exists(args.config):
        print(f'Config file {args.config} not found')
        sys.exit(1)

    record_name = "record_name"
    expire_time = "1h"
    share_name = "share_name"
    output_destination = "stdout" # 'stdout' for printing the link in console or 'clipboard' to copy it to clipboard
    is_editable = True # True or None

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)

    kwargs = {
        'record': record_name,
        'expire': expire_time,
        'share_name': share_name,
        'output': output_destination,
        'is_editable': is_editable # If is_editable is sent, it will be considered True regardless of value, unless set as None
    }

    print(f"Creating one-time share for record: {record_name}")
    print(f"Expiration: {expire_time}, Name: {share_name}, Editable: {is_editable}")
    
    try:
        execute_one_time_share_create(context, **kwargs)
        print(f'One-time share URL created successfully')
        sys.exit(0)
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()
