#!/usr/bin/env python3
#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper SDK for Python
# Copyright 2025 Keeper Security Inc.
# Contact: commander@keepersecurity.com
#
# Example showing how to delete a custom record type
# using the Keeper SDK architecture.
#

import argparse
import json
import os
import sys
import logging

from keepersdk.vault import record_type_management, vault_online

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


def delete_custom_record_type(
    vault: vault_online.VaultOnline,
    record_type_id: int,
    force: bool = False
):
    """
    Delete a custom record type from the Keeper vault. 
    This function removes a custom record type by its ID.
    """
    try:
        if not force:
            response = input(f'Are you sure you want to delete custom record type ID {record_type_id}? (y/N): ')
            if response.lower() not in ['y', 'yes']:
                print('Deletion cancelled.')
                return False
        
        result = record_type_management.delete_custom_record_types(vault, record_type_id)
        
        if result:
            print(f'Successfully deleted custom record type ID: {record_type_id}')
            return True
        else:
            print(f'Failed to delete custom record type ID: {record_type_id}')
            return False
        
    except Exception as e:
        print(f'Error deleting custom record type {record_type_id}: {str(e)}')
        return False


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Delete a custom record type using Keeper SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python delete_custom_record_type.py
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

    record_type_id = 000000
    force = True # True or False

    print(f"Note: This example will attempt to delete record type ID {record_type_id}")

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
        success = delete_custom_record_type(context.vault, record_type_id, force)
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()
