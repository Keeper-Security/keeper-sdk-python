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

from keepersdk.vault import record_type_management, vault_online
from keepercli.params import KeeperParams
from keepercli.login import LoginFlow

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
    username = config_data.get('user', config_data.get('username'))
    password = config_data.get('password', '')
    if not username:
        raise ValueError('Username not found in config file')
    context = KeeperParams(config_filename=filename, config=config_data)
    if username:
        context.username = username
    if password:
        context.password = password
    logged_in = LoginFlow.login(context, username=username, password=password or None, resume_session=bool(username))
    if not logged_in:
        raise Exception('Failed to authenticate with Keeper')
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
    
    parser.add_argument(
        '-c', '--config',
        default='myconfig.json',
        help='Configuration file (default: myconfig.json)'
    )

    args = parser.parse_args()

    if not os.path.exists(args.config):
        print(f'Config file {args.config} not found')
        sys.exit(1)

    record_type_id = 24375
    force = True

    print(f"Note: This example will attempt to delete record type ID {record_type_id}")

    try:
        vault = login_to_keeper_with_config(args.config).vault
        success = delete_custom_record_type(vault, record_type_id, force)
        
        if not success:
            sys.exit(1)
        
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)