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
# Example showing how to create a new Secrets Manager application
# using the Keeper SDK architecture.
#

import argparse
import json
import os
import sys

from keepersdk.vault import ksm_management, vault_online
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

def create_secrets_manager_app(
    vault: vault_online.VaultOnline,
    app_name: str,
    force_add: bool = False
):
    """
    Create a new Secrets Manager application in the Keeper vault.
    
    This function creates a new Secrets Manager application that can be used
    to programmatically access vault records through the Secrets Manager API.
    The application will be configured with appropriate permissions and credentials.
    """
    try:
        result = ksm_management.create_secrets_manager_app(
            vault=vault, 
            name=app_name, 
            force_add=force_add
        )
        
        if result:
            print(f'Successfully created Secrets Manager application: {app_name}, UID: {result}')
            return result
        else:
            print(f'Failed to create Secrets Manager application: {app_name}')
            return None
        
    except Exception as e:
        print(f'Error creating Secrets Manager application {app_name}: {str(e)}')
        return None

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Create a Secrets Manager application using Keeper SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python create_secrets_manager_app.py
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

    app_name = "Secrets Manager App 1"
    force = True

    try:
        vault = login_to_keeper_with_config(args.config).vault
        result = create_secrets_manager_app(vault, app_name, force)
        
        if result is None:
            sys.exit(1)
        
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)