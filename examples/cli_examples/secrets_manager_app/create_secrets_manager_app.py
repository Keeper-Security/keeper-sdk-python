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
import logging

from keepersdk.vault import ksm_management, vault_online
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

    app_name = "Secrets Manager App 1"
    force = True # Set to True to overwrite if app with same name exists, set to None to send as False

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
        result = create_secrets_manager_app(context.vault, app_name, force)
        
        if result is None:
            sys.exit(1)
        
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()
