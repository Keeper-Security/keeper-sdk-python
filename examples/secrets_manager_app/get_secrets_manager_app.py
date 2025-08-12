#!/usr/bin/env python3
#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper SDK for Python
# Copyright 2023 Keeper Security Inc.
# Contact: commander@keepersecurity.com
#
# Example showing how to get details of a specific Secrets Manager application
# using the Keeper SDK architecture.
#

import argparse
import json
import os
import sqlite3
import sys

from keepersdk.authentication import login_auth, configuration, endpoint
from keepersdk.vault import sqlite_storage, vault_online, ksm_management


def login_to_keeper_with_config(filename):
    if not os.path.exists(filename):
        raise FileNotFoundError(f'Config file {filename} not found')
    
    with open(filename, 'r') as f:
        config_data = json.load(f)
    
    username = config_data.get('user', config_data.get('username'))
    password = config_data.get('password', '')
    
    if not username:
        raise ValueError('Username not found in config file')
    
    config = configuration.JsonConfigurationStorage()
    keeper_endpoint = endpoint.KeeperEndpoint(config)
    login_auth_instance = login_auth.LoginAuth(keeper_endpoint)
    
    login_auth_instance.login(username=username)
    
    if password:
        login_auth_instance.login_step.verify_password(password)
    
    if isinstance(login_auth_instance.login_step, login_auth.LoginStepConnected):
        keeper_auth = login_auth_instance.login_step.take_keeper_auth()
        
        db_path = config_data.get('db_path', 'keeper.sqlite')
        conn = sqlite3.Connection(f'file:{db_path}', uri=True)
        vault_storage = sqlite_storage.SqliteVaultStorage(
            lambda: conn, 
            vault_owner=bytes(keeper_auth.auth_context.username, 'utf-8')
        )
        
        vault = vault_online.VaultOnline(keeper_auth, vault_storage)
        vault.sync_down(force=True)
        
        return vault
    else:
        raise Exception('Failed to authenticate with Keeper')


def get_secrets_manager_app(vault, app_id):
    try:
        app_details = ksm_management.get_secrets_manager_app(vault, app_id)
        
        if not app_details:
            print(f'No Secrets Manager application found with ID: {app_id}')
            return None
        
        print(f'Secrets Manager Application Details:')
        print('=' * 50)
        
        if isinstance(app_details, dict):
            for key, value in app_details.items():
                formatted_key = key.replace('_', ' ').title()
                print(f'{formatted_key}: {value}')
        else:
            print(f'Application Details: {app_details}')
        
        print('=' * 50)
        
        return app_details
        
    except Exception as e:
        print(f'Error getting Secrets Manager application {app_id}: {str(e)}')
        return None


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Get details of a Secrets Manager application using Keeper SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python get_secrets_manager_app.py
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

    app_id = "FBO4hsQ6HUEU2mLn2vzZYg"

    print(f"Note: This example will attempt to get details for app ID '{app_id}'")
    print("Make sure this app exists in your vault or update the hard-coded value")

    try:
        vault = login_to_keeper_with_config(args.config)
        app_details = get_secrets_manager_app(vault, app_id)
        
        if app_details is None:
            sys.exit(1)
        
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)