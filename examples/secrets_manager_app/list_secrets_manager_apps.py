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
# Example showing how to list Secrets Manager applications
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


def list_secrets_manager_apps(vault, show_details=False):
    try:
        apps = ksm_management.list_secrets_manager_apps(vault=vault)
        
        if not apps:
            print('No Secrets Manager applications found.')
            return
        
        print(f'Found {len(apps)} Secrets Manager application(s):')
        print('-' * 80)
        
        for app in apps:
            if isinstance(app, dict):
                app_name = app.get('name', 'Unknown')
                app_id = app.get('id', app.get('app_uid', 'Unknown'))
                created_on = app.get('created_on', 'Unknown')
                
                print(f'Name: {app_name}')
                print(f'ID: {app_id}')
                if show_details:
                    print(f'Created On: {created_on}')
                    # Print other available details
                    for key, value in app.items():
                        if key not in ['name', 'id', 'app_uid', 'created_on']:
                            print(f'{key.replace("_", " ").title()}: {value}')
            else:
                print(f'Application: {app}')
            
            print('-' * 80)
        
        return apps
        
    except Exception as e:
        print(f'Error listing Secrets Manager applications: {str(e)}')
        return None


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='List Secrets Manager applications using Keeper SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python list_secrets_manager_apps.py
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

    show_details = True

    try:
        vault = login_to_keeper_with_config(args.config)
        list_secrets_manager_apps(vault, show_details)
        
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)