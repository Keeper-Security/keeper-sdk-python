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
# Example showing how to remove a Secrets Manager application
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


def remove_secrets_manager_app(vault, uid_or_name, force=False):
    try:
        try:
            app_details = ksm_management.get_secrets_manager_app(vault, uid_or_name)
            print(f'Found Secrets Manager Application:')
            print('=' * 50)
            print(f'Name: {app_details.name}')
            print(f'UID: {app_details.uid}')
            print(f'Records: {app_details.records}')
            print(f'Folders: {app_details.folders}')
            print(f'Client Count: {app_details.count}')
            print('=' * 50)
            
            if (app_details.records > 0 or app_details.folders > 0 or app_details.count > 0) and not force:
                print('WARNING: This application has:')
                if app_details.records > 0:
                    print(f'  - {app_details.records} shared record(s)')
                if app_details.folders > 0:
                    print(f'  - {app_details.folders} shared folder(s)')
                if app_details.count > 0:
                    print(f'  - {app_details.count} client device(s)')
                print('Use --force flag to remove the application anyway.')
                return None
                
        except Exception as e:
            print(f'Warning: Could not retrieve app details: {str(e)}')
            print('Proceeding with removal attempt...')
        
        removed_uid = ksm_management.remove_secrets_manager_app(vault, uid_or_name, force=force)
        
        print(f'Successfully removed Secrets Manager application: {removed_uid}')
        return removed_uid
        
    except ValueError as e:
        if 'Cannot remove application with clients' in str(e):
            print(f'Error: {str(e)}')
            print('Use --force flag to remove the application anyway.')
        else:
            print(f'Error: {str(e)}')
        return None
    except Exception as e:
        print(f'Error removing Secrets Manager application {uid_or_name}: {str(e)}')
        return None


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Remove a Secrets Manager application using Keeper SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python remove_secrets_manager_app.py
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

    uid_or_name = "MyApp1"
    force = True

    print(f"Note: This example will attempt to remove app '{uid_or_name}'")
    print("Make sure this app exists in your vault or update the hard-coded value")

    try:
        vault = login_to_keeper_with_config(args.config)
        removed_app = remove_secrets_manager_app(vault, uid_or_name, force)
        
        if removed_app is None:
            sys.exit(1)
        
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)