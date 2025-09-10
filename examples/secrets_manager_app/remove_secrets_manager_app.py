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
# Example showing how to remove a Secrets Manager application
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

def remove_secrets_manager_app(
    vault: vault_online.VaultOnline,
    uid_or_name: str,
    force: bool = False
):
    """
    Remove a Secrets Manager application by UID or name.

    This function removes a Secrets Manager application by its UID or name.
    """
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

    uid_or_name = "Secrets Manager App 1"
    force = True

    print(f"Note: This example will attempt to remove app '{uid_or_name}'")

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
        removed_app = remove_secrets_manager_app(context.vault, uid_or_name, force)
        
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()