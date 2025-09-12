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
# Example showing how to remove a client from a Secrets Manager application
# using the SecretsManagerClientCommand from the CLI package.
#

import argparse
import json
import os
import sys
from typing import List

from keepersdk.vault import ksm_management
from keepercli.commands.secrets_manager import SecretsManagerClientCommand
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


def remove_client_from_app(
    context: KeeperParams,
    app_id: str,
    client_names_or_ids: List[str],
    force: bool = False
):
    """
    Remove client(s) from a Secrets Manager application.
    
    This function removes one or more clients from a Secrets Manager application
    using the CLI command infrastructure. It provides confirmation prompts
    unless force is True.
    """
    try:
        client_command = SecretsManagerClientCommand()
        
        if len(client_names_or_ids) == 1 and client_names_or_ids[0] in ['*', 'all']:
            print(f'Removing ALL clients from application "{app_id}"...')
        else:
            clients_text = ', '.join(client_names_or_ids)
            print(f'Removing client(s) from application "{app_id}": {clients_text}')
        
        if force:
            print('- Force mode: Skipping confirmation prompts')
        
        kwargs = {
            'command': 'remove',
            'app': app_id,
            'client_names_or_ids': client_names_or_ids,
            'force': force
        }
        
        client_command.execute(context=context, **kwargs)
        print(f'Successfully removed client(s) from application: {app_id}')
        context.vault.sync_down()
        return True
        
    except Exception as e:
        print(f'Error removing client from Secrets Manager application: {str(e)}')
        return False
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Remove a client from a Secrets Manager application using Keeper SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python secrets_manager_client_remove.py
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

    app_id = "RlO6y-idGBqu1Ax2yUYXKw"
    client_names_or_ids = ["DemoClient"]
    force = True # Set to True to skip confirmation prompts, set to None to send as False

    print(f"Note: This example will attempt to remove clients from app ID '{app_id}'")

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
        success = remove_client_from_app(
            context=context,
            app_id=app_id,
            client_names_or_ids=client_names_or_ids,
            force=force
        )
        
        if not success:
            sys.exit(1)
        
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()