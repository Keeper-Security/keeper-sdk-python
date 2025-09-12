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
# Example showing how to add shares to a Secrets Manager application
# using the Keeper SDK architecture.
#

import argparse
import json
import os
import sys
from typing import List

from keepercli.commands.secrets_manager import SecretsManagerShareCommand
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

def add_secrets_to_app(
    context: KeeperParams,
    app_id: str,
    secret_uids: List[str],
    is_editable: bool = False
):
    """
    Add secrets (records) to a Secrets Manager application.
    
    This function adds one or more secrets to an existing Secrets Manager application,
    allowing the application to access those secrets through the Secrets Manager API.
    The secrets can be configured as read-only or editable.
    """
    try:
        print(f'Adding secrets to application "{app_id}"...')
        
        sm_share_command = SecretsManagerShareCommand()
        
        editable_text = " (editable)" if is_editable else " (read-only)"
        secret_list = ', '.join(secret_uids)
        print(f'Adding secrets to application "{app_id}"{editable_text}...')
        print(f'Secret UIDs: {secret_list}')
        
        kwargs = {
            'command': 'add',
            'app': app_id,
            'secret': ' '.join(secret_uids),
            'editable': is_editable
        }
            
        sm_share_command.execute(context=context, **kwargs)
        
        print(f'Successfully added {len(secret_uids)} secret(s) to application: {app_id}')
        
        context.vault.sync_down()
        return True
        
    except Exception as e:
        print(f'Error adding secrets to Secrets Manager application: {str(e)}')
        return False

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Add secrets to a Secrets Manager application using Keeper SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python secrets_manager_share_add.py
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
    secret_uids = ["YJAAssUpHCf-2Xfjnlw5cw"]
    is_editable = None # Set to True to make secrets editable, set to None to send as False

    print(f"Note: This example will attempt to add secrets to app ID '{app_id}'")

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
        success = add_secrets_to_app(
            context=context,
            app_id=app_id,
            secret_uids=secret_uids,
            is_editable=is_editable
        )
        
        if not success:
            sys.exit(1)
        
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()