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
# Example showing how to share a Secrets Manager application with another user
# using the Keeper SDK architecture.
#

import argparse
import json
import os
import sys

from keepercli.commands.secrets_manager import SecretsManagerAppCommand
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

def share_secrets_manager_app(
    context: KeeperParams,
    app_id: str,
    user_email: str,
    is_admin: bool = False
):
    """
    Share a Secrets Manager application with a user; optionally grant admin permissions.
    
    This function shares a Secrets Manager application with another user. It first retrieves
    the application details, then shares it with the specified user. If the user is granted
    admin permissions, the application will be shared with full access.
    """
    try:
        sm_app_command = SecretsManagerAppCommand()
        kwargs = {
            'command': 'share',
            'app': app_id,
            'email': user_email
        }
        
        if is_admin:
            kwargs['admin'] = True
            
        sm_app_command.execute(context=context, **kwargs)
        
        print(f'Successfully shared with user: {user_email}')
        context.vault.sync_down()
        
        return True
        
    except Exception as e:
        print(f'Error sharing Secrets Manager application: {str(e)}')
        return False

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Share a Secrets Manager application with another user using Keeper SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python share_secrets_manager_app.py
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
    user_email = "example@example.com"
    is_admin = False

    print(f"Note: This example will attempt to share app ID '{app_id}'")

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
        success = share_secrets_manager_app(
            context=context,
            app_id=app_id,
            user_email=user_email,
            is_admin=is_admin
        )
        
        if not success:
            sys.exit(1)
        
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()