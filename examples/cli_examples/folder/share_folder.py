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
# Example showing how to share a folder with another user
# using the ShareFolderCommand from the CLI package.
#

import argparse
import json
import os
import sys
from typing import Optional

from keepercli.commands.share_management import ShareFolderCommand
from keepercli.params import KeeperParams, KeeperConfig
from keepercli.login import LoginFlow


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

    username = config_data.get('user', config_data.get('username'))
    password = config_data.get('password', '')
    if not username:
        raise ValueError('Username not found in config file')

    keeper_config = KeeperConfig(config_filename=filename, config=config_data)
    auth = LoginFlow.login(keeper_config, username=username, password=password or None, resume_session=bool(username))
    if not auth:
        raise Exception('Failed to authenticate with Keeper')

    context = KeeperParams(keeper_config=keeper_config)
    context.set_auth(auth)

    return context


def share_folder_with_user(
    context: KeeperParams,
    folder_uid: str,
    user_email: str,
    manage_records: Optional[str] = None,
    manage_users: Optional[str] = None,
    action: str = 'grant'
):
    """
    Share a folder with another user.
    This function shares a folder with a user and returns True if successful, False otherwise.
    """
    try:
        share_command = ShareFolderCommand()
        
        permissions = []
        if manage_records == 'on':
            permissions.append("manage records")
        if manage_users == 'on':
            permissions.append("manage users")
        
        permissions_text = f" with {', '.join(permissions)} permissions" if permissions else " (default permissions)"
        print(f'Sharing folder "{folder_uid}" with user "{user_email}"{permissions_text}...')

        kwargs = {
            'folder': [folder_uid],
            'user': [user_email],
            'action': action,
            'force': True
        }
        
        if manage_records:
            kwargs['manage_records'] = manage_records
        if manage_users:
            kwargs['manage_users'] = manage_users
        
        share_command.execute(context=context, **kwargs)
        
        print(f'Successfully {action}ed folder access for user: {user_email}')
        
        print('\nShare operation completed successfully')
        print('-' * 40)
        
        context.vault.sync_down()
        
        print(f'Status: Successfully {action}ed access for {user_email}')
        
        return True
        
    except Exception as e:
        print(f'Error sharing folder: {str(e)}')
        return False


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Share a folder with another user using Keeper SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python share_folder.py
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

    folder_uid = "t5C4bl3iWmOPWugaWGaMIQ"
    user_email = "example@example.com"
    manage_records = 'on' # 'on' or 'off'
    manage_users = 'off' # 'on' or 'off'
    action = 'grant' # 'grant' or 'remove' with grant being default if skipped

    print(f"Note: This example will attempt to share folder '{folder_uid}' with '{user_email}'")

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
        success = share_folder_with_user(
            context=context,
            folder_uid=folder_uid,
            user_email=user_email,
            manage_records=manage_records,
            manage_users=manage_users,
            action=action
        )
        
        if not success:
            sys.exit(1)
        
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()
