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
# Example showing how to share a record with another user
# using the ShareRecordCommand from the CLI package.
#

import argparse
import json
import os
import sys

from keepercli.commands.share_management import ShareRecordCommand
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

def share_record_with_user(
    context: KeeperParams,
    record_uid: str,
    user_email: str,
    can_edit: bool = False,
    can_share: bool = False,
    action: str = 'grant'
):
    """
    Share a record with another user.
    
    This function shares a vault record with another user using the CLI
    command infrastructure. It allows configuring edit and share permissions
    for the recipient.
    """
    try:
        share_command = ShareRecordCommand()
        
        permissions = []
        if can_edit:
            permissions.append("edit")
        if can_share:
            permissions.append("re-share")
        
        permissions_text = f" with {', '.join(permissions)} permissions" if permissions else " (read-only)"
        print(f'Sharing record "{record_uid}" with user "{user_email}"{permissions_text}...')
        
        kwargs = {
            'record': record_uid,
            'email': [user_email],
            'action': action,
            'can_edit': can_edit,
            'can_share': can_share,
            'force': True
        }
        
        share_command.execute(context=context, **kwargs)
        
        print(f'Successfully {action}ed record access for user: {user_email}')
        
        print('\nShare operation completed successfully')
        print('-' * 40)
        
        context.vault.sync_down()
        
        print(f'Status: Successfully {action}ed access for {user_email}')
        
        return True
        
    except Exception as e:
        print(f'Error sharing record: {str(e)}')
        return False

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Share a record with another user using Keeper SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python share_record.py
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

    record_uid = "UkezdUGQoTOztfi5cGFJnQ"
    user_email = "example@example.com"
    can_edit = True
    can_share = False
    action = 'grant'

    print(f"Note: This example will attempt to share record '{record_uid}' with '{user_email}'")

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
        success = share_record_with_user(
            context=context,
            record_uid=record_uid,
            user_email=user_email,
            can_edit=can_edit,
            can_share=can_share,
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