#!/usr/bin/env python3
#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper CLI for Python
# Copyright 2025 Keeper Security Inc.
# Contact: commander@keepersecurity.com
#
# Example showing how to transfer user accounts from one user to another
# using the Keeper CLI architecture.
#

import argparse
import json
import os
import sys
import logging

from keepercli.commands.transfer_account import EnterpriseTransferAccountCommand
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


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Transfer user accounts using Keeper SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python transfer_user.py
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

    # Configuration constants - modify these values as needed
    # Bool flags can be set to True or None (to be sent as False)
    source_users = ['testuser@example.com']  # List of source user emails
    target_user = 'admin@example.com'  # Target user email
    mapping_file = None  # Path to existing mapping file (overrides other options if set)
    force = None  # Set to True to skip confirmation prompts

    # Validate email formats (basic check)
    all_emails = source_users + [target_user] if target_user else source_users
    for email in all_emails:
        if '@' not in email:
            print(f'Error: Invalid email address format: {email}')
            sys.exit(1)
    
    # Check for self-transfer
    if target_user and target_user in source_users:
        print('Error: Target user cannot be the same as source user')
        sys.exit(1)

    # Display test configuration
    print(f'Using source users: {", ".join(source_users)}')
    print(f'Using target user: {target_user}')
    print(f'Force mode: {force}')

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
        
        # Ensure enterprise data is loaded
        if not context.enterprise_data:
            print('Loading enterprise data...')
            context.enterprise_loader.load()

        # Prepare command invocation
        transfer_command = EnterpriseTransferAccountCommand()
        if mapping_file:
            if not os.path.exists(mapping_file):
                print(f'Error: Mapping file {mapping_file} not found')
                sys.exit(1)
            print(f'Using external mapping file: {mapping_file}')
            transfer_command.execute(
                context=context,
                email=[f'@{mapping_file}'],
                force=force
            )
        else:
            transfer_command.execute(
                context=context,
                email=source_users,
                target_user=target_user,
                force=force
            )
        
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()
