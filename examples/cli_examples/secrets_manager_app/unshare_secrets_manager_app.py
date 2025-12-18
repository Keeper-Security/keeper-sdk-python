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
# Example showing how to unshare a Secrets Manager application from a user
# using the Keeper SDK architecture.
#

import argparse
import json
import logging
import os
import sys

from keepercli.commands.secrets_manager import SecretsManagerAppCommand
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

    keeper_config = KeeperConfig(config_filename=filename, config=config_data)
    auth = LoginFlow.login(keeper_config)
    if not auth:
        raise Exception('Failed to authenticate with Keeper')

    context = KeeperParams(keeper_config=keeper_config)
    context.set_auth(auth)

    return context


def unshare_secrets_manager_app(
    context: KeeperParams,
    app_id: str,
    user_email: str
):
    """Unshare a Secrets Manager application from a specific user.
    
    This function unshares a Secrets Manager application from a specific user. It first retrieves
    the application details, then unshares it from the specified user.
    """
    try:
        sm_app_command = SecretsManagerAppCommand()
        kwargs = {
            'command': 'unshare',
            'app': app_id,
            'email': user_email
        }
            
        sm_app_command.execute(context=context, **kwargs)
        
        print(f'Successfully unshared from user: {user_email}')

        return True
        
    except Exception as e:
        print(f'Error unsharing Secrets Manager application: {str(e)}')
        return False


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Unshare a Secrets Manager application from a user using Keeper SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python unshare_secrets_manager_app.py
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

    app_id = "RlO6y-idGBqu1Ax2yUYXKw"
    user_email = "example@example.com"

    print(f"Note: This example will attempt to unshare app ID '{app_id}'")

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
        success = unshare_secrets_manager_app(
            context=context,
            app_id=app_id,
            user_email=user_email
        )
        
        if not success:
            sys.exit(1)
        
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()
