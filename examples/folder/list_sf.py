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
# Example showing how to list shared folders in the vault
# using the Keeper CLI package.
#

import argparse
import json
import os
import sys
import logging
from typing import Optional

from keepercli.commands.vault_record import SharedFolderListCommand
from keepercli.params import KeeperParams
from keepercli.login import LoginFlow

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

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

def list_shared_folders(
    context: KeeperParams,
    criteria: Optional[str] = None,
    verbose: Optional[bool] = None,
):
    """
    List shared folders in the Keeper vault.
    
    This function uses the Keeper CLI `SharedFolderListCommand` to retrieve and display
    shared folders.
    """
    try:
        command = SharedFolderListCommand()

        kwargs = {
            'pattern': criteria,
            'verbose': verbose,
        }
        command.execute(context=context, **kwargs)
        return True
        
    except Exception as e:
        logger.error(f'Error listing shared folders: {str(e)}')
        return False


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='List all shared folders in the vault using Keeper SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python list_sf.py
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

    # Bool flags can be set to True or None (to be sent as False)
    criteria = 'folder_title_pattern'
    verbose = None

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
        list_shared_folders(
            context, 
            criteria=criteria,
            verbose=verbose,
        )
        
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()