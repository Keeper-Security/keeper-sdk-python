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
# Example showing how to list ownerless records in the Keeper vault and optionally claim them
# using the Keeper CLI package.
#

import argparse
import json
import os
import sys
import logging
from typing import Optional

from keepercli.commands.register import FindOwnerlessCommand
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

def find_ownerless(
    context: KeeperParams,
    claim: Optional[bool] = None,
    folder: Optional[str] = None,
    verbose: Optional[bool] = None,
):
    """
    List ownerless records in the Keeper vault and optionally claim them.
    
    This function uses the Keeper CLI `FindOwnerlessCommand` to retrieve and display
    ownerless records in the Keeper vault and optionally claim them.
    """
    try:
        command = FindOwnerlessCommand()

        kwargs = {
            'claim': claim,
            'folder': folder,
            'verbose': verbose,
        }
        command.execute(context=context, **kwargs)
        return True
        
    except Exception as e:
        logger.error(f'Error listing ownerless records: {str(e)}')
        return False


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='List ownerless records in the Keeper vault and optionally claim them',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python find_ownerless.py
        '''
    )
    
    parser.add_argument(
        '-c', '--config',
        default='myconfig.json',
        help='Configuration file (default: myconfig.json)'
    )

    args = parser.parse_args()

    if not os.path.exists(args.config):
        logger.error(f'Config file {args.config} not found')
        sys.exit(1)

    # Bool flags can be set to True or None (to be sent as False)
    claim = None # Claim the ownerless records Boolean flag
    folder = None # Folder path or UID
    verbose = None # Display verbose information Boolean flag   

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
        find_ownerless(
            context,
            claim=claim,
            folder=folder,
            verbose=verbose,
        )
        
    except Exception as e:
        logger.error(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()