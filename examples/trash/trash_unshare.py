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
# Example showing how to unshare a shared trashed record in the trash
# using the Keeper CLI package.
#

import argparse
import json
import os
import sys
import logging
from typing import Optional

from keepercli.commands.trash import TrashUnshareCommand
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

def unshare_trash_record(
    context: KeeperParams,
    record_uid: str,
    force: Optional[bool] = None,
):
    """
    Unshare a shared trashed record from the Keeper vault trash.
    
    This function uses the Keeper CLI `TrashUnshareCommand` to unshare a shared trashed record
    records based on the provided criteria and filters.
    """
    try:
        unshare_command = TrashUnshareCommand()

        kwargs = {
            'records': [record_uid],
            'force': force,
        }

        unshare_command.execute(context=context, **kwargs)
        return True
        
    except Exception as e:
        print(f'Error unsharing record: {str(e)}')
        return False


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Unshare a shared trashed record from the Keeper vault trash using Keeper CLI package',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python trash_unshare.py
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

    record_uid = 'record_uid' # Record UID to unshare

    # Bool flags can be set to True or None (to be sent as False)
    force = None

    print(f"Note: This example will attempt to unshare a shared trashed record '{record_uid}'")

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
        unshare_trash_record(
            context, 
            record_uid=record_uid,
            force=force,
        )
        
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()