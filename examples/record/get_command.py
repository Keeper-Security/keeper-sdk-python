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
# Example showing how to get record details
# using the RecordGetCommand from the CLI package.
#

import argparse
import json
import os
import sys
import logging

from keepercli.commands.record_edit import RecordGetCommand
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

def get(
    context: KeeperParams,
    uid: str,
):
    """
    Get detailed information about a record/folder/team.
    
    This function retrieves and displays detailed information about a record/folder/team
    using the CLI command infrastructure. It supports different output formats
    and can optionally unmask sensitive data.
    """
    try:
        get_command = RecordGetCommand()
        kwargs = {
            'uid': uid, # 'team'/'folder'/'record' can be used to specify type and will replace uid
        }
        get_command.execute(context=context, **kwargs)
        print('Details retrieved successfully!')
        return True
        
    except Exception as e:
        print(f'Error getting record/folder/team details: {str(e)}')
        return False

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Get record/folder/team details using Keeper SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python get_command.py
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

    uid = "record_uid"  # Replace with actual record/folder/team UID or path or title
    
    print(f"Note: This example will attempt to get details for record/folder/team '{uid}'")

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
        success = get(
            context=context,
            uid=uid,
        )
        
        if not success:
            sys.exit(1)
        
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()