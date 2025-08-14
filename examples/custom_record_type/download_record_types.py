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
# Example showing how to download custom record types to a JSON file
# using the Keeper SDK architecture.
#

import argparse
import json
import os
import sys

from keepercli.commands.record_type import DownloadRecordTypesCommand
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
    
def download_record_types(context: KeeperParams, **kwargs):
    """
    Download custom record types to a JSON file.
    
    This function downloads all custom record types from the vault and saves them
    to a JSON file using the CLI command infrastructure.
    """
    try:
        download_command = DownloadRecordTypesCommand()
        
        if not kwargs["source"]:
            kwargs["source"] = "keeper"

        if not kwargs["name"]:
            kwargs["name"] = "record_types.json"

        download_command.execute(context=context, **kwargs)
        
        print(f'Successfully downloaded record types to: {kwargs["name"]}')
        return True
        
    except Exception as e:
        print(f'Error downloading record types: {str(e)}')
        return False

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Download custom record types to a JSON file using Keeper CLI',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python download_record_types.py
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

    try:
        context = login_to_keeper_with_config(args.config)

        kwargs = {
            'source': 'keeper',
            'name': 'record_types.json'
        }

        success = download_record_types(context, **kwargs)
        
        if not success:
            sys.exit(1)
        
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)