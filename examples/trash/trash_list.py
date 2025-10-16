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
# Example showing how to list and filter records in the trash
# using the Keeper CLI package.
#

import argparse
import json
import os
import sys
from typing import Optional

from keepercli.commands.trash import TrashListCommand
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

def list_trash_records(
    context: KeeperParams,
    show_details: Optional[bool] = None,
    criteria: Optional[str] = None,
    format: str = 'table',
    output_path: Optional[str] = None
):
    """
    List and display records from the Keeper trash with optional filtering.
    
    This function uses the Keeper CLI `TrashListCommand` to retrieve and display
    records based on the provided criteria and filters.
    """
    try:
        list_command = TrashListCommand()

        kwargs = {
            'verbose': show_details,
            'format': format,
            'pattern': criteria,
            'output': output_path,
        }

        list_command.execute(context=context, **kwargs)
        return True
        
    except Exception as e:
        print(f'Error listing trashed records: {str(e)}')
        return False


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='List all trashed records and folders in the trash using Keeper SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python trash_list.py
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
    show_details = None # Display verbose information Boolean flag
    criteria = None # Search pattern
    format = 'table' # Format of output (table, json, csv)
    output_path = None # Path to output file for csv format

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
        list_trash_records(
            context, 
            show_details=show_details,
            criteria=criteria,
            format=format,
            output_path=output_path,
        )
        
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()