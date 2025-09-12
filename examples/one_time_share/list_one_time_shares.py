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
# Example showing how to list one-time shares for a record
# using the Keeper CLI architecture.
#

import argparse
import json
import os
import sys

from keepercli.commands.share_management import OneTimeShareListCommand
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

def execute_one_time_share_list(context: KeeperParams, **kwargs):
    """
    Execute one-time share list command.
    
    This function retrieves and displays one-time shares for a record
    using the Keeper CLI command infrastructure.
    """
    one_time_share_list_command = OneTimeShareListCommand()
    
    try:
        one_time_share_list_command.execute(context=context, **kwargs)
    except Exception as e:
        raise Exception(f'Error: {str(e)}')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='List one-time shares for a record using Keeper SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python list_one_time_shares.py
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

    record_name = "record_name"
    recursive = None
    verbose = None
    show_all = None

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)

    kwargs = {
        'record': record_name,
        'recursive': recursive, # If recursive is sent, it will be considered True regardless of value (True or False), unless set as None
        'verbose': verbose, # If verbose is sent, it will be considered True regardless of value (True or False), unless set as None
        'show_all': show_all # If show_all is sent, it will be considered True regardless of value (True or False), unless set as None
    }

    print(f"Listing one-time shares for record: {record_name}")
    try:
        execute_one_time_share_list(context, **kwargs)
        print(f'One-time shares listed successfully')
        sys.exit(0)
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()
