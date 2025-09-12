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
# Example showing how to list breached passwords
# using the Keeper CLI architecture.
#

import argparse
import json
import os
import sys
import logging

from keepercli.commands.breachwatch import BreachWatchListCommand
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

def execute_breachwatch_list(context: KeeperParams, **kwargs):
    """
    Execute breachwatch list command.
    
    This function lists all breached passwords in the vault
    using the Keeper CLI command infrastructure.
    """
    breachwatch_list_command = BreachWatchListCommand()
    
    try:
        breachwatch_list_command.execute(context=context, **kwargs)
    except Exception as e:
        raise Exception(f'Error: {str(e)}')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='List breached passwords using Keeper SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python breachwatch_list.py
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

    # Set all flags as either True for setting or None for False
    show_all = True
    owned_only = None
    numbered = True

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)

    kwargs = {
        'all': show_all,
        'owned': owned_only,
        'numbered': numbered
    }

    print("Listing all breached passwords...")
    try:
        execute_breachwatch_list(context, **kwargs)
        print('Breach watch list completed successfully')
        sys.exit(0)
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()
