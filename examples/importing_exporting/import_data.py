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
# Example showing how to import data into Keeper vault
# using the Keeper CLI architecture.
#

import argparse
import json
import os
import sys
import logging

from keepercli.commands.importer_commands import ImportCommand
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

def execute_import_data(context: KeeperParams, **kwargs):
    """
    Execute import data command.
    
    This function imports data into the Keeper vault
    using the Keeper CLI command infrastructure.
    """
    import_command = ImportCommand()
    
    try:
        import_command.execute(context=context, **kwargs)
    except Exception as e:
        raise Exception(f'Error: {str(e)}')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Import data into Keeper vault using Keeper SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python import_data.py
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

    # Example parameters - customize these for your import
    import_source = "csv"  # Can be csv, json, keepass, etc.
    import_file = "import_data.csv"  # Replace with your import file
    
    context = None
    try:
        context = login_to_keeper_with_config(args.config)
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)

    # Flags can be set as None for false and True for true
    kwargs = {
        'source': import_source,
        'name': import_file,
        'display_csv': None,
        'overwrite': None,
        'login_replace': None,
        'ignore_csv': None,
        'skip_errors': None,
        'format': 'json',
        'share_existing': None
    }

    print(f"Importing data from: {import_file}")
    print(f"Source format: {import_source}")
    try:
        execute_import_data(context, **kwargs)
        print('Data import completed successfully')
        sys.exit(0)
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()
