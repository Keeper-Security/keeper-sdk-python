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
# Example showing how to export data from Keeper vault
# using the Keeper CLI architecture.
#

import argparse
import json
import os
import sys
import logging

from keepercli.commands.importer_commands import ExportCommand
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

def execute_export_data(context: KeeperParams, **kwargs):
    """
    Execute export data command.
    
    This function exports data from the Keeper vault
    using the Keeper CLI command infrastructure.
    """
    export_command = ExportCommand()
    
    try:
        export_command.execute(context=context, **kwargs)
    except Exception as e:
        raise Exception(f'Error: {str(e)}')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Export data from Keeper vault using Keeper SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python export_data.py
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

    # Example parameters - customize these for your export
    export_format = "json"  # Can be csv, json, etc.
    output_file = "exported_vault.json"  # Replace with your desired output file
    
    context = None
    try:
        context = login_to_keeper_with_config(args.config)
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)

    kwargs = {
        'format': export_format,
        'output': output_file,
        'max_size': 100,  # Maximum file size in MB
        'max_records': 10000,  # Maximum number of records
        'regex': None,  # Optional regex filter
        'only_password': False,
        'display': False,
        'title': True,
        'notes': True,
        'custom': True,
        'type': True,
        'folders': True,
        'attachments': False
    }

    print(f"Exporting data to: {output_file}")
    print(f"Export format: {export_format}")
    try:
        execute_export_data(context, **kwargs)
        print('Data export completed successfully')
        sys.exit(0)
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()
