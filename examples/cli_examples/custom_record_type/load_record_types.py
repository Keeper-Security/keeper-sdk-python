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
# Example showing how to load custom record types from a JSON file
# using the Keeper SDK architecture.
#

import argparse
import json
import os
import sys
import logging

from keepercli.commands.record_type import LoadRecordTypesCommand
from keepercli.params import KeeperParams, KeeperConfig
from keepercli.login import LoginFlow


logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)


def get_default_config_path() -> str:
    """
    Get the default config file path following the same logic as JsonFileLoader.
    
    First checks if 'config.json' exists in the current directory.
    If not, uses ~/.keeper/config.json.
    """
    file_name = 'config.json'
    if os.path.isfile(file_name):
        return os.path.abspath(file_name)
    else:
        keeper_dir = os.path.join(os.path.expanduser('~'), '.keeper')
        if not os.path.exists(keeper_dir):
            os.mkdir(keeper_dir)
        return os.path.join(keeper_dir, file_name)
        

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

    keeper_config = KeeperConfig(config_filename=filename, config=config_data)
    auth = LoginFlow.login(keeper_config, username=username, password=password or None, resume_session=bool(username))
    if not auth:
        raise Exception('Failed to authenticate with Keeper')

    context = KeeperParams(keeper_config=keeper_config)
    context.set_auth(auth)

    return context


def load_record_types(context: KeeperParams, **kwargs):
    """
    Load custom record types from a JSON file.
    
    This function loads custom record types from a JSON file and imports them
    into the vault using the CLI command infrastructure.
    """
    try:
        if not os.path.exists(kwargs['file']):
            print(f'Input file {kwargs["file"]} not found')
            return False
        
        load_command = LoadRecordTypesCommand()
        
        load_command.execute(context=context, **kwargs)
        
        print(f'Successfully loaded record types from: {kwargs["file"]}')
        return True
        
    except Exception as e:
        print(f'Error loading record types: {str(e)}')
        return False


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Load custom record types from JSON file using Keeper SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python load_record_types.py
        '''
    )
    
    default_config_path = get_default_config_path()
    parser.add_argument(
        '-c', '--config',
        default=default_config_path,
        help=f'Configuration file (default: {default_config_path})'
    )

    args = parser.parse_args()

    if not os.path.exists(args.config):
        print(f'Config file {args.config} not found')
        sys.exit(1)

    json_file = 'record_types.json'

    if not os.path.exists(json_file):
        print(f'JSON file {json_file} not found')
        print("You can create one first using the download_record_types.py example.")
        sys.exit(1)

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
        kwargs = {
            'file': json_file
        }
        success = load_record_types(context, **kwargs)
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()
