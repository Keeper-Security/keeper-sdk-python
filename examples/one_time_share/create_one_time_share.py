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
# Example showing how to create a one-time share URL for a record
# using the Keeper CLI architecture.
#

import argparse
import json
import os
import sys

from keepercli.commands.share_management import OneTimeShareCreateCommand
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

def execute_one_time_share_create(context: KeeperParams, **kwargs):
    """
    Execute one-time share create command.
    
    This function creates a one-time share URL for a record
    using the Keeper CLI command infrastructure.
    """
    one_time_share_create_command = OneTimeShareCreateCommand()
    
    try:
        one_time_share_create_command.execute(context=context, **kwargs)
    except Exception as e:
        raise Exception(f'Error: {str(e)}')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Create a one-time share URL for a record using Keeper SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python create_one_time_share.py
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
    expire_time = "1h"
    share_name = "share_name"
    output_destination = "stdout"
    is_editable = True

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)

    kwargs = {
        'record': record_name,
        'expire': expire_time,
        'share_name': share_name,
        'output': output_destination,
        'is_editable': is_editable # If is_editable is sent, it will be considered True regardless of value, unless set as None
    }

    print(f"Creating one-time share for record: {record_name}")
    print(f"Expiration: {expire_time}, Name: {share_name}, Editable: {is_editable}")
    
    try:
        execute_one_time_share_create(context, **kwargs)
        print(f'One-time share URL created successfully')
        sys.exit(0)
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()
