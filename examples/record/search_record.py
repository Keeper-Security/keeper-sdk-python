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
# Example showing how to get records which match a search pattern
# using the find_records function from the Keeper SDK.

import argparse
import json
import os
import sys
import logging
from typing import Optional

from keepersdk.vault import vault_online
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

def search(
    vault: vault_online.VaultOnline,
    pattern: str,
    record_type: Optional[str] = None,
    record_version: Optional[int] = None,
):
    """
    Search for records which match the search pattern.
    
    This function retrieves a list of records which match the search pattern.
    using the Keeper SDK function.
    """
    try:
        records = vault.vault_data.find_records(criteria=pattern, record_type=record_type, record_version=record_version)
        print(f'Found {len(records)} records')
        for record in records:
            print(f'{record.title} ({record.record_uid}) {record.record_type} {record.record_version}')
        return True
    except Exception as e:
        print(f'Error searching for records: {str(e)}')
        return False

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Search for records using Keeper SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python search_record.py
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

    pattern = "record_pattern"  # Title, uid, path, or pattern
    record_type = "record_type"  # record_type
    record_version = "record_version"  # record_version int value

    print(f"Note: This example will attempt to search for records matching '{pattern}'")

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
        success = search(
            vault=context.vault,
            pattern=pattern,
            record_type=record_type,
            record_version=record_version,
        )
        
        if not success:
            sys.exit(1)
        
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()