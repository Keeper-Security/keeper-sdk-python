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
# Example showing how to find duplicate records in the vault
# using the Keeper SDK functions directly.
#

import argparse
import json
import os
import sys
import logging
from typing import Optional

from keepercli.params import KeeperParams
from keepercli.login import LoginFlow
from keepercli.commands.record_handling_commands import FindDuplicateCommand

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

def find_duplicate_records(
    context: KeeperParams,
    match_by_title: Optional[bool] = None,
    match_by_login: Optional[bool] = None,
    match_by_password: Optional[bool] = None,
    match_by_url: Optional[bool] = None,
    match_by_shares: Optional[bool] = None,
    match_full: Optional[bool] = None,
    quiet: Optional[bool] = None,
    output_format: Optional[str] = None,
    merge: Optional[bool] = None,
    ignore_shares_on_merge: Optional[bool] = None,
    force: Optional[bool] = None,
    dry_run: Optional[bool] = None,
    scope: Optional[str] = None,
    refresh_data: Optional[bool] = None,
    output: Optional[str] = None
):
    """
    Find duplicate records in the vault based on specified criteria using
    the Keeper CLI FindDuplicateCommand implementation.
    """
    try:
        if not context.vault:
            raise Exception('Vault is not initialized')

        print('Finding duplicate records via FindDuplicateCommand...')

        
        kwargs = {
            'title': match_by_title,
            'login': match_by_login,
            'password': match_by_password,
            'url': match_by_url,
            'shares': match_by_shares,
            'full': match_full,
            'merge': merge,
            'ignore_shares_on_merge': ignore_shares_on_merge,
            'force': force,
            'dry_run': dry_run,
            'quiet': quiet,
            'scope': scope,
            'refresh_data': refresh_data,
            'format': output_format,
            'output': output,
        }

        cmd = FindDuplicateCommand()
        cmd.execute(context, **kwargs)
        print('\nFind duplicate operation completed successfully')
        return True

    except Exception as e:
        print(f'Error finding duplicate records: {str(e)}')
        return False


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Find duplicate records in the vault using Keeper SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python find_duplicate.py
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

    # Configuration constants - modify these values as needed
    # Boolean flags can be set to True or None (to be sent as False)
    match_by_title = True  # Match duplicates by title
    match_by_login = None  # Match duplicates by login
    match_by_password = None  # Match duplicates by password
    match_by_url = None  # Match duplicates by URL
    match_by_shares = None  # Match duplicates by share permissions
    match_full = None  # Match duplicates by all fields (overrides individual settings)
    output_format = None  # Options: 'table', 'csv', 'json'
    quiet = None  # Set to True to suppress warning messages during processing
    merge = None  # Set to True to merge duplicates
    ignore_shares_on_merge = None  # Set to True to ignore share permissions when merging duplicates
    force = None  # Set to True to force the operation
    dry_run = None  # Set to True to simulate the operation
    scope = None  # Set the scope of the search
    refresh_data = None  # Set to True to refresh the data
    output = None  # Set the output format

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
        success = find_duplicate_records(
            context=context,
            match_by_title=match_by_title,
            match_by_login=match_by_login,
            match_by_password=match_by_password,
            match_by_url=match_by_url,
            match_by_shares=match_by_shares,
            match_full=match_full,
            quiet=quiet,
            output_format=output_format,
            merge=merge,
            ignore_shares_on_merge=ignore_shares_on_merge,
            force=force,
            dry_run=dry_run,
            scope=scope,
            refresh_data=refresh_data,
            output=output,
        )
        
        if not success:
            sys.exit(1)
        
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()
