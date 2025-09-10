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
# Example showing how to delete a record from the vault
# using the Keeper SDK architecture.
#

import argparse
import json
import os
import sys
from typing import Optional

from keepersdk.vault import vault_types, record_management, vault_online
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

def delete_record(vault: vault_online.VaultOnline, record_uid: str, force: bool = False):
    """
    Delete a record from the Keeper vault.
    
    This function locates a record by its UID and removes it from the vault.
    If force is False, it will prompt for confirmation before deletion.
    """
    try:
        record = vault.vault_data.get_record(record_uid)
        if not record:
            print(f"Record with UID '{record_uid}' not found.")
            return False
        
        print(f"Found record: '{record.title}'")
        
        record_path = vault_types.RecordPath(record_uid=record_uid, folder_uid='')
        
        def confirm_deletion(summary: str) -> bool:
            if force:
                return True
            print("Deletion Summary:")
            print(summary)
            response = input("Proceed with deletion? (y/n): ").lower()
            return response in ['y', 'yes']
        
        record_management.delete_vault_objects(vault, [record_path], confirm=confirm_deletion)
        print(f'Successfully deleted record: {record.title} ({record_uid})')
        return True
        
    except Exception as e:
        print(f'Error deleting record {record_uid}: {str(e)}')
        return False


def find_record_by_title(vault: vault_online.VaultOnline, title: str) -> Optional[str]:
    """
    Find a record's UID by searching for its title.
    
    Performs a case-insensitive search through all records in the vault
    to find one with a matching title.
    """
    try:
        for record in vault.vault_data.records():
            if record.title.lower() == title.lower():
                return record.record_uid
        return None
    except Exception as e:
        print(f'Error searching for record: {str(e)}')
        return None


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Delete a record from the vault using Keeper SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python delete_record.py
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

    title_to_delete = "Test Record 1"
    force_delete = True

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
        vault = context.vault
        record_uid = find_record_by_title(vault, title_to_delete)
        if not record_uid:
            print(f"No record found with title: '{title_to_delete}'")
            print(f"Note: This example looks for a record titled '{title_to_delete}'")
            print("You can create one first using the add_record.py example.")
            sys.exit(1)

        success = delete_record(vault, record_uid, force_delete)
        
        if not success:
            sys.exit(1)
        
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()