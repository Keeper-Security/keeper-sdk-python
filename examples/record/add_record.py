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
# Example showing how to add a new record to the vault
# using the Keeper SDK architecture.
#

import argparse
import json
import os
import sys
from typing import Optional

from keepersdk.vault import vault_record, record_management, vault_online
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

def add_record(
    vault: vault_online.VaultOnline, 
    title: str, 
    login: str, 
    password: str, 
    url: Optional[str] = None, 
    notes: Optional[str] = None, 
    folder_uid: Optional[str] = None
):
    """
    Add a new password record to the Keeper vault.
    
    This function creates a new password record with the specified credentials
    and adds it to the vault. The record can optionally be placed in a specific
    folder and include additional metadata like URL and notes.
    """
    try:
        record = vault_record.PasswordRecord()
        record.title = title
        record.login = login
        record.password = password
        
        if url:
            record.link = url
        if notes:
            record.notes = notes
        
        result = record_management.add_record_to_folder(vault, record, folder_uid)
        
        print(f'Successfully added record: {title}')
        print(f'Record UID: {result}')
        print(f'Login: {login}')
        print(f'URL: {url or "N/A"}')
        print(f'Notes: {notes or "N/A"}')
        if folder_uid:
            print(f'Folder UID: {folder_uid}')
        
        return result
        
    except Exception as e:
        print(f'Error adding record {title}: {str(e)}')
        return None


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Add a new record to the vault using Keeper SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python add_record.py
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

    title = "Test Record 1"
    login = "example@example.com"
    password = "ExamplePassword123!"
    url = "https://example.com"
    notes = "This is an example record created by the Keeper SDK"
    folder_uid = None

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
        add_record(context.vault, title, login, password, url, notes, folder_uid)
        
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()