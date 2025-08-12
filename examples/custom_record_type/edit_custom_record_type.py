#!/usr/bin/env python3
#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper SDK for Python
# Copyright 2023 Keeper Security Inc.
# Contact: commander@keepersecurity.com
#
# Example showing how to edit a custom record type
# using the Keeper SDK architecture.
#

import argparse
import json
import os
import sqlite3
import sys

from keepersdk.authentication import login_auth, configuration, endpoint
from keepersdk.vault import sqlite_storage, vault_online, record_type_management

def login_to_keeper_with_config(filename):
    if not os.path.exists(filename):
        raise FileNotFoundError(f'Config file {filename} not found')
    
    with open(filename, 'r') as f:
        config_data = json.load(f)
    
    username = config_data.get('user', config_data.get('username'))
    password = config_data.get('password', '')
    
    if not username:
        raise ValueError('Username not found in config file')
    
    config = configuration.JsonConfigurationStorage()
    keeper_endpoint = endpoint.KeeperEndpoint(config)
    login_auth_instance = login_auth.LoginAuth(keeper_endpoint)
    
    login_auth_instance.login(username=username)
    
    if password:
        login_auth_instance.login_step.verify_password(password)
    
    if isinstance(login_auth_instance.login_step, login_auth.LoginStepConnected):
        keeper_auth = login_auth_instance.login_step.take_keeper_auth()
        
        db_path = config_data.get('db_path', 'keeper.sqlite')
        conn = sqlite3.Connection(f'file:{db_path}', uri=True)
        vault_storage = sqlite_storage.SqliteVaultStorage(
            lambda: conn, 
            vault_owner=bytes(keeper_auth.auth_context.username, 'utf-8')
        )
        
        vault = vault_online.VaultOnline(keeper_auth, vault_storage)
        vault.sync_down(force=True)
        
        return vault
    else:
        raise Exception('Failed to authenticate with Keeper')


def edit_custom_record_type(vault, record_type_id, title=None, fields=None, description=None, categories=None):
    try:
        result = record_type_management.edit_custom_record_types(
            vault, 
            record_type_id,
            title,
            fields, 
            description, 
            categories
        )
        
        print(f'Successfully edited custom record type ID: {record_type_id}')
        if title:
            print(f'Title: {title}')
        if description:
            print(f'Description: {description}')
        if categories:
            print(f'Categories: {", ".join(categories)}')
        print(f'Fields: {", ".join([field.get("$ref", str(field)) for field in fields])}')
        print(f'Result: {result}')
        
        return result
        
    except Exception as e:
        print(f'Error editing custom record type {record_type_id}: {str(e)}')
        return None


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Edit a custom record type using Keeper SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python edit_custom_record_type.py
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

    record_type_id = 24312
    title = "Updated Custom Record Type" # Max 32 characters
    description = "An example custom record type created by the Keeper SDK"
    categories = ["custom", "example"]
    field_names = ["login", "password", "url"]
    fields = [{"$ref": field} for field in field_names if field]
    print(f"Note: This example will attempt to edit record type ID {record_type_id}")
    print("Make sure this ID exists in your vault or update the hard-coded value")

    try:
        vault = login_to_keeper_with_config(args.config)
        edit_custom_record_type(vault, record_type_id, title, fields, description, categories)
        
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)