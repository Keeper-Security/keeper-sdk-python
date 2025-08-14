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
# Example showing how to create a custom record type
# using the Keeper SDK architecture.
#

import argparse
import json
import os
import sys
from typing import Optional, List, Dict, Any

from keepersdk.vault import record_type_management, vault_online
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

def create_custom_record_type(
    vault: vault_online.VaultOnline,
    record_type_title: str,
    description: Optional[str] = None,
    categories: Optional[List[str]] = None,
    fields: Optional[List[Dict[str, Any]]] = None
):
    """
    Create a new custom record type in the Keeper vault.
    
    This function creates a custom record type with the specified title,
    description, categories, and field definitions.
    """
    if description is None:
        description = f"Custom record type: {record_type_title}"
    
    if categories is None:
        categories = ["custom", "example"]
    
    try:
        result = record_type_management.create_custom_record_type(
            vault,
            record_type_title, 
            fields, 
            description, 
            categories=categories
        )
        
        print(f'Successfully created custom record type: {record_type_title}')
        print(f'Description: {description}')
        print(f'Categories: {", ".join(categories)}')
        print(f'Fields: {", ".join([field.get("$ref", str(field)) for field in fields])}')
        print(f'Result: {result}')
        
        return result
        
    except Exception as e:
        print(f'Error creating custom record type {record_type_title}: {str(e)}')
        return None


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Create a custom record type using Keeper SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python create_custom_record_type.py
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

    record_type_title = "New Custom Record Type" # Max 32 characters
    description = "An example custom record type created by the Keeper SDK"
    categories = ["custom", "example"]
    field_names = ["login", "password", "url"]
    fields = [{"$ref": field} for field in field_names if field]

    try:
        vault = login_to_keeper_with_config(args.config).vault
        create_custom_record_type(vault, record_type_title, description, categories, fields)
        
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)
