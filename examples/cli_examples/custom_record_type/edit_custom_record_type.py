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
# Example showing how to edit a custom record type
# using the Keeper SDK architecture.
#

import argparse
import json
import logging
import os
import sys

from typing import Optional, Dict, Any, List

from keepersdk.vault import record_type_management, vault_online
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

    keeper_config = KeeperConfig(config_filename=filename, config=config_data)
    auth = LoginFlow.login(keeper_config)
    if not auth:
        raise Exception('Failed to authenticate with Keeper')

    context = KeeperParams(keeper_config=keeper_config)
    context.set_auth(auth)

    return context


def edit_custom_record_type(
    vault: vault_online.VaultOnline,
    record_type_id: int,
    title: Optional[str] = None,
    fields: Optional[List[Dict[str, Any]]] = None,
    description: Optional[str] = None,
    categories: Optional[List[str]] = None
):
    """
    Edit an existing custom record type in the Keeper vault.

    This function updates a custom record type identified by its ID. You can
    update the title, description, categories, and field definitions. Field
    definitions should be provided as a list of objects containing a "$ref"
    key that points to a valid record field name.
    """
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

    record_type_id = 24356
    title = "Updated Custom Record New" # Max 32 characters
    description = "An example custom record type created by the Keeper SDK"
    categories = ["custom", "example"]
    field_names = ["login", "password", "url"] # For valid fields refer to record_types.FieldTypes and record_types.RecordFields in keepersdk.vault
    fields = [{"$ref": field} for field in field_names if field]
    print(f"Note: This example will attempt to edit record type ID {record_type_id}")

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
        edit_custom_record_type(context.vault, record_type_id, title, fields, description, categories)
        
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()
