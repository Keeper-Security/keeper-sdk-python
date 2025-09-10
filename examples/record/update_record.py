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
# Example showing how to update an existing record in the vault
# using the Keeper SDK architecture with record_management.update_record.
#

import argparse
import json
import os
import sys
from typing import Optional, Dict, Any

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

def find_record_by_criteria(
    vault: vault_online.VaultOnline, 
    criteria: str, 
    record_type: Optional[str] = None, 
    record_version: Optional[int] = None
):
    """
    Find a record by various criteria including UID, title, or search terms.
    
    This function searches for records using multiple methods:
    1. Direct UID lookup
    2. Search by criteria with optional type/version filters
    3. Interactive selection if multiple matches 
    """
    record_info = vault.vault_data.get_record(criteria)
    if record_info:
        return record_info
    
    records = list(vault.vault_data.find_records(criteria=criteria, record_type=record_type, record_version=record_version))
    
    if not records:
        return None
    elif len(records) == 1:
        return records[0]
    else:
        print(f'Found {len(records)} records matching "{criteria}":')
        for i, record in enumerate(records, 1):
            print(f'{i}. {record.title} ({record.record_uid})')
        
        while True:
            try:
                choice = int(input('Select a record (number): ')) - 1
                if 0 <= choice < len(records):
                    return records[choice]
                else:
                    print('Invalid choice. Please try again.')
            except ValueError:
                print('Please enter a valid number.')


def update_password_record(
    vault: vault_online.VaultOnline, 
    record_uid: str, 
    updates: Dict[str, str]
):
    """
    Update a password record with new field values.
    
    This function loads a password record and updates its fields with the
    provided values. It validates that the record is indeed a password record
    and provides detailed feedback about the changes being made.
    """
    record = vault.vault_data.load_record(record_uid)
    if not isinstance(record, vault_record.PasswordRecord):
        raise ValueError(f'Record {record_uid} is not a password record')
    
    print(f'Updating password record: {record.title}')
    
    if 'title' in updates:
        print(f'  Title: "{record.title}" -> "{updates["title"]}"')
        record.title = updates['title']
    
    if 'login' in updates:
        print(f'  Username: "{record.login or ""}" -> "{updates["login"]}"')
        record.login = updates['login']
    
    if 'password' in updates:
        print(f'  Password: {"*" * len(record.password or "")} -> {"*" * len(updates["password"])}')
        record.password = updates['password']
    
    if 'link' in updates:
        print(f'  URL: "{record.link or ""}" -> "{updates["link"]}"')
        record.link = updates['link']
    
    if 'notes' in updates:
        notes_preview = (record.notes[:50] + '...') if record.notes and len(record.notes) > 50 else (record.notes or '')
        new_notes_preview = (updates['notes'][:50] + '...') if len(updates['notes']) > 50 else updates['notes']
        print(f'  Notes: "{notes_preview}" -> "{new_notes_preview}"')
        record.notes = updates['notes']
    
    return record


def update_typed_record(
    vault: vault_online.VaultOnline, 
    record_uid: str, 
    updates: Dict[str, Any]
):
    """
    Update a typed record with new field values.
    
    This function loads a typed record (v3 record format) and updates its
    fields with the provided values. It handles the complex field structure
    of typed records and provides detailed feedback about changes.
    """
    record = vault.vault_data.load_record(record_uid)
    if not isinstance(record, vault_record.TypedRecord):
        raise ValueError(f'Record {record_uid} is not a typed record')
    
    print(f'Updating typed record: {record.title} (type: {record.record_type})')
    
    if 'title' in updates:
        print(f'  Title: "{record.title}" -> "{updates["title"]}"')
        record.title = updates['title']
    
    if 'notes' in updates:
        notes_preview = (record.notes[:50] + '...') if record.notes and len(record.notes) > 50 else (record.notes or '')
        new_notes_preview = (updates['notes'][:50] + '...') if len(updates['notes']) > 50 else updates['notes']
        print(f'  Notes: "{notes_preview}" -> "{new_notes_preview}"')
        record.notes = updates['notes']
    
    for field_name, field_value in updates.items():
        if field_name in ('title', 'notes'):
            continue
            
        field_found = False
        for field in record.fields:
            if field.type == field_name:
                if hasattr(field, 'value') and field.value:
                    old_value = field.value[0] if isinstance(field.value, list) and field.value else field.value
                    print(f'  {field_name}: "{old_value}" -> "{field_value}"')
                    field.value = [field_value] if isinstance(field.value, list) else field_value
                    field_found = True
                    break
        
        if not field_found:
            print(f'  Warning: Field "{field_name}" not found in record')
    
    return record


def update_record(vault: vault_online.VaultOnline, record_criteria: str, updates: Dict[str, Any], record_type: Optional[str] = None, record_version: Optional[int] = None):
    """
    Update an existing record in the vault.
    
    This function finds a record by criteria, updates its fields, and saves the changes.
    It supports both password and typed record formats.
    """
    try:
        record_info = find_record_by_criteria(vault, record_criteria, record_type=record_type, record_version=record_version)
        if not record_info:
            print(f'No record found matching "{record_criteria}"')
            return False
        
        print(f'Found record: {record_info.title} ({record_info.record_uid})')
        
        if record_info.version == 2:
            updated_record = update_password_record(vault, record_info.record_uid, updates)
        elif record_info.version == 3:
            updated_record = update_typed_record(vault, record_info.record_uid, updates)
        else:
            raise ValueError(f'Unsupported record version: {record_info.version}')
        
        print('\nSaving changes...')
        record_management.update_record(vault, updated_record)
        
        vault.sync_down()
        
        print(f'Successfully updated record: {updated_record.title}')
        return True
        
    except Exception as e:
        print(f'Error updating record: {str(e)}')
        return False


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Update an existing record in the vault using Keeper SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python update_record.py
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

    record_to_update_uid = "UkezdUGQoTOztfi5cGFJnQ"
    record_type = None
    record_version = None
    updates = {
        'title': 'Updated Example Record',
        'login': 'updated@example.com',
        'password': 'UpdatedPassword123!',
        'link': 'https://updated-example.com',
        'notes': 'This record has been updated by the Keeper SDK example'
    }

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
        success = update_record(context.vault, record_to_update_uid, updates, record_type=record_type, record_version=record_version)
        
        if success:
            print('\nRecord update completed successfully!')
        else:
            sys.exit(1)
        
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()