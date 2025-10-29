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
import hashlib
from typing import Optional, Dict, Set, List
from collections import defaultdict

from keepersdk.vault import vault_record
from keepercli.params import KeeperParams
from keepercli.login import LoginFlow
from keepercli.helpers import report_utils

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

def create_record_hash(record, match_fields: Dict[str, bool]) -> str:
    """Create a hash for a record based on the specified match fields."""
    hash_components = []
    
    if match_fields.get('title', False):
        hash_components.append(getattr(record, 'title', '') or '')
    
    if match_fields.get('login', False):
        login = ''
        if isinstance(record, vault_record.PasswordRecord):
            login = getattr(record, 'login', '') or ''
        elif isinstance(record, vault_record.TypedRecord):
            # For typed records, look for login field
            for field in record.fields:
                if field.type == 'login':
                    login = str(field.value[0]) if field.value else ''
                    break
        hash_components.append(login)
    
    if match_fields.get('password', False):
        password = ''
        if isinstance(record, vault_record.PasswordRecord):
            password = getattr(record, 'password', '') or ''
        elif isinstance(record, vault_record.TypedRecord):
            # For typed records, look for password field
            for field in record.fields:
                if field.type == 'password':
                    password = str(field.value[0]) if field.value else ''
                    break
        hash_components.append(password)
    
    if match_fields.get('url', False):
        url = ''
        if isinstance(record, vault_record.PasswordRecord):
            url = getattr(record, 'link', '') or ''
        elif isinstance(record, vault_record.TypedRecord):
            # For typed records, look for url field
            for field in record.fields:
                if field.type == 'url':
                    url = str(field.value[0]) if field.value else ''
                    break
        hash_components.append(url)
    
    # Join all components and create hash
    to_hash = '|'.join(hash_components)
    if not to_hash.strip('|'):  # If all components are empty, return empty hash
        return ''
    
    h = hashlib.sha256()
    h.update(to_hash.encode('utf-8'))
    return h.hexdigest()

def find_duplicate_records(
    context: KeeperParams,
    match_by_title: bool = False,
    match_by_login: bool = False,
    match_by_password: bool = False,
    match_by_url: bool = False,
    match_by_shares: bool = False,
    match_full: bool = False,
    quiet: bool = False,
    output_format: str = 'table'
):
    """
    Find duplicate records in the vault based on specified criteria.
    
    This function uses Keeper SDK functions directly to identify
    duplicate records based on various field combinations.
    """
    try:
        vault = context.vault
        if not vault:
            raise Exception('Vault is not initialized')

        # Determine match fields
        match_fields = {
            'title': match_by_title or match_full,
            'login': match_by_login or match_full,
            'password': match_by_password or match_full,
            'url': match_by_url or match_full,
            'shares': match_by_shares or match_full
        }

        print('Finding duplicate records...')
        criteria_list = [k for k, v in match_fields.items() if v and k != 'shares']  # Note: shares matching not fully implemented
        print(f'Match criteria: {", ".join(criteria_list)}')
        
        if match_fields.get('shares', False):
            print('Note: Share-based matching is not fully implemented in this example')

        # Build hash table of records
        record_hashes: Dict[str, List[str]] = defaultdict(list)
        total_records = 0
        processed_records = 0

        for record_uid in vault.vault_data._records:
            total_records += 1
            try:
                record = vault.vault_data.load_record(record_uid)
                if not record or not isinstance(record, (vault_record.PasswordRecord, vault_record.TypedRecord)):
                    continue

                record_hash = create_record_hash(record, match_fields)
                if record_hash:  # Only add if hash is not empty
                    record_hashes[record_hash].append(record_uid)
                    processed_records += 1

            except Exception as e:
                if not quiet:
                    print(f'Warning: Could not process record {record_uid}: {str(e)}')
                continue

        # Find duplicates (hash groups with more than 1 record)
        duplicate_groups = [(hash_val, uids) for hash_val, uids in record_hashes.items() if len(uids) > 1]

        print(f'Processed {processed_records} of {total_records} records')
        
        if not duplicate_groups:
            print('No duplicate records found.')
            return True

        print(f'Found {len(duplicate_groups)} duplicate groups with {sum(len(uids) for _, uids in duplicate_groups)} total records')

        # Display results
        if output_format == 'table':
            display_duplicates_table(vault, duplicate_groups)
        elif output_format == 'json':
            display_duplicates_json(vault, duplicate_groups)
        elif output_format == 'csv':
            display_duplicates_csv(vault, duplicate_groups)

        print('\nFind duplicate operation completed successfully')
        return True
        
    except Exception as e:
        print(f'Error finding duplicate records: {str(e)}')
        return False

def display_duplicates_table(vault, duplicate_groups):
    """Display duplicates in table format."""
    print('\nDuplicate Records Found:')
    print('=' * 80)
    
    for i, (hash_val, record_uids) in enumerate(duplicate_groups, 1):
        print(f'\nDuplicate Group {i} ({len(record_uids)} records):')
        print('-' * 60)
        
        table_data = []
        headers = ['Record UID', 'Title', 'Login', 'URL', 'Type']
        
        for record_uid in record_uids:
            try:
                record = vault.vault_data.load_record(record_uid)
                title = getattr(record, 'title', '') or 'N/A'
                login = 'N/A'
                url = 'N/A'
                record_type = type(record).__name__
                
                if isinstance(record, vault_record.PasswordRecord):
                    login = getattr(record, 'login', '') or 'N/A'
                    url = getattr(record, 'link', '') or 'N/A'
                elif isinstance(record, vault_record.TypedRecord):
                    # Extract login and URL from typed record fields
                    for field in record.fields:
                        if field.type == 'login' and field.value:
                            login = str(field.value[0])
                        elif field.type == 'url' and field.value:
                            url = str(field.value[0])
                
                # Truncate long values for display
                title = title[:30] + '...' if len(title) > 30 else title
                login = login[:20] + '...' if len(login) > 20 else login
                url = url[:30] + '...' if len(url) > 30 else url
                
                table_data.append([record_uid[:8] + '...', title, login, url, record_type])
                
            except Exception as e:
                table_data.append([record_uid[:8] + '...', 'Error loading', str(e)[:20], '', 'Unknown'])
        
        report_utils.dump_report_data(table_data, headers=headers, fmt='table')

def display_duplicates_json(vault, duplicate_groups):
    """Display duplicates in JSON format."""
    result = []
    
    for hash_val, record_uids in duplicate_groups:
        group = {
            'hash': hash_val,
            'count': len(record_uids),
            'records': []
        }
        
        for record_uid in record_uids:
            try:
                record = vault.vault_data.load_record(record_uid)
                record_info = {
                    'uid': record_uid,
                    'title': getattr(record, 'title', '') or '',
                    'type': type(record).__name__
                }
                
                if isinstance(record, vault_record.PasswordRecord):
                    record_info['login'] = getattr(record, 'login', '') or ''
                    record_info['url'] = getattr(record, 'link', '') or ''
                
                group['records'].append(record_info)
                
            except Exception as e:
                group['records'].append({
                    'uid': record_uid,
                    'error': str(e)
                })
        
        result.append(group)
    
    print(json.dumps(result, indent=2))

def display_duplicates_csv(vault, duplicate_groups):
    """Display duplicates in CSV format."""
    print('Group,Record_UID,Title,Login,URL,Type')
    
    for group_num, (hash_val, record_uids) in enumerate(duplicate_groups, 1):
        for record_uid in record_uids:
            try:
                record = vault.vault_data.load_record(record_uid)
                title = (getattr(record, 'title', '') or '').replace(',', ';')
                login = 'N/A'
                url = 'N/A'
                record_type = type(record).__name__
                
                if isinstance(record, vault_record.PasswordRecord):
                    login = (getattr(record, 'login', '') or '').replace(',', ';')
                    url = (getattr(record, 'link', '') or '').replace(',', ';')
                
                print(f'{group_num},{record_uid},{title},{login},{url},{record_type}')
                
            except Exception as e:
                print(f'{group_num},{record_uid},Error loading,{str(e).replace(",", ";")},,')


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
    match_by_title = True  # Match duplicates by title
    match_by_login = False  # Match duplicates by login
    match_by_password = False  # Match duplicates by password
    match_by_url = False  # Match duplicates by URL
    match_by_shares = False  # Match duplicates by share permissions
    match_full = False  # Match duplicates by all fields (overrides individual settings)
    output_format = 'table'  # Options: 'table', 'csv', 'json'
    quiet = False  # Set to True to suppress warning messages during processing

    # Validate arguments
    if not any([match_by_title, match_by_login, match_by_password, match_by_url, match_by_shares, match_full]):
        print('Error: At least one match criterion must be enabled (match_by_title, match_by_login, match_by_password, match_by_url, match_by_shares, or match_full)')
        sys.exit(1)

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
            output_format=output_format
        )
        
        if not success:
            sys.exit(1)
        
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()
