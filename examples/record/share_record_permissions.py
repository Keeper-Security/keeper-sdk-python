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
# Example showing how to manage record sharing permissions
# using the Keeper CLI architecture.
#

import argparse
import json
import os
import sys
import logging
from typing import Optional, List

from keepercli.commands.share_management import ShareRecordCommand
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

def manage_record_permissions(
    context: KeeperParams,
    record_uid_or_title: str,
    email_addresses: List[str],
    action: str = 'grant',
    can_edit: bool = False,
    can_share: bool = False,
    contacts_only: bool = False,
    force: bool = False,
    dry_run: bool = False,
    recursive: bool = False,
    expire_at: Optional[str] = None,
    expire_in: Optional[str] = None
):
    """
    Manage record sharing permissions.
    
    This function changes the sharing permissions of an individual record
    using the Keeper CLI `ShareRecordCommand`.
    """
    try:
        share_command = ShareRecordCommand()

        kwargs = {
            'record': record_uid_or_title,
            'email': email_addresses,
            'action': action,
            'can_edit': can_edit,
            'can_share': can_share,
            'contacts_only': contacts_only,
            'force': force,
            'dry_run': dry_run,
            'recursive': recursive
        }
        
        if expire_at:
            kwargs['expire_at'] = expire_at
        if expire_in:
            kwargs['expire_in'] = expire_in

        print(f'Managing record permissions...')
        print(f'Record: {record_uid_or_title}')
        print(f'Email addresses: {", ".join(email_addresses)}')
        print(f'Action: {action}')
        print(f'Can edit: {can_edit}')
        print(f'Can share: {can_share}')
        print(f'Contacts only: {contacts_only}')
        print(f'Force: {force}')
        print(f'Dry run: {dry_run}')
        print(f'Recursive: {recursive}')
        
        if expire_at:
            print(f'Expire at: {expire_at}')
        if expire_in:
            print(f'Expire in: {expire_in}')
        
        if dry_run:
            print('\nDRY RUN MODE: No changes will be made')

        share_command.execute(context=context, **kwargs)
        
        print(f'\nRecord permission operation completed successfully!')
        return True
        
    except Exception as e:
        print(f'Error managing record permissions: {str(e)}')
        return False


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Manage record sharing permissions using Keeper SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python share_record_permissions.py
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
    record_uid_or_title = 'Test Record'  # Record name, path, or UID
    email_addresses = ['testuser@example.com']  # List of email addresses to share with
    action = 'grant'  # Options: 'grant', 'remove'
    can_edit = False  # Allow users to modify the record
    can_share = False  # Allow users to re-share the record
    contacts_only = False  # Share only to known contacts/targets
    force = False  # Skip confirmation prompts
    dry_run = False  # Display permission changes without committing them
    recursive = False  # Apply command to shared folder hierarchy
    expire_at = None  # Share expiration: never or UTC datetime
    expire_in = None  # Share expiration: never or period (e.g., 7d, 1h, 30m)

    # Validate email formats (basic check)
    for email in email_addresses:
        if '@' not in email:
            print(f'Error: Invalid email address format: {email}')
            sys.exit(1)

    # Display test configuration
    print(f'Using record: {record_uid_or_title}')
    print(f'Using email addresses: {", ".join(email_addresses)}')
    print(f'Action: {action}')
    
    permission_summary = []
    if can_edit:
        permission_summary.append("edit")
    if can_share:
        permission_summary.append("share")
    if not permission_summary:
        permission_summary.append("read-only")
    
    print(f'Permissions: {", ".join(permission_summary)}')
    
    if dry_run:
        print('Mode: DRY RUN (no changes will be made)')

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
        
        success = manage_record_permissions(
            context=context,
            record_uid_or_title=record_uid_or_title,
            email_addresses=email_addresses,
            action=action,
            can_edit=can_edit,
            can_share=can_share,
            contacts_only=contacts_only,
            force=force,
            dry_run=dry_run,
            recursive=recursive,
            expire_at=expire_at,
            expire_in=expire_in
        )
        
        if not success:
            sys.exit(1)
        
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()
