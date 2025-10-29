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
Examples:
  # Share record with default permissions (read-only)
  python share_record_permissions.py --record "Test Record" --email user@example.com
  
  # Share record with edit permissions
  python share_record_permissions.py --record "Test Record" --email user@example.com --can-edit
  
  # Share record with full permissions (edit + share)
  python share_record_permissions.py --record "Test Record" --email user@example.com --can-edit --can-share
  
  # Remove sharing permissions
  python share_record_permissions.py --record "Test Record" --email user@example.com --action remove
  
  # Share with multiple users
  python share_record_permissions.py --record "Test Record" --email user1@example.com user2@example.com --can-edit
  
  # Dry run to preview changes
  python share_record_permissions.py --record "Test Record" --email user@example.com --can-edit --dry-run
  
  # Share with expiration
  python share_record_permissions.py --record "Test Record" --email user@example.com --expire-in "7d"
  
  # Force share without confirmation
  python share_record_permissions.py --record "Test Record" --email user@example.com --can-edit --force
        '''
    )
    
    parser.add_argument(
        '-c', '--config',
        default='myconfig.json',
        help='Configuration file (default: myconfig.json)'
    )
    
    parser.add_argument(
        '--record',
        default='Test Record',
        help='Record name, path, or UID (default: Test Record)'
    )
    
    parser.add_argument(
        '--email',
        nargs='+',
        default=['testuser@example.com'],
        help='Account email addresses to share with (default: testuser@example.com)'
    )
    
    parser.add_argument(
        '--action',
        choices=['grant', 'remove'],
        default='grant',
        help='Share action: grant or remove permissions (default: grant)'
    )
    
    parser.add_argument(
        '--can-edit',
        action='store_true',
        help='Allow users to modify the record'
    )
    
    parser.add_argument(
        '--can-share',
        action='store_true',
        help='Allow users to re-share the record'
    )
    
    parser.add_argument(
        '--contacts-only',
        action='store_true',
        help='Share only to known contacts/targets'
    )
    
    parser.add_argument(
        '--force',
        action='store_true',
        help='Skip confirmation prompts'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Display permission changes without committing them'
    )
    
    parser.add_argument(
        '--recursive',
        action='store_true',
        help='Apply command to shared folder hierarchy'
    )
    
    expiration = parser.add_mutually_exclusive_group()
    expiration.add_argument(
        '--expire-at',
        help='Share expiration: never or UTC datetime'
    )
    expiration.add_argument(
        '--expire-in',
        help='Share expiration: never or period (e.g., 7d, 1h, 30m)'
    )

    args = parser.parse_args()

    if not os.path.exists(args.config):
        print(f'Config file {args.config} not found')
        sys.exit(1)

    # Validate email formats (basic check)
    for email in args.email:
        if '@' not in email:
            print(f'Error: Invalid email address format: {email}')
            sys.exit(1)

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
        
        # Display test configuration
        print(f'Using record: {args.record}')
        print(f'Using email addresses: {", ".join(args.email)}')
        print(f'Action: {args.action}')
        
        permission_summary = []
        if args.can_edit:
            permission_summary.append("edit")
        if args.can_share:
            permission_summary.append("share")
        if not permission_summary:
            permission_summary.append("read-only")
        
        print(f'Permissions: {", ".join(permission_summary)}')
        
        if args.dry_run:
            print('Mode: DRY RUN (no changes will be made)')
        
        success = manage_record_permissions(
            context=context,
            record_uid_or_title=args.record,
            email_addresses=args.email,
            action=args.action,
            can_edit=args.can_edit,
            can_share=args.can_share,
            contacts_only=args.contacts_only,
            force=args.force,
            dry_run=args.dry_run,
            recursive=args.recursive,
            expire_at=args.expire_at,
            expire_in=args.expire_in
        )
        
        if not success:
            sys.exit(1)
        
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()
