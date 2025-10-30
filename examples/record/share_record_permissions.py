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

from keepercli.commands.record_handling_commands import RecordPermissionCommand
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
    folder: Optional[str] = None,
    action: str = 'grant',
    can_edit: Optional[bool] = None,
    can_share: Optional[bool] = None,
    force: Optional[bool] = None,
    dry_run: Optional[bool] = None,
    recursive: Optional[bool] = None,
    share_record: Optional[bool] = None,
    share_folder: Optional[bool] = None
):
    """
    Manage record permissions using RecordPermissionCommand.

    This adjusts the "Can Edit" and/or "Can Share" flags on records within a
    folder (optionally recursively). You can scope the change to direct record
    shares (share_record), shared folder shares (share_folder), or both.
    """
    try:
        cmd = RecordPermissionCommand()

        kwargs = {
            'folder': folder or '',
            'action': action,
            'can_edit': can_edit,
            'can_share': can_share,
            'force': force,
            'dry_run': dry_run,
            'recursive': recursive,
            'share_record': share_record,
            'share_folder': share_folder,
        }

        print('Managing record permissions...')
        print(f'Folder: {folder or "<root>"}')
        print(f'Action: {action}')
        print(f'Can edit: {can_edit}')
        print(f'Can share: {can_share}')
        print(f'Scope - share_record: {share_record}, share_folder: {share_folder}')
        print(f'Force: {force}')
        print(f'Dry run: {dry_run}')
        print(f'Recursive: {recursive}')

        if dry_run:
            print('\nDRY RUN MODE: No changes will be made')

        cmd.execute(context=context, **kwargs)

        print('\nRecord permission operation completed successfully!')
        return True

    except Exception as e:
        print(f'Error managing record permissions: {str(e)}')
        return False


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Manage record permissions using RecordPermissionCommand',
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
    # Bool flags can be set to True or None (to be sent as False)
    folder = "folder_uid_or_path"  # Folder path or folder UID (None for root)
    action = 'grant'  # 'grant' or 'revoke'
    can_edit = True  # Set "Can Edit" permission
    can_share = None  # Set "Can Share" permission
    share_record = None  # Modify direct record shares
    share_folder = None  # Modify shared folder record shares
    recursive = None  # Apply to sub-folders
    force = None  # Apply changes without confirmation
    dry_run = None  # Show changes without applying

    # Display selected configuration
    print(f'Folder: {folder or "<root>"}')
    print(f'Action: {action}')
    summary = []
    if can_edit:
        summary.append('edit')
    if can_share:
        summary.append('share')
    if not summary:
        summary.append('no-change')
    print(f'Permissions: {", ".join(summary)}')
    print(f'Scope - share_record: {share_record}, share_folder: {share_folder}')
    if dry_run:
        print('Mode: DRY RUN (no changes will be made)')

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
        
        success = manage_record_permissions(
            context=context,
            folder=folder,
            action=action,
            can_edit=can_edit,
            can_share=can_share,
            force=force,
            dry_run=dry_run,
            recursive=recursive,
            share_record=share_record,
            share_folder=share_folder,
        )
        
        if not success:
            sys.exit(1)
        
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()
