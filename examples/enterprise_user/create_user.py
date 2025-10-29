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
# Example showing how to create an enterprise user
# using the Keeper CLI architecture.
#

import argparse
import json
import os
import sys
import logging
from typing import Optional

from keepercli.commands.enterprise_user import EnterpriseUserAddCommand
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

def create_enterprise_user(
    context: KeeperParams,
    email: str,
    full_name: Optional[str] = None,
    parent_node: Optional[str] = None,
    job_title: Optional[str] = None,
    add_roles: Optional[list] = None,
    add_teams: Optional[list] = None,
    hide_shared_folders: Optional[str] = None
):
    """
    Create a new enterprise user.
    
    This function creates a new enterprise user using the Keeper CLI
    `EnterpriseUserAddCommand` and returns True if successful.
    """
    try:
        create_command = EnterpriseUserAddCommand()

        kwargs = {
            'email': [email]  # EnterpriseUserAddCommand expects a list
        }
        
        if full_name:
            kwargs['full_name'] = full_name
        if parent_node:
            kwargs['parent'] = parent_node
        if job_title:
            kwargs['job_title'] = job_title
        if add_roles:
            kwargs['add_role'] = add_roles
        if add_teams:
            kwargs['add_team'] = add_teams
        if hide_shared_folders:
            kwargs['hide_shared_folders'] = hide_shared_folders

        print(f'Creating enterprise user: {email}')
        if full_name:
            print(f'Full name: {full_name}')
        if parent_node:
            print(f'Parent node: {parent_node}')
        if job_title:
            print(f'Job title: {job_title}')
        if add_roles:
            print(f'Roles: {", ".join(add_roles)}')
        if add_teams:
            print(f'Teams: {", ".join(add_teams)}')
        if hide_shared_folders:
            print(f'Hide shared folders: {hide_shared_folders}')

        # Execute the create user command
        create_command.execute(context=context, **kwargs)
        
        print(f'\nEnterprise user created successfully!')
        print(f'Email: {email}')
        return True
        
    except Exception as e:
        print(f'Error creating enterprise user: {str(e)}')
        return False


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Create an enterprise user using Keeper SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Create user with default settings (testuser@example.com in TestNode)
  python create_user.py
  
  # Create user with custom email
  python create_user.py --email user@example.com
  
  # Create user with full name and job title
  python create_user.py --email user@example.com --name "John Doe" --job-title "Developer"
  
  # Create user with roles and teams
  python create_user.py --email user@example.com --add-role "Admin" --add-team "IT Team"
  
  # Create user with hidden shared folders
  python create_user.py --email user@example.com --hide-shared-folders on
        '''
    )
    
    parser.add_argument(
        '-c', '--config',
        default='myconfig.json',
        help='Configuration file (default: myconfig.json)'
    )
    
    parser.add_argument(
        '--email',
        default='testuser@example.com',
        help='User email address (default: testuser@example.com)'
    )
    
    parser.add_argument(
        '--name',
        help='User full name'
    )
    
    parser.add_argument(
        '--parent',
        default='TestNode',
        help='Parent node name or node ID (default: TestNode)'
    )
    
    parser.add_argument(
        '--job-title',
        help='User job title'
    )
    
    parser.add_argument(
        '--add-role',
        action='append',
        help='Role name or role ID (can be repeated)'
    )
    
    parser.add_argument(
        '--add-team',
        action='append',
        help='Team name or team UID (can be repeated)'
    )
    
    parser.add_argument(
        '--hide-shared-folders',
        choices=['on', 'off'],
        help='User does not see shared folders (only valid with --add-team)'
    )

    args = parser.parse_args()

    if not os.path.exists(args.config):
        print(f'Config file {args.config} not found')
        sys.exit(1)

    # Validate email format (basic check)
    if '@' not in args.email:
        print('Error: Invalid email address format')
        sys.exit(1)
    
    # Validate hide-shared-folders usage
    if args.hide_shared_folders and not args.add_team:
        print('Warning: --hide-shared-folders only works with --add-team')

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
        
        # Ensure enterprise data is loaded
        if not context.enterprise_data:
            print('Loading enterprise data...')
            context.enterprise_loader.load()
        
        # Set defaults for test example
        full_name = args.name or "Test User"
        job_title = getattr(args, 'job_title', None) or "Test Employee"
        
        print(f'Using test email: {args.email}')
        print(f'Using parent node: {args.parent}')
        print(f'Using full name: {full_name}')
        print(f'Using job title: {job_title}')
        
        success = create_enterprise_user(
            context=context,
            email=args.email,
            full_name=full_name,
            parent_node=args.parent,
            job_title=job_title,
            add_roles=getattr(args, 'add_role', None),
            add_teams=getattr(args, 'add_team', None),
            hide_shared_folders=getattr(args, 'hide_shared_folders', None)
        )
        
        if not success:
            sys.exit(1)
        
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()
