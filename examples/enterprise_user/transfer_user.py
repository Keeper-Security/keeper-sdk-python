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
# Example showing how to transfer user accounts from one user to another
# using the Keeper CLI architecture.
#

import argparse
import json
import os
import sys
import logging
from typing import Optional, List
import tempfile

from keepercli.commands.transfer_account import EnterpriseTransferAccountCommand
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

def create_mapping_file(source_users: List[str], target_user: str) -> str:
    """
    Create a temporary mapping file for user transfers.
    
    This creates a mapping file with the format:
    source_user@example.com -> target_user@example.com
    """
    # Create temporary file
    temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8')
    
    try:
        # Write header comment
        temp_file.write("# Transfer mapping file - automatically generated\n")
        temp_file.write("# Format: source_user -> target_user\n")
        temp_file.write("# Lines starting with # are comments\n\n")
        
        # Write mappings
        for source_user in source_users:
            temp_file.write(f"{source_user} -> {target_user}\n")
        
        temp_file.flush()
        return temp_file.name
    finally:
        temp_file.close()

def transfer_user_accounts(
    context: KeeperParams,
    source_users: List[str],
    target_user: Optional[str] = None,
    force: bool = False,
    use_mapping_file: bool = False
):
    """
    Transfer user accounts from source users to target user.
    
    This function transfers all vault data (records, shared folders, teams,
    user folders) from source users to the target user using the Keeper CLI
    `EnterpriseTransferAccountCommand`.
    """
    try:
        transfer_command = EnterpriseTransferAccountCommand()

        # Prepare arguments
        kwargs = {
            'force': force
        }
        
        if use_mapping_file:
            # Create and use mapping file
            if not target_user:
                raise ValueError("Target user is required when using mapping file")
            
            mapping_file = create_mapping_file(source_users, target_user)
            print(f'Created mapping file: {mapping_file}')
            
            # Read and display mapping file contents
            with open(mapping_file, 'r') as f:
                print("Mapping file contents:")
                print("-" * 40)
                for line in f:
                    if not line.startswith('#'):
                        print(line.strip())
                print("-" * 40)
            
            kwargs['email'] = [f'@{mapping_file}']
            
            try:
                print(f'Transferring accounts using mapping file...')
                if not force:
                    print('WARNING: This action cannot be undone!')
                    print('Source users will be locked during transfer.')
                
                transfer_command.execute(context=context, **kwargs)
                print(f'\nUser account transfer completed successfully!')
                return True
                
            finally:
                # Clean up temporary file
                try:
                    os.unlink(mapping_file)
                    print(f'Cleaned up mapping file: {mapping_file}')
                except OSError:
                    print(f'Warning: Could not delete temporary file: {mapping_file}')
        else:
            # Use command line arguments
            if not target_user:
                raise ValueError("Target user is required")
            
            kwargs['target_user'] = target_user
            kwargs['email'] = source_users
            
            print(f'Transferring accounts from {", ".join(source_users)} to {target_user}...')
            if not force:
                print('WARNING: This action cannot be undone!')
                print('Source users will be locked during transfer.')
            
            transfer_command.execute(context=context, **kwargs)
            print(f'\nUser account transfer completed successfully!')
            return True
        
    except Exception as e:
        print(f'Error transferring user accounts: {str(e)}')
        return False


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Transfer user accounts using Keeper SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Transfer single user with default settings
  python transfer_user.py --source-user testuser1@example.com
  
  # Transfer multiple users to specific target
  python transfer_user.py --source-user testuser1@example.com testuser2@example.com --target-user admin@example.com
  
  # Transfer using mapping file approach
  python transfer_user.py --source-user testuser1@example.com --target-user admin@example.com --use-mapping-file
  
  # Force transfer without confirmation
  python transfer_user.py --source-user testuser1@example.com --target-user admin@example.com --force
  
  # Load mapping from external file
  python transfer_user.py --mapping-file my_mappings.txt
  
Mapping file format:
  # Lines starting with # are comments
  user1@example.com -> admin@example.com
  user2@example.com <- admin@example.com  
  old.user@example.com = new.admin@example.com
  source@example.com target@example.com
        '''
    )
    
    parser.add_argument(
        '-c', '--config',
        default='myconfig.json',
        help='Configuration file (default: myconfig.json)'
    )
    
    parser.add_argument(
        '--source-user',
        nargs='+',
        default=['testuser1@example.com'],
        help='Source user email(s) to transfer from (default: testuser1@example.com)'
    )
    
    parser.add_argument(
        '--target-user',
        default='admin@example.com',
        help='Target user email to transfer to (default: admin@example.com)'
    )
    
    parser.add_argument(
        '--use-mapping-file',
        action='store_true',
        help='Create and use a temporary mapping file for the transfer'
    )
    
    parser.add_argument(
        '--mapping-file',
        help='Use existing mapping file (overrides other user options)'
    )
    
    parser.add_argument(
        '-f', '--force',
        action='store_true',
        help='Do not prompt for confirmation (DANGEROUS - cannot be undone!)'
    )

    args = parser.parse_args()

    if not os.path.exists(args.config):
        print(f'Config file {args.config} not found')
        sys.exit(1)

    # Validate email formats (basic check)
    all_emails = args.source_user + [args.target_user] if args.target_user else args.source_user
    for email in all_emails:
        if '@' not in email:
            print(f'Error: Invalid email address format: {email}')
            sys.exit(1)
    
    # Check for self-transfer
    if args.target_user and args.target_user in args.source_user:
        print('Error: Target user cannot be the same as source user')
        sys.exit(1)

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
        
        # Ensure enterprise data is loaded
        if not context.enterprise_data:
            print('Loading enterprise data...')
            context.enterprise_loader.load()
        
        # Display test configuration
        print(f'Using source users: {", ".join(args.source_user)}')
        print(f'Using target user: {args.target_user}')
        print(f'Force mode: {args.force}')
        print(f'Use mapping file: {args.use_mapping_file}')
        
        if args.mapping_file:
            # Use external mapping file
            if not os.path.exists(args.mapping_file):
                print(f'Error: Mapping file {args.mapping_file} not found')
                sys.exit(1)
            
            print(f'Using external mapping file: {args.mapping_file}')
            
            transfer_command = EnterpriseTransferAccountCommand()
            success = transfer_command.execute(
                context=context,
                email=[f'@{args.mapping_file}'],
                force=args.force
            )
        else:
            # Use source/target user parameters
            success = transfer_user_accounts(
                context=context,
                source_users=args.source_user,
                target_user=args.target_user,
                force=args.force,
                use_mapping_file=args.use_mapping_file
            )
        
        if not success:
            sys.exit(1)
        
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()
