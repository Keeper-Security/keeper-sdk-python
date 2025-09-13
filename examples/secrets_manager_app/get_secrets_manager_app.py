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
# Example showing how to get details of a specific Secrets Manager application
# using the Keeper SDK architecture.
#

import argparse
import json
import logging
import os
import sys

from keepersdk.vault import ksm_management, vault_online
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

def print_client_device_info(client_devices):
    """Print client device information in a table-like format."""
    for index, client_device in enumerate(client_devices, start=1):
        client_devices_str = f"\nClient Device {index}\n" \
                                    f"=============================\n" \
                                    f'  Device Name: {client_device.name}\n' \
                                    f'  Short ID: {client_device.short_id}\n' \
                                    f'  Created On: {client_device.created_on}\n' \
                                    f'  Expires On: {client_device.expires_on}\n' \
                                    f'  First Access: {client_device.first_access}\n' \
                                    f'  Last Access: {client_device.last_access}\n' \
                                    f'  IP Lock: {client_device.ip_lock}\n' \
                                    f'  IP Address: {client_device.ip_address or "--"}'
        logger.info(client_devices_str)

def print_shared_secrets_info(shared_secrets):
    """Print shared secrets information in a table-like format."""
    if not shared_secrets:
        return
        
    # Print table header
    logger.info(f"\n{'Share Type':<15} {'UID':<25} {'Title':<30} {'Permissions'}")
    logger.info("-" * 85)
    
    # Print each shared secret
    for secrets in shared_secrets:
        share_type = str(secrets.type)[:14]
        uid = str(secrets.uid)[:24]
        name = str(secrets.name)[:29]
        permissions = str(secrets.permissions)
        logger.info(f"{share_type:<15} {uid:<25} {name:<30} {permissions}")

def get_secrets_manager_app(vault: vault_online.VaultOnline, app_id: str):
    """Retrieve and display Secrets Manager application details by UID or title."""
    try:
        app = ksm_management.get_secrets_manager_app(vault, app_id)
        
        if not app:
            logger.info(f'No Secrets Manager application found with ID: {app_id}')
            return None
        
        # Use the same format as keepercli secrets_manager.py
        logger.info(f'\nSecrets Manager Application\n'
                f'App Name: {app.name}\n'
                f'App UID: {app.uid}')

        if app.client_devices and len(app.client_devices) > 0:
            print_client_device_info(app.client_devices)
        else:
            logger.info('\nNo client devices registered for this Application\n')

        if app.shared_secrets:
            print_shared_secrets_info(app.shared_secrets)
        else:
            logger.info('\tThere are no shared secrets to this application')
        
        return app
        
    except Exception as e:
        logger.error(f'Error getting Secrets Manager application {app_id}: {str(e)}')
        return None

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Get details of a Secrets Manager application using Keeper SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python get_secrets_manager_app.py
        '''
    )
    
    parser.add_argument(
        '-c', '--config',
        default='myconfig.json',
        help='Configuration file (default: myconfig.json)'
    )

    args = parser.parse_args()

    if not os.path.exists(args.config):
        logger.error(f'Config file {args.config} not found')
        sys.exit(1)

    app_id = "7SkD_s3S9AghvrRP8D0gPQ"

    logger.info(f"Note: This example will attempt to get details for app ID '{app_id}'")

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
        app_details = get_secrets_manager_app(context.vault, app_id)
        
        if app_details is None:
            sys.exit(1)
        
    except Exception as e:
        logger.error(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()