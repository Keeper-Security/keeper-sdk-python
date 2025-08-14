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
# Example showing how to list Secrets Manager applications
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

def print_apps_table(apps):
    """Print applications in a table-like format with key attributes."""
    if not apps:
        logger.info('No Secrets Manager applications found.')
        return
    
    logger.info(f"\n{'App name':<20} {'App UID':<25} {'Records':<8} {'Folders':<8} {'Devices':<8} {'Last Access'}")
    logger.info("-" * 95)
    
    for app in apps:
        app_name = str(app.name)[:19] if hasattr(app, 'name') else 'Unknown'
        app_uid = str(app.uid)[:24] if hasattr(app, 'uid') else 'Unknown'
        records = str(app.records) if hasattr(app, 'records') else '0'
        folders = str(app.folders) if hasattr(app, 'folders') else '0'
        devices = str(app.count) if hasattr(app, 'count') else '0'
        last_access = str(app.last_access) if hasattr(app, 'last_access') else 'Never'
        
        logger.info(f"{app_name:<20} {app_uid:<25} {records:<8} {folders:<8} {devices:<8} {last_access}")

def list_secrets_manager_apps(vault: vault_online.VaultOnline):
    """
    List all Secrets Manager applications in the Keeper vault.
    
    This function retrieves and displays all Secrets Manager applications
    associated with the current vault.
    """
    try:
        apps = ksm_management.list_secrets_manager_apps(vault)
        
        if not apps:
            logger.info('No Secrets Manager applications found.')
            return None
        
        print_apps_table(apps)
        
        return apps
        
    except Exception as e:
        logger.error(f'Error listing Secrets Manager applications: {str(e)}')
        return None

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='List Secrets Manager applications using Keeper SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python list_secrets_manager_apps.py
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

    try:
        vault = login_to_keeper_with_config(args.config).vault
        list_secrets_manager_apps(vault)
        
    except Exception as e:
        logger.error(f'Error: {str(e)}')
        sys.exit(1)