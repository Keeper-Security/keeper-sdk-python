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
# Example showing how to generate advanced passwords with complexity rules
# and BreachWatch scanning using the Keeper CLI package.
#

import argparse
import json
import os
import sys
import logging
from typing import Optional

from keepercli.commands.password_generate import PasswordGenerateCommand
from keepercli.params import KeeperParams
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

def generate_advanced_passwords(context: KeeperParams):
    """
    Generate advanced passwords with complexity rules and BreachWatch scanning.
    
    This function uses the Keeper CLI `PasswordGenerateCommand` to generate passwords
    with specific complexity requirements and BreachWatch scanning.
    """
    try:
        command = PasswordGenerateCommand()
        command.execute(context=context, number=3, length=24, symbols=3, digits=3, uppercase=3, lowercase=3)
        return True
        
    except Exception as e:
        logger.error(f'Error generating advanced passwords: {str(e)}')
        return False


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Generate advanced passwords with complexity rules using Keeper SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python advanced_password_generation.py
        '''
    )
    
    default_config = get_default_config_path()
    parser.add_argument(
        '-c', '--config',
        default=default_config,
        help=f'Configuration file (default: {default_config})'
    )

    args = parser.parse_args()

    if not os.path.exists(args.config):
        logger.error(f'Config file {args.config} not found')
        sys.exit(1)

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
        
        logger.info("Generating 3 advanced passwords of length 24...")
        logger.info("Complexity: 3+ symbols, 3+ digits, 3+ uppercase, 3+ lowercase")
        logger.info('BreachWatch scanning: Enabled')
        
        generate_advanced_passwords(context)
        
    except Exception as e:
        logger.error(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()
