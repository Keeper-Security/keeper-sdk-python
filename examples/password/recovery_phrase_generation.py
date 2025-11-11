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
# Example showing how to generate 24-word recovery phrases
# using the Keeper CLI package.
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

def generate_recovery_phrases(context: KeeperParams):
    """
    Generate 24-word recovery phrases.
    
    This function uses the Keeper CLI `PasswordGenerateCommand` to generate recovery phrases
    suitable for cryptocurrency wallets and other applications requiring mnemonic phrases.
    """
    try:
        command = PasswordGenerateCommand()
        command.execute(context=context, recoveryphrase=True, number=2, no_breachwatch=True)
        return True
        
    except Exception as e:
        logger.error(f'Error generating recovery phrases: {str(e)}')
        return False


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Generate 24-word recovery phrases using Keeper SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python recovery_phrase_generation.py
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

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
        
        logger.info("Generating 2 recovery phrases...")
        logger.info("These are 24-word phrases suitable for cryptocurrency wallet recovery")
        
        generate_recovery_phrases(context)
        
    except Exception as e:
        logger.error(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()
