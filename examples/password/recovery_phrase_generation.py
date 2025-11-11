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

def generate_recovery_phrases(
    context: KeeperParams,
    number: Optional[int] = None,
    output_format: Optional[str] = None,
    output_file: Optional[str] = None,
    clipboard: Optional[bool] = None,
    password_list: Optional[bool] = None,
    no_breachwatch: Optional[bool] = None,
):
    """
    Generate 24-word recovery phrases.
    
    This function uses the Keeper CLI `PasswordGenerateCommand` to generate recovery phrases
    suitable for cryptocurrency wallets and other applications requiring mnemonic phrases.
    """
    try:
        command = PasswordGenerateCommand()

        kwargs = {
            'recoveryphrase': True,
            'number': number or 2,
            'output_format': output_format or 'table',
            'output_file': output_file,
            'clipboard': clipboard or False,
            'password_list': password_list or False,
            'no_breachwatch': no_breachwatch or True,  # Recovery phrases usually skip BreachWatch
        }

        command.execute(context=context, **kwargs)
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
  python recovery_phrase_generation.py --number 3
  python recovery_phrase_generation.py --output recovery_phrases.txt --password-list
  python recovery_phrase_generation.py --clipboard --format json
        '''
    )
    
    parser.add_argument(
        '-c', '--config',
        default='myconfig.json',
        help='Configuration file (default: myconfig.json)'
    )
    parser.add_argument(
        '-n', '--number',
        type=int,
        default=2,
        help='Number of recovery phrases to generate (default: 2)'
    )
    parser.add_argument(
        '-f', '--format',
        choices=['table', 'json'],
        default='table',
        help='Output format (default: table)'
    )
    parser.add_argument(
        '-o', '--output',
        help='Write output to specified file'
    )
    parser.add_argument(
        '--clipboard',
        action='store_true',
        help='Copy generated phrases to clipboard'
    )
    parser.add_argument(
        '-p', '--password-list',
        action='store_true',
        help='Include phrase list in addition to formatted output'
    )
    parser.add_argument(
        '--enable-breachwatch',
        action='store_true',
        help='Enable BreachWatch scanning (disabled by default for recovery phrases)'
    )

    args = parser.parse_args()

    if not os.path.exists(args.config):
        logger.error(f'Config file {args.config} not found')
        sys.exit(1)

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
        
        using_defaults = (args.number == 2 and args.format == 'table' and 
                         not any([args.output, args.clipboard, args.password_list, args.enable_breachwatch]))
        
        if using_defaults:
            logger.info("Running with default settings - generating 2 recovery phrases")
            logger.info("These are 24-word phrases suitable for cryptocurrency wallet recovery")
            logger.info("Use --help to see all available options")
        else:
            logger.info(f'Generating {args.number} recovery phrase(s)...')
            logger.info('These are 24-word phrases suitable for cryptocurrency wallets')
        
        generate_recovery_phrases(
            context,
            number=args.number,
            output_format=args.format,
            output_file=args.output,
            clipboard=args.clipboard,
            password_list=args.password_list,
            no_breachwatch=not args.enable_breachwatch,
        )
        
    except Exception as e:
        logger.error(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()
