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

def generate_advanced_passwords(
    context: KeeperParams,
    number: Optional[int] = None,
    length: Optional[int] = None,
    symbols: Optional[int] = None,
    digits: Optional[int] = None,
    uppercase: Optional[int] = None,
    lowercase: Optional[int] = None,
    rules: Optional[str] = None,
    output_format: Optional[str] = None,
    output_file: Optional[str] = None,
    clipboard: Optional[bool] = None,
    password_list: Optional[bool] = None,
):
    """
    Generate advanced passwords with complexity rules and BreachWatch scanning.
    
    This function uses the Keeper CLI `PasswordGenerateCommand` to generate passwords
    with specific complexity requirements, BreachWatch scanning, and various output options.
    """
    try:
        command = PasswordGenerateCommand()

        kwargs = {
            'number': number or 3,
            'length': length or 24,
            'symbols': symbols,
            'digits': digits,
            'uppercase': uppercase,
            'lowercase': lowercase,
            'rules': rules,
            'output_format': output_format or 'table',
            'output_file': output_file,
            'clipboard': clipboard or False,
            'password_list': password_list or False,
            'no_breachwatch': False,  # Enable BreachWatch scanning
        }

        command.execute(context=context, **kwargs)
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
  python advanced_password_generation.py --length 32 --symbols 4 --digits 4
  python advanced_password_generation.py --rules "3,3,3,3" --output passwords.json --format json
  python advanced_password_generation.py --clipboard --password-list
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
        default=3,
        help='Number of passwords to generate (default: 3)'
    )
    parser.add_argument(
        '-l', '--length',
        type=int,
        default=24,
        help='Password length (default: 24)'
    )
    parser.add_argument(
        '-s', '--symbols',
        type=int,
        help='Minimum number of symbol characters'
    )
    parser.add_argument(
        '-d', '--digits',
        type=int,
        help='Minimum number of digit characters'
    )
    parser.add_argument(
        '-u', '--uppercase',
        type=int,
        help='Minimum number of uppercase characters'
    )
    parser.add_argument(
        '--lowercase',
        type=int,
        help='Minimum number of lowercase characters'
    )
    parser.add_argument(
        '-r', '--rules',
        help='Complexity rules as comma-separated integers: uppercase,lowercase,digits,symbols'
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
        help='Copy generated passwords to clipboard'
    )
    parser.add_argument(
        '-p', '--password-list',
        action='store_true',
        help='Include password list in addition to formatted output'
    )

    args = parser.parse_args()

    if not os.path.exists(args.config):
        logger.error(f'Config file {args.config} not found')
        sys.exit(1)

    # Set some defaults for better demo when no args provided
    if not any([args.symbols, args.digits, args.uppercase, args.lowercase, args.rules]):
        # If no complexity rules specified, use some defaults for demo
        if args.length == 24 and args.number == 3:  # Using defaults
            args.symbols = 3
            args.digits = 3
            args.uppercase = 3
            args.lowercase = 3

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
        
        # Show what we're generating
        using_defaults = (args.number == 3 and args.length == 24 and not args.rules and 
                         not any([args.output, args.clipboard, args.password_list]))
        
        if using_defaults:
            logger.info("Running with enhanced defaults - generating 3 advanced passwords of length 24")
            logger.info("Complexity: 3+ symbols, 3+ digits, 3+ uppercase, 3+ lowercase")
            logger.info("Use --help to see all available options")
        else:
            logger.info(f'Generating {args.number} advanced password(s)...')
            logger.info(f'Length: {args.length}')
            if args.symbols: logger.info(f'Minimum symbols: {args.symbols}')
            if args.digits: logger.info(f'Minimum digits: {args.digits}')
            if args.uppercase: logger.info(f'Minimum uppercase: {args.uppercase}')
            if args.lowercase: logger.info(f'Minimum lowercase: {args.lowercase}')
            if args.rules: logger.info(f'Complexity rules: {args.rules}')
        
        logger.info('BreachWatch scanning: Enabled')
        
        generate_advanced_passwords(
            context,
            number=args.number,
            length=args.length,
            symbols=args.symbols,
            digits=args.digits,
            uppercase=args.uppercase,
            lowercase=args.lowercase,
            rules=args.rules,
            output_format=args.format,
            output_file=args.output,
            clipboard=args.clipboard,
            password_list=args.password_list,
        )
        
    except Exception as e:
        logger.error(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()
