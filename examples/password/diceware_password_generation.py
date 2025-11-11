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
# Example showing how to generate diceware passwords
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

def generate_diceware_passwords(
    context: KeeperParams,
    number: Optional[int] = None,
    dice_rolls: Optional[int] = None,
    delimiter: Optional[str] = None,
    word_list: Optional[str] = None,
    output_format: Optional[str] = None,
    quiet: Optional[bool] = None,
    no_breachwatch: Optional[bool] = None,
):
    """
    Generate diceware passwords.
    
    This function uses the Keeper CLI `PasswordGenerateCommand` to generate diceware-style passwords
    using dice rolls to select words from a word list.
    """
    try:
        command = PasswordGenerateCommand()

        kwargs = {
            'number': number or 3,
            'dice_rolls': dice_rolls or 6,
            'delimiter': delimiter or ' ',
            'word_list': word_list,
            'output_format': output_format or 'table',
            'quiet': quiet or False,
            'no_breachwatch': no_breachwatch or False,
        }

        command.execute(context=context, **kwargs)
        return True
        
    except Exception as e:
        logger.error(f'Error generating diceware passwords: {str(e)}')
        return False


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Generate diceware passwords using Keeper SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python diceware_password_generation.py
  python diceware_password_generation.py --dice-rolls 8 --delimiter "-"
  python diceware_password_generation.py --word-list custom_words.txt --quiet
  python diceware_password_generation.py --number 5 --delimiter "_" --format json
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
        '--dice-rolls',
        type=int,
        default=6,
        help='Number of dice rolls for diceware generation (default: 6)'
    )
    parser.add_argument(
        '--delimiter',
        choices=['-', '+', ':', '.', '/', '_', '=', ' '],
        default=' ',
        help='Word delimiter for diceware (default: space)'
    )
    parser.add_argument(
        '--word-list',
        help='Path to custom word list file for diceware'
    )
    parser.add_argument(
        '-f', '--format',
        choices=['table', 'json'],
        default='table',
        help='Output format (default: table)'
    )
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Only print password list (minimal output)'
    )
    parser.add_argument(
        '--no-breachwatch',
        action='store_true',
        help='Skip BreachWatch scanning'
    )

    args = parser.parse_args()

    if not os.path.exists(args.config):
        logger.error(f'Config file {args.config} not found')
        sys.exit(1)

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
        
        # Show what we're generating
        using_defaults = (args.number == 3 and args.dice_rolls == 6 and args.delimiter == ' ' and 
                         not args.word_list and args.format == 'table' and not args.quiet and not args.no_breachwatch)
        
        if using_defaults:
            logger.info("Running with default settings - generating 3 diceware passwords")
            logger.info("Using 6 dice rolls with space delimiter and default word list")
            logger.info("Use --help to see all available options")
        else:
            logger.info(f'Generating {args.number} diceware password(s)...')
            logger.info(f'Dice rolls: {args.dice_rolls}')
            logger.info(f'Word delimiter: "{args.delimiter}"')
            if args.word_list:
                logger.info(f'Custom word list: {args.word_list}')
            else:
                logger.info('Using default word list')
        
        generate_diceware_passwords(
            context,
            number=args.number,
            dice_rolls=args.dice_rolls,
            delimiter=args.delimiter,
            word_list=args.word_list,
            output_format=args.format,
            quiet=args.quiet,
            no_breachwatch=args.no_breachwatch,
        )
        
    except Exception as e:
        logger.error(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()
