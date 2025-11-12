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
# Comprehensive example showing all password generation features
# using the Keeper CLI package.
#

import argparse
import json
import os
import sys
import logging

from keepercli.commands.password_generate import PasswordGenerateCommand
from keepercli.params import KeeperParams
from keepercli.login import LoginFlow

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

def demonstrate_all_password_types(context: KeeperParams):
    """
    Demonstrate all available password generation types and features.
    """
    command = PasswordGenerateCommand()
    
    print("\n" + "="*80)
    print("COMPREHENSIVE PASSWORD GENERATION DEMONSTRATION")
    print("="*80)
    
    # 1. Basic Random Passwords
    print("\n1. BASIC RANDOM PASSWORDS (Default)")
    print("-" * 40)
    kwargs = {
        'number': 3,
        'length': 16,
        'output_format': 'table',
        'no_breachwatch': True,  # Skip for demo speed
    }
    command.execute(context=context, **kwargs)
    
    # 2. Advanced Random with Complexity Rules
    print("\n2. ADVANCED RANDOM WITH COMPLEXITY RULES")
    print("-" * 40)
    print("Rules: 3 uppercase, 3 lowercase, 3 digits, 2 symbols")
    kwargs = {
        'number': 2,
        'length': 20,
        'uppercase': 3,
        'lowercase': 3,
        'digits': 3,
        'symbols': 2,
        'output_format': 'table',
        'no_breachwatch': True,
    }
    command.execute(context=context, **kwargs)
    
    # 3. Using Rules String Format
    print("\n3. USING RULES STRING FORMAT")
    print("-" * 40)
    print("Rules string: '4,4,4,3' (uppercase,lowercase,digits,symbols)")
    kwargs = {
        'number': 2,
        'length': 24,
        'rules': '4,4,4,3',
        'output_format': 'table',
        'no_breachwatch': True,
    }
    command.execute(context=context, **kwargs)
    
    # 4. Diceware Passwords
    print("\n4. DICEWARE PASSWORDS")
    print("-" * 40)
    print("Using 6 dice rolls with space delimiter")
    kwargs = {
        'number': 3,
        'dice_rolls': 6,
        'delimiter': ' ',
        'output_format': 'table',
        'no_breachwatch': True,
    }
    command.execute(context=context, **kwargs)
    
    # 5. Diceware with Different Delimiter
    print("\n5. DICEWARE WITH DASH DELIMITER")
    print("-" * 40)
    print("Using 5 dice rolls with dash delimiter")
    kwargs = {
        'number': 2,
        'dice_rolls': 5,
        'delimiter': '-',
        'output_format': 'table',
        'no_breachwatch': True,
    }
    command.execute(context=context, **kwargs)
    
    # 6. Crypto-style Passwords
    print("\n6. CRYPTO-STYLE PASSWORDS")
    print("-" * 40)
    print("High-entropy passwords for cryptocurrency applications")
    kwargs = {
        'crypto': True,
        'number': 2,
        'output_format': 'table',
        'no_breachwatch': True,
    }
    command.execute(context=context, **kwargs)
    
    # 7. Recovery Phrases
    print("\n7. RECOVERY PHRASES (24-word)")
    print("-" * 40)
    print("Mnemonic phrases for wallet recovery")
    kwargs = {
        'recoveryphrase': True,
        'number': 1,
        'output_format': 'table',
        'no_breachwatch': True,
    }
    command.execute(context=context, **kwargs)
    
    # 8. JSON Output Format
    print("\n8. JSON OUTPUT FORMAT")
    print("-" * 40)
    print("Same data in JSON format with indentation")
    kwargs = {
        'number': 2,
        'length': 16,
        'output_format': 'json',
        'json_indent': 2,
        'no_breachwatch': True,
    }
    command.execute(context=context, **kwargs)
    
    # 9. With BreachWatch Scanning (if available)
    print("\n9. WITH BREACHWATCH SCANNING")
    print("-" * 40)
    print("Scanning passwords against known breaches")
    kwargs = {
        'number': 2,
        'length': 16,
        'output_format': 'table',
        'no_breachwatch': False,  # Enable BreachWatch
    }
    try:
        command.execute(context=context, **kwargs)
    except Exception as e:
        logger.warning(f"BreachWatch scanning failed: {e}")
        logger.info("This may occur if BreachWatch is not enabled or configured")
    
    print("\n" + "="*80)
    print("DEMONSTRATION COMPLETE")
    print("="*80)

def generate_custom_passwords(
    context: KeeperParams,
    password_type: str,
    **kwargs
):
    """
    Generate passwords based on specified type and parameters.
    """
    try:
        command = PasswordGenerateCommand()
        
        # Set default parameters based on type
        if password_type == 'basic':
            default_kwargs = {
                'number': 3,
                'length': 20,
                'output_format': 'table',
            }
        elif password_type == 'advanced':
            default_kwargs = {
                'number': 3,
                'length': 24,
                'symbols': 3,
                'digits': 3,
                'uppercase': 3,
                'lowercase': 3,
                'output_format': 'table',
            }
        elif password_type == 'diceware':
            default_kwargs = {
                'number': 3,
                'dice_rolls': 6,
                'delimiter': ' ',
                'output_format': 'table',
            }
        elif password_type == 'crypto':
            default_kwargs = {
                'crypto': True,
                'number': 3,
                'output_format': 'table',
            }
        elif password_type == 'recovery':
            default_kwargs = {
                'recoveryphrase': True,
                'number': 2,
                'output_format': 'table',
            }
        else:
            raise ValueError(f"Unknown password type: {password_type}")
        
        # Merge user parameters with defaults
        final_kwargs = {**default_kwargs, **kwargs}
        
        command.execute(context=context, **final_kwargs)
        return True
        
    except Exception as e:
        logger.error(f'Error generating {password_type} passwords: {str(e)}')
        return False


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Comprehensive password generation example using Keeper SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python comprehensive_password_generation.py --demo
  python comprehensive_password_generation.py --type basic --number 5 --length 16
  python comprehensive_password_generation.py --type advanced --symbols 4 --digits 4
  python comprehensive_password_generation.py --type diceware --dice-rolls 8 --delimiter "-"
  python comprehensive_password_generation.py --type crypto --number 3 --format json
  python comprehensive_password_generation.py --type recovery --output recovery.txt
        '''
    )
    
    default_config = get_default_config_path()
    parser.add_argument(
        '-c', '--config',
        default=default_config,
        help=f'Configuration file (default: {default_config})'
    )
    parser.add_argument(
        '--demo',
        action='store_true',
        help='Run comprehensive demonstration of all password types'
    )
    parser.add_argument(
        '--type',
        choices=['basic', 'advanced', 'diceware', 'crypto', 'recovery'],
        help='Type of password to generate'
    )
    parser.add_argument(
        '-n', '--number',
        type=int,
        help='Number of passwords to generate'
    )
    parser.add_argument(
        '-l', '--length',
        type=int,
        help='Password length (for basic/advanced types)'
    )
    parser.add_argument(
        '--symbols',
        type=int,
        help='Minimum number of symbol characters'
    )
    parser.add_argument(
        '--digits',
        type=int,
        help='Minimum number of digit characters'
    )
    parser.add_argument(
        '--uppercase',
        type=int,
        help='Minimum number of uppercase characters'
    )
    parser.add_argument(
        '--lowercase',
        type=int,
        help='Minimum number of lowercase characters'
    )
    parser.add_argument(
        '--dice-rolls',
        type=int,
        help='Number of dice rolls for diceware generation'
    )
    parser.add_argument(
        '--delimiter',
        choices=['-', '+', ':', '.', '/', '_', '=', ' '],
        help='Word delimiter for diceware'
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
        '--no-breachwatch',
        action='store_true',
        help='Skip BreachWatch scanning'
    )

    args = parser.parse_args()

    if not os.path.exists(args.config):
        logger.error(f'Config file {args.config} not found')
        sys.exit(1)

    # If no arguments provided, default to demo mode
    if not args.demo and not args.type:
        args.demo = True
        logger.info("No arguments provided, running comprehensive demonstration")
        logger.info("Use --help to see all available options")

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
        
        if args.demo:
            demonstrate_all_password_types(context)
        else:
            # Build kwargs from command line arguments
            kwargs = {
                'output_format': args.format,
                'no_breachwatch': args.no_breachwatch,
            }
            
            if args.number:
                kwargs['number'] = args.number
            if args.length:
                kwargs['length'] = args.length
            if args.symbols:
                kwargs['symbols'] = args.symbols
            if args.digits:
                kwargs['digits'] = args.digits
            if args.uppercase:
                kwargs['uppercase'] = args.uppercase
            if args.lowercase:
                kwargs['lowercase'] = args.lowercase
            if args.dice_rolls:
                kwargs['dice_rolls'] = args.dice_rolls
            if args.delimiter:
                kwargs['delimiter'] = args.delimiter
            if args.output:
                kwargs['output_file'] = args.output
            
            generate_custom_passwords(context, args.type, **kwargs)
        
    except Exception as e:
        logger.error(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()
