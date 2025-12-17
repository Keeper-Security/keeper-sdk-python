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
# Example showing how to generate a report of passwords in the Keeper vault folders
# using the Keeper CLI package.
#

import argparse
import logging
import json
import os
import sys
from typing import Optional

from keepercli.commands.password_report import PasswordReportCommand
from keepercli.params import KeeperParams, KeeperConfig
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

    keeper_config = KeeperConfig(config_filename=filename, config=config_data)
    auth = LoginFlow.login(keeper_config)
    if not auth:
        raise Exception('Failed to authenticate with Keeper')

    context = KeeperParams(keeper_config=keeper_config)
    context.set_auth(auth)

    return context


def password_report(
    context: KeeperParams,
    format: Optional[str] = None,
    output_path: Optional[str] = None,
    policy: Optional[str] = None,
    length: Optional[int] = None,
    upper: Optional[int] = None,
    lower: Optional[int] = None,
    digits: Optional[int] = None,
    special: Optional[int] = None,
    folder: Optional[str] = None,
    verbose: Optional[bool] = None,
):
    """
    Generate a report of passwords in the Keeper vault.
    
    This function uses the Keeper CLI `PasswordReportCommand` to retrieve and display
    records based on the provided criteria and filters.
    """
    try:
        command = PasswordReportCommand()

        kwargs = {
            'format': format,
            'output': output_path,
            'policy': policy,
            'length': length,
            'upper': upper,
            'lower': lower,
            'digits': digits,
            'special': special,
            'folder': folder,
            'verbose': verbose,
        }

        command.execute(context=context, **kwargs)
        return True
        
    except Exception as e:
        print(f'Error generating password report: {str(e)}')
        return False


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Generate a report of passwords in the Keeper vault using Keeper SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python password_report.py
        '''
    )
    
    default_config_path = get_default_config_path()
    parser.add_argument(
        '-c', '--config',
        default=default_config_path,
        help=f'Configuration file (default: {default_config_path})'
    )

    args = parser.parse_args()

    if not os.path.exists(args.config):
        print(f'Config file {args.config} not found')
        sys.exit(1)

    # Example parameters - customize these for your password report
    format = "table" # Format of output (table, json, csv)
    output_path = "password_report.csv" # Path to output file for csv format
    policy = "12,2,2,2,0" # Password complexity policy. Length,Lower,Upper,Digits,Special. Default is 12,2,2,2,0
    length = 12 # Minimum password length.
    upper = 2 # Minimum uppercase characters.
    lower = 2 # Minimum lowercase characters.
    digits = 2 # Minimum digits.
    special = 0 # Minimum special characters.
    folder = 'folder_uid' # Folder path or UID
    verbose = None # Display verbose information

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
        password_report(
            context,
            format=format,
            output_path=output_path,
            policy=policy,
            length=length,
            upper=upper,
            lower=lower,
            digits=digits,
            special=special,
            folder=folder,
            verbose=verbose,
        )
        
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()
