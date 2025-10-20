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
# Example showing how to send a record password to the clipboard
# using the Keeper CLI package.
#

import argparse
import json
import os
import sys
import logging
from typing import Optional

from keepercli.commands.record_handling_commands import ClipboardCommand
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

def clipboard_copy(
    context: KeeperParams,
    record_uid: str,
    output_type: Optional[str] = None,
    name: Optional[str] = None,
    copy_uid: Optional[bool] = None,
    login: Optional[bool] = None,
    totp: Optional[bool] = None,
    field: Optional[str] = None,
    revision: Optional[int] = None,
):
    """
    Send a record password to the clipboard.
    
    This function uses the Keeper CLI `ClipboardCommand` to send a record password to the clipboard.
    """
    try:
        command = ClipboardCommand()

        kwargs = {
            'record': record_uid,
            'output': output_type,
            'name': name,
            'copy_uid': copy_uid,
            'login': login,
            'totp': totp,
            'field': field,
            'revision': revision,
        }
        command.execute(context=context, **kwargs)
        return True
        
    except Exception as e:
        logger.error(f'Error sending record password to clipboard: {str(e)}')
        return False


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Send a record password to the clipboard',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python clipboard_copy.py
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

    # Bool flags can be set to True or None (to be sent as False)
    record_uid = 'record_uid'
    output_type = 'clipboard' # clipboard, stdout, stdouthidden, variable
    name = 'password' # Variable name if output is set to variable
    copy_uid = None # Output uid instead of password
    login = None # Output login name
    totp = None # Output totp code
    field = None # Output custom field
    revision = None # Use a specific record revision

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
        clipboard_copy(
            context,
            record_uid=record_uid,
            output_type=output_type,
            name=name,
            copy_uid=copy_uid,
            login=login,
            totp=totp,
            field=field,
            revision=revision,
        )
        
    except Exception as e:
        logger.error(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()