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
# Example showing how to add a client to a Secrets Manager application
# using the SecretsManagerClientCommand from the CLI package.
#

import argparse
import json
import os
import sys
from typing import Optional

from keepercli.commands.secrets_manager import SecretsManagerClientCommand
from keepercli.params import KeeperParams
from keepercli.login import LoginFlow

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

def add_client_to_app(
    context: KeeperParams, 
    app_id: str, 
    client_name: str, 
    count: int = 1, 
    unlock_ip: bool = False,
    first_access_expires_in: int = 60, 
    access_expire_in_min: Optional[int] = None, 
    return_tokens: bool = False
):
    """
    Add a client to a Secrets Manager application.
    
    This function adds one or more clients to an existing Secrets Manager application,
    allowing the clients to access secrets through the Secrets Manager API. The function
    provides comprehensive configuration options for client access control.
    """
    try:
        client_command = SecretsManagerClientCommand()
        
        print(f'Adding {count} client(s) to application "{app_id}"...')
        if client_name:
            print(f'Client name: {client_name}')
        if unlock_ip:
            print('- IP address unlocked')
        else:
            print('- IP address locked (default)')
        print(f'- First access expires in: {first_access_expires_in} minutes')
        if access_expire_in_min:
            print(f'- Access expires in: {access_expire_in_min} minutes')
        
        kwargs = {
            'command': 'add',
            'app': app_id,
            'name': client_name,
            'count': count,
            'unlockIp': unlock_ip,
            'firstAccessExpiresIn': first_access_expires_in,
            'accessExpireInMin': access_expire_in_min,
            'returnTokens': return_tokens
        }
        
        result = client_command.execute(context=context, **kwargs)
        
        print('=' * 60)
        print(f'Successfully added {count} client(s) to application: {app_id}')
        
        if return_tokens and result:
            print(f'Generated tokens: {result}')
        
        return True
        
    except Exception as e:
        print(f'Error adding client to Secrets Manager application: {str(e)}')
        return False


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Add a client to a Secrets Manager application using Keeper SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python secrets_manager_client_add.py
        '''
    )
    
    parser.add_argument(
        '-c', '--config',
        default='myconfig.json',
        help='Configuration file (default: myconfig.json)'
    )

    args = parser.parse_args()

    if not os.path.exists(args.config):
        print(f'Config file {args.config} not found')
        sys.exit(1)

    app_id = "RlO6y-idGBqu1Ax2yUYXKw"
    client_name = "DemoClient"
    count = 1
    unlock_ip = False
    first_access_expires_in = 60
    access_expire_in_min = None
    return_tokens = True

    print(f"Note: This example will attempt to add a client to app ID '{app_id}'")

    try:
        context = login_to_keeper_with_config(args.config)
        success = add_client_to_app(
            context=context,
            app_id=app_id,
            client_name=client_name,
            count=count,
            unlock_ip=unlock_ip,
            first_access_expires_in=first_access_expires_in,
            access_expire_in_min=access_expire_in_min,
            return_tokens=return_tokens
        )
        
        if not success:
            sys.exit(1)
        
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)