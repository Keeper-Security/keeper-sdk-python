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
# Example showing how to transform a folder or move it from one location to another
# using the Keeper CLI package.
#

import argparse
import json
import os
import sys
import logging
from typing import Optional

from keepercli.commands.vault_folder import FolderTransformCommand
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


def transform_folder(
    context: KeeperParams,
    folder: str,
    target: str,
    force: Optional[bool] = None,
    link: Optional[bool] = None,
    dry_run: Optional[bool] = None,
    folder_type: Optional[str] = None,
):
    """
    Transform a folder or move it from one location to another.
    
    This function uses the Keeper CLI `FolderTransformCommand` to transform a folder or move it from one location to another.
    """
    try:
        command = FolderTransformCommand()

        kwargs = {
            'folder': folder,
            'target': target,
            'force': force,
            'link': link,
            'dry_run': dry_run,
            'folder_type': folder_type,
        }
        command.execute(context=context, **kwargs)
        return True
        
    except Exception as e:
        logger.error(f'Error changing folder type or moving it to a new location: {str(e)}')
        return False


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Change folder type or move it to a new location',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python transform_folder.py
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
        logger.error(f'Config file {args.config} not found')
        sys.exit(1)

    # Bool flags can be set to True or None (to be sent as False)
    folder = 'folder_uid'
    target = 'target_folder_uid'
    force = None
    link = None
    dry_run = None
    folder_type = 'shared' # 'shared' or 'personal'

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
        transform_folder(
            context,
            folder=folder,
            target=target,
            force=force,
            link=link,
            dry_run=dry_run,
            folder_type=folder_type,
        )
        
    except Exception as e:
        logger.error(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()
