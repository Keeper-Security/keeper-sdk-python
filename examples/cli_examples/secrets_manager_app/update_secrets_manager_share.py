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
# Example showing how to update share permissions on secrets in a Secrets Manager application
# using the Keeper SDK architecture.
#

import argparse
import json
import os
import sys
import logging
from typing import List

from keepercli.commands.secrets_manager import SecretsManagerShareCommand
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


def update_secrets_manager_share(
    context: KeeperParams,
    app_id: str,
    secret_uids: List[str],
    is_editable: bool = False,
):
    """
    Update editable/read-only permissions on existing shares in a Secrets Manager application.

    Equivalent to one of:
      secrets-manager-share --command update --app <id> --secret <uids> --editable
      secrets-manager-share --command update --app <id> --secret <uids> --readonly
    """
    try:
        sm_share_command = SecretsManagerShareCommand()

        perm = 'editable' if is_editable else 'read-only'
        secret_list = ', '.join(secret_uids)
        print(f'Updating share permissions to {perm} for application "{app_id}"...')
        print(f'Secret UIDs: {secret_list}')

        kwargs = {
            'command': 'update',
            'app': app_id,
            'secret': ' '.join(secret_uids),
        }
        if is_editable:
            kwargs['editable'] = True
        else:
            kwargs['readonly'] = True

        sm_share_command.execute(context=context, **kwargs)

        print(f'Successfully updated {len(secret_uids)} share(s) to {perm}')
        return True

    except Exception as e:
        print(f'Error updating Secrets Manager share permissions: {str(e)}')
        return False


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Update share permissions on a Secrets Manager application using Keeper SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python update_secrets_manager_share.py
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

    app_id = "RlO6y-idGBqu1Ax2yUYXKw"
    secret_uids = ["YJAAssUpHCf-2Xfjnlw5cw"]
    # Set to True for --editable; False for --readonly
    is_editable = True

    print(f"Note: This example will attempt to update shares on app ID '{app_id}'")

    context = None
    try:
        context = login_to_keeper_with_config(args.config)
        success = update_secrets_manager_share(
            context=context,
            app_id=app_id,
            secret_uids=secret_uids,
            is_editable=is_editable,
        )

        if not success:
            sys.exit(1)

    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()
