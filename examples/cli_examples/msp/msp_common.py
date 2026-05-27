#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper CLI for Python
# Copyright 2025 Keeper Security Inc.
# Contact: commander@keepersecurity.com
#
# Shared helpers for MSP CLI examples in this folder.
#

import argparse
import json
import os
import sys
from typing import Callable, Optional

from keepercli.login import LoginFlow
from keepercli.params import KeeperConfig, KeeperParams


def get_default_config_path() -> str:
    """Resolve config.json (cwd) or ~/.keeper/config.json."""
    file_name = 'config.json'
    if os.path.isfile(file_name):
        return os.path.abspath(file_name)
    keeper_dir = os.path.join(os.path.expanduser('~'), '.keeper')
    if not os.path.exists(keeper_dir):
        os.mkdir(keeper_dir)
    return os.path.join(keeper_dir, file_name)


def login_to_keeper_with_config(filename: str) -> KeeperParams:
    """Authenticate and return KeeperParams (enterprise loader available for MSP admin)."""
    if not os.path.exists(filename):
        raise FileNotFoundError(f'Config file {filename} not found')
    with open(filename, 'r') as f:
        config_data = json.load(f)

    keeper_config = KeeperConfig(config_filename=filename, config=config_data)
    auth = LoginFlow.login(keeper_config)
    if not auth:
        raise RuntimeError('Failed to authenticate with Keeper')

    context = KeeperParams(keeper_config=keeper_config)
    context.set_auth(auth)
    return context


def add_config_argument(parser: argparse.ArgumentParser) -> None:
    default_config_path = get_default_config_path()
    parser.add_argument(
        '-c', '--config',
        default=default_config_path,
        help=f'Configuration file (default: {default_config_path})',
    )


def run_example(
    description: str,
    epilog: str,
    execute_fn: Callable[[KeeperParams], None],
) -> None:
    """Parse --config, login, run execute_fn(context), then clear session."""
    parser = argparse.ArgumentParser(
        description=description,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=epilog,
    )
    add_config_argument(parser)
    args = parser.parse_args()

    if not os.path.exists(args.config):
        print(f'Config file {args.config} not found')
        sys.exit(1)

    context: Optional[KeeperParams] = None
    try:
        context = login_to_keeper_with_config(args.config)
        execute_fn(context)
    except Exception as e:
        print(f'Error: {e}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()
