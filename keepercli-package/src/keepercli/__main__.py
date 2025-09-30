#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2023 Keeper Security Inc.
# Contact: commander@keepersecurity.com
#

import argparse
import json
import logging
import os
import pathlib
import re
import shutil
import sys
from typing import Any, Dict, Optional, Union, List, Tuple

from colorama import Fore, Back, Style

from . import __version__, cli, versioning, register_commands, params
from .commands import base


def get_keeper_config(config_filename: Optional[str]=None) -> params.KeeperConfig:
    if os.getenv("KEEPER_COMMANDER_DEBUG"):
        logging.getLogger().setLevel(logging.DEBUG)
        logging.info('Debug ON')

    def get_env_config() -> Optional[str]:
        path = os.getenv('KEEPER_CONFIG_FILE')
        if path:
            logging.debug(f'Setting config file from KEEPER_CONFIG_FILE env variable {path}')
        return path

    def get_default_path() -> pathlib.Path:
        default_path = pathlib.Path.home().joinpath('.keeper')
        default_path.mkdir(parents=True, exist_ok=True)
        return default_path

    config_filename = config_filename or get_env_config()
    if not config_filename:
        config_filename = 'config.json'
        if not os.path.isfile(config_filename):
            config_filename = os.path.join(get_default_path(), config_filename)
        else:
            config_filename = os.path.join(os.getcwd(), config_filename)
    else:
        config_filename = os.path.expanduser(config_filename)

    config: Optional[Dict[str, Any]] = None
    if os.path.exists(config_filename):
        try:
            try:
                with open(config_filename) as config_file:
                    config = json.load(config_file)
            except Exception as e:
                logging.error('Unable to parse JSON configuration file "%s"', os.path.abspath(config_filename))
                answer = input('Do you want to delete it (y/N): ')
                if answer in ['y', 'Y']:
                    os.remove(config_filename)
                else:
                    raise e
        except IOError as ioe:
            logging.warning('Error: Unable to open config file %s: %s', config_filename, ioe)

    return params.KeeperConfig(config_filename=config_filename, config=config or {})


def usage(message: str) -> None:
    print(message)
    parser.print_help()
    # cli.display_command_help()
    sys.exit(1)


def welcome() -> None:
    lines: List[Union[str, Tuple[str, str]]] = []
    lines.append( r'         /#############/   /#\ ')
    lines.append( r'        /#############/   /###\      _    __  _______  _______  ______   _______  ______ (R)')
    lines.append( r'       /#############/   /#####\    | |  / / |  ____/ |  ____/ |  ___ \ |  ____/ |  ___ \ ')
    lines.append( r'      /######/           \######\   | | / /  | |____  | |____  | | __| || |____  | | __| | ')
    lines.append( r'     /######/             \######\  | |< <   |  ___/  |  ___/  | |/___/ |  ___/  | |/_  / ')
    lines.append( r'    /######/               \######\ | | \ \  | |_____ | |_____ | |      | |_____ | |  \ \ ')
    lines.append( r'    \######\               /######/ |_|  \_\ |_______||_______||_|      |_______||_|   \_\ ')
    lines.append((r'     \######\             /######/', r'     ____                                          _ '))
    lines.append((r'      \######\           /######/ ', r'   /  ___|___  _ __ ___  _ __ ___   __ _ _ __   __| | ___ _ __ '))
    lines.append((r'       \#############\   \#####/  ', r"  /  /   / _ \| '_ ` _ \| '_ ` _ \ / _` | '_ \ / _` |/ _ \ '__| "))
    lines.append((r'        \#############\   \###/   ', r'  \  \__| (_) | | | | | | | | | | | (_| | | | | (_| |  __/ | '))
    lines.append((r'         \#############\   \#/    ', r'   \_____\___/|_| |_| |_|_| |_| |_|\__,_|_| |_|\__,_|\___|_| '))
    lines.append('')

    try:
        width = shutil.get_terminal_size(fallback=(160, 50)).columns
    except Exception:
        width = 160
    print(Style.RESET_ALL)
    print(Back.BLACK + Style.BRIGHT + '\n')
    for line in lines:
        if isinstance(line, str):
            if len(line) > width:
                line = line[:width]
            print('\033[2K' + Fore.LIGHTYELLOW_EX + line)
        elif isinstance(line, tuple):
            yellow_line = line[0] if len(line) > 0 else ''
            white_line = line[1] if len(line) > 1 else ''
            if len(yellow_line) > width:
                yellow_line = yellow_line[:width]
            if len(yellow_line) + len(white_line) > width:
                if len(yellow_line) < width:
                    white_line = white_line[:width - len(yellow_line)]
                else:
                    white_line = ''
            print('\033[2K' + Fore.LIGHTYELLOW_EX + yellow_line + Fore.LIGHTWHITE_EX + white_line)

    print('\033[2K' + Fore.LIGHTBLACK_EX + f'{("v" + __version__):>93}\n')
    print(Style.RESET_ALL)


parser = argparse.ArgumentParser(prog='keeper', add_help=False, allow_abbrev=False)
parser.add_argument('--server', '-ks', dest='server', action='store', help='Keeper Host address.')
parser.add_argument('--user', '-ku', dest='user', action='store', help='Email address for the account.')
parser.add_argument('--password', '-kp', dest='password', action='store', help='Master password for the account.')
parser.add_argument('--version', dest='version', action='store_true', help='Display version')
parser.add_argument('--config', dest='config', action='store', help='Config file to use')
parser.add_argument('--debug', dest='debug', action='store_true', help='Turn on debug mode')
parser.add_argument('--batch-mode', dest='batch_mode', action='store_true', help='Run commander in batch or basic UI mode.')
parser.add_argument('--proxy', dest='proxy', action='store', help='Proxy server')
unmask_help = 'Disable default masking of sensitive information (e.g., passwords) in output'
parser.add_argument('--unmask-all', action='store_true', help=unmask_help)
fail_on_throttle_help = 'Disable default client-side pausing of command execution and re-sending of requests upon ' \
                        'server-side throttling'
parser.add_argument('--fail-on-throttle', dest='fail_on_throttle', action='store_true', help=fail_on_throttle_help)
parser.add_argument('--skip-vault', dest='skip_vault', action='store_true', help='Skip loading vault')
parser.add_argument('--skip-enterprise', dest='skip_enterprise', action='store_true', help='Skip loading enterprise')
parser.add_argument('command', nargs='?', type=str, action='store', help='Command')
parser.add_argument('options', nargs='*', action='store', help='Options')
setattr(parser, 'error', usage)


def main():
    logging.basicConfig(format='%(message)s')

    sys.argv[0] = re.sub(r'(-script\.pyw?|\.exe)?$', '', sys.argv[0])
    opts, flags = parser.parse_known_args(sys.argv[1:])

    app_config = get_keeper_config(opts.config)

    if opts.batch_mode:
        app_config.batch_mode = True

    if opts.debug:
        app_config.debug = opts.debug

    logging.getLogger().setLevel(logging.WARNING if app_config.batch_mode else logging.DEBUG if opts.debug else logging.INFO)

    if opts.version:
        print(f'Keeper Commander, version {__version__}')
        return

    if opts.unmask_all:
        app_config.unmask_all = opts.unmask_all

    if opts.skip_vault:
        app_config.skip_vault = True

    if opts.skip_enterprise:
        app_config.skip_enterprise = True

    if opts.fail_on_throttle:
        app_config.fail_on_throttle = opts.fail_on_throttle

    if opts.server:
        app_config.server = opts.server

    if opts.user:
        app_config.username = opts.user

    if opts.password:
        app_config.password = opts.password
    else:
        pwd = os.getenv('KEEPER_PASSWORD')
        if pwd:
            app_config.password = pwd

    if not opts.command:
        opts.command = 'shell'

    if not app_config.batch_mode:
        welcome()
        versioning.welcome_print_version()

    commands = base.CliCommands()
    register_commands.register_commands(commands)
    r_code = cli.loop(app_config, commands)
    sys.exit(r_code)


if __name__ == '__main__':
    main()