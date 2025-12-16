#!/usr/bin/env python3
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
# Example showing how to generate audit reports
# using the Keeper CLI architecture.
#

import argparse
import json
import os
import sys
import logging

from keepercli.commands.audit_report import EnterpriseAuditReport
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

    username = config_data.get('user', config_data.get('username'))
    password = config_data.get('password', '')
    if not username:
        raise ValueError('Username not found in config file')

    keeper_config = KeeperConfig(config_filename=filename, config=config_data)
    auth = LoginFlow.login(keeper_config, username=username, password=password or None, resume_session=bool(username))
    if not auth:
        raise Exception('Failed to authenticate with Keeper')

    context = KeeperParams(keeper_config=keeper_config)
    context.set_auth(auth)

    return context


def execute_audit_report(context: KeeperParams, **kwargs):
    """
    Execute audit report command.
    
    This function generates audit reports
    using the Keeper CLI command infrastructure.
    """
    audit_report_command = EnterpriseAuditReport()
    
    try:
        audit_report_command.execute(context=context, **kwargs)
    except Exception as e:
        raise Exception(f'Error: {str(e)}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Generate audit reports using Keeper SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python audit_report.py
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

    # Example parameters - customize these for your audit report
    report_type = "raw"  # Can be: raw, dim, hour, day, week, month, span
    report_format = "message"  # message or fields (raw reports only)
    created_filter = "last_7_days"  # Filter by creation date
    event_type = "login"  # Audit event type filter
    
    context = None
    try:
        context = login_to_keeper_with_config(args.config)
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)

    kwargs = {
        'report_type': report_type,
        'report_format': report_format,
        'created': created_filter,
        'event_type': event_type,
        'limit': 100,  # Maximum number of returned rows
        'order': 'desc',  # Sort order: desc or asc
        'timezone': None,  # Specific timezone
        'columns': ['username', 'audit_event_type'] if report_type != 'raw' else None,  # Columns for aggregate reports
        'aggregates': ['occurrences'] if report_type != 'raw' else None,  # Aggregated values - 'occurrences', 'first_created', 'last_created'
        'username': None,  # Filter by username
        'to_username': None,  # Filter by target username
        'from_username': None,  # Filter by source username
        'record_uid': None,  # Filter by record UID
        'shared_folder_uid': None,  # Filter by shared folder UID
        'geo_location': None,  # Filter by geo location
        'ip_address': None,  # Filter by IP address
        'device_type': None,  # Filter by device type
        'output': None,  # Output file path
        'format': 'table'  # Output format: table, csv, json
    }

    print(f"Generating audit report:")
    print(f"  Report type: {report_type}")
    print(f"  Report format: {report_format}")
    print(f"  Created filter: {created_filter}")
    print(f"  Event type: {event_type}")
    
    try:
        execute_audit_report(context, **kwargs)
        print('Audit report generation completed successfully')
        sys.exit(0)
    except Exception as e:
        print(f'Error: {str(e)}')
        sys.exit(1)
    finally:
        if context:
            context.clear_session()
