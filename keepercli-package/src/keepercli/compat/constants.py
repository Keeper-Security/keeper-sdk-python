#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import os


def get_keeper_host_for_services(server_hostname: str) -> str:
    if server_hostname.startswith('dev.'):
        return server_hostname[4:]
    return server_hostname


def get_router_host(server_hostname: str) -> str:
    krouter_url = os.getenv('KROUTER_URL')
    if krouter_url:
        return krouter_url.replace('https://', '').replace('http://', '').rstrip('/')
    return f'connect.{get_keeper_host_for_services(server_hostname)}'


def get_relay_host(server_hostname: str) -> str:
    krelay_url = os.getenv('KRELAY_URL')
    if krelay_url:
        return krelay_url.replace('https://', '').replace('http://', '').rstrip('/')
    return f'krelay.{get_keeper_host_for_services(server_hostname)}'
