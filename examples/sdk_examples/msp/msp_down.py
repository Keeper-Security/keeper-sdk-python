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
# Example: msp_down() — refresh MSP enterprise data via keepersdk.enterprise.msp_auth.
#

from keepersdk.enterprise import msp_auth

from msp_common import close_loader_and_auth, login_with_enterprise

RESET = False


def main():
    auth, loader = login_with_enterprise()
    if not auth or not loader:
        print('Login failed.')
        return
    try:
        touched = msp_auth.msp_down(loader, reset=RESET)
        print(f'MSP data synced ({len(touched)} entity type(s) updated).')
    finally:
        close_loader_and_auth(loader, auth)


if __name__ == '__main__':
    main()
