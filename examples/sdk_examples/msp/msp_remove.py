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
# Example: msp_remove_managed_company() — remove a managed company tenant.
#

from keepersdk.enterprise import msp_auth

from msp_common import close_loader_and_auth, login_with_enterprise

MANAGED_COMPANY = 'SDK MSP Example MC'


def main():
    auth, loader = login_with_enterprise()
    if not auth or not loader:
        print('Login failed.')
        return
    try:
        msp_auth.msp_down(loader, reset=False)
        eid = msp_auth.msp_remove_managed_company(loader, managed_company=MANAGED_COMPANY)
        print(f'Removed managed company id={eid}.')
    finally:
        close_loader_and_auth(loader, auth)


if __name__ == '__main__':
    main()
