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
# Example: msp_copy_role() — copy MSP roles and enforcements to managed companies.
#

from typing import List

from keepersdk.enterprise import msp_auth

from msp_common import close_loader_and_auth, login_with_enterprise

ROLES: List[str] = ['Keeper Administrator']
MANAGED_COMPANIES: List[str] = ['SDK MSP Example MC']


def main():
    auth, loader = login_with_enterprise()
    if not auth or not loader:
        print('Login failed.')
        return
    try:
        msp_auth.msp_down(loader, reset=False)
        synced = msp_auth.msp_copy_role(
            loader,
            roles=ROLES,
            managed_companies=MANAGED_COMPANIES,
        )
        print(f'Roles synced to managed company id(s): {sorted(synced)}')
    finally:
        close_loader_and_auth(loader, auth)


if __name__ == '__main__':
    main()
