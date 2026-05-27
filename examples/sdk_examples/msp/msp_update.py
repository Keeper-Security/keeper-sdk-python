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
# Example: msp_update_managed_company() — update managed company license or name.
#

from typing import List, Optional

from keepersdk.enterprise import msp_auth

from msp_common import close_loader_and_auth, login_with_enterprise

MANAGED_COMPANY = 'SDK MSP Example MC'
NEW_NAME: Optional[str] = None
PLAN: Optional[str] = None
SEATS: Optional[int] = None
FILE_PLAN: Optional[str] = None
ADD_ADDONS: Optional[List[str]] = None
REMOVE_ADDONS: Optional[List[str]] = None


def main():
    auth, loader = login_with_enterprise()
    if not auth or not loader:
        print('Login failed.')
        return
    try:
        msp_auth.msp_down(loader, reset=False)
        eid = msp_auth.msp_update_managed_company(
            loader,
            managed_company=MANAGED_COMPANY,
            new_name=NEW_NAME,
            plan=PLAN,
            seats=SEATS,
            file_plan=FILE_PLAN,
            add_addons=ADD_ADDONS,
            remove_addons=REMOVE_ADDONS,
        )
        print(f'Updated managed company id={eid}.')
    finally:
        close_loader_and_auth(loader, auth)


if __name__ == '__main__':
    main()
