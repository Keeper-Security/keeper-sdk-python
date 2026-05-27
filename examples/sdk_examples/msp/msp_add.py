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
# Example: msp_add_managed_company() — register a new managed company.
#

from typing import List, Optional

from keepersdk.enterprise import msp_auth

from msp_common import close_loader_and_auth, login_with_enterprise

MC_NAME = 'SDK MSP Example MC'
PLAN = 'business'
SEATS: Optional[int] = 10
FILE_PLAN: Optional[str] = None
ADDONS: Optional[List[str]] = None


def main():
    auth, loader = login_with_enterprise()
    if not auth or not loader:
        print('Login failed.')
        return
    try:
        msp_auth.msp_down(loader, reset=False)
        root_node_id = loader.enterprise_data.root_node.node_id
        mc_id = msp_auth.msp_add_managed_company(
            loader,
            enterprise_name=MC_NAME,
            plan=PLAN,
            node_id=root_node_id,
            seats=SEATS,
            file_plan=FILE_PLAN,
            addons=ADDONS,
        )
        print(f'Created managed company "{MC_NAME}" (enterprise id={mc_id}).')
    finally:
        close_loader_and_auth(loader, auth)


if __name__ == '__main__':
    main()
