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
# Example: login_to_managed_company() and switch_to_msp() from msp_auth.
#

import sqlite3

from keepersdk.enterprise import enterprise_loader, msp_auth, sqlite_enterprise_storage

from msp_common import close_loader_and_auth, login_with_enterprise

MANAGED_COMPANY_ID = 0


def main():
    auth, loader = login_with_enterprise()
    if not auth or not loader:
        print('Login failed.')
        return
    if not MANAGED_COMPANY_ID:
        print('Set MANAGED_COMPANY_ID (from msp_info.py) before running.')
        close_loader_and_auth(loader, auth)
        return

    mc_auth = None
    mc_loader = None
    try:
        msp_auth.msp_down(loader, reset=False)
        print(f'Logging into managed company {MANAGED_COMPANY_ID}...')
        mc_auth, mc_tree_key = msp_auth.login_to_managed_company(loader, MANAGED_COMPANY_ID)

        conn = sqlite3.Connection('file::memory:', uri=True)
        mc_storage = sqlite_enterprise_storage.SqliteEnterpriseStorage(
            lambda: conn, MANAGED_COMPANY_ID
        )
        mc_loader = enterprise_loader.EnterpriseLoader(mc_auth, mc_storage, tree_key=mc_tree_key)
        mc_loader.load()
        mc_name = mc_loader.enterprise_data.enterprise_info.enterprise_name
        print(f'Connected to managed company: {mc_name}')

        print('Switching back to MSP context...')
        msp_auth.switch_to_msp(loader)
        print('MSP enterprise data refreshed.')
    finally:
        if mc_loader is not None:
            mc_loader.close()
        if mc_auth is not None:
            mc_auth.close()
        close_loader_and_auth(loader, auth)


if __name__ == '__main__':
    main()
