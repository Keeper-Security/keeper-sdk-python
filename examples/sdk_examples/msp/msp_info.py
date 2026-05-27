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
# Example: msp_info() — list managed companies using keepersdk.enterprise.msp_auth.
#

from typing import Optional

from keepersdk.enterprise import msp_auth

from msp_common import (
    close_loader_and_auth,
    login_with_enterprise,
    print_msp_info_report,
)

MANAGED_COMPANY: Optional[str] = None
SHOW_PRICING = False
SHOW_RESTRICTION = False
VERBOSE = False


def main():
    auth, loader = login_with_enterprise()
    if not auth or not loader:
        print('Login failed.')
        return
    try:
        msp_auth.msp_down(loader, reset=False)
        report = msp_auth.msp_info(
            loader,
            restriction=SHOW_RESTRICTION,
            pricing=SHOW_PRICING,
            managed_company=MANAGED_COMPANY,
            verbose=VERBOSE,
        )
        print_msp_info_report(report)
    finally:
        close_loader_and_auth(loader, auth)


if __name__ == '__main__':
    main()
