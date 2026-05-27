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
# Example: msp_legacy_report() — legacy MSP billing report.
#

from typing import Optional

from keepersdk.enterprise import msp_auth

from msp_common import (
    close_loader_and_auth,
    login_with_enterprise,
    print_msp_legacy_report,
)

RANGE_NAME = 'last_30_days'
FROM_DATE: Optional[str] = None
TO_DATE: Optional[str] = None


def main():
    auth, loader = login_with_enterprise()
    if not auth or not loader:
        print('Login failed.')
        return
    try:
        msp_auth.msp_down(loader, reset=False)
        report = msp_auth.msp_legacy_report(
            loader,
            range_name=RANGE_NAME,
            from_date=FROM_DATE,
            to_date=TO_DATE,
        )
        print_msp_legacy_report(report)
    finally:
        close_loader_and_auth(loader, auth)


if __name__ == '__main__':
    main()
