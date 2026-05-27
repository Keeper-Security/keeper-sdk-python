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
# Example: msp_billing_report() — MSP billing report via keepersdk.enterprise.msp_auth.
#

from typing import Optional

from keepersdk.enterprise import msp_auth

from msp_common import (
    close_loader_and_auth,
    login_with_enterprise,
    print_msp_billing_report,
)

MONTH: Optional[str] = None
SHOW_DATE = False
SHOW_COMPANY = False


def main():
    auth, loader = login_with_enterprise()
    if not auth or not loader:
        print('Login failed.')
        return
    try:
        msp_auth.msp_down(loader, reset=False)
        report = msp_auth.msp_billing_report(
            loader,
            month=MONTH,
            show_date=SHOW_DATE,
            show_company=SHOW_COMPANY,
        )
        print_msp_billing_report(report)
    finally:
        close_loader_and_auth(loader, auth)


if __name__ == '__main__':
    main()
