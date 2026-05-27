#!/usr/bin/env python3
#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper CLI for Python
# Copyright 2025 Keeper Security Inc.
# Contact: commander@keepersecurity.com
#
# Example: msp-billing-report — MSP billing report.
#

import logging
from typing import Optional

from keepercli.commands.msp import MspBillingReportCommand

from msp_common import run_example

logging.basicConfig(level=logging.INFO, format='%(message)s')

MONTH: Optional[str] = None  # YYYY-MM, e.g. '2025-01'
SHOW_DATE = None
SHOW_COMPANY = None
OUTPUT_FORMAT = 'table'


def main(context):
    kwargs = {'format': OUTPUT_FORMAT}
    if MONTH:
        kwargs['month'] = MONTH
    if SHOW_DATE is True:
        kwargs['show_date'] = True
    if SHOW_COMPANY is True:
        kwargs['show_company'] = True
    MspBillingReportCommand().execute(context=context, **kwargs)


if __name__ == '__main__':
    run_example(
        description='Generate MSP billing report (msp-billing-report)',
        epilog='Example:\n  python msp_billing_report.py',
        execute_fn=main,
    )
