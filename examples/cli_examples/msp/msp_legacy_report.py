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
# Example: msp-legacy-report — MSP legacy billing report.
#

import logging
from typing import Optional

from keepercli.commands.msp import MspLegacyReportCommand

from msp_common import run_example

logging.basicConfig(level=logging.INFO, format='%(message)s')

RANGE_NAME = 'last_30_days'
FROM_DATE: Optional[str] = None  # YYYY-MM-DD
TO_DATE: Optional[str] = None
OUTPUT_FORMAT = 'table'


def main(context):
    kwargs = {
        'format': OUTPUT_FORMAT,
        'range': RANGE_NAME,
    }
    if FROM_DATE:
        kwargs['from_date'] = FROM_DATE
    if TO_DATE:
        kwargs['to_date'] = TO_DATE
    MspLegacyReportCommand().execute(context=context, **kwargs)


if __name__ == '__main__':
    run_example(
        description='Generate MSP legacy billing report (msp-legacy-report)',
        epilog='Example:\n  python msp_legacy_report.py',
        execute_fn=main,
    )
