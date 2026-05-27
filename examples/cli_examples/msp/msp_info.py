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
# Example: msp-info — MSP details and managed companies.
#

import logging
from typing import Optional

from keepercli.commands.msp import MspInfoCommand

from msp_common import run_example

logging.basicConfig(level=logging.INFO, format='%(message)s')

# Optional filters (set to None to omit).
MANAGED_COMPANY: Optional[str] = None
SHOW_PRICING = None
SHOW_RESTRICTION = None
VERBOSE = None
OUTPUT_FORMAT = 'table'  # 'table' or 'json'


def main(context):
    kwargs = {'format': OUTPUT_FORMAT}
    if MANAGED_COMPANY:
        kwargs['managed_company'] = MANAGED_COMPANY
    if SHOW_PRICING is True:
        kwargs['pricing'] = True
    if SHOW_RESTRICTION is True:
        kwargs['restriction'] = True
    if VERBOSE is True:
        kwargs['verbose'] = True
    MspInfoCommand().execute(context=context, **kwargs)


if __name__ == '__main__':
    run_example(
        description='Display MSP info using the msp-info CLI command',
        epilog='Example:\n  python msp_info.py',
        execute_fn=main,
    )
