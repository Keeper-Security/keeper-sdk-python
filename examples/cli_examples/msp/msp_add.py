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
# Example: msp-add — add a managed company to the MSP tenant.
#

import logging
from typing import List, Optional

from keepercli.commands.msp import MspAddCommand

from msp_common import run_example

logging.basicConfig(level=logging.INFO, format='%(message)s')

# Edit before running.
MC_NAME = 'CLI MSP Example MC'
PLAN = 'business'  # business, businessPlus, enterprise, enterprisePlus
SEATS: Optional[int] = 10
NODE: Optional[str] = None  # node name or ID; None = enterprise root
FILE_PLAN: Optional[str] = None
ADDONS: Optional[List[str]] = None  # e.g. ['connection_manager:25']


def main(context):
    kwargs = {
        'name': MC_NAME,
        'plan': PLAN,
    }
    if SEATS is not None:
        kwargs['seats'] = SEATS
    if NODE:
        kwargs['node'] = NODE
    if FILE_PLAN:
        kwargs['file_plan'] = FILE_PLAN
    if ADDONS:
        kwargs['addon'] = ADDONS
    MspAddCommand().execute(context=context, **kwargs)


if __name__ == '__main__':
    run_example(
        description='Add a managed company using the msp-add CLI command',
        epilog='Example:\n  python msp_add.py\n\nEdit MC_NAME, PLAN, and other constants in this file first.',
        execute_fn=main,
    )
