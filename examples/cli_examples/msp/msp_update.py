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
# Example: msp-update — update a managed company license or name.
#

import logging
from typing import List, Optional

from keepercli.commands.msp import MspUpdateCommand

from msp_common import run_example

logging.basicConfig(level=logging.INFO, format='%(message)s')

# Edit before running: managed company name or numeric enterprise id.
MANAGED_COMPANY = 'CLI MSP Example MC'
NEW_NAME: Optional[str] = None
PLAN: Optional[str] = None
SEATS: Optional[int] = None
NODE: Optional[str] = None
FILE_PLAN: Optional[str] = None
ADD_ADDONS: Optional[List[str]] = None
REMOVE_ADDONS: Optional[List[str]] = None


def main(context):
    kwargs = {'mc': MANAGED_COMPANY}
    if NEW_NAME:
        kwargs['name'] = NEW_NAME
    if PLAN:
        kwargs['plan'] = PLAN
    if SEATS is not None:
        kwargs['seats'] = SEATS
    if NODE:
        kwargs['node'] = NODE
    if FILE_PLAN:
        kwargs['file_plan'] = FILE_PLAN
    if ADD_ADDONS:
        kwargs['add_addon'] = ADD_ADDONS
    if REMOVE_ADDONS:
        kwargs['remove_addon'] = REMOVE_ADDONS
    MspUpdateCommand().execute(context=context, **kwargs)


if __name__ == '__main__':
    run_example(
        description='Update a managed company using the msp-update CLI command',
        epilog='Example:\n  python msp_update.py',
        execute_fn=main,
    )
