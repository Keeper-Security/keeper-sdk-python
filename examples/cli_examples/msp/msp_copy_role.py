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
# Example: msp-copy-role — copy MSP roles (and enforcements) to managed companies.
#

import logging
from typing import List

from keepercli.commands.msp import MspCopyRoleCommand

from msp_common import run_example

logging.basicConfig(level=logging.INFO, format='%(message)s')

# Edit before running.
ROLES: List[str] = ['Keeper Administrator']
MANAGED_COMPANIES: List[str] = ['CLI MSP Example MC']


def main(context):
    MspCopyRoleCommand().execute(
        context=context,
        role=ROLES,
        mc=MANAGED_COMPANIES,
    )


if __name__ == '__main__':
    run_example(
        description='Copy roles to managed companies (msp-copy-role)',
        epilog='Example:\n  python msp_copy_role.py',
        execute_fn=main,
    )
