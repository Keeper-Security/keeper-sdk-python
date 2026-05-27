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
# Example: msp-remove — remove a managed company from the MSP tenant.
#

import logging

from keepercli.commands.msp import MspRemoveCommand

from msp_common import run_example

logging.basicConfig(level=logging.INFO, format='%(message)s')

# Edit before running. Destructive — use a test MC only.
MANAGED_COMPANY = 'CLI MSP Example MC'
FORCE = True  # True skips interactive confirmation prompt


def main(context):
    kwargs = {
        'mc': MANAGED_COMPANY,
    }
    if FORCE is True:
        kwargs['force'] = True
    MspRemoveCommand().execute(context=context, **kwargs)


if __name__ == '__main__':
    run_example(
        description='Remove a managed company using the msp-remove CLI command',
        epilog='Example:\n  python msp_remove.py\n\nWARNING: This expires MC licenses and removes admin access.',
        execute_fn=main,
    )
