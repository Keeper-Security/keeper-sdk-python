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
# Example: msp-down — download / refresh MSP enterprise data from the cloud.
#

import logging

from keepercli.commands.msp import MspDownCommand

from msp_common import run_example

logging.basicConfig(level=logging.INFO, format='%(message)s')

# Set True to clear sync token and reload from scratch; None leaves reset off.
RESET = None


def main(context):
    kwargs = {}
    if RESET is True:
        kwargs['reset'] = True
    MspDownCommand().execute(context=context, **kwargs)


if __name__ == '__main__':
    run_example(
        description='Refresh MSP data using the msp-down CLI command',
        epilog='Example:\n  python msp_down.py',
        execute_fn=main,
    )
