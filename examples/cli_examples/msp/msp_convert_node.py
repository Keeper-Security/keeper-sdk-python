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
# Example: msp-convert-node — convert an enterprise subtree into a managed company.
#

import logging
from typing import Optional

from keepercli.commands.msp import MspConvertNodeCommand

from msp_common import run_example

logging.basicConfig(level=logging.INFO, format='%(message)s')

# Edit before running.
NODE = 'root'  # node name or ID (subtree root)
SEATS: Optional[int] = None
PLAN: Optional[str] = None  # defaults to business on the server


def main(context):
    kwargs = {'node': NODE}
    if SEATS is not None:
        kwargs['seats'] = SEATS
    if PLAN:
        kwargs['plan'] = PLAN
    MspConvertNodeCommand().execute(context=context, **kwargs)


if __name__ == '__main__':
    run_example(
        description='Convert a node subtree to a managed company (msp-convert-node)',
        epilog='Example:\n  python msp_convert_node.py',
        execute_fn=main,
    )
