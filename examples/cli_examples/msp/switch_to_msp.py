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
# Example: switch-to-msp — restore MSP tenant context after switch-to-mc.
#
# In the interactive CLI, switch-to-mc stores __msp_context__ on the session.
# This script simulates that by switching to an MC, then calling switch-to-msp.
#

import logging

from keepercli.commands.msp import SwitchToManagedCompanyCommand, SwitchToMspCommand

from msp_common import run_example

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

MANAGED_COMPANY_ID = 0


def main(context):
    if not MANAGED_COMPANY_ID:
        raise ValueError('Set MANAGED_COMPANY_ID for the demo switch cycle')

    mc_context = SwitchToManagedCompanyCommand().execute(
        context=context,
        mc_id=MANAGED_COMPANY_ID,
    )
    if mc_context is None:
        return

    try:
        restored = SwitchToMspCommand().execute(context=mc_context)
        if restored is not None:
            logger.info('MSP context restored for session')
    finally:
        mc_context.clear_session()


if __name__ == '__main__':
    run_example(
        description='Switch back to MSP after visiting a managed company (switch-to-msp)',
        epilog='Example:\n  python switch_to_msp.py',
        execute_fn=main,
    )
