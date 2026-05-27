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
# Example: switch-to-mc — log into a managed company context from the MSP tenant.
#

import logging

from keepercli.commands.enterprise_info import EnterpriseInfoTreeCommand
from keepercli.commands.msp import SwitchToManagedCompanyCommand

from msp_common import run_example

logging.basicConfig(level=logging.INFO, format='%(message)s')

# Numeric managed company enterprise id (from msp-info). Edit before running.
MANAGED_COMPANY_ID = 0

# Set True to run enterprise-info in the MC context after switching.
RUN_ENTERPRISE_INFO_AFTER_SWITCH = True


def main(context):
    if not MANAGED_COMPANY_ID:
        raise ValueError('Set MANAGED_COMPANY_ID to your managed company enterprise id (from msp-info)')

    mc_context = SwitchToManagedCompanyCommand().execute(
        context=context,
        mc_id=MANAGED_COMPANY_ID,
    )
    if mc_context is None:
        return

    try:
        if RUN_ENTERPRISE_INFO_AFTER_SWITCH is True:
            EnterpriseInfoTreeCommand().execute(context=mc_context)
    finally:
        mc_context.clear_session()


if __name__ == '__main__':
    run_example(
        description='Switch to a managed company context (switch-to-mc)',
        epilog=(
            'Example:\n'
            '  python switch_to_mc.py\n\n'
            'Obtain MANAGED_COMPANY_ID from msp_info.py, then use switch_to_msp.py to return.'
        ),
        execute_fn=main,
    )
