#!/usr/bin/env python3
#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper SDK for Python
# Copyright 2025 Keeper Security Inc.
# Contact: commander@keepersecurity.com
#
# Example: update share permissions on secrets in a Secrets Manager application.
# Equivalent to:
#   secrets-manager-share --command update --app <id> --secret <uids> --editable
#   secrets-manager-share --command update --app <id> --secret <uids> --readonly
#
# Uses: keepersdk.vault.ksm_management.update_secrets_manager_app_shares
#

from typing import List

from keepersdk.vault import ksm_management

from ksm_common import open_vault, run_login

# Set before running
APP_UID_OR_NAME = 'RlO6y-idGBqu1Ax2yUYXKw'
SECRET_UIDS = ['YJAAssUpHCf-2Xfjnlw5cw']
# True = editable; False = read-only
IS_EDITABLE = True


def update_secrets_manager_share_permissions(
    keeper_auth_context,
    app_uid_or_name: str,
    secret_uids: List[str],
    is_editable: bool = False,
) -> None:
    vault, _ = open_vault(keeper_auth_context)
    try:
        perm = 'editable' if is_editable else 'read-only'
        print(f'Updating {len(secret_uids)} share(s) to {perm} on app "{app_uid_or_name}"...')

        updated = ksm_management.update_secrets_manager_app_shares(
            vault=vault,
            uid_or_name=app_uid_or_name,
            secret_uids=secret_uids,
            is_editable=is_editable,
        )
        vault.sync_down()

        if updated:
            print(f'Successfully updated share permissions to {perm}:')
            for uid in updated:
                print(f'  {uid}')
        else:
            print('No shares were updated (secrets may not be shared with the app yet).')
    finally:
        vault.close()
        keeper_auth_context.close()


def main() -> None:
    keeper_auth_context, _ = run_login()
    if not keeper_auth_context:
        print('Login failed.')
        return

    update_secrets_manager_share_permissions(
        keeper_auth_context,
        APP_UID_OR_NAME,
        SECRET_UIDS,
        is_editable=IS_EDITABLE,
    )


if __name__ == '__main__':
    main()
