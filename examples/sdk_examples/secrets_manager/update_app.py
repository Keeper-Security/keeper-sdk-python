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
# Example: rename a Secrets Manager application using the Keeper SDK.
# Equivalent to: secrets-manager-app --command update --app <uid_or_name> --name <new_name>
#
# Uses: keepersdk.vault.ksm_management.update_secrets_manager_app
#

from keepersdk.vault import ksm_management

from ksm_common import open_vault, run_login

# Set before running
APP_UID_OR_NAME = 'RlO6y-idGBqu1Ax2yUYXKw'
NEW_APP_NAME = 'Secrets Manager App Renamed'


def update_secrets_manager_application(
    keeper_auth_context,
    app_uid_or_name: str,
    new_name: str,
) -> None:
    vault, _ = open_vault(keeper_auth_context)
    try:
        app_uid, old_name, updated_name = ksm_management.update_secrets_manager_app(
            vault=vault,
            uid_or_name=app_uid_or_name,
            new_name=new_name,
        )
        vault.sync_down()
        print(f'Application "{old_name}" renamed to "{updated_name}" (UID: {app_uid})')
    finally:
        vault.close()
        keeper_auth_context.close()


def main() -> None:
    keeper_auth_context, _ = run_login()
    if not keeper_auth_context:
        print('Login failed.')
        return

    print(f"Updating app '{APP_UID_OR_NAME}' to name '{NEW_APP_NAME}'...")
    update_secrets_manager_application(keeper_auth_context, APP_UID_OR_NAME, NEW_APP_NAME)


if __name__ == '__main__':
    main()
