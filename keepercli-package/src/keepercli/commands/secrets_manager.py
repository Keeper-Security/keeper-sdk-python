import argparse

from keepersdk.vault import ksm_management

from . import base
from .. import api
from ..params import KeeperParams
from ..helpers import report_utils


logger = api.get_logger()


class SecretsManagerCommand(base.ArgparseCommand):

    def __init__(self):
        self.parser = argparse.ArgumentParser(
            prog='secrets-manager',
            description='Keeper Secrets Manager (KSM) Commands',
        )
        SecretsManagerCommand.add_arguments_to_parser(self.parser)
        super().__init__(self.parser)

    def add_arguments_to_parser(parser: argparse.ArgumentParser):

        parser.add_argument(
            'command', type=str, action='store', nargs="*",
            help='One of: "app list", "app get", "app create", "app remove", "app share", "app unshare", "client add", "client remove", "share add" or "share remove"'
            )
        parser.add_argument(
            '--secret', '-s', type=str, action='append', required=False, help='Record UID'
            )
        parser.add_argument(
            '--app', '-a', type=str, dest='app', action='store', required=False, help='Application Name or UID'
            )
        parser.add_argument(
            '--client', '-i', type=str, dest='client_names_or_ids', action='append', required=False, help='Client Name or ID'
            )
        parser.add_argument(
            '--first-access-expires-in-min', '-x', type=int, dest='firstAccessExpiresIn', action='store', default=60,
            help='Time for the first request to expire in minutes from the time when this command is executed. Maximum 1440 minutes (24 hrs). Default: 60'
            )
        parser.add_argument(
            '--access-expire-in-min', '-p', type=int, dest='accessExpireInMin', action='store',
            help='Time interval that this client can access the KSM application. After this time, access is denied. Time is entered in minutes starting from the time when command is executed. Default: Not expiration'
            )
        parser.add_argument(
            '--count', '-c', type=int, dest='count', action='store', help='Number of tokens to return. Default: 1', default=1
            )
        parser.add_argument(
            '--editable', '-e', action='store_true', required=False, help='Is this share going to be editable or not.'
            )
        parser.add_argument(
            '--unlock-ip', '-l', dest='unlockIp', action='store_true', help='Unlock IP Address.'
            )
        parser.add_argument(
            '--return-tokens', dest='returnTokens', action='store_true', help='Return Tokens'
            )
        parser.add_argument(
            '--name', '-n', type=str, dest='name', action='store', help='client name'
            )
        parser.add_argument(
            '--purge', dest='purge', action='store_true', help='remove the record from all folders and purge it from the trash'
            )
        parser.add_argument(
            '-f', '--force', dest='force', action='store_true', help='do not prompt'
            )
        parser.add_argument(
            '--config-init', type=str, dest='config_init', action='store', help='Initialize client config'
            )
        parser.add_argument(
            '--email', action='store', type=str, dest='email', help='Email of user to grant / remove application access to / from'
            )
        parser.add_argument(
            '--admin', action='store_true', help='Allow share recipient to manage application'
            )

    def execute(self, context: KeeperParams, **kwargs) -> None:
        if not context.vault:
            raise ValueError("Vault is not initialized.")

        command = kwargs.get('command')

        if len(command) == 0:
            logger.error("No command provided. Use 'app list', 'app get', 'app create', 'app remove', 'app share', 'app unshare', 'client add', 'client remove', 'share add' or 'share remove'.")
            return

        if command[0] == 'app':
            if len(command) < 2:
                logger.error("No subcommand provided for 'app'. Use 'list', 'get', 'create', 'remove', 'share' or 'unshare'.")
                return

            subcommand = command[1]

            if subcommand == 'list':
                app_list = ksm_management.list_secrets_manager_apps(context.vault)
                headers = ['App name', 'App UID', 'Records', 'Folders', 'Devices', 'Last Access']
                rows = [
                    [app.name, app.uid, app.records, app.folders, app.count, app.last_access]
                    for app in app_list
                ]
                return report_utils.dump_report_data(rows, headers=headers, fmt='table')

            elif subcommand == 'get':
                app_name = kwargs.get('app') or command[2]
                if not app_name:
                    logger.error("Application name or UID is required for 'app get'.")
                    return

                app = ksm_management.get_secrets_manager_app(context.vault, app_name)

                logger.info(f'\nSecrets Manager Application\n'
                      f'App Name: {app.name}\n'
                      f'App UID: {app.uid}')

                if len(app.client_devices) > 0:
                    client_count = 1
                    for client_device in app.client_devices:
                        client_devices_str = f"\nClient Device {client_count}\n" \
                                                    f"=============================\n" \
                                                    f'  Device Name: {client_device.name}\n' \
                                                    f'  Short ID: {client_device.short_id}\n' \
                                                    f'  Created On: {client_device.created_on}\n' \
                                                    f'  Expires On: {client_device.expires_on}\n' \
                                                    f'  First Access: {client_device.first_access}\n' \
                                                    f'  Last Access: {client_device.last_access}\n' \
                                                    f'  IP Lock: {client_device.ip_lock}\n' \
                                                    f'  IP Address: {client_device.ip_address or "--"}'
                        logger.info(client_devices_str)
                        client_count += 1
                else:
                    logger.info('\nNo client devices registered for this Application\n')

                if app.shared_secrets:
                    shares_table_fields = ['Share Type', 'UID', 'Title', 'Permissions']
                    rows = [
                        [secrets.type, secrets.uid, secrets.name, secrets.permissions]
                        for secrets in app.shared_secrets
                    ]
                    return report_utils.dump_report_data(rows, shares_table_fields, fmt='table')
                else:
                    logger.info('\tThere are no shared secrets to this application')


            # elif subcommand == 'create':
            #     app_name = kwargs.get('app')
            #     if not app_name:
            #         logger.error("Application name is required for 'app create'.")
            #         return
            #     ksm_management.create_secrets_manager_app(context.vault, app_name)
            # elif subcommand == 'remove':
            #     app_name = kwargs.get('app')
            #     if not app_name:
            #         logger.error("Application name or UID is required for 'app remove'.")
            #         return
            #     ksm_management.remove_secrets_manager_app(context.vault, app_name, kwargs.get('force', False))
            # elif subcommand in ['share', 'unshare']:
            #     if subcommand == 'unshare':
            #         share = False
            #     else:
            #         share = True
            #     app_name = kwargs.get('app')
            #     email = kwargs.get('email')
            #     is_admin = kwargs.get('admin', False)
            #     if not app_name or not email:
            #         logger.error("Application name and email are required for 'app share'.")
            #         return
            #     ksm_management.share_secrets_manager_app(context.vault, app_name, email, is_admin, share)