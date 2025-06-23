import argparse
from typing import Optional

from keepersdk.vault import ksm_management

from . import base
from .. import api
from ..params import KeeperParams
from ..helpers import report_utils, ksm_utils


logger = api.get_logger()


class SecretsManagerAppCommand(base.ArgparseCommand):

    def __init__(self):
        self.parser = argparse.ArgumentParser(
            prog='secrets-manager app',
            description='Keeper Secrets Manager (KSM) Commands',
        )
        SecretsManagerAppCommand.add_arguments_to_parser(self.parser)
        super().__init__(self.parser)

    def add_arguments_to_parser(parser: argparse.ArgumentParser):

        parser.add_argument(
            '--command', type=str, action='store', required=True, dest='command',
            help='One of: "list", "get", "create", "remove", "share" or "unshare"'
            )
        parser.add_argument(
            '--name', '-n', type=str, dest='name', action='store', required=False, help='Application Name or UID'
            )
        parser.add_argument(
            '-f', '--force', dest='force', action='store_true', help='Force add or remove app'
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
        uid_or_name = kwargs.get('name')
        force = kwargs.get('force')

        def list_app():
            return self.list_app(vault=context.vault)

        def get_app():
            return self.get_app(vault=context.vault, uid_or_name=uid_or_name)

        def create_app():
            self.create_app(vault=context.vault, name=uid_or_name, force=force)
            return context.vault_down()

        def remove_app():
            self.remove_app(vault=context.vault, uid_or_name=uid_or_name, force=force)
            return

        command_map = {
            'list': list_app,
            'get': get_app,
            'create': create_app,
            'remove': remove_app,
        }

        action = command_map.get(command)
        if action:
            return action()
        else:
            logger.error(f"Unknown command '{command}'. Available commands: list, get, create, remove")
            return


    def list_app(self, vault: KeeperParams.vault):
        app_list = ksm_management.list_secrets_manager_apps(vault)
        headers = ['App name', 'App UID', 'Records', 'Folders', 'Devices', 'Last Access']
        rows = [
            [app.name, app.uid, app.records, app.folders, app.count, app.last_access]
            for app in app_list
        ]
        report_utils.dump_report_data(rows, headers=headers, fmt='table')
    

    def get_app(self, vault: KeeperParams.vault, uid_or_name: str):
        if not uid_or_name:
            logger.error("Application name or UID is required for 'app get'. Use --name='example' to set it.")
            return

        app = ksm_management.get_secrets_manager_app(vault=vault, uid_or_name=uid_or_name)

        logger.info(f'\nSecrets Manager Application\n'
                f'App Name: {app.name}\n'
                f'App UID: {app.uid}')

        if len(app.client_devices) > 0:
            ksm_utils.print_client_device_info(app.client_devices)
        else:
            logger.info('\nNo client devices registered for this Application\n')

        if app.shared_secrets:
            ksm_utils.print_shared_secrets_info(app.shared_secrets)
        else:
            logger.info('\tThere are no shared secrets to this application')
        return
    
    
    def create_app(self, vault: KeeperParams.vault, name: str, force: Optional[bool] = False):
        if not name:
            logger.error("Application name or UID is required for 'app create'. Use --name='example' to set it.")
            return
        
        app_uid = ksm_management.create_secrets_manager_app(vault=vault, name=name, force_add=force)
        
        logger.info(f'Application was successfully added (UID: {app_uid})')
    
    
    def remove_app(self, vault: KeeperParams.vault, uid_or_name: str, force: Optional[bool] = False):
        if not uid_or_name:
            logger.error("Application name or UID is required for 'app remove'. Use --name='example' to set it.")
            return
        
        app_uid = ksm_management.remove_secrets_manager_app(vault=vault, uid_or_name=uid_or_name, force=force)
        
        logger.info(f'Application was successfully removed (UID: {app_uid})')