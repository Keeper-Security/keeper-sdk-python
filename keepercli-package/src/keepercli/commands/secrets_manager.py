import argparse
from enum import Enum
import time
from typing import Optional, List, Set, Tuple

from keepersdk import utils
from keepersdk.proto.enterprise_pb2 import GENERAL
from keepersdk.vault import ksm_management, vault_online

from . import base
from .shares import ShareAction
from .. import api, prompt_utils
from ..helpers import ksm_utils, report_utils
from ..params import KeeperParams


logger = api.get_logger()


MILLISECONDS_PER_MINUTE = 60 * 1000
MILLISECONDS_PER_SECOND = 1000
DEFAULT_FIRST_ACCESS_EXPIRES_IN_MINUTES = 60
DEFAULT_TOKEN_COUNT = 1


SHARE_ACTION_GRANT = ShareAction.GRANT.value
SHARE_ACTION_REVOKE = ShareAction.REVOKE.value
SHARE_ACTION_REMOVE = ShareAction.REMOVE.value


USER_CHOICE_DEFAULT_NO = 'n'
USER_CHOICE_YES = 'y'


WILDCARD_ALL = '*'
WILDCARD_ALL_ALIAS = 'all'


class SecretsManagerCommand(Enum):
    LIST = "list"
    GET = "get"
    ADD = 'add'
    CREATE = "create"
    REMOVE = "remove"
    SHARE = "share"
    UNSHARE = "unshare"

class SecretsManagerAppCommand(base.ArgparseCommand):

    def __init__(self):
        self.parser = argparse.ArgumentParser(
            prog='secrets-manager-app',
            description='Keeper Secrets Manager (KSM) App Commands'
        )
        SecretsManagerAppCommand.add_arguments_to_parser(self.parser)
        super().__init__(self.parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):

        parser.add_argument(
            '--command', type=str, action='store', dest='command',
            choices=[cmd.value for cmd in SecretsManagerCommand],
            help = f"One of: {', '.join(cmd.value for cmd in SecretsManagerCommand)}"
            )
        parser.add_argument(
            '--app', '-a', type=str, dest='app', action='store', help='Application Name or UID'
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
        self._validate_vault(context)
        
        command = kwargs.get('command')
        if not command:
            return self.get_parser().print_help()

        self._validate_app_parameter(command, kwargs.get('app'))
        
        command_handler = self._get_command_handler(context, command, kwargs)
        if command_handler:
            return command_handler()
        
        available_commands = ', '.join([cmd.value for cmd in SecretsManagerCommand])
        raise ValueError(f"Unknown command '{command}'. Available commands: {available_commands}")

    def _validate_vault(self, context: KeeperParams) -> None:
        """Validate that vault is initialized."""
        if not context.vault:
            raise ValueError("Vault is not initialized.")

    def _validate_app_parameter(self, command: str, uid_or_name: Optional[str]) -> None:
        """Validate that app parameter is provided when required."""
        if command != SecretsManagerCommand.LIST.value and not uid_or_name:
            raise ValueError("Application name or UID is required. Use --app='example' to set it.")

    def _get_command_handler(self, context: KeeperParams, command: str, kwargs: dict):
        """Get the appropriate command handler function."""
        vault = context.vault
        uid_or_name = kwargs.get('app')
        force = kwargs.get('force')
        email = kwargs.get('email')
        is_admin = kwargs.get('admin', False)

        command_handlers = {
            SecretsManagerCommand.LIST.value: lambda: self.list_app(vault=vault),
            SecretsManagerCommand.GET.value: lambda: self.get_app(vault=vault, uid_or_name=uid_or_name),
            SecretsManagerCommand.CREATE.value: lambda: self._handle_create_app(context, vault, uid_or_name, force),
            SecretsManagerCommand.ADD.value: lambda: self._handle_create_app(context, vault, uid_or_name, force),
            SecretsManagerCommand.REMOVE.value: lambda: self.remove_app(vault=vault, uid_or_name=uid_or_name, force=force),
            SecretsManagerCommand.SHARE.value: lambda: self._handle_share_app(context, uid_or_name, email, is_admin, unshare=False),
            SecretsManagerCommand.UNSHARE.value: lambda: self._handle_share_app(context, uid_or_name, email, is_admin, unshare=True)
        }
        
        return command_handlers.get(command)

    def _handle_create_app(self, context: KeeperParams, vault, name: str, force: bool) -> None:
        """Handle app creation and sync vault."""
        self.create_app(vault=vault, name=name, force=force)
        context.vault_down()

    def _handle_share_app(self, context: KeeperParams, uid_or_name: str, email: Optional[str], 
                          is_admin: bool, unshare: bool) -> None:
        """Handle app sharing/unsharing and sync vault."""
        self.share_app(context=context, uid_or_name=uid_or_name, unshare=unshare, email=email, is_admin=is_admin)
        context.vault_down()


    def list_app(self, vault: vault_online.VaultOnline):
        app_list = ksm_management.list_secrets_manager_apps(vault)
        headers = ['App name', 'App UID', 'Records', 'Folders', 'Devices', 'Last Access']
        rows = [
            [app.name, app.uid, app.records, app.folders, app.count, app.last_access]
            for app in app_list
        ]
        report_utils.dump_report_data(rows, headers=headers, fmt='table')
    

    def get_app(self, vault: vault_online.VaultOnline, uid_or_name: str):
        app = ksm_management.get_secrets_manager_app(vault=vault, uid_or_name=uid_or_name)
        logger.info(f'\nSecrets Manager Application\n'
                f'App Name: {app.name}\n'
                f'App UID: {app.uid}')

        if app.client_devices and len(app.client_devices) > 0:
            ksm_utils.print_client_device_info(app.client_devices)
        else:
            logger.info('\nNo client devices registered for this Application\n')

        if app.shared_secrets:
            ksm_utils.print_shared_secrets_info(app.shared_secrets)
        else:
            logger.info('\tThere are no shared secrets to this application')
        return
    
    
    def create_app(self, vault: vault_online.VaultOnline, name: str, force: Optional[bool] = False):
        app_uid = ksm_management.create_secrets_manager_app(vault=vault, name=name, force_add=force)
        logger.info(f'Application was successfully added (UID: {app_uid})')
    
    
    def remove_app(self, vault: vault_online.VaultOnline, uid_or_name: str, force: Optional[bool] = False):
        app_uid = ksm_management.remove_secrets_manager_app(vault=vault, uid_or_name=uid_or_name, force=force)
        logger.info(f'Application was successfully removed (UID: {app_uid})')
    
    def share_app(self, context: KeeperParams, uid_or_name: str, unshare: bool = False, 
                  email: Optional[str] = None, is_admin: Optional[bool] = False):
        """Share or unshare an application with a user."""
        self._validate_email_parameter(email)
        
        app_uid = self._find_app_uid(context.vault, uid_or_name)

        action = SHARE_ACTION_REVOKE if unshare else SHARE_ACTION_GRANT
        can_edit = is_admin and not unshare
        can_share = is_admin and not unshare

        success_responses, failed_responses = ksm_management.share_secrets_manager_app(
            vault=context.vault, enterprise=context.enterprise_data, app_uid=app_uid, emails=[email], action=action, can_edit=can_edit, can_share=can_share
        )
        if success_responses:
            logger.info(f'{len(success_responses)} share requests were successfully processed')
        if failed_responses:
            logger.error(f'{len(failed_responses)} share requests failed to process')
            for failed_response in failed_responses:
                logger.error(f'Failed to process share request: {failed_response}')

    def _validate_email_parameter(self, email: Optional[str]) -> None:
        """Validate that email parameter is provided."""
        if not email:
            raise ValueError("Email parameter is required for sharing. Use --email='user@example.com' to set it.")

    def _find_app_uid(self, vault: vault_online.VaultOnline, uid_or_name: str) -> str:
        """Find application UID by name or UID."""
        app_record = next(
            (r for r in vault.vault_data.records() 
             if r.record_uid == uid_or_name or r.title == uid_or_name), 
            None
        )
        
        if not app_record:
            raise ValueError(f'No application found with UID/Name: {uid_or_name}')
        
        return app_record.record_uid


class SecretsManagerClientCommand(base.ArgparseCommand):

    def __init__(self):
        self.parser = argparse.ArgumentParser(
            prog='secrets-manager-client',
            description='Keeper Secrets Manager (KSM) Client Commands'
        )
        SecretsManagerClientCommand.add_arguments_to_parser(self.parser)
        super().__init__(self.parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):

        parser.add_argument(
            '--command', type=str, action='store', dest='command',
            choices=[SecretsManagerCommand.ADD.value, SecretsManagerCommand.REMOVE.value], 
            help = f"One of: {SecretsManagerCommand.ADD.value}, {SecretsManagerCommand.REMOVE.value}"
        )
        parser.add_argument(
            '--app', '-a', type=str, action='store', help='Application Name or UID'
        )
        parser.add_argument(
            '--name', '-n', type=str, dest='name', action='store', required=False, help='client name'
        )
        parser.add_argument(
            '--client', '-i', type=str, dest='client_names_or_ids', action='append', required=False, 
            help='Client Name or ID. Use * or all to remove all clients'
        )
        parser.add_argument(
            '--unlock-ip', '-l', dest='unlockIp', action='store_true', help='Unlock IP Address.'
        )
        parser.add_argument(
            '--return-tokens', dest='returnTokens', action='store_true', help='Return Tokens'
        )
        parser.add_argument(
            '--secret', '-s', type=str, action='append', required=False, help='Record UID'
        )
        parser.add_argument(
            '--count', '-c', type=int, dest='count', action='store', 
            help='Number of tokens to return. Default: 1', default=1
        )
        parser.add_argument(
            '--first-access-expires-in-min', '-x', type=int, dest='firstAccessExpiresIn', action='store', 
            help='Time for the first request to expire in minutes from the time when this command is executed. '
                 'Maximum 1440 minutes (24 hrs). Default: 60', default=60
        )
        parser.add_argument(
            '-f', '--force', dest='force', action='store_true', help='Force add or remove app'
            )
        parser.add_argument(
            '--access-expire-in-min', '-p', type=int, dest='accessExpireInMin', action='store', 
            help='Time interval that this client can access the KSM application. After this time, access is denied. '
                 'Time is entered in minutes starting from the time when command is executed. Default: Not expiration'
        )
    
    def execute(self, context: KeeperParams, **kwargs) -> None:
        if not context.vault:
            raise ValueError("Vault is not initialized.")
        
        command = kwargs.get('command')
        if not command:
            return self.get_parser().print_help()
        
        uid = self._get_app_uid(context.vault, kwargs.get('app'))
        
        if command == SecretsManagerCommand.ADD.value:
            return self._handle_add_client(context, uid, kwargs)
        elif command == SecretsManagerCommand.REMOVE.value:
            return self._handle_remove_client(context.vault, uid, kwargs)
        else:
            available_commands = f"{SecretsManagerCommand.ADD.value}, {SecretsManagerCommand.REMOVE.value}"
            raise base.CommandError(f"Unknown command '{command}'. Available commands: {available_commands}")

    def _get_app_uid(self, vault, uid_or_name: Optional[str]) -> str:
        """Get application UID from name or UID."""
        if not uid_or_name:
            raise ValueError('Application UID or name is required. Use --app="uid_or_name".')
        
        ksm_app = next(
            (r for r in vault.vault_data.records() 
             if r.record_uid == uid_or_name or r.title == uid_or_name), 
            None
        )
        
        if not ksm_app:
            raise ValueError(f'No application found with UID/Name: {uid_or_name}')
        
        return ksm_app.record_uid

    def _handle_add_client(self, context: KeeperParams, uid: str, kwargs: dict) -> Optional[str]:
        """Handle add client command."""
        count = kwargs.get('count', DEFAULT_TOKEN_COUNT)
        unlock_ip = kwargs.get('unlockIp', False)
        client_name = kwargs.get('name')
        first_access_expire_in = kwargs.get('firstAccessExpiresIn', DEFAULT_FIRST_ACCESS_EXPIRES_IN_MINUTES)
        access_expire_in_min = kwargs.get('accessExpireInMin')
        is_return_tokens = kwargs.get('returnTokens', False)

        tokens_and_device = SecretsManagerClientCommand.add_client(
            vault=context.vault, 
            uid=uid, 
            count=count, 
            client_name=client_name, 
            unlock_ip=unlock_ip, 
            first_access_expire_duration=first_access_expire_in,
            access_expire_in_min=access_expire_in_min, 
            server=context.auth.keeper_endpoint.server
        )

        if is_return_tokens:
            tokens_only = [d['oneTimeToken'] for d in tokens_and_device]
            return ', '.join(tokens_only)
        
        return None

    def _handle_remove_client(self, vault, uid: str, kwargs: dict) -> None:
        """Handle remove client command."""
        client_names_or_ids = kwargs.get('client_names_or_ids')
        if not client_names_or_ids:
            raise ValueError('Client name or id is required. Example: --client="new client"')
        
        force = kwargs.get('force', False)

        if self._is_remove_all_clients(client_names_or_ids):
            SecretsManagerClientCommand.remove_all_clients(vault=vault, uid=uid, force=force)
        else:
            SecretsManagerClientCommand.remove_client(
                vault=vault, 
                uid=uid, 
                client_names_and_ids=client_names_or_ids, 
                force=force
            )

    def _is_remove_all_clients(self, client_names_or_ids: list) -> bool:
        """Check if remove all clients is requested."""
        return (len(client_names_or_ids) == 1 and 
                client_names_or_ids[0] in [WILDCARD_ALL, WILDCARD_ALL_ALIAS])

    @staticmethod
    def add_client(
            vault: vault_online.VaultOnline, 
            uid: str, 
            count: int, 
            client_name: str,  
            unlock_ip: bool, 
            first_access_expire_duration: int, 
            access_expire_in_min: Optional[int],
            server: str):
        """Add client devices to a KSM application."""
        current_time_ms = int(time.time() * MILLISECONDS_PER_SECOND)
        
        first_access_expire_duration_ms = (
            current_time_ms + first_access_expire_duration * MILLISECONDS_PER_MINUTE
        )
        access_expire_in_ms = (
            access_expire_in_min * MILLISECONDS_PER_MINUTE 
            if access_expire_in_min else None
        )
        
        master_key = vault.vault_data.get_record_key(record_uid=uid)
        tokens = []
        output_lines = []
        
        for i in range(count):
            token_data = ksm_management.KSMClientManagement.add_client_to_ksm_app(
                vault=vault,
                uid=uid,
                client_name=client_name,
                count=count,
                index=i,
                unlock_ip=unlock_ip,
                first_access_expire_duration_ms=first_access_expire_duration_ms,
                access_expire_in_ms=access_expire_in_ms,
                master_key=master_key,
                server=server
            )
            
            tokens.append(token_data['token_info'])
            output_lines.append(token_data['output_string'])
        
        one_time_access_token = ''.join(output_lines)
        SecretsManagerClientCommand._log_success_message(one_time_access_token)
        
        if not unlock_ip:
            SecretsManagerClientCommand._log_ip_lock_warning()
        
        return tokens

    @staticmethod
    def _log_success_message(output_string: str) -> None:
        """Log success message with generated client information."""
        logger.info(f'\nSuccessfully generated Client Device\n'
                   f'====================================\n'
                   f'{output_string}')

    @staticmethod
    def _log_ip_lock_warning() -> None:
        """Log warning about IP lock configuration."""
        logger.info("Warning: Configuration is now locked to your current IP. To keep in unlock you can add flag `--unlock-ip` "
                   "or use the One-time token to generate configuration on the host that has the IP that needs to be locked.")
        logger.warning('')

    @staticmethod
    def remove_all_clients(vault: vault_online.VaultOnline, uid: str, force: bool):
        """Remove all clients from a KSM application."""
        app_info = ksm_management.get_app_info(vault=vault, app_uid=uid)
        clients_count = len(app_info[0].clients)

        if clients_count == 0:
            logger.warning('No client devices registered for this Application\n')
            return

        if not force:
            if not SecretsManagerClientCommand._confirm_remove_all_clients(clients_count):
                return

        client_ids_to_remove = [
            utils.base64_url_encode(c.clientId) 
            for ai in app_info
            for c in ai.clients 
            if c.appClientType == GENERAL
        ]
        
        if client_ids_to_remove:
            SecretsManagerClientCommand.remove_client(
                vault=vault, 
                uid=uid, 
                client_names_and_ids=client_ids_to_remove, 
                force=force
            )

    @staticmethod
    def _confirm_remove_all_clients(clients_count: int) -> bool:
        """Confirm removal of all clients."""
        logger.info(f"This app has {clients_count} client(s) connections.")
        user_choice = prompt_utils.user_choice(
            'Are you sure you want to delete all clients from this application?', 
            'yn', 
            default=USER_CHOICE_DEFAULT_NO
        )
        return user_choice.lower() == USER_CHOICE_YES

    @staticmethod
    def remove_client(vault: vault_online.VaultOnline, uid: str, client_names_and_ids: List[str], force: bool = False):
        """Remove client devices from a KSM application."""
        ksm_management.KSMClientManagement.remove_clients_from_ksm_app(
            vault=vault, 
            uid=uid, 
            client_names_and_ids=client_names_and_ids, 
            callable=SecretsManagerClientCommand._confirm_remove_clients if not force else None
        )
        logger.info('\nClient removal was successful\n')

    @staticmethod
    def _confirm_remove_clients(clients_count: int) -> bool:
        """Confirm removal of clients."""
        user_choice = prompt_utils.user_choice(
            f'Are you sure you want to delete {clients_count} matching client(s) from this application?',
            'yn', 
            default=USER_CHOICE_DEFAULT_NO
        )
        return user_choice.lower() == USER_CHOICE_YES


class SecretsManagerShareCommand(base.ArgparseCommand):

    def __init__(self):
        self.parser = argparse.ArgumentParser(
            prog='secrets-manager-share',
            description='Keeper Secrets Manager (KSM) Share Commands'
        )
        SecretsManagerShareCommand.add_arguments_to_parser(self.parser)
        super().__init__(self.parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            '--command', type=str, action='store', dest='command',
            choices=[SecretsManagerCommand.ADD.value, SecretsManagerCommand.REMOVE.value],
            help=f"One of: {SecretsManagerCommand.ADD.value}, {SecretsManagerCommand.REMOVE.value}"
        )
        parser.add_argument(
            '--editable', '-e', action='store_true', required=False,
            help='Is this share going to be editable or not'
        )
        parser.add_argument(
            '--app', '-a', type=str, action='store', help='Application Name or UID'
        )
        parser.add_argument(
            '--secret', '-s', type=str, required=False,
            help='Record UID(s) - space separated (e.g., "uid1 uid2 uid3")'
        )

    def execute(self, context: KeeperParams, **kwargs) -> None:
        if not context.vault:
            raise ValueError("Vault is not initialized.")

        command = kwargs.get('command')
        if not command:
            return self.get_parser().print_help()

        app_uid = self._get_app_uid_from_kwargs(context.vault, kwargs.get('app'))
        secret_uids = self._parse_secret_uids(kwargs.get('secret'))

        if command == SecretsManagerCommand.ADD.value:
            is_editable = kwargs.get('editable', False)
            self._handle_add_share(context, app_uid, secret_uids, is_editable)
        elif command == SecretsManagerCommand.REMOVE.value:
            SecretsManagerShareCommand.remove_share(
                vault=context.vault, 
                app_uid=app_uid, 
                secret_uids=secret_uids
            )
        else:
            available_commands = f"{SecretsManagerCommand.ADD.value}, {SecretsManagerCommand.REMOVE.value}"
            raise base.CommandError(f"Unknown command '{command}'. Available commands: {available_commands}")

    def _get_app_uid_from_kwargs(self, vault, app_uid_or_name: Optional[str]) -> str:
        """Get application UID from kwargs."""
        if not app_uid_or_name:
            raise ValueError('Application UID or name is required. Use --app="uid_or_name".')

        ksm_app = self._find_ksm_application(vault, app_uid_or_name)
        if not ksm_app:
            raise ValueError(f'No application found with UID/Name: {app_uid_or_name}')
        
        return ksm_app.record_uid

    def _parse_secret_uids(self, secret_uids_str: Optional[str]) -> List[str]:
        """Parse secret UIDs from string."""
        if not secret_uids_str:
            return []
        return [uid.strip() for uid in secret_uids_str.split() if uid.strip()]

    def _find_ksm_application(self, vault: vault_online.VaultOnline, app_uid_or_name: str):
        return next(
            (r for r in vault.vault_data.records() 
             if r.record_uid == app_uid_or_name or r.title == app_uid_or_name), 
            None
        )

    def _handle_add_share(self, context: KeeperParams, app_uid: str, secret_uids: List[str], is_editable: bool) -> None:
        """Handle adding shares to a KSM application."""
        if not context.vault:
            raise ValueError("Vault is not initialized.")
            
        master_key = self._get_master_key(context.vault, app_uid)
        
        try:
            added_secret_info = ksm_management.KSMShareManagement.add_secrets_to_ksm_app(
                vault=context.vault, 
                enterprise=context.enterprise_data,
                app_uid=app_uid, 
                secret_uids=secret_uids, 
                master_key=master_key, 
                is_editable=is_editable
            )
            if added_secret_info:
                SecretsManagerShareCommand._log_share_success(app_uid, is_editable, added_secret_info)
        except base.errors.KeeperApiError as kae:
            SecretsManagerShareCommand._handle_share_error(kae)

    def _get_master_key(self, vault, app_uid: str) -> bytes:
        """Get master key for application."""
        master_key = vault.vault_data.get_record_key(record_uid=app_uid)
        if not master_key:
            raise ValueError(f"Could not retrieve master key for application {app_uid}")
        return master_key

    @staticmethod
    def _log_share_success(app_uid: str, is_editable: bool, added_secret_info: list) -> None:
        """Log successful share operation."""
        logger.info(f'\nSuccessfully added secrets to app uid={app_uid}, editable={is_editable}:')
        for secret_uid, secret_type in added_secret_info:
            logger.info(f'{secret_uid} \t{secret_type}')

    @staticmethod
    def _handle_share_error(kae: base.errors.KeeperApiError) -> bool:
        """Handle share request errors."""
        if kae.message == 'Duplicate share, already added':
            logger.error(
                "One of the secret UIDs is already shared to this application. "
                "Please remove already shared UIDs from your command and try again."
            )
            return False
        else:
            raise ValueError(f"Failed to share secrets: {kae}")

    @staticmethod
    def remove_share(vault: vault_online.VaultOnline, app_uid: str, secret_uids: List[str]) -> None:
        """Remove shares from a KSM application."""
        if not secret_uids:
            logger.warning("No secret UIDs provided for removal.")
            return

        current_shared_uids = SecretsManagerShareCommand._get_current_shared_uids(vault, app_uid)
        valid_uids, invalid_uids = SecretsManagerShareCommand._validate_share_uids(
            secret_uids, current_shared_uids
        )

        SecretsManagerShareCommand._log_invalid_uids(invalid_uids)

        if not valid_uids:
            logger.warning(
                "None of the provided secret UIDs are shared with this application. Nothing to remove."
            )
            return

        ksm_management.KSMShareManagement.remove_secrets_from_ksm_app(vault, app_uid, valid_uids)
        logger.info("Shared secrets were successfully removed from the application\n")

    @staticmethod
    def _get_current_shared_uids(vault: vault_online.VaultOnline, app_uid: str) -> Set:
        """Get currently shared UIDs for the application."""
        app_infos = ksm_management.get_app_info(vault=vault, app_uid=app_uid)
        if not app_infos:
            raise ValueError(f"Could not retrieve application info for UID: {app_uid}")
        
        app_info = app_infos[0]
        return {
            utils.base64_url_encode(share.secretUid) 
            for share in getattr(app_info, 'shares', [])
        }

    @staticmethod
    def _validate_share_uids(secret_uids: List[str], current_shared_uids: Set) -> Tuple[List, List]:
        """Validate secret UIDs against currently shared UIDs."""
        valid_uids = [uid for uid in secret_uids if uid in current_shared_uids]
        invalid_uids = [uid for uid in secret_uids if uid not in current_shared_uids]
        return valid_uids, invalid_uids

    @staticmethod
    def _log_invalid_uids(invalid_uids: List[str]) -> None:
        """Log warnings for invalid UIDs."""
        for uid in invalid_uids:
            logger.warning(f"Secret UID '{uid}' is not shared with this application. Skipping.")
