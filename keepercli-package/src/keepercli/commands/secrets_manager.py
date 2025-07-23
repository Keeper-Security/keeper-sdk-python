import argparse
import datetime
from enum import Enum
import hmac
import os
import time
from typing import Optional
from urllib import parse

from keepersdk import crypto, utils
from keepersdk.proto.APIRequest_pb2 import AddAppClientRequest, Device, RemoveAppClientsRequest, AppShareAdd, ApplicationShareType, AddAppSharesRequest, RemoveAppSharesRequest
from keepersdk.proto.enterprise_pb2 import GENERAL
from keepersdk.vault import ksm_management, vault_online

from . import base
from .share_management import ShareAction, ShareFolderCommand, ShareRecordCommand
from .. import api, constants, prompt_utils
from ..helpers import ksm_utils, report_utils, share_utils
from ..params import KeeperParams


logger = api.get_logger()
CLIENT_ADD_URL = 'vault/app_client_add'
CLIENT_REMOVE_URL = 'vault/app_client_remove'
SHARE_ADD_URL = 'vault/app_share_add'
SHARE_REMOVE_URL = 'vault/app_share_remove'


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
            prog='secrets-manager app',
            description='Keeper Secrets Manager (KSM) App Commands',
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
            '--app', '-n', type=str, dest='app', action='store', help='Application Name or UID'
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

        vault = context.vault
        command = kwargs.get('command')
        uid_or_name = kwargs.get('app')
        force = kwargs.get('force')
        email = kwargs.get('email')
        is_admin = kwargs.get('admin', False)

        if not command:
            return self.get_parser().print_help()

        if command != SecretsManagerCommand.LIST.value and not uid_or_name:
            raise ValueError("Application name or UID is required. Use --name='example' to set it.")

        def list_app():
            return self.list_app(vault=vault)

        def get_app():
            return self.get_app(vault=vault, uid_or_name=uid_or_name)

        def create_app():
            self.create_app(vault=vault, name=uid_or_name, force=force)
            return context.vault_down()

        def remove_app():
            self.remove_app(vault=vault, uid_or_name=uid_or_name, force=force)
            return
        
        def share_app():
            self.share_app(context=context, uid_or_name=uid_or_name, unshare=False, email=email, is_admin=is_admin)
            return context.vault_down()
        
        def unshare_app():
            self.share_app(context=context, uid_or_name=uid_or_name, unshare=True, email=email, is_admin=is_admin)
            return context.vault_down()

        command_map = {
            SecretsManagerCommand.LIST.value: list_app,
            SecretsManagerCommand.GET.value: get_app,
            SecretsManagerCommand.CREATE.value: create_app,
            SecretsManagerCommand.ADD.value: create_app,
            SecretsManagerCommand.REMOVE.value: remove_app,
            SecretsManagerCommand.SHARE.value: share_app,
            SecretsManagerCommand.UNSHARE.value: unshare_app
        }
            
        action = command_map.get(command)
        if action:
            return action()
        else:
            raise ValueError(f"Unknown command '{command}'. Available commands: {', '.join([cmd.value for cmd in SecretsManagerCommand])}")


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
        if not email:
            raise ValueError("Email parameter is required for sharing. Use --email='user@example.com' to set it.")
            
        app_record = next((r for r in context.vault.vault_data.records() if r.record_uid == uid_or_name or r.title == uid_or_name), None)
        
        if not app_record:
            raise ValueError(f'No application found with UID/Name: {uid_or_name}')
        
        app_uid = app_record.record_uid
        action = ShareAction.REVOKE.value if unshare else ShareAction.GRANT.value
        emails = [email]
        can_edit=is_admin and not unshare
        can_share=is_admin and not unshare
        args = {
            "action": action,
            "email": emails,
            "record": app_uid,
            "can_edit": can_edit,
            "can_share": can_share
        }
        
        share_record_command = ShareRecordCommand()
        share_record_command.execute(context=context, **args)
        
        context.vault.sync_down()
        
        SecretsManagerAppCommand.update_shares_user_permissions(context=context, uid=app_uid, removed=unshare)

    @staticmethod
    def update_shares_user_permissions(context: KeeperParams, uid: str, removed: bool):
        
        vault = context.vault

        # Get user permissions for the app
        user_perms = SecretsManagerAppCommand._get_app_user_permissions(vault, uid)
        
        # Get app info and shared secrets
        app_infos = ksm_management.get_app_info(vault=vault, app_uid=uid)
        app_info = app_infos[0]
        if not app_info:
            return
            
        # Separate shared records and folders
        shared_recs, shared_folders = SecretsManagerAppCommand._separate_shared_items(
            vault, app_info.shares
        )
        
        # Create share requests for users that need updates
        SecretsManagerAppCommand._process_share_updates(
            context, vault, user_perms, shared_recs, shared_folders, removed
        )

    @staticmethod
    def _get_app_user_permissions(vault: vault_online.VaultOnline, uid: str) -> list:
        """Get user permissions for the application."""
        share_info = share_utils.get_record_shares(vault=vault, record_uids=[uid], is_share_admin=False)
        user_perms = []
        if share_info:
            for record_info in share_info:
                if record_info.get('record_uid') == uid:
                    user_perms = record_info.get('shares', {}).get('user_permissions', [])
                    break
        return user_perms

    @staticmethod
    def _separate_shared_items(vault: vault_online.VaultOnline, shared_secrets):
        """Separate shared secrets into records and folders."""
        from keepersdk.proto.APIRequest_pb2 import ApplicationShareType
        from keepersdk import utils
        shared_recs = []
        shared_folders = []
        for share in shared_secrets:
            uid_str = utils.base64_url_encode(share.secretUid)
            share_type = ApplicationShareType.Name(share.shareType)
            if share_type == 'SHARE_TYPE_RECORD':
                shared_recs.append(uid_str)
            elif share_type == 'SHARE_TYPE_FOLDER':
                shared_folders.append(uid_str)
        
        if shared_recs:
            share_utils.get_record_shares(vault=vault, record_uids=shared_recs, is_share_admin=False)
            
        return shared_recs, shared_folders

    @staticmethod
    def _process_share_updates(context: KeeperParams, vault: vault_online.VaultOnline, 
                             user_perms: list, shared_recs: list, shared_folders: list, removed: bool):
        """Process share updates for users."""
        # Get admin and viewer users
        admins = [up.get('username') for up in user_perms if up.get('editable')]
        admins = [x for x in admins if x != vault.keeper_auth.auth_context.username]
        viewers = [up.get('username') for up in user_perms if not up.get('editable')]
        app_users_map = dict(admins=admins, viewers=viewers)
        
        # Create share requests
        sf_requests = []
        rec_requests = []
        
        for group, users in app_users_map.items():
            users_needing_update = [
                u for u in users 
                if SecretsManagerAppCommand._user_needs_update(vault, u, shared_recs + shared_folders, removed)
            ]
            
            if not users_needing_update:
                continue
                
            # Process folder share requests
            folder_requests = SecretsManagerAppCommand._create_folder_share_requests(
                vault, shared_folders, users_needing_update, removed
            )
            sf_requests.append(folder_requests)
            
            # Process record share requests
            record_requests = SecretsManagerAppCommand._create_record_share_requests(
                context, shared_recs, users_needing_update, removed
            )
            rec_requests.extend(record_requests)

        if sf_requests:
            ShareFolderCommand.send_requests(vault, sf_requests)
        if rec_requests:
            ShareRecordCommand.send_requests(vault, rec_requests)
        logger.info("Share updates processed successfully")

    @staticmethod
    def _user_needs_update(vault: vault_online.VaultOnline, user: str, share_uids: list, removed: bool) -> bool:
        """Check if a user needs share permission updates."""
        # Get the share information for records
        record_share_info = share_utils.get_record_shares(vault=vault, record_uids=share_uids, is_share_admin=False)
        record_permissions = {}
        if record_share_info:
            for record_info in record_share_info:
                record_uid = record_info.get('record_uid')
                if record_uid:
                    record_permissions[record_uid] = record_info.get('shares', {}).get('user_permissions', [])
        
        record_cache = {x.record_uid: x for x in vault.vault_data.records()}
        
        for share_uid in share_uids:
            is_rec_share = share_uid in record_cache
            
            if is_rec_share:
                # Use the permissions we fetched above
                share_user_permissions = record_permissions.get(share_uid, [])
            else:
                # For shared folders, get users from the folder object
                shared_folder_obj = vault.vault_data.load_shared_folder(shared_folder_uid=share_uid)
                if shared_folder_obj and shared_folder_obj.user_permissions:
                    share_user_permissions = shared_folder_obj.user_permissions
                else:
                    share_user_permissions = []
                
            user_permissions_set = {up.get('username') for up in share_user_permissions if isinstance(up, dict)}
            if user not in user_permissions_set:
                return True
        return False

    @staticmethod
    def _create_folder_share_requests(vault: vault_online.VaultOnline, shared_folders: list, 
                                    users: list, removed: bool) -> list:
        """Create folder share requests."""
        if not shared_folders:
            return []
            
        sf_action = ShareAction.REMOVE.value if removed else ShareAction.GRANT.value
        
        requests = []
        for folder_uid in shared_folders:
            for user in users:
                if SecretsManagerAppCommand._user_needs_update(vault, user, [folder_uid], removed):
                    sh_fol = vault.vault_data.load_shared_folder(folder_uid)
                    shared_folder_revision = vault.vault_data.storage.shared_folders.get_entity(folder_uid).revision
                    sf_unencrypted_key = vault.vault_data.get_shared_folder_key(shared_folder_uid=folder_uid)
                    sf_info = {
                        'shared_folder_uid': folder_uid,
                        'users': sh_fol.user_permissions,
                        'teams': [],
                        'records': sh_fol.record_permissions,
                        'shared_folder_key_unencrypted': sf_unencrypted_key,
                        'default_manage_users': sh_fol.default_can_share,
                        'default_manage_records': sh_fol.default_can_edit,
                        'revision': shared_folder_revision
                    }
                    request = ShareFolderCommand.prepare_request(
                        vault=vault,
                        kwargs={'action': sf_action},
                        curr_sf=sf_info,
                        users=[user],
                        teams=[],
                        rec_uids=[],
                        default_record=False,
                        default_account=False,
                        share_expiration=-1
                    )
                    requests.append(request)
        return requests

    @staticmethod
    def _create_record_share_requests(context: KeeperParams, shared_recs: list, 
                                    users: list, removed: bool) -> list:
        """Create record share requests."""
        if not shared_recs or not context.vault:
            return []
            
        rec_action = ShareAction.REVOKE.value if removed else ShareAction.GRANT.value
        
        requests = []
        for record_uid in shared_recs:
            for user in users:
                if SecretsManagerAppCommand._user_needs_update(context.vault, user, [record_uid], removed):
                    request = ShareRecordCommand.prep_request(
                        context=context,
                        emails=[user],
                        action=rec_action,
                        uid_or_name=record_uid,
                        share_expiration=-1,
                        dry_run=False,
                        can_edit=False,
                        can_share=False
                    )
                    requests.append(request)
        return requests


class SecretsManagerClientCommand(base.ArgparseCommand):

    def __init__(self):
        self.parser = argparse.ArgumentParser(
            prog='secrets-manager-client',
            description='Keeper Secrets Manager (KSM) Client Commands',
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
        
        vault = context.vault
        command = kwargs.get('command')
        uid_or_name = kwargs.get('app')
        
        if not command:
            return self.get_parser().print_help()
        
        if not uid_or_name:
            raise ValueError('Application UID or name is required. Use --app="uid_or_name".')
        
        ksm_app = next((r for r in vault.vault_data.records() if r.record_uid == uid_or_name or r.title == uid_or_name), None)
        if not ksm_app:
            raise ValueError(f'No application found with UID/Name: {uid_or_name}')
        uid = ksm_app.record_uid
        
        if command == SecretsManagerCommand.ADD.value:
            count = kwargs.get('count', 1)
            unlock_ip = kwargs.get('unlockIp', False)

            client_name = kwargs.get('name')

            first_access_expire_in = kwargs.get('firstAccessExpiresIn', 60)
            access_expire_in_min = kwargs.get('accessExpireInMin')

            is_return_tokens = kwargs.get('returnTokens', False)

            tokens_and_device = SecretsManagerClientCommand.add_client(
                vault=vault, uid=uid, count=count, client_name=client_name, 
                unlock_ip=unlock_ip, first_access_expire_duration=first_access_expire_in, 
                access_expire_in_min=access_expire_in_min, server=context.server
            )

            tokens_only = [d['oneTimeToken'] for d in tokens_and_device]

            return ', '.join(tokens_only) if is_return_tokens else None
        
        elif command == SecretsManagerCommand.REMOVE.value:
            client_names_or_ids = kwargs.get('client_names_or_ids')
            if not client_names_or_ids:
                raise ValueError('Client name or id is required. Example: --client="new client"')
            
            force = kwargs.get('force', False)

            if len(client_names_or_ids) == 1 and client_names_or_ids[0] in ['*', 'all']:
                SecretsManagerClientCommand.remove_all_clients(vault=vault, uid=uid, force=force)
            else:
                SecretsManagerClientCommand.remove_client(vault=vault, uid=uid, client_names_and_ids=client_names_or_ids, force=force)

            return
    
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
        
        current_time_ms = int(time.time( ) * 1000)
        
        first_access_expire_duration_ms = current_time_ms + first_access_expire_duration * 60 * 1000
        access_expire_in_ms = None
        if access_expire_in_min:
            access_expire_in_ms = access_expire_in_min * 60 * 1000
        
        master_key = vault.vault_data.get_record_key(record_uid=uid)
        
        tokens = []
        output_lines = []
        
        for i in range(count):
            token_data = SecretsManagerClientCommand._generate_single_client(
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
    def _generate_single_client(
            vault: vault_online.VaultOnline,
            uid: str,
            client_name: str,
            count: int,
            index: int,
            unlock_ip: bool,
            first_access_expire_duration_ms: int,
            access_expire_in_ms: Optional[int],
            master_key: bytes,
            server: str) -> dict:
        """Generate a single client device and return token info and output string."""
        
        # Generate secret and client ID
        secret_bytes = os.urandom(32)
        client_id = SecretsManagerClientCommand._generate_client_id(secret_bytes)
        
        encrypted_master_key = crypto.encrypt_aes_v2(master_key, secret_bytes)
        
        # Create and send request
        device = SecretsManagerClientCommand._create_client_request(
            vault=vault,
            uid=uid,
            encrypted_master_key=encrypted_master_key,
            unlock_ip=unlock_ip,
            first_access_expire_duration_ms=first_access_expire_duration_ms,
            access_expire_in_ms=access_expire_in_ms,
            client_id=client_id,
            client_name=client_name,
            count=count,
            index=index
        )
        
        # Generate token with server prefix
        token_with_prefix = SecretsManagerClientCommand._generate_token_with_prefix(
            secret_bytes=secret_bytes,
            server=server
        )
        
        output_string = SecretsManagerClientCommand._create_output_string(
            token_with_prefix=token_with_prefix,
            client_name=client_name,
            unlock_ip=unlock_ip,
            first_access_expire_duration_ms=first_access_expire_duration_ms,
            access_expire_in_ms=access_expire_in_ms
        )
        
        return {
            'token_info': {
                'oneTimeToken': token_with_prefix,
                'deviceToken': utils.base64_url_encode(device.encryptedDeviceToken)
            },
            'output_string': output_string
        }

    @staticmethod
    def _generate_client_id(secret_bytes: bytes) -> bytes:
        """Generate client ID using HMAC."""
        counter_bytes = b'KEEPER_SECRETS_MANAGER_CLIENT_ID'
        digest = 'sha512'
        
        try:
            return hmac.new(secret_bytes, counter_bytes, digest).digest()
        except Exception as e:
            logger.error(e)
            raise

    @staticmethod
    def _create_client_request(
            vault: vault_online.VaultOnline,
            uid: str,
            encrypted_master_key: bytes,
            unlock_ip: bool,
            first_access_expire_duration_ms: int,
            access_expire_in_ms: Optional[int],
            client_id: bytes,
            client_name: str,
            count: int,
            index: int) -> Device:
        """Create and send client request to server."""
        
        request = AddAppClientRequest()
        request.appRecordUid = utils.base64_url_decode(uid)
        request.encryptedAppKey = encrypted_master_key
        request.lockIp = not unlock_ip
        request.firstAccessExpireOn = first_access_expire_duration_ms
        request.appClientType = GENERAL
        request.clientId = client_id
        
        if access_expire_in_ms:
            request.accessExpireOn = access_expire_in_ms
        
        if client_name:
            request.id = client_name if count == 1 else f"{client_name} {index + 1}"
        
        device = vault.keeper_auth.execute_auth_rest(
            rest_endpoint=CLIENT_ADD_URL, 
            request=request, 
            response_type=Device
        )
        
        if not device or not device.encryptedDeviceToken:
            raise ValueError("Failed to create client device - no device token received")
        
        return device

    @staticmethod
    def _generate_token_with_prefix(secret_bytes: bytes, server: str) -> str:
        """Generate token with server prefix."""
        token = utils.base64_url_encode(secret_bytes)
        
        # Get server abbreviation
        abbrev = constants.get_abbrev_by_host(server)
        
        if abbrev:
            return f'{abbrev}:{token}'
        else:
            tmp_server = server if server.startswith(('http://', 'https://')) else f"https://{server}"
            
            return f'{parse.urlparse(tmp_server).netloc.lower()}:{token}'

    @staticmethod
    def _create_output_string(
            token_with_prefix: str,
            client_name: str,
            unlock_ip: bool,
            first_access_expire_duration_ms: int,
            access_expire_in_ms: Optional[int]) -> str:
        """Create formatted output string for logging."""
        
        output_lines = [f'\nOne-Time Access Token: {token_with_prefix}']
        
        if client_name:
            output_lines.append(f'Name: {client_name}')
        
        ip_lock = 'Disabled' if unlock_ip else 'Enabled'
        output_lines.append(f'IP Lock: {ip_lock}')
        
        try:
            exp_date_str = datetime.datetime.fromtimestamp(
                first_access_expire_duration_ms / 1000
            ).strftime('%Y-%m-%d %H:%M:%S')
        except (OSError, ValueError) as e:
            exp_date_str = 'Invalid timestamp'
        output_lines.append(f'Token Expires On: {exp_date_str}')
        
        if access_expire_in_ms:
            app_expire_on_str = datetime.datetime.fromtimestamp(
                access_expire_in_ms / 1000
            ).strftime('%Y-%m-%d %H:%M:%S')
        else:
            app_expire_on_str = "Never"
        
        output_lines.append(f'App Access Expires on: {app_expire_on_str}')
        
        return '\n'.join(output_lines)

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

        app_info = ksm_management.get_app_info(vault=vault, app_uid=uid)

        clients_count = len(app_info[0].clients)

        if clients_count == 0:
            logger.warning('No client devices registered for this Application\n')
            return

        if not force:
            logger.info(f"This app has {clients_count} client(s) connections.")
            uc = prompt_utils.user_choice('Are you sure you want to delete all clients from this application?', 'yn', default='n')
            if uc.lower() != 'y':
                return

        client_ids_to_remove = [utils.base64_url_encode(c.clientId) for ai in app_info
                             for c in ai.clients if c.appClientType == GENERAL]
        
        if len(client_ids_to_remove) > 0:
            SecretsManagerClientCommand.remove_client(vault=vault, uid=uid, client_names_and_ids=client_ids_to_remove, force=force)

    @staticmethod
    def remove_client(vault: vault_online.VaultOnline, uid: str, client_names_and_ids: list[str], force=False):

        def convert_ids_and_hashes_to_hashes(client_names_and_ids, uid):
            exact_matches = set()
            partial_matches = set()
            
            for name in client_names_and_ids:
                if len(name) >= ksm_management.CLIENT_SHORT_ID_LENGTH:
                    partial_matches.add(name)
                else:
                    exact_matches.add(name)
            
            client_id_hashes_bytes = []
            app_infos = ksm_management.get_app_info(vault=vault, app_uid=uid)
            app_info = app_infos[0]
            
            for client in app_info.clients:
                if client.id in exact_matches:
                    client_id_hashes_bytes.append(client.clientId)
                    continue
                
                if partial_matches:
                    client_id = utils.base64_url_encode(client.clientId)
                    for partial_name in partial_matches:
                        if client_id.startswith(partial_name):
                            client_id_hashes_bytes.append(client.clientId)
                            break
            
            return client_id_hashes_bytes

        client_hashes = convert_ids_and_hashes_to_hashes(client_names_and_ids=client_names_and_ids, uid=uid)

        found_clients_count = len(client_hashes)
        if found_clients_count == 0:
            logger.warning('No Client Devices found with given name or ID\n')
            return
        elif not force:
            uc = prompt_utils.user_choice(f'Are you sure you want to delete {found_clients_count} matching client(s) from this application?',
                             'yn', default='n')
            if uc.lower() != 'y':
                return

        request = RemoveAppClientsRequest()

        request.appRecordUid = utils.base64_url_decode(uid)
        request.clients.extend(client_hashes)
        vault.keeper_auth.execute_auth_rest(rest_endpoint=CLIENT_REMOVE_URL, request=request)
        logger.info('\nClient removal was successful\n')


class SecretsManagerShareCommand(base.ArgparseCommand):

    def __init__(self):
        self.parser = argparse.ArgumentParser(
            prog='secrets-manager-share',
            description='Keeper Secrets Manager (KSM) Share Commands',
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
            help='Is this share going to be editable or not.'
        )
        parser.add_argument(
            '--app', '-a', type=str, action='store', help='Application Name or UID'
        )
        parser.add_argument(
            '--secret', '-s', type=str, action='append', required=False,
            help='Record UID(s)'
        )

    def execute(self, context: KeeperParams, **kwargs) -> None:
        if not context.vault:
            raise ValueError("Vault is not initialized.")

        vault = context.vault
        command = kwargs.get('command')
        app_uid_or_name = kwargs.get('app')
        secret_uids = kwargs.get('secret')

        if not command:
            return self.get_parser().print_help()

        if not app_uid_or_name:
            raise ValueError('Application UID or name is required. Use --app="uid_or_name".')

        ksm_app = self._find_ksm_application(vault, app_uid_or_name)
        if not ksm_app:
            raise ValueError(f'No application found with UID/Name: {app_uid_or_name}')
        
        app_uid = ksm_app.record_uid

        if command == SecretsManagerCommand.ADD.value:
            is_editable = kwargs.get('editable', False)
            self._handle_add_share(context, app_uid, secret_uids, is_editable)
        elif command == SecretsManagerCommand.REMOVE.value:
            SecretsManagerShareCommand.remove_share(vault=vault, app_uid=app_uid, secret_uids=secret_uids)

    def _find_ksm_application(self, vault: vault_online.VaultOnline, app_uid_or_name: str):
        return next(
            (r for r in vault.vault_data.records() 
             if r.record_uid == app_uid_or_name or r.title == app_uid_or_name), 
            None
        )

    def _handle_add_share(self, context: KeeperParams, app_uid: str, secret_uids: list[str], is_editable: bool) -> None:
        if not context.vault:
            raise ValueError("Vault is not initialized.")
            
        master_key = context.vault.vault_data.get_record_key(record_uid=app_uid)
        if not master_key:
            raise ValueError(f"Could not retrieve master key for application {app_uid}")

        success = SecretsManagerShareCommand.share_secret(
            vault=context.vault, 
            app_uid=app_uid, 
            secret_uids=secret_uids, 
            master_key=master_key, 
            is_editable=is_editable
        )

        if success:
            context.vault.sync_down()
            SecretsManagerAppCommand.update_shares_user_permissions(context=context, uid=app_uid, removed=False)

    @staticmethod
    def share_secret(vault: vault_online.VaultOnline, app_uid: str, master_key: bytes, 
                    secret_uids: list[str], is_editable: bool = False) -> bool:
        if not secret_uids:
            logger.warning("No secret UIDs provided for sharing.")
            return False

        app_shares = []
        added_secret_info = []

        for secret_uid in secret_uids:
            share_info = SecretsManagerShareCommand._process_secret(
                vault, secret_uid, master_key, is_editable
            )
            
            if share_info:
                app_shares.append(share_info['app_share'])
                added_secret_info.append(share_info['secret_info'])

        if not added_secret_info:
            logger.warning("No valid secrets found to share.")
            return False

        return SecretsManagerShareCommand._send_share_request(
            vault, app_uid, app_shares, added_secret_info, is_editable
        )

    @staticmethod
    def _process_secret(vault: vault_online.VaultOnline, secret_uid: str, 
                              master_key: bytes, is_editable: bool) -> Optional[dict]:
        is_record = secret_uid in vault.vault_data._records
        is_shared_folder = secret_uid in vault.vault_data._shared_folders

        if is_record:
            share_key_decrypted = vault.vault_data.get_record_key(record_uid=secret_uid)
            share_type = ApplicationShareType.SHARE_TYPE_RECORD
            secret_type_name = 'Record'
        elif is_shared_folder:
            share_key_decrypted = vault.vault_data.get_shared_folder_key(shared_folder_uid=secret_uid)
            share_type = ApplicationShareType.SHARE_TYPE_FOLDER
            secret_type_name = 'Shared Folder'
        else:
            logger.error(
                f"UID='{secret_uid}' is not a Record nor Shared Folder. "
                "Only individual records or Shared Folders can be added to the application. "
                "Make sure your local cache is up to date by running 'sync-down' command and trying again."
            )
            return None

        if not share_key_decrypted:
            logger.error(f"Could not retrieve key for secret {secret_uid}")
            return None

        app_share = AppShareAdd()
        app_share.secretUid = utils.base64_url_decode(secret_uid)
        app_share.shareType = share_type
        app_share.encryptedSecretKey = crypto.encrypt_aes_v2(share_key_decrypted, master_key)
        app_share.editable = is_editable

        return {
            'app_share': app_share,
            'secret_info': (secret_uid, secret_type_name)
        }

    @staticmethod
    def _send_share_request(vault: vault_online.VaultOnline, app_uid: str, 
                          app_shares: list, added_secret_info: list, is_editable: bool) -> bool:
        """Send the share request to the server."""
        request = AddAppSharesRequest()
        request.appRecordUid = utils.base64_url_decode(app_uid)
        request.shares.extend(app_shares)

        try:
            vault.keeper_auth.execute_auth_rest(rest_endpoint=SHARE_ADD_URL, request=request)
            
            logger.info(f'\nSuccessfully added secrets to app uid={app_uid}, editable={is_editable}:')
            for secret_uid, secret_type in added_secret_info:
                logger.info(f'{secret_uid} \t{secret_type}')
            logger.info('')
            return True
            
        except base.errors.KeeperApiError as kae:
            if kae.message == 'Duplicate share, already added':
                logger.error(
                    "One of the secret UIDs is already shared to this application. "
                    "Please remove already shared UIDs from your command and try again."
                )
            else:
                logger.error(f"Failed to share secrets: {kae}")
            return False

    @staticmethod
    def remove_share(vault: vault_online.VaultOnline, app_uid: str, secret_uids: list[str]) -> None:
        """Remove shares from a KSM application."""
        if not secret_uids:
            logger.warning("No secret UIDs provided for removal.")
            return

        request = RemoveAppSharesRequest()
        request.appRecordUid = utils.base64_url_decode(app_uid)
        request.shares.extend(utils.base64_url_decode(uid) for uid in secret_uids)
        
        try:
            vault.keeper_auth.execute_auth_rest(rest_endpoint=SHARE_REMOVE_URL, request=request)
            logger.info("Shared secrets were successfully removed from the application\n")
        except Exception as e:
            logger.error(f"Failed to remove shared secrets: {e}")
            raise