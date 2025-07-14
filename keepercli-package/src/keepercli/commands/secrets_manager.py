import argparse
from enum import Enum
from typing import Optional

from keepersdk.vault import ksm_management, vault_online

from . import base
from .share_management import ShareAction, ShareRecordCommand, ShareFolderCommand
from .. import api
from ..helpers import ksm_utils, report_utils, share_utils
from ..params import KeeperParams


logger = api.get_logger()


class SecretsManagerCommand(Enum):
    LIST = "list"
    GET = "get"
    CREATE = "create"
    REMOVE = "remove"
    SHARE = "share"
    UNSHARE = "unshare"


class SecretsManagerAppCommand(base.ArgparseCommand):

    def __init__(self):
        self.parser = argparse.ArgumentParser(
            prog='secrets-manager app',
            description='Keeper Secrets Manager (KSM) Commands',
        )
        SecretsManagerAppCommand.add_arguments_to_parser(self.parser)
        super().__init__(self.parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):

        parser.add_argument(
            '--command', type=str, action='store', required=True, dest='command',
            choices=[cmd.value for cmd in SecretsManagerCommand],
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

        vault = context.vault
        command = kwargs.get('command')
        uid_or_name = kwargs.get('name')
        force = kwargs.get('force')
        email = kwargs.get('email')
        is_admin = kwargs.get('admin', False)

        if not command:
            raise ValueError("Command is required. Available commands: list, get, create, remove, share, unshare")

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
            "emails": emails,
            "uid": app_uid,
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
        app_info = ksm_management.get_secrets_manager_app(vault=vault, uid_or_name=uid)
        if not app_info:
            return
            
        # Separate shared records and folders
        shared_recs, shared_folders = SecretsManagerAppCommand._separate_shared_items(
            vault, app_info.shared_secrets
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
        share_uids = [secret.uid for secret in shared_secrets]
        record_cache = {x.record_uid: x for x in vault.vault_data.records()}
        
        shared_recs = [uid for uid in share_uids if uid in record_cache]
        shared_folders = [uid for uid in share_uids if uid not in shared_recs]
        
        if shared_recs:
            share_utils.get_record_shares(vault=vault, record_uids=shared_recs, is_share_admin=False)
            
        return shared_recs, shared_folders

    @staticmethod
    def _process_share_updates(context: KeeperParams, vault: vault_online.VaultOnline, 
                             user_perms: list, shared_recs: list, shared_folders: list, removed: bool):
        """Process share updates for users."""
        # Get admin and viewer users
        admins = [up.get('username') for up in user_perms if up.get('editable')]
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
            sf_requests.extend(folder_requests)
            
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
        if removed:
            return False
            
        # Get the share information for records
        record_share_info = share_utils.get_record_shares(vault=vault, record_uids=share_uids, is_share_admin=False)
        record_permissions = {}
        if record_share_info:
            for record_info in record_share_info:
                record_uid = record_info.get('record_uid')
                if record_uid:
                    record_permissions[record_uid] = record_info.get('shares', {}).get('user_permissions', [])
        
        record_cache = {x.record_uid: x for x in vault.vault_data.records()}
        shared_folder_cache = {x.shared_folder_uid: x for x in vault.vault_data.shared_folders()}
        
        for share_uid in share_uids:
            is_rec_share = share_uid in record_cache
            
            if is_rec_share:
                # Use the permissions we fetched above
                share_user_permissions = record_permissions.get(share_uid, [])
            else:
                # For shared folders, get users from the folder object
                folder_obj = shared_folder_cache.get(share_uid)
                if folder_obj and hasattr(folder_obj, 'users'):
                    share_user_permissions = getattr(folder_obj, 'users', [])
                else:
                    share_user_permissions = []
                
            # Check if user already has permissions
            if not any(up.get('username') == user for up in share_user_permissions if isinstance(up, dict)):
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
                    request = ShareFolderCommand.prepare_request(
                        vault=vault,
                        kwargs={'action': sf_action},
                        curr_sf={'shared_folder_uid': folder_uid, 'users': [], 'teams': [], 'records': []},
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
