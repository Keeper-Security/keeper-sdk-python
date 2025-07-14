import argparse
from itertools import groupby, product
from typing import Optional

from keepersdk.vault import ksm_management, vault_online

from . import base, share_management
from .. import api
from ..helpers import ksm_utils, report_utils, share_utils
from ..params import KeeperParams


logger = api.get_logger()


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

        def list_app():
            return self.list_app(vault=vault)

        def get_app():
            if not uid_or_name:
                logger.error("Application name or UID is required for 'app get'. Use --name='example' to set it.")
                return
            return self.get_app(vault=vault, uid_or_name=uid_or_name)

        def create_app():
            if not uid_or_name:
                logger.error("Application name or UID is required for 'app create'. Use --name='example' to set it.")
                return
            self.create_app(vault=vault, name=uid_or_name, force=force)
            return context.vault_down()

        def remove_app():
            if not uid_or_name:
                logger.error("Application name or UID is required for 'app remove'. Use --name='example' to set it.")
                return
            self.remove_app(vault=vault, uid_or_name=uid_or_name, force=force)
            return
        
        def share_app():
            if not uid_or_name:
                logger.error("Application name or UID is required for 'app share'. Use --name='example' to set it.")
                return
            self.share_app(context=context, uid_or_name=uid_or_name, force=force, unshare=False, email=email, is_admin=is_admin)
            return context.vault_down()
        
        def unshare_app():
            if not uid_or_name:
                logger.error("Application name or UID is required for 'app unshare'. Use --name='example' to set it.")
                return
            self.share_app(context=context, uid_or_name=uid_or_name, force=force, unshare=True, email=email, is_admin=is_admin)
            return context.vault_down()

        command_map = {
            'list': list_app,
            'get': get_app,
            'create': create_app,
            'remove': remove_app,
            'share': share_app,
            'unshare': unshare_app
        }

        if not command:
            logger.error("Command is required. Available commands: list, get, create, remove, share, unshare")
            return
            
        action = command_map.get(command)
        if action:
            return action()
        else:
            logger.error(f"Unknown command '{command}'. Available commands: list, get, create, remove, share, unshare")
            return


    def list_app(self, vault: vault_online.VaultOnline):
        app_list = ksm_management.list_secrets_manager_apps(vault)
        headers = ['App name', 'App UID', 'Records', 'Folders', 'Devices', 'Last Access']
        rows = [
            [app.name, app.uid, app.records, app.folders, app.count, app.last_access]
            for app in app_list
        ]
        report_utils.dump_report_data(rows, headers=headers, fmt='table')
    

    def get_app(self, vault: vault_online.VaultOnline, uid_or_name: str):
        if not uid_or_name:
            logger.error("Application name or UID is required for 'app get'. Use --name='example' to set it.")
            return

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
        if not name:
            logger.error("Application name or UID is required for 'app create'. Use --name='example' to set it.")
            return
        
        app_uid = ksm_management.create_secrets_manager_app(vault=vault, name=name, force_add=force)
        
        logger.info(f'Application was successfully added (UID: {app_uid})')
    
    
    def remove_app(self, vault: vault_online.VaultOnline, uid_or_name: str, force: Optional[bool] = False):
        if not uid_or_name:
            logger.error("Application name or UID is required for 'app remove'. Use --name='example' to set it.")
            return
        
        app_uid = ksm_management.remove_secrets_manager_app(vault=vault, uid_or_name=uid_or_name, force=force)
        
        logger.info(f'Application was successfully removed (UID: {app_uid})')
    
    def share_app(self, context: KeeperParams, uid_or_name: str, force: Optional[bool] = False, unshare: bool = False, email: Optional[str] = None, is_admin: Optional[bool] = False):
        if not email:
            logger.error("Email parameter is required for sharing. Use --email='user@example.com' to set it.")
            return
            
        if not context.vault:
            logger.error("Vault is not initialized.")
            return
            
        app_record = next((r for r in context.vault.vault_data.records() if r.record_uid == uid_or_name or r.title == uid_or_name), None)
        
        if not app_record:
            raise ValueError(f'No application found with UID/Name: {uid_or_name}')
        
        app_uid = app_record.record_uid
        action = share_management.ShareAction.REVOKE.value if unshare else share_management.ShareAction.GRANT.value
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
        
        share_record_command = share_management.ShareRecordCommand()
        share_record_command.execute(context=context, **args)
        
        context.vault.sync_down()
        
        SecretsManagerAppCommand.update_shares_user_permissions(context=context, uid=app_uid, removed=unshare)

    @staticmethod
    def update_shares_user_permissions(context: KeeperParams, uid: str, removed: bool):
        if not context.vault:
            logger.error("Vault is not initialized.")
            return
        
        vault = context.vault
        app_rec = vault.vault_data.get_record(record_uid=uid)
        if app_rec is None:
            logger.warning('Application "%s" not found.' % uid)
            return

        share_info = share_utils.get_record_shares(vault=vault, record_uids=[uid], is_share_admin=False)
        user_perms = []
        if share_info:
            for record_info in share_info:
                if record_info.get('record_uid') == uid:
                    user_perms = record_info.get('shares', {}).get('user_permissions', [])
                    break
        
        sf_perm_keys = ('manage_users', 'manage_records')
        rec_user_permissions = ('editable', 'shareable')

        try:
            app_info = ksm_management.get_secrets_manager_app(vault=vault, uid_or_name=uid)
            if not app_info or not app_info.shared_secrets:
                return
            
            share_uids = [secret.uid for secret in app_info.shared_secrets]
            record_cache = {x.record_uid: x for x in vault.vault_data.records()}
            shared_folder_cache = {x.shared_folder_uid: x for x in vault.vault_data.shared_folders()}
            
            shared_recs = [uid for uid in share_uids if uid in record_cache]
            shared_folders = [uid for uid in share_uids if uid not in shared_recs]

            if shared_recs:
                share_utils.get_record_shares(vault=vault, record_uids=shared_recs, is_share_admin=False)

            def share_needs_update(user: str, share_uid: str):
                if removed:
                    return False
                is_rec_share = share_uid in record_cache
                perm_keys, share_cache = (rec_user_permissions, record_cache) if is_rec_share \
                    else (sf_perm_keys, shared_folder_cache)
                get_user_permissions = lambda cached_share: cached_share.get('shares', {}).get('user_permissions',{}) if is_rec_share else cached_share.get('users')
                share_user_permissions = get_user_permissions(share_cache.get(share_uid, {}))
                return not any(up for up in share_user_permissions if up.get('username') == user)

            admins = [up.get('username') for up in user_perms if up.get('editable')]
            viewers = [up.get('username') for up in user_perms if not up.get('editable')]
            app_users_map = dict(admins=admins, viewers=viewers)

            user_needs_update = lambda u, adm: any(share_needs_update(u, uid) for uid in share_uids)

            def group_by_app_share(products):
                first_element = lambda x: x[0]
                products = sorted(products, key=first_element)
                products = groupby(products, key=first_element)
                return {uid: [user for _, user in pair] for uid, pair in products}

            sf_requests = []
            rec_requests = []
            for group, users in app_users_map.items():
                is_admin = group == 'admins'
                users = [u for u in users if user_needs_update(u, is_admin)]
                sf_action = share_management.ShareAction.REMOVE.value if removed else share_management.ShareAction.GRANT.value
                rec_action = share_management.ShareAction.REVOKE.value if removed else share_management.ShareAction.GRANT.value

                prep_sf_rq = lambda u, uid: share_management.ShareFolderCommand.prepare_request(
                    vault=vault,
                    kwargs={'action': sf_action},
                    curr_sf={'shared_folder_uid': uid, 'users': [], 'teams': [], 'records': []},
                    users=u,
                    teams=[],
                    rec_uids=[],
                    default_record=False,
                    default_account=False,
                    share_expiration=-1
                )
                sf_updates = {(sf, user) for sf, user in product(shared_folders, users) if share_needs_update(user, sf)}
                sf_updates = group_by_app_share(sf_updates)
                sf_requests.append([prep_sf_rq(users, uid) for uid, users in sf_updates.items() if users])

                prep_rec_rq = lambda u, uid: share_management.ShareRecordCommand.prep_request(
                    context=context,
                    emails=[u],
                    action=rec_action,
                    uid_or_name=uid,
                    share_expiration=-1,
                    dry_run=False,
                    can_edit=False,
                    can_share=False
                )
                rec_updates = {(rec, user) for rec, user in product(shared_recs, users) if share_needs_update(user, rec)}
                rec_updates = group_by_app_share(rec_updates)
                rec_requests.extend([prep_rec_rq(users, rec) for rec, users in rec_updates.items() if users])
                rec_requests = [rq for rq in rec_requests if rq]

            share_management.ShareFolderCommand.send_requests(vault, sf_requests)
            share_management.ShareRecordCommand.send_requests(vault, rec_requests)
            logger.info("Share updates would be processed here if ShareFolderCommand and ShareRecordCommand were available")
            
        except Exception as e:
            logger.error(f"Error updating shares user permissions: {e}")
    