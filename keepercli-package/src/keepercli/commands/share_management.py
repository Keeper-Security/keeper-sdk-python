import argparse
import datetime
import hashlib
import json
import logging
import math
import re
import urllib.parse
from enum import Enum
from typing import Optional
from tabulate import tabulate

from keepersdk import crypto, utils
from keepersdk.proto import folder_pb2, record_pb2, APIRequest_pb2
from keepersdk.vault import ksm_management, vault_online, vault_utils

from . import base, record_edit
from .. import api, prompt_utils, constants
from ..helpers import folder_utils, record_utils, report_utils, share_utils, timeout_utils, share_record
from ..params import KeeperParams


class ApiUrl(Enum):
    SHARE_ADMIN = 'vault/am_i_share_admin'
    SHARE_UPDATE = 'vault/records_share_update'
    SHARE_FOLDER_UPDATE = 'vault/shared_folder_update_v3'
    REMOVE_EXTERNAL_SHARE = 'vault/external_share_remove'


class ShareAction(Enum):
    GRANT = 'grant'
    REVOKE = 'revoke'
    OWNER = 'owner'
    CANCEL = 'cancel'
    REMOVE = 'remove'


class ManagePermission(Enum):
    ON = 'on'
    OFF = 'off'


logger = api.get_logger()


# Import share record classes
SharePermissions = share_record.SharePermissions
SharedRecord = share_record.SharedRecord
get_shared_records = share_record.get_shared_records




def get_record_share_info(context, record_uids):
    """Get actual share information for records using share_utils"""
    if not context.vault or not record_uids:
        return {}
    
    try:
        share_infos = share_utils.get_record_shares(vault=context.vault, record_uids=record_uids)
        if not share_infos:
            return {}
    except Exception:
        # If share_utils.get_record_shares fails, return empty result
        return {}
    
    result = {}
    for share_info in (share_infos or []):
        record_uid = share_info.get('record_uid')
        if record_uid:
            shares = share_info.get('shares', {})
            user_permissions = shares.get('user_permissions', [])
            
            # Get usernames that this record is shared with
            shared_users = []
            for up in user_permissions:
                username = up.get('username', '')
                if username:
                    shared_users.append(username)
            
            result[record_uid] = {
                'shared_users': shared_users,
                'owner': context.auth.auth_context.username if context.auth and context.auth.auth_context else ''
            }
    
    return result

TIMESTAMP_MILLISECONDS_FACTOR = 1000
TRUNCATE_SUFFIX = '...'

def set_expiration_fields(obj, expiration):
    """Set expiration and timerNotificationType fields on proto object if expiration is provided."""
    if isinstance(expiration, int):
        if expiration > 0:
            obj.expiration = expiration * TIMESTAMP_MILLISECONDS_FACTOR
            obj.timerNotificationType = record_pb2.NOTIFY_OWNER
        elif expiration < 0:
            obj.expiration = -1


class ShareRecordCommand(base.ArgparseCommand):
    
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            prog='share-record',
            description='Change the sharing permissions of an individual record',
        )
        ShareRecordCommand.add_arguments_to_parser(self.parser)
        super().__init__(self.parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):

        parser.add_argument(
            '-e', '--email', dest='email', action='append', help='account email'
        )
        parser.add_argument(
            '--contacts-only', action='store_true', 
            help="Share only to known targets; Allows routing to alternate domains with matching usernames if needed"
        )
        parser.add_argument(
            '-f', '--force', action='store_true', help='Skip confirmation prompts'
        )
        parser.add_argument(
            '-a', '--action', dest='action', choices=[action.value for action in ShareAction],
            default=ShareAction.GRANT.value, action='store', help='user share action. \'grant\' if omitted'
        )
        parser.add_argument(
            '-s', '--share', dest='can_share', action='store_true', help='can re-share record'
        )
        parser.add_argument(
            '-w', '--write', dest='can_edit', action='store_true', help='can modify record'
        )
        parser.add_argument(
            '-R', '--recursive', dest='recursive', action='store_true', 
            help='apply command to shared folder hierarchy'
        )
        parser.add_argument(
            '--dry-run', dest='dry_run', action='store_true', 
            help='display the permissions changes without committing them'
        )
        expiration = parser.add_mutually_exclusive_group()
        expiration.add_argument(
            '--expire-at', dest='expire_at', action='store', help='share expiration: never or UTC datetime'
        )
        expiration.add_argument(
            '--expire-in', dest='expire_in', action='store', 
            metavar='<NUMBER>[(mi)nutes|(h)ours|(d)ays|(mo)nths|(y)ears]',
            help='share expiration: never or period'
        )
        parser.add_argument(
            'record', nargs='?', type=str, action='store', help='record/shared folder path/UID'
        )
    
    def execute(self, context: KeeperParams, **kwargs) -> None:
        if not context.vault:
            raise ValueError("Vault is not initialized.")
        vault = context.vault
        
        uid_or_name = kwargs.get('record')
        if not uid_or_name:
            return self.get_parser().print_help()
        
        emails = kwargs.get('email') or []
        if not emails:
            raise ValueError('share-record', '\'email\' parameter is missing')
        
        force = kwargs.get('force')
        action = kwargs.get('action', ShareAction.GRANT.value)
        contacts_only = kwargs.get('contacts_only')
        dry_run = kwargs.get('dry_run')
        can_edit = kwargs.get('can_edit')
        can_share = kwargs.get('can_share')
        recursive = kwargs.get('recursive')
    
        if contacts_only:
            shared_objects = share_utils.get_share_objects(vault=vault)
            known_users = shared_objects.get('users', {})
            known_emails = [u.casefold() for u in known_users.keys()]
            def is_unknown(e):
                return e.casefold() not in known_emails and utils.is_email(e)
            unknowns = [e for e in emails if is_unknown(e)]
            if unknowns:
                username_map = {
                    e: ShareRecordCommand.get_contact(e, known_users) 
                    for e in unknowns
                }
                table = [[k, v] for k, v in username_map.items()]
                logger.info(f'{len(unknowns)} unrecognized share recipient(s) and closest matching contact(s)')
                report_utils.dump_report_data(table, ['Username', 'From Contacts'])
                confirmed = force or prompt_utils.user_choice('\tReplace with known matching contact(s)?', 'yn', default='n') == 'y'
                if confirmed:
                    good_emails = [e for e in emails if e not in unknowns]
                    replacements = [e for e in username_map.values() if e]
                    emails = [*good_emails, *replacements]

        if action == ShareAction.CANCEL.value:
            ShareRecordCommand.cancel_share(vault, emails)
            vault.sync_down()
            return
        else:
            share_expiration = share_utils.get_share_expiration(kwargs.get('expire_at'), kwargs.get('expire_in'))
                
            request = ShareRecordCommand.prep_request(
                context=context, 
                uid_or_name=uid_or_name, 
                emails=emails, 
                share_expiration=share_expiration, 
                action=action, 
                dry_run=dry_run or False, 
                can_edit=can_edit, 
                can_share=can_share, 
                recursive=recursive
            )
            if request:
                ShareRecordCommand.send_requests(vault, [request])
    
    @staticmethod
    def get_contact(user, contacts):
        if not user or not contacts:
            return None
            
        user_username = user.split('@')[0].casefold()
        
        for contact in contacts:
            contact_username = contact.split('@')[0].casefold()
            if user_username == contact_username:
                return contact
                
        return None

    @staticmethod
    def prep_request(context: KeeperParams,
                    emails: list[str],
                    action: str,
                    uid_or_name: str,
                    share_expiration: int,
                    dry_run: bool,
                    recursive: Optional[bool] = False,
                    can_edit: Optional[bool] = False,
                    can_share: Optional[bool] = False):
        if not context or not hasattr(context, 'vault') or not context.vault or not hasattr(context.vault, 'vault_data') or not context.vault.vault_data:
            raise ValueError("Vault or vault data is not initialized")
        vault = context.vault
        record_uid = None
        folder_uid = None
        shared_folder_uid = None
        record_cache = {x.record_uid: x for x in vault.vault_data.records()}
        shared_folder_cache = {x.shared_folder_uid: x for x in vault.vault_data.shared_folders()}
        folder_cache = {x: x for x in getattr(vault.vault_data, '_folders', [])}
        
        if uid_or_name in record_cache:
            record_uid = uid_or_name
        elif uid_or_name in shared_folder_cache:
            shared_folder_uid = uid_or_name
        elif uid_or_name in folder_cache:
            folder_uid = uid_or_name
        else:
            for sf_info in vault.vault_data.shared_folders():
                if uid_or_name == sf_info.name:
                    shared_folder_uid = sf_info.shared_folder_uid
                    break
            
            if shared_folder_uid is None and record_uid is None:
                rs = folder_utils.try_resolve_path(context, uid_or_name)
                if rs is not None:
                    folder, name = rs
                    if name:
                        for record in vault.vault_data.records():
                            if record.title.lower() == name.lower():
                                record_uid = record.record_uid
                                break
                    else:
                        # Handle shared folder types
                        if folder.folder_type == 'shared_folder':
                            folder_uid = folder.folder_uid
                            shared_folder_uid = folder_uid
                        elif folder.folder_type == 'shared_folder_folder':
                            folder_uid = folder.folder_uid
                            shared_folder_uid = folder.subfolders
        
        # Check share admin status
        is_share_admin = False
        if record_uid is None and folder_uid is None and shared_folder_uid is None:
            if context._enterprise_loader:
                try:
                    uid = utils.base64_url_decode(uid_or_name)
                    if isinstance(uid, bytes) and len(uid) == 16:
                        request = record_pb2.AmIShareAdmin()
                        obj_share_admin = record_pb2.IsObjectShareAdmin()
                        obj_share_admin.uid = uid
                        obj_share_admin.objectType = record_pb2.CHECK_SA_ON_RECORD
                        request.isObjectShareAdmin.append(obj_share_admin)
                        response = vault.keeper_auth.execute_auth_rest(
                            request=request, 
                            response_type=record_pb2.AmIShareAdmin, 
                            rest_endpoint=ApiUrl.SHARE_ADMIN.value
                        )
                        if response and response.isObjectShareAdmin and response.isObjectShareAdmin[0].isAdmin:
                            is_share_admin = True
                            record_uid = uid_or_name
                except Exception:
                    pass

        if record_uid is None and folder_uid is None and shared_folder_uid is None:
            raise ValueError('share-record', 'Enter name or uid of existing record or shared folder')
        
        # Collect record UIDs
        record_uids = set()
        if record_uid:
            record_uids.add(record_uid)
        elif folder_uid:
            folders = {folder_uid}
            folder = vault.vault_data.get_folder(folder_uid)
            if recursive and folder:
                vault_utils.traverse_folder_tree(
                    vault=vault.vault_data, 
                    folder=folder, 
                    callback=lambda x: folders.add(x.folder_uid)
                )
            record_uids = {uid for uid in folders if uid in record_cache}
        elif shared_folder_uid:
            if not recursive:
                raise ValueError('share-record', '--recursive parameter is required')
            if isinstance(shared_folder_uid, str):
                sf = vault.vault_data.load_shared_folder(shared_folder_uid=shared_folder_uid)
                if sf and sf.record_permissions:
                    record_uids.update(x.record_uid for x in sf.record_permissions)
            elif isinstance(shared_folder_uid, list):
                for sf_uid in shared_folder_uid:
                    if isinstance(sf_uid, str):
                        sf = vault.vault_data.load_shared_folder(shared_folder_uid=sf_uid)
                        if sf and sf.record_permissions:
                            record_uids.update(x.record_uid for x in sf.record_permissions)

        if not record_uids:
            raise ValueError('share-record', 'There are no records to share selected')

        if action == 'owner' and len(emails) > 1:
            raise ValueError('share-record', 'You can transfer ownership to a single account only')

        all_users = {email.casefold() for email in emails}
        
        # Handle user invitations and key loading
        if not dry_run and action in (ShareAction.GRANT.value, ShareAction.OWNER.value):
            invited = vault.keeper_auth.load_user_public_keys(list(all_users), send_invites=True)
            if invited:
                for email in invited:
                    logger.warning('Share invitation has been sent to \'%s\'', email)
                logger.warning('Please repeat this command when invitation is accepted.')
                all_users.difference_update(invited)
            
            if vault.keeper_auth._key_cache:
                all_users.intersection_update(vault.keeper_auth._key_cache.keys())

        if not all_users:
            raise ValueError('share-record', 'Nothing to do.')

        # Load records in shared folders
        if shared_folder_uid:
            if isinstance(shared_folder_uid, str):
                share_utils.load_records_in_shared_folder(vault=vault, shared_folder_uid=shared_folder_uid, record_uids=record_uids)
            elif isinstance(shared_folder_uid, list):
                for sf_uid in shared_folder_uid:
                    share_utils.load_records_in_shared_folder(vault=vault, shared_folder_uid=sf_uid, record_uids=record_uids)

        # Get share information for records not in cache
        not_owned_records = {} if is_share_admin else None
        share_info = share_utils.get_record_shares(vault=vault, record_uids=list(record_uids), is_share_admin=False)
        if share_info and not_owned_records is not None:
            for record_info in share_info:
                record_uid = record_info.get('record_uid')
                if record_uid:
                    not_owned_records[record_uid] = record_info

        # Build the request
        rq = record_pb2.RecordShareUpdateRequest()
        existing_shares = {}
        record_titles = {}
        transfer_ruids = set()
        
        for record_uid in record_uids:
            # Get record data
            if record_uid in record_cache:
                rec = record_cache[record_uid]
            elif not_owned_records and record_uid in not_owned_records:
                rec = not_owned_records[record_uid]
            elif is_share_admin:
                rec = {
                    'record_uid': record_uid,
                    'shares': {
                        'user_permissions': [{
                            'username': x,
                            'owner': False,
                            'share_admin': False,
                            'shareable': action == 'revoke',
                            'editable': action == 'revoke',
                        } for x in all_users]
                    }
                }
            else:
                continue

            existing_shares.clear()
            if isinstance(rec, dict):
                if 'shares' in rec:
                    shares = rec['shares']
                    if 'user_permissions' in shares:
                        for po in shares['user_permissions']:
                            existing_shares[po['username'].lower()] = po
                    del rec['shares']
                
                if 'data_unencrypted' in rec:
                    try:
                        data = json.loads(rec['data_unencrypted'].decode())
                        if isinstance(data, dict) and 'title' in data:
                            record_titles[record_uid] = data['title']
                    except (ValueError, AttributeError):
                        pass

            record_path = share_utils.resolve_record_share_path(context=context, record_uid=record_uid)
            
            # Process each user
            for email in all_users:
                ro = record_pb2.SharedRecord()
                ro.toUsername = email
                ro.recordUid = utils.base64_url_decode(record_uid)
                
                if record_path:
                    if 'shared_folder_uid' in record_path:
                        ro.sharedFolderUid = utils.base64_url_decode(record_path['shared_folder_uid'])
                    if 'team_uid' in record_path:
                        ro.teamUid = utils.base64_url_decode(record_path['team_uid'])

                if action in {ShareAction.GRANT.value, ShareAction.OWNER.value}:
                    record_uid_to_use = rec.get('record_uid', record_uid) if isinstance(rec, dict) else getattr(rec, 'record_uid', record_uid)
                    record_key = vault.vault_data.get_record_key(record_uid=record_uid_to_use)
                    if record_key and email not in existing_shares and vault.keeper_auth._key_cache and email in vault.keeper_auth._key_cache:
                        keys = vault.keeper_auth._key_cache[email]
                        if vault.keeper_auth.auth_context.forbid_rsa and keys.ec:
                            ec_key = crypto.load_ec_public_key(keys.ec)
                            ro.recordKey = crypto.encrypt_ec(record_key, ec_key)
                            ro.useEccKey = True
                        elif not vault.keeper_auth.auth_context.forbid_rsa and keys.rsa:
                            rsa_key = crypto.load_rsa_public_key(keys.rsa)
                            ro.recordKey = crypto.encrypt_rsa(record_key, rsa_key)
                            ro.useEccKey = False
                        
                        if action == ShareAction.OWNER.value:
                            ro.transfer = True
                            transfer_ruids.add(record_uid)
                        else:
                            ro.editable = bool(can_edit)
                            ro.shareable = bool(can_share)
                            set_expiration_fields(ro, share_expiration)
                    elif email in existing_shares:
                        current = existing_shares[email]
                        if action == ShareAction.OWNER.value:
                            ro.transfer = True
                            transfer_ruids.add(record_uid)
                        else:
                            ro.editable = can_edit if can_edit is not None else current.get('editable')
                            ro.shareable = can_share if can_share is not None else current.get('shareable')
                            set_expiration_fields(ro, share_expiration)
                    
                    if email in existing_shares:
                        rq.updateSharedRecord.append(ro)
                    else:
                        rq.addSharedRecord.append(ro)
                else:
                    if can_share or can_edit:
                        if email in existing_shares:
                            current = existing_shares[email]
                            ro.editable = False if can_edit else current.get('editable')
                            ro.shareable = False if can_share else current.get('shareable')
                            set_expiration_fields(ro, share_expiration)
                        rq.updateSharedRecord.append(ro)
                    else:
                        rq.removeSharedRecord.append(ro)
        
        return rq

    @staticmethod
    def cancel_share(vault: vault_online.VaultOnline, emails: list[str]):
        for email in emails:
            request = {
                'command': 'cancel_share',
                'to_email': email
            }
            try:
                vault.keeper_auth.execute_auth_command(request=request)
            except Exception as e:
                logger.warning(f'Failed to cancel share for {email}:{e}')
                continue
        vault.sync_down()
        return

    @staticmethod
    def send_requests(vault: vault_online.VaultOnline, requests):
        MAX_BATCH_SIZE = 990
        STATUS_ATTRIBUTES = {
            'addSharedRecordStatus': ('granted to', 'grant'),
            'updateSharedRecordStatus': ('changed for', 'change'), 
            'removeSharedRecordStatus': ('revoked from', 'revoke')
        }
        
        def create_batch_request(request, max_size):
            """Create a batch request by taking items from the source request."""
            batch = record_pb2.RecordShareUpdateRequest()
            remaining = max_size
            
            # Process each record type in priority order
            for attr_name in ['addSharedRecord', 'updateSharedRecord', 'removeSharedRecord']:
                if remaining <= 0:
                    break
                    
                source_list = getattr(request, attr_name)
                if not source_list:
                    continue
                    
                # Take items from the source list
                items_to_take = min(remaining, len(source_list))
                target_list = getattr(batch, attr_name)
                target_list.extend(source_list[:items_to_take])
                
                # Remove taken items from source
                del source_list[:items_to_take]
                remaining -= items_to_take
                
            return batch
        
        def process_response_statuses(response):
            """Process and log the status of each operation in the response."""
            for attr_name, (success_verb, failure_verb) in STATUS_ATTRIBUTES.items():
                if not hasattr(response, attr_name):
                    continue
                    
                statuses = getattr(response, attr_name)
                for status_record in statuses:
                    record_uid = utils.base64_url_encode(status_record.recordUid)
                    status = status_record.status
                    email = status_record.username
                    
                    if status == 'success':
                        logger.info(
                            'Record "%s" access permissions has been %s user \'%s\'', 
                            record_uid, success_verb, email
                        )
                    else:
                        logger.info(
                            'Failed to %s record "%s" access permissions for user \'%s\': %s', 
                            failure_verb, record_uid, email, status_record.message
                        )
        
        for request in requests:
            # Process request in batches until all records are handled
            while (len(request.addSharedRecord) > 0 or 
                len(request.updateSharedRecord) > 0 or 
                len(request.removeSharedRecord) > 0):
                
                # Create a batch request
                batch_request = create_batch_request(request, MAX_BATCH_SIZE)
                
                # Send the batch request
                response = vault.keeper_auth.execute_auth_rest(
                    rest_endpoint=ApiUrl.SHARE_UPDATE.value, 
                    request=batch_request, 
                    response_type=record_pb2.RecordShareUpdateResponse
                )
                
                process_response_statuses(response)


class ShareFolderCommand(base.ArgparseCommand):
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            prog='share-folder',
            description='Change the sharing permissions of shared folders'
        )
        ShareFolderCommand.add_arguments_to_parser(self.parser)
        super().__init__(self.parser)
        
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument(
            '-a', '--action', dest='action', choices=[ShareAction.GRANT.value, ShareAction.REMOVE.value], 
            default=ShareAction.GRANT.value, action='store', 
            help='shared folder action. \'grant\' if omitted'
        )
        parser.add_argument(
            '-e', '--email', dest='user', action='append',
            help='account email, team, @existing for all users and teams in the folder, or \'*\' as default folder permission'
        )
        parser.add_argument(
            '-r', '--record', dest='record', action='append', 
            help='record name, record UID, @existing for all records in the folder, or \'*\' as default folder permission'
        )
        parser.add_argument(
            '-p', '--manage-records', dest='manage_records', action='store', 
            choices=[perm.value for perm in ManagePermission], help='account permission: can manage records.'
        )
        parser.add_argument(
            '-o', '--manage-users', dest='manage_users', action='store', 
            choices=[perm.value for perm in ManagePermission], help='account permission: can manage users.'
        )
        parser.add_argument(
            '-s', '--can-share', dest='can_share', action='store', 
            choices=[perm.value for perm in ManagePermission], help='record permission: can be shared'
        )
        parser.add_argument(
            '-d', '--can-edit', dest='can_edit', action='store', 
            choices=[perm.value for perm in ManagePermission], help='record permission: can be modified.'
        )
        parser.add_argument(
            '-f', '--force', dest='force', action='store_true', 
            help='Apply permission changes ignoring default folder permissions. Used on the initial sharing action'
        )
        expiration = parser.add_mutually_exclusive_group()
        expiration.add_argument(
            '--expire-at', dest='expire_at', action='store', metavar='TIMESTAMP', 
            help='share expiration: never or ISO datetime (yyyy-MM-dd[ hh:mm:ss])'
        )
        expiration.add_argument(
            '--expire-in', dest='expire_in', action='store', metavar='PERIOD', 
            help='share expiration: never or period (<NUMBER>[(y)ears|(mo)nths|(d)ays|(h)ours(mi)nutes]'
        )
        parser.add_argument(
            'folder', nargs='+', type=str, action='store', help='shared folder path or UID'
        )
    
    def execute(self, context: KeeperParams, **kwargs) -> None:
        if not context.vault:
            raise ValueError('Vault is not initialized.')
        
        vault = context.vault
        
        def get_share_admin_obj_uids(vault: vault_online.VaultOnline, obj_names, obj_type):
            if not obj_names:
                return None
            try:
                rq = record_pb2.AmIShareAdmin()
                for name in obj_names:
                    try:
                        uid = utils.base64_url_decode(name)
                        if isinstance(uid, bytes) and len(uid) == 16:
                            osa = record_pb2.IsObjectShareAdmin()
                            osa.uid = uid
                            osa.objectType = obj_type
                            rq.isObjectShareAdmin.append(osa)
                    except:
                        pass
                if len(rq.isObjectShareAdmin) > 0:
                    rs = vault.keeper_auth.execute_auth_rest(rest_endpoint=ApiUrl.SHARE_ADMIN.value, request=rq, response_type=record_pb2.AmIShareAdmin)
                    if rs and hasattr(rs, 'isObjectShareAdmin'):
                        sa_obj_uids = {sa_obj.uid for sa_obj in rs.isObjectShareAdmin if sa_obj.isAdmin}
                        sa_obj_uids = {utils.base64_url_encode(uid) for uid in sa_obj_uids}
                        return sa_obj_uids
            except (ValueError, AttributeError) as e:
                raise ValueError(f'get_share_admin: msg = {e}') from e

        def get_folder_uids(context: KeeperParams, name: str) -> set[str]:
            """Get folder UIDs by name or path."""
            folder_uids = set()
            
            if not context.vault or not context.vault.vault_data:
                return folder_uids
            
            if name in context.vault.vault_data._folders:
                folder_uids.add(name)
                return folder_uids
            
            for folder in context.vault.vault_data.folders():
                if folder.name == name:
                    folder_uids.add(folder.folder_uid)
            
            if not folder_uids:
                try:
                    folder, _ = folder_utils.try_resolve_path(context, name)
                    if folder:
                        folder_uids.add(folder.folder_uid)
                except (ValueError, AttributeError):
                    pass
            
            return folder_uids

        def get_record_uids(context: KeeperParams, name: str) -> set[str]:
            """Get record UIDs by name or UID."""
            record_uids = set()
            
            if not context.vault or not context.vault.vault_data:
                return record_uids
            
            record = context.vault.vault_data.get_record(name)
            if record:
                record_uids.add(name)
                return record_uids
            
            for record_info in context.vault.vault_data.records():
                if record_info.title == name:
                    record_uids.add(record_info.record_uid)
            
            return record_uids

        names = kwargs.get('folder')
        if not isinstance(names, list):
            names = [names]

        all_folders = any(True for x in names if x == '*')
        if all_folders:
            names = [x for x in names if x != '*']

        shared_folder_cache = {x.shared_folder_uid: x for x in vault.vault_data.shared_folders()}
        folder_cache = {x.folder_uid: x for x in vault.vault_data.folders()}
        shared_folder_uids = set()
        if all_folders:
            shared_folder_uids.update(shared_folder_cache.keys())
        else:
            def get_folder_by_uid(uid):
                return folder_cache.get(uid)
            folder_uids = {
                uid 
                for name in names if name 
                for uid in get_folder_uids(context, name)
            }
            folders = {get_folder_by_uid(uid) for uid in folder_uids if get_folder_by_uid(uid)}
            shared_folder_uids.update([uid for uid in folder_uids if uid in shared_folder_cache])

            sf_subfolders = {f for f in folders if f and f.folder_type == 'shared_folder_folder'}
            shared_folder_uids.update({f.folder_scope_uid for f in sf_subfolders if f.folder_scope_uid})

            unresolved_names = [name for name in names if name and not get_folder_uids(context, name)]
            share_admin_folder_uids = get_share_admin_obj_uids(vault=vault, obj_names=unresolved_names, obj_type=record_pb2.CHECK_SA_ON_SF)
            shared_folder_uids.update(share_admin_folder_uids or [])

        if not shared_folder_uids:
            raise ValueError('share-folder', 'Enter name of at least one existing folder')

        action = kwargs.get('action') or ShareAction.GRANT.value

        share_expiration = None
        if action == ShareAction.GRANT.value:
            share_expiration = share_utils.get_share_expiration(kwargs.get('expire_at'), kwargs.get('expire_in'))

        as_users = set()
        as_teams = set()

        all_users = False
        default_account = False
        if 'user' in kwargs:
            for u in (kwargs.get('user') or []):
                if u == '*':
                    default_account = True
                elif u in ('@existing', '@current'):
                    all_users = True
                else:
                    em = re.match(constants.EMAIL_PATTERN, u)
                    if em is not None:
                        as_users.add(u.lower())
                    else:
                        teams = share_utils.get_share_objects(vault=vault).get('teams', {})
                        teams_map = {uid: team.get('name') for uid, team in teams.items()}
                        if len(teams) >= 500:
                            teams = vault_utils.load_available_teams(auth=vault.keeper_auth)
                            teams_map.update({t.team_uid: t.name for t in teams})

                        matches = [uid for uid, name in teams_map.items() if u in (name, uid)]
                        if len(matches) != 1:
                            logger.warning(f'User "{u}" could not be resolved as email or team' if not matches
                                            else f'Multiple matches were found for team "{u}". Try using its UID -- which can be found via `list-team` -- instead')
                        else:
                            [team] = matches
                            as_teams.add(team)

        record_uids = set()
        all_records = False
        default_record = False
        unresolved_names = []
        if 'record' in kwargs:
            records = kwargs.get('record') or []
            for r in records:
                if r == '*':
                    default_record = True
                elif r in ('@existing', '@current'):
                    all_records = True
                else:
                    r_uids = get_record_uids(context, r)
                    if r_uids:
                        record_uids.update(r_uids)
                    else:
                        unresolved_names.append(r)

            if unresolved_names:
                sa_record_uids = get_share_admin_obj_uids(vault=vault, obj_names=unresolved_names, obj_type=record_pb2.CHECK_SA_ON_RECORD)
                record_uids.update(sa_record_uids or {})

        if len(as_users) == 0 and len(as_teams) == 0 and len(record_uids) == 0 and \
                not default_record and not default_account and \
                not all_users and not all_records:
            logger.info('Nothing to do')
            return

        rq_groups = []

        def prep_rq(recs, users, curr_sf):
            return self.prepare_request(vault, kwargs, curr_sf, users, sf_teams, recs, default_record=default_record,
                                        default_account=default_account, share_expiration=share_expiration)

        for sf_uid in shared_folder_uids:
            sf_users = as_users.copy()
            sf_teams = as_teams.copy()
            sf_records = record_uids.copy()

            if sf_uid in shared_folder_cache:
                sh_fol = vault.vault_data.load_shared_folder(sf_uid)
                if (all_users or all_records) and sh_fol:
                    if all_users:
                        if sh_fol.user_permissions:
                            sf_users.update((x.name for x in sh_fol.user_permissions if x.name != context.username))
                    if all_records:
                        if sh_fol and sh_fol.record_permissions:
                            sf_records.update((x.record_uid for x in sh_fol.record_permissions))
            else:
                sh_fol = {
                    'shared_folder_uid': sf_uid,
                    'users': [{'username': x, 'manage_records': action != ShareAction.GRANT.value, 'manage_users': action != ShareAction.GRANT.value}
                              for x in as_users],
                    'teams': [{'team_uid': x, 'manage_records': action != ShareAction.GRANT.value, 'manage_users': action != ShareAction.GRANT.value}
                              for x in as_teams],
                    'records': [{'record_uid': x, 'can_share': action != ShareAction.GRANT.value, 'can_edit': action != ShareAction.GRANT.value}
                                for x in record_uids]
                }
            chunk_size = 500
            rec_list = list(sf_records)
            user_list = list(sf_users)
            num_rec_chunks = math.ceil(len(sf_records) / chunk_size)
            num_user_chunks = math.ceil(len(sf_users) / chunk_size)
            num_rq_groups = num_user_chunks or 1 * num_rec_chunks or 1
            while len(rq_groups) < num_rq_groups:
                rq_groups.append([])
            rec_chunks = [rec_list[i * chunk_size:(i + 1) * chunk_size] for i in range(num_rec_chunks)] or [[]]
            user_chunks = [user_list[i * chunk_size:(i + 1) * chunk_size] for i in range(num_user_chunks)] or [[]]
            group_idx = 0
            shared_folder_revision = vault.vault_data.storage.shared_folders.get_entity(sf_uid).revision
            sf_unencrypted_key = vault.vault_data.get_shared_folder_key(shared_folder_uid=sh_fol.shared_folder_uid)
            for r_chunk in rec_chunks:
                for u_chunk in user_chunks:
                    sf_info = sh_fol.copy() if isinstance(sh_fol, dict) else {
                        'shared_folder_uid': sf_uid,
                        'users': sh_fol.user_permissions,
                        'teams': [],
                        'records': sh_fol.record_permissions,
                        'shared_folder_key_unencrypted': sf_unencrypted_key,
                        'default_manage_users': sh_fol.default_can_share,
                        'default_manage_records': sh_fol.default_can_edit,
                        'revision': shared_folder_revision
                    }
                    if group_idx and isinstance(sf_info, dict) and 'revision' in sf_info:
                        del sf_info['revision']
                    rq_groups[group_idx].append(prep_rq(r_chunk, u_chunk, sf_info))
                    group_idx += 1
        self.send_requests(vault=vault, partitioned_requests=rq_groups)

    @staticmethod
    def prepare_request(vault: vault_online.VaultOnline, kwargs, curr_sf, users, teams, rec_uids, *,
                        default_record=False, default_account=False,
                        share_expiration=None):
        rq = folder_pb2.SharedFolderUpdateV3Request()
        rq.sharedFolderUid = utils.base64_url_decode(curr_sf['shared_folder_uid'])
        if 'revision' in curr_sf:
            rq.revision = curr_sf['revision']
        else:
            rq.forceUpdate = True
        action = kwargs.get('action') or ShareAction.GRANT.value
        mr = kwargs.get('manage_records')
        mu = kwargs.get('manage_users')
        if default_account and action == ShareAction.GRANT.value:
            if mr is not None:
                rq.defaultManageRecords = folder_pb2.BOOLEAN_TRUE if mr == 'on' else folder_pb2.BOOLEAN_FALSE
            else:
                rq.defaultManageRecords = folder_pb2.BOOLEAN_NO_CHANGE
            if mu is not None:
                rq.defaultManageUsers = folder_pb2.BOOLEAN_TRUE if mu == 'on' else folder_pb2.BOOLEAN_FALSE
            else:
                rq.defaultManageUsers = folder_pb2.BOOLEAN_NO_CHANGE

        if len(users) > 0:
            existing_users = {x['username'] if isinstance(x, dict) else x.name for x in curr_sf.get('users', [])}
            for email in users:
                uo = folder_pb2.SharedFolderUpdateUser()
                uo.username = email
                set_expiration_fields(uo, share_expiration)
                if email in existing_users:
                    if action == ShareAction.GRANT.value:
                        uo.manageRecords = folder_pb2.BOOLEAN_NO_CHANGE if mr is None else folder_pb2.BOOLEAN_TRUE if mr == ManagePermission.ON.value else folder_pb2.BOOLEAN_FALSE
                        uo.manageUsers = folder_pb2.BOOLEAN_NO_CHANGE if mu is None else folder_pb2.BOOLEAN_TRUE if mu == ManagePermission.ON.value else folder_pb2.BOOLEAN_FALSE
                        rq.sharedFolderUpdateUser.append(uo)
                    elif action == ShareAction.REMOVE.value:
                        rq.sharedFolderRemoveUser.append(uo.username)
                elif action == ShareAction.GRANT.value:
                    invited = vault.keeper_auth.load_user_public_keys([email], send_invites=True)
                    if invited:
                        for username in invited:
                            logger.warning('Share invitation has been sent to \'%s\'', username)
                        logger.warning('Please repeat this command when invitation is accepted.')
                    keys = vault.keeper_auth._key_cache.get(email) if vault.keeper_auth._key_cache else None
                    if keys and (keys.rsa or keys.ec):
                        uo.manageRecords = folder_pb2.BOOLEAN_TRUE if curr_sf.get('default_manage_records') is True and mr is None else folder_pb2.BOOLEAN_TRUE if mr == ManagePermission.ON.value else folder_pb2.BOOLEAN_FALSE
                        uo.manageUsers = folder_pb2.BOOLEAN_TRUE if curr_sf.get('default_manage_users') is True and mu is None else folder_pb2.BOOLEAN_TRUE if mu == ManagePermission.ON.value else folder_pb2.BOOLEAN_FALSE
                        sf_key = curr_sf.get('shared_folder_key_unencrypted')
                        if sf_key:
                            if vault.keeper_auth.auth_context.forbid_rsa and keys.ec:
                                ec_key = crypto.load_ec_public_key(keys.ec)
                                uo.typedSharedFolderKey.encryptedKey = crypto.encrypt_ec(sf_key, ec_key)
                                uo.typedSharedFolderKey.encryptedKeyType = folder_pb2.encrypted_by_public_key_ecc
                            elif not vault.keeper_auth.auth_context.forbid_rsa and keys.rsa:
                                rsa_key = crypto.load_rsa_public_key(keys.rsa)
                                uo.typedSharedFolderKey.encryptedKey = crypto.encrypt_rsa(sf_key, rsa_key)
                                uo.typedSharedFolderKey.encryptedKeyType = folder_pb2.encrypted_by_public_key

                        rq.sharedFolderAddUser.append(uo)
                    else:
                        logger.warning('User %s not found', email)

        if len(teams) > 0:
            existing_teams = {x['team_uid']: x for x in curr_sf.get('teams', [])}
            for team_uid in teams:
                to = folder_pb2.SharedFolderUpdateTeam()
                to.teamUid = utils.base64_url_decode(team_uid)
                set_expiration_fields(to, share_expiration)
                if team_uid in existing_teams:
                    team = existing_teams[team_uid]
                    if action == ShareAction.GRANT.value:
                        to.manageRecords = team.get('manage_records') is True if mr is None else mr == ManagePermission.ON.value
                        to.manageUsers = team.get('manage_users') is True if mu is None else mu == ManagePermission.ON.value
                        rq.sharedFolderUpdateTeam.append(to)
                    elif action == ShareAction.REMOVE.value:
                        rq.sharedFolderRemoveTeam.append(to.teamUid)
                elif action == ShareAction.GRANT.value:
                    to.manageRecords = True if mr else curr_sf.get('default_manage_records') is True
                    to.manageUsers = True if mu else curr_sf.get('default_manage_users') is True
                    team_sf_key = curr_sf.get('shared_folder_key_unencrypted')  # type: Optional[bytes]
                    if team_sf_key:
                        vault.keeper_auth.load_team_keys([team_uid])
                        keys = vault.keeper_auth._key_cache.get(team_uid) if vault.keeper_auth._key_cache else None
                        if keys:
                            if keys.aes:
                                if vault.keeper_auth.auth_context.forbid_rsa:
                                    to.typedSharedFolderKey.encryptedKey = crypto.encrypt_aes_v2(team_sf_key, keys.aes)
                                    to.typedSharedFolderKey.encryptedKeyType = folder_pb2.encrypted_by_data_key_gcm
                                else:
                                    to.typedSharedFolderKey.encryptedKey = crypto.encrypt_aes_v1(team_sf_key, keys.aes)
                                    to.typedSharedFolderKey.encryptedKeyType = folder_pb2.encrypted_by_data_key
                            elif vault.keeper_auth.auth_context.forbid_rsa and keys.ec:
                                ec_key = crypto.load_ec_public_key(keys.ec)
                                to.typedSharedFolderKey.encryptedKey = crypto.encrypt_ec(team_sf_key, ec_key)
                                to.typedSharedFolderKey.encryptedKeyType = folder_pb2.encrypted_by_public_key_ecc
                            elif not vault.keeper_auth.auth_context.forbid_rsa and keys.rsa:
                                rsa_key = crypto.load_rsa_public_key(keys.rsa)
                                to.typedSharedFolderKey.encryptedKey = crypto.encrypt_rsa(team_sf_key, rsa_key)
                                to.typedSharedFolderKey.encryptedKeyType = folder_pb2.encrypted_by_public_key
                            else:
                                continue
                        else:
                            continue
                    else:
                        logger.info('Shared folder key is not available.')
                    rq.sharedFolderAddTeam.append(to)

        ce = kwargs.get('can_edit')
        cs = kwargs.get('can_share')

        if default_record and action == ShareAction.GRANT.value:
            rq.defaultCanEdit = folder_pb2.BOOLEAN_NO_CHANGE if ce is None else folder_pb2.BOOLEAN_TRUE if ce == ManagePermission.ON.value else folder_pb2.BOOLEAN_FALSE
            rq.defaultCanShare = folder_pb2.BOOLEAN_NO_CHANGE if cs is None else  folder_pb2.BOOLEAN_TRUE if cs == ManagePermission.ON.value else folder_pb2.BOOLEAN_FALSE

        if len(rec_uids) > 0:
            existing_records = {x['record_uid'] for x in curr_sf.get('records', [])}
            for record_uid in rec_uids:
                ro = folder_pb2.SharedFolderUpdateRecord()
                ro.recordUid = utils.base64_url_decode(record_uid)
                set_expiration_fields(ro, share_expiration)

                if record_uid in existing_records:
                    if action == ShareAction.GRANT.value:
                        ro.canEdit = folder_pb2.BOOLEAN_NO_CHANGE if ce is None else  folder_pb2.BOOLEAN_TRUE if ce == ManagePermission.ON.value else folder_pb2.BOOLEAN_FALSE
                        ro.canShare = folder_pb2.BOOLEAN_NO_CHANGE if cs is None else folder_pb2.BOOLEAN_TRUE if cs == ManagePermission.ON.value else folder_pb2.BOOLEAN_FALSE
                        rq.sharedFolderUpdateRecord.append(ro)
                    elif action == ShareAction.REMOVE.value:
                        rq.sharedFolderRemoveRecord.append(ro.recordUid)
                else:
                    if action == ShareAction.GRANT.value:
                        ro.canEdit = folder_pb2.BOOLEAN_TRUE if curr_sf.get('default_can_edit') is True and ce is None else folder_pb2.BOOLEAN_TRUE if ce == ManagePermission.ON.value else folder_pb2.BOOLEAN_FALSE
                        ro.canShare = folder_pb2.BOOLEAN_TRUE if curr_sf.get('default_can_share') is True and cs is None else folder_pb2.BOOLEAN_TRUE if cs == ManagePermission.ON.value else folder_pb2.BOOLEAN_FALSE
                        sf_key = curr_sf.get('shared_folder_key_unencrypted')
                        if sf_key:
                            rec = vault.vault_data.get_record(record_uid)
                            if rec:
                                rec_key = vault.vault_data.get_record_key(record_uid)
                                if rec_key:
                                    if rec.version < 3:
                                        ro.encryptedRecordKey = crypto.encrypt_aes_v1(rec_key, sf_key)
                                    else:
                                        ro.encryptedRecordKey = crypto.encrypt_aes_v2(rec_key, sf_key)
                        rq.sharedFolderAddRecord.append(ro)
        return rq

    @staticmethod
    def send_requests(vault:vault_online.VaultOnline, partitioned_requests):
        for requests in partitioned_requests:
            while requests:
                vault.auto_sync = True
                chunk = requests[:999]
                requests = requests[999:]
                rqs = folder_pb2.SharedFolderUpdateV3RequestV2()
                rqs.sharedFoldersUpdateV3.extend(chunk)
                try:
                    rss = vault.keeper_auth.execute_auth_rest(rest_endpoint=ApiUrl.SHARE_FOLDER_UPDATE.value, request=rqs, response_type=folder_pb2.SharedFolderUpdateV3ResponseV2, payload_version=1)
                    if rss and hasattr(rss, 'sharedFoldersUpdateV3Response'):
                        for rs in rss.sharedFoldersUpdateV3Response:
                            team_cache = vault.vault_data.teams()
                            for attr in (
                                    'sharedFolderAddTeamStatus', 'sharedFolderUpdateTeamStatus',
                                    'sharedFolderRemoveTeamStatus'):
                                if hasattr(rs, attr):
                                    statuses = getattr(rs, attr)
                                    for t in statuses:
                                        team_uid = utils.base64_url_encode(t.teamUid)
                                        team = next((x for x in team_cache if x.team_uid == team_uid), None)
                                        if team:
                                            status = t.status
                                            if status == 'success':
                                                logger.info('Team share \'%s\' %s', team.name,
                                                             'added' if attr == 'sharedFolderAddTeamStatus' else
                                                             'updated' if attr == 'sharedFolderUpdateTeamStatus' else
                                                             'removed')
                                            else:
                                                logger.warning('Team share \'%s\' failed', team.name)

                            for attr in (
                                    'sharedFolderAddUserStatus', 'sharedFolderUpdateUserStatus',
                                    'sharedFolderRemoveUserStatus'):
                                if hasattr(rs, attr):
                                    statuses = getattr(rs, attr)
                                    for s in statuses:
                                        username = s.username
                                        status = s.status
                                        if status == 'success':
                                            logger.info('User share \'%s\' %s', username,
                                                         'added' if attr == 'sharedFolderAddUserStatus' else
                                                         'updated' if attr == 'sharedFolderUpdateUserStatus' else
                                                         'removed')
                                        elif status == 'invited':
                                            logger.info('User \'%s\' invited', username)
                                        else:
                                            logger.warning('User share \'%s\' failed', username)

                            for attr in ('sharedFolderAddRecordStatus', 'sharedFolderUpdateRecordStatus',
                                         'sharedFolderRemoveRecordStatus'):
                                if hasattr(rs, attr):
                                    statuses = getattr(rs, attr)
                                    for r in statuses:
                                        record_uid = utils.base64_url_encode(r.recordUid)
                                        status = r.status
                                        if record_uid in vault.vault_data._records:
                                            rec = vault.vault_data.get_record(record_uid)
                                            title = rec.title if rec else record_uid
                                        else:
                                            title = record_uid
                                        if status == 'success':
                                            logger.info('Record share \'%s\' %s', title,
                                                         'added' if attr == 'sharedFolderAddRecordStatus' else
                                                         'updated' if attr == 'sharedFolderUpdateRecordStatus' else
                                                         'removed')
                                        else:
                                            logger.warning('Record share \'%s\' failed', title)
                except Exception as kae:
                    logger.error(kae)
                    return


class OneTimeShareListCommand(base.ArgparseCommand):

    def __init__(self):
        self.parser = argparse.ArgumentParser(
            prog='share-list',
            description='Displays a list of one-time shares for a record',
            parents=[base.report_output_parser]
        )
        OneTimeShareListCommand.add_arguments_to_parser(self.parser)
        super().__init__(self.parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument(
            '-R', '--recursive', dest='recursive', action='store_true', 
            help='Traverse recursively through subfolders'
        )
        parser.add_argument(
            '-v', '--verbose', dest='verbose', action='store_true', help='verbose output.'
        )
        parser.add_argument(
            '-a', '--all', dest='show_all', action='store_true', help='show all one-time shares including expired.'
        )
        parser.add_argument(
            'record', nargs='?', type=str, action='store', help='record/folder path/UID'
        )

    def execute(self, context: KeeperParams, **kwargs):
        if not context.vault:
            raise ValueError('Vault is not initialized.')
        
        vault = context.vault
        
        records = kwargs['record'] if 'record' in kwargs else None
        if not records:
            self.get_parser().print_help()
            return
        if isinstance(records, str):
            records = [records]
        
        record_uids = self._resolve_record_uids(context, vault, records, kwargs.get('recursive', False))
        if not record_uids:
            raise base.CommandError('one-time-share', 'No records found')

        applications = self._get_applications(vault, record_uids)
        table_data = self._build_share_table(applications, kwargs)
        
        return self._format_output(table_data, kwargs)

    def _resolve_record_uids(self, context: KeeperParams, vault, records: list, recursive: bool) -> set:
        """Resolve record names/paths to UIDs."""
        record_uids = set()
        
        for name in records:
            record_uid = None
            folder_uid = None
            if name in vault.vault_data._records:
                record_uid = name
            elif name in vault.vault_data._folders:
                folder_uid = name
            else:
                rs = folder_utils.try_resolve_path(context, name)
                if rs is not None:
                    folder, r_name = rs
                    if r_name:
                        f_uid = folder.folder_uid or ''
                        if f_uid in vault.vault_data._folders:
                            for uid in folder.records:
                                rec = vault.vault_data.get_record(record_uid=uid)
                                if rec and rec.version in (2, 3) and rec.title.lower() == r_name.lower():
                                    record_uid = uid
                                    break
                    else:
                        folder_uid = folder.folder_uid or ''
            
            if record_uid is not None:
                record_uids.add(record_uid)
            elif folder_uid is not None:
                self._add_folder_records(vault, folder_uid, record_uids, recursive)
        
        return record_uids

    def _add_folder_records(self, vault, folder_uid: str, record_uids: set, recursive: bool):
        """Add records from a folder to the record_uids set."""
        def on_folder(f):
            f_uid = f.folder_uid or ''
            if f_uid in vault.vault_data._folders:
                folder = vault.vault_data.get_folder(folder_uid=f_uid)
                recs = folder.records
                if recs:
                    record_uids.update(recs)

        folder = vault.vault_data.get_folder(folder_uid=folder_uid)
        if recursive:
            vault_utils.traverse_folder_tree(vault, folder_uid, on_folder)
        else:
            on_folder(folder)

    def _get_applications(self, vault, record_uids: set):
        """Get application info for the given record UIDs."""
        r_uids = list(record_uids)
        MAX_BATCH_SIZE = 1000
        if len(r_uids) >= MAX_BATCH_SIZE:
            logger.info('Trimming result to %d records', MAX_BATCH_SIZE)
            r_uids = r_uids[:MAX_BATCH_SIZE - 1]
        return ksm_management.get_app_info(vault=vault, app_uid=r_uids)

    def _build_share_table(self, applications, kwargs):
        """Build table data from applications."""
        show_all = kwargs.get('show_all', False)
        verbose = kwargs.get('verbose', False)
        now = utils.current_milli_time()
        
        fields = ['record_uid', 'share_link_name', 'share_link_id', 'generated', 'opened', 'expires']
        if show_all:
            fields.append('status')
        
        table = []
        output_format = kwargs.get('format')
        
        for app_info in applications:
            if not app_info.isExternalShare:
                continue
                
            for client in app_info.clients:
                if not show_all and now > client.accessExpireOn:
                    continue
                    
                link = self._create_share_link_data(app_info, client, verbose, output_format, now)
                table.append([link.get(x, '') for x in fields])
        
        return table, fields

    def _create_share_link_data(self, app_info, client, verbose: bool, output_format: str, now: int):
        """Create share link data dictionary."""
        link = {
            'record_uid': utils.base64_url_encode(app_info.appRecordUid),
            'name': client.id,
            'share_link_id': utils.base64_url_encode(client.clientId),
            'generated': datetime.datetime.fromtimestamp(client.createdOn / TIMESTAMP_MILLISECONDS_FACTOR),
            'expires': datetime.datetime.fromtimestamp(client.accessExpireOn / TIMESTAMP_MILLISECONDS_FACTOR),
        }
        
        TRUNCATE_LENGTH = 20
        if output_format == 'table' and not verbose:
            link['share_link_id'] = utils.base64_url_encode(client.clientId)[:TRUNCATE_LENGTH] + TRUNCATE_SUFFIX
        else:
            link['share_link_id'] = utils.base64_url_encode(client.clientId)

        if client.firstAccess > 0:
            link['opened'] = datetime.datetime.fromtimestamp(client.firstAccess / TIMESTAMP_MILLISECONDS_FACTOR)
            link['accessed'] = datetime.datetime.fromtimestamp(client.lastAccess / TIMESTAMP_MILLISECONDS_FACTOR)

        if now > client.accessExpireOn:
            link['status'] = 'Expired'
        elif client.firstAccess > 0:
            link['status'] = 'Opened'
        else:
            link['status'] = 'Generated'
        
        return link

    def _format_output(self, table_data, kwargs):
        """Format and return the output."""
        table, fields = table_data
        output_format = kwargs.get('format')
        
        if output_format == 'table':
            fields = [report_utils.field_to_title(x) for x in fields]
        
        return report_utils.dump_report_data(table, fields, fmt=output_format, filename=kwargs.get('output'))


class OneTimeShareCreateCommand(base.ArgparseCommand):

    def __init__(self):
        self.parser = argparse.ArgumentParser(
            prog='share-create',
            description='Creates one-time share URL for a record'
        )
        OneTimeShareCreateCommand.add_arguments_to_parser(self.parser)
        super().__init__(self.parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument(
            '--output', dest='output', choices=['clipboard', 'stdout'], action='store', 
            help='URL output destination'
        )
        parser.add_argument(
            '--name', dest='share_name', action='store', help='one-time share URL name'
        )
        parser.add_argument(
            '-e', '--expire', dest='expire', action='store', metavar='<NUMBER>[(mi)nutes|(h)ours|(d)ays]', 
            help='time period record share URL is valid.'
        )
        parser.add_argument(
            '--editable', dest='is_editable', action='store_true', help='allow the user to edit the shared record'
        )
        parser.add_argument(
            'record', nargs='?', type=str, action='store', help='record path or UID. Can be repeated'
        )

    def execute(self, context: KeeperParams, **kwargs):
        if not context.vault:
            raise ValueError('Vault is not initialized.')
        
        vault = context.vault

        record_names = kwargs.get('record')
        period_str = kwargs.get('expire')
        name = kwargs.get('share_name', '')
        is_editable = kwargs.get('is_editable', False)
        if isinstance(record_names, str):
            record_names = [record_names]
        if not record_names:
            self.get_parser().print_help()
            return None
        if not period_str:
            logger.warning('URL expiration period parameter \"--expire\" is required.')
            self.get_parser().print_help()
            return None
        
        period = self._validate_and_parse_expiration(period_str)
        
        urls = self._create_share_urls(context, vault, record_names, period, name, is_editable)
        
        return self._handle_output(context, urls, kwargs)

    def _validate_and_parse_expiration(self, period_str):
        """Validate and parse the expiration period."""
        period = timeout_utils.parse_timeout(period_str)        
        SIX_MONTHS_IN_SECONDS = 182 * 24 * 60 * 60
        if period.total_seconds() > SIX_MONTHS_IN_SECONDS:
            raise base.CommandError('one-time-share', 'URL expiration period cannot be greater than 6 months.')
        return period

    def _create_share_urls(self, context: KeeperParams, vault, record_names: list, period, name: str, is_editable: bool):
        """Create share URLs for the given records."""
        urls = {}
        for record_name in record_names:
            record_uid = record_utils.resolve_record(context=context, name=record_name)
            record = vault.vault_data.load_record(record_uid=record_uid)
            url = record_utils.process_external_share(
                context=context, expiration_period=period, record=record, name=name, is_editable=is_editable, is_self_destruct=False
            )
            urls[record_uid] = str(url)
        return urls

    def _handle_output(self, context: KeeperParams, urls: dict, kwargs):
        """Handle different output formats for the URLs."""
        if context.batch_mode:
            return '\n'.join(urls.values())
        
        output = kwargs.get('output') or ''
        if len(urls) > 1 and not output:
            output = 'stdout'
            
        if output == 'clipboard' and len(urls) == 1:
            return self._copy_to_clipboard(urls)
        elif output == 'stdout':
            return self._output_to_stdout(urls)
        else:
            return '\n'.join(urls.values())

    def _copy_to_clipboard(self, urls: dict):
        """Copy URL to clipboard."""
        import pyperclip
        url = next(iter(urls.values()))
        pyperclip.copy(url)
        logger.info('One-Time record share URL is copied to clipboard')
        return None

    def _output_to_stdout(self, urls: dict):
        """Output URLs to stdout in table format."""
        table = [list(x) for x in urls.items()]
        headers = ['Record UID', 'URL']
        report_utils.dump_report_data(table, headers)
        return None


class OneTimeShareRemoveCommand(base.ArgparseCommand):

    def __init__(self):
        self.parser = argparse.ArgumentParser(
            prog = 'share-remove',
            description= 'Removes one-time share URL for a record'
        )
        OneTimeShareRemoveCommand.add_arguments_to_parser(self.parser)
        super().__init__(self.parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument(
            'record', nargs='?', type=str, action='store', help='record path or UID'
        )
        parser.add_argument(
            'share', nargs='?', type=str, action='store', help='one-time share name or ID'
        )
    
    def execute(self, context: KeeperParams, **kwargs):
        if not context.vault:
            raise ValueError('Vault is not initialized.')
        
        vault = context.vault

        record_name = kwargs.get('record')
        if not record_name:
            self.get_parser().print_help()
            return

        record_uid = record_utils.resolve_record(context=context, name=record_name)
        applications = ksm_management.get_app_info(vault=vault, app_uid=record_uid)
        
        if len(applications) == 0:
            logger.info('There are no one-time shares for record \"%s\"', record_name)
            return

        share_name = kwargs.get('share')
        if not share_name:
            self.get_parser().print_help()
            return

        client_id = self._find_client_id(applications, share_name)
        if not client_id:
            return

        self._remove_share(vault, record_uid, client_id, share_name, record_name)

    def _find_client_id(self, applications, share_name: str) -> Optional[bytes]:
        
        cleaned_name = share_name[:-len(TRUNCATE_SUFFIX)] if share_name.endswith(TRUNCATE_SUFFIX) else share_name
        cleaned_name_lower = cleaned_name.lower()
        
        partial_matches = []
        
        for app_info in applications:
            if not app_info.isExternalShare:
                continue
                
            for client in app_info.clients:
                if client.id.lower() == cleaned_name_lower:
                    return client.clientId
                
                encoded_client_id = utils.base64_url_encode(client.clientId)
                if encoded_client_id == cleaned_name:
                    return client.clientId
                
                if encoded_client_id.startswith(cleaned_name):
                    partial_matches.append(client.clientId)
        
        return self._resolve_partial_matches(partial_matches, share_name)

    def _resolve_partial_matches(self, partial_matches: list[bytes], original_name: str) -> Optional[bytes]:
        """
        Resolve partial matches to a single client ID.
        
        Args:
            partial_matches: List of client IDs that partially match
            original_name: Original share name for error reporting
            
        Returns:
            bytes: Single client ID if exactly one match, None otherwise
        """
        if not partial_matches:
            logger.warning('No one-time share found matching "%s"', original_name)
            return None
            
        if len(partial_matches) == 1:
            return partial_matches[0]
            
        # Multiple matches found
        logger.warning('Multiple one-time shares found matching "%s". Please use a more specific identifier.', original_name)
        return None

    def _remove_share(self, vault, record_uid: str, client_id: bytes, share_name: str, record_name: str):
        """Remove the one-time share."""
        rq = APIRequest_pb2.RemoveAppClientsRequest()
        rq.appRecordUid = utils.base64_url_decode(record_uid)
        rq.clients.append(client_id)

        vault.keeper_auth.execute_auth_rest(request=rq, rest_endpoint=ApiUrl.REMOVE_EXTERNAL_SHARE.value)
        logger.info('One-time share \"%s\" is removed from record \"%s\"', share_name, record_name)

class FindDuplicatesCommand(base.ArgparseCommand):
    """Finds duplicate records and merge them in the vault"""

    def __init__(self):
        self.parser = argparse.ArgumentParser(
            prog='find-duplicates',
            description='Finds duplicates in the vault'
        )
        FindDuplicatesCommand.add_arguments_to_parser(self.parser)
        super().__init__(self.parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument(
            '--output', dest='output', choices=['clipboard', 'stdout'], action='store', 
            help='path to resulting output file (ignored for "table" format)'
        )
        parser.add_argument(
            '--format', dest='format', choices=['table', 'csv', 'json'],
            default='table', help='format of output'
        )
        parser.add_argument(
            '--title', action='store_true', help='Match duplicates by title.'
        )
        parser.add_argument(
            '--login', action='store_true', help='Match duplicates by login.'
        )
        parser.add_argument(
            '--password', action='store_true', help='Match duplicates by password.'
        )
        parser.add_argument(
            '--url', action='store_true', help='Match duplicates by url.'
        )
        parser.add_argument(
            '--shares', action='store_true', help='Match duplicates by shares.'
        )
        parser.add_argument(
            '--full', action='store_true', help='Match duplicates by all fields.'
        )
        parser.add_argument(
            '--force', action='store_true', help='Delete duplicates w/o being prompted for confirmation (valid only w/ --merge option)'
        )
        parser.add_argument(
            '-m', '--merge', action='store_true', help='Merge duplicates into a single record (matched by all fields, including shares)'
        )
        parser.add_argument(
            '--ignore-shares-on-merge', action='store_true', help='ignore share permissions when grouping duplicate records to merge'
        )
        parser.add_argument(
            '-n', '--dry-run', action='store_true', help='Simulate removing duplicates (with this flag, no records are ever removed or modified). Valid only w/ --merge flag'
        )
        parser.add_argument(
            '-q', '--quiet', action='store_true', help='Suppress screen output, valid only w/ --force flag'
        )
        parser.add_argument(
            '-s','--scope', action='store', choices=['vault', 'enterprise'], help='The scope of the search (limited to current vault if not specified)'
        )
        parser.add_argument(
            '-r','--refresh-data', action='store_true', help='Populate local cache with latest compliance data . Valid only w/ --scope=enterprise option.'
        )
    
    def execute(self, context: KeeperParams, **kwargs):
        """Execute the find-duplicate command."""
        out_fmt = kwargs.get('format', 'table')
        out_dst = kwargs.get('output')

        scope = kwargs.get('scope', 'vault')
        if scope == 'enterprise':
            return self._scan_enterprise_vaults(context, kwargs)

        quiet = kwargs.get('quiet', False)
        dry_run = kwargs.get('dry_run', False)
        quiet = quiet and not dry_run
        logging_fn = logging.info if not quiet else logging.debug

        search_criteria = self._determine_search_criteria(kwargs)
        
        if not context.vault or not context.vault.vault_data:
            logging_fn('Vault data not available')
            return

        hashes = self._find_duplicate_hashes(context, search_criteria)
        
        field_names = self._get_field_names(search_criteria)
        logging_fn('Find duplicated records by: %s', ', '.join(field_names))
        
        partitions = [rec_uids for rec_uids in hashes.values() if len(rec_uids) > 1]
        
        if not partitions:
            logging_fn('No duplicates found')
            return

        if search_criteria['by_shares']:
            r_uids = [rec_uid for duplicates in partitions for rec_uid in duplicates]
            shared_records_lookup = get_shared_records(context, r_uids, cache_only=True)
            partitions = self._partition_by_shares(partitions, shared_records_lookup)

        return self._generate_results(
            context, partitions, search_criteria, 
            out_fmt, out_dst, kwargs, dry_run, logging_fn)

    def _scan_enterprise_vaults(self, context: KeeperParams, kwargs):
        """Scan enterprise vaults for duplicates."""
        if not context.auth or not context.auth.auth_context:
            raise ValueError('User is not authenticated')
        
        if not context.auth.auth_context.is_enterprise_admin:
            raise ValueError(
                'This feature is available only to enterprise account administrators')
        
        refresh_data = kwargs.get('refresh_data')
        context.enterprise_loader.load(refresh_data)
        raise ValueError(
            'Enterprise scope not yet implemented')

    def _determine_search_criteria(self, kwargs):
        """Determine which fields to search for duplicates."""
        by_title = kwargs.get('title', False)
        by_login = kwargs.get('login', False)
        by_password = kwargs.get('password', False)
        by_url = kwargs.get('url', False)
        by_custom = kwargs.get('full', False)
        by_shares = kwargs.get('shares', False)
        consolidate = kwargs.get('merge', False)

        by_custom = consolidate or by_custom

        if by_custom:
            by_title = True
            by_login = True
            by_password = True
            by_url = True
            by_shares = (not kwargs.get('ignore_shares_on_merge') 
                        if consolidate else True)
        elif (not by_title and not by_login and 
              not by_password and not by_url):
            by_title = True
            by_login = True
            by_password = True

        return {
            'by_title': by_title,
            'by_login': by_login,
            'by_password': by_password,
            'by_url': by_url,
            'by_custom': by_custom,
            'by_shares': by_shares,
            'consolidate': consolidate
        }

    def _get_field_names(self, search_criteria):
        """Get field names for logging."""
        fields = []
        if search_criteria['by_title']:
            fields.append('Title')
        if search_criteria['by_login']:
            fields.append('Login')
        if search_criteria['by_password']:
            fields.append('Password')
        if search_criteria['by_url']:
            fields.append('Website Address')
        if search_criteria['by_custom']:
            fields.append('Custom Fields')
        if search_criteria['by_shares']:
            fields.append('Shares')
        return fields

    def _find_duplicate_hashes(self, context: KeeperParams, search_criteria):
        """Find duplicate records by generating hashes."""
        hashes = {}
        record_cache = {
            x.record_uid: x for x in context.vault.vault_data.records()
        }
        
        for record_uid in record_cache:
            rec = record_cache[record_uid]
            if rec.version not in {2, 3}:
                continue
            
            record = context.vault.vault_data.load_record(record_uid)
            if not record:
                continue

            tokens = self._extract_record_tokens(record, search_criteria)
            custom_hash = self._generate_custom_hash(record, search_criteria)

            hasher = hashlib.sha256()
            non_empty = 0
            
            for token in tokens:
                if token:
                    non_empty += 1
                hasher.update(token.encode())

            if custom_hash:
                hasher.update(custom_hash.encode('utf-8'))
                non_empty += 1

            if non_empty > 0:
                hash_value = hasher.hexdigest()
                rec_uids = hashes.get(hash_value, set())
                rec_uids.add(record_uid)
                hashes[hash_value] = rec_uids

        return hashes

    def _extract_record_tokens(self, record, search_criteria):
        """Extract tokens from record for duplicate detection."""
        tokens = []
        
        if search_criteria['by_title']:
            tokens.append((record.title or '').strip().lower())
        
        if search_criteria['by_login']:
            login_value = self._get_login_value(record)
            tokens.append((login_value or '').lower())
        
        if search_criteria['by_password']:
            password_value = record.extract_password() or ''
            tokens.append(password_value or '')
        
        if search_criteria['by_url']:
            url_value = record.extract_url() or ''
            tokens.append(url_value or '')
        
        return tokens

    def _get_login_value(self, record):
        """Get login value from record, handling different record types."""
        if hasattr(record, 'login'):
            return record.login or ''
        elif hasattr(record, 'get_typed_field'):
            login_field = record.get_typed_field('login')
            return (login_field.get_default_value(str) 
                   if login_field else '')
        return ''

    def _generate_custom_hash(self, record, search_criteria):
        """Generate hash for custom fields if needed."""
        if not search_criteria['by_custom']:
            return None
        
        customs = self._extract_custom_fields(record)
        
        self._add_totp_to_customs(record, customs)
        
        if hasattr(record, 'record_type') and record.record_type:
            customs['type:'] = record.record_type
        
        if not customs:
            return None
        
        keys = list(customs.keys())
        keys.sort()
        custom_hash = ''
        for key in keys:
            custom_hash += f'{key}={customs[key]}'
        
        return custom_hash

    def _extract_custom_fields(self, record):
        """Extract custom fields from record."""
        customs = {}
        
        if hasattr(record, 'custom') and hasattr(record, 'fields'):
            all_fields = list(record.fields) + list(record.custom)
            for field in all_fields:
                name = field.label or field.type
                value = (field.get_default_value() 
                        if hasattr(field, 'get_default_value') else None)
                if name and value:
                    processed_value = self._process_field_value(value)
                    if processed_value:
                        customs[name] = processed_value
        
        elif hasattr(record, 'custom_fields'):
            for x in record.custom_fields:
                name = x.get('name')
                value = x.get('value')
                if name and value:
                    processed_value = self._process_field_value(value)
                    if processed_value:
                        customs[name] = processed_value
        
        return customs

    def _process_field_value(self, value):
        """Process field value for hashing."""
        if isinstance(value, list):
            value = [str(x) for x in value]
            value.sort()
            return '|'.join(value)
        elif isinstance(value, int):
            return str(value) if value != 0 else None
        elif isinstance(value, dict):
            keys = list(value.keys())
            keys.sort()
            return ';'.join(
                (f'{x}:{value[x]}' for x in keys if value.get(x)))
        elif isinstance(value, str):
            return value
        else:
            return str(value) if value is not None else None

    def _add_totp_to_customs(self, record, customs):
        """Add TOTP to customs if available."""
        if hasattr(record, 'get_typed_field'):
            totp_field = record.get_typed_field('oneTimeCode')
            if totp_field:
                totp_value = totp_field.get_default_value(str)
                if totp_value:
                    customs['totp'] = totp_value
        elif hasattr(record, 'totp') and record.totp:
            customs['totp'] = record.totp
                
    def _partition_by_shares(self, duplicate_sets, shared_recs_lookup):
        """Partition duplicates by share permissions."""
        result = []
        for duplicates in duplicate_sets:
            recs_by_hash = {}
            for rec_uid in duplicates:
                h = hashlib.sha256()
                shared_rec = shared_recs_lookup.get(rec_uid)
                if not shared_rec:
                    continue
                
                permissions = shared_rec.permissions
                tu_type = SharePermissions.SharePermissionsType.TEAM_USER
                permissions = {k: p for k, p in permissions.items() 
                             if tu_type not in p.types or len(p.types) > 1}
                permissions = {k: p for k, p in permissions.items() 
                             if p.to_name != shared_rec.owner}
                
                permissions_keys = list(permissions.keys())
                permissions_keys.sort()

                to_hash = ';'.join(f'{k}={permissions.get(k).permissions_text}' 
                                 for k in permissions_keys)
                to_hash = to_hash or 'non-shared'
                h.update(to_hash.encode())
                h_val = h.hexdigest()
                r_uids = recs_by_hash.get(h_val, set())
                r_uids.add(rec_uid)
                recs_by_hash[h_val] = r_uids
            
            result.extend([r for r in recs_by_hash.values() if len(r) > 1])
        return result

    def _generate_results(self, context, partitions, search_criteria, 
                         out_fmt, out_dst, kwargs, dry_run, logging_fn):
        """Generate and display results."""
        headers = ['group', 'title', 'login']
        if search_criteria['by_url']:
            headers.append('url')
        headers.extend(['uid', 'record_owner', 'shared_to'])
        headers = [report_utils.field_to_title(h) for h in headers] if out_fmt != 'json' else headers
        
        table_raw = []
        table = []
        to_remove = set()
        
        r_uids = [rec_uid for duplicates in partitions for rec_uid in duplicates]
        shared_records_lookup = get_shared_records(context, r_uids, cache_only=True)
        
        for i, partition in enumerate(partitions):
            for j, record_uid in enumerate(partition):
                row = self._create_table_row(
                    context, record_uid, i, 
                    search_criteria, shared_records_lookup)
                table.append(row)
                
                if j != 0:
                    to_remove.add(record_uid)
                    table_raw.append(row)
        
        if search_criteria['consolidate']:
            return self._remove_duplicates(
                table_raw, headers, to_remove, 
                kwargs, dry_run, logging_fn, context)
        else:
            title = 'Duplicates Found:'
            return report_utils.dump_report_data(
                table, headers, title=title, 
                fmt=out_fmt, filename=out_dst, group_by=0)

    def _create_table_row(self, context, record_uid, group_num, 
                         search_criteria, shared_records_lookup):
        """Create a table row for a record."""
        shared_record = shared_records_lookup.get(record_uid)
        record = context.vault.vault_data.load_record(record_uid)
        title = record.title or ''
        
        login = self._get_login_value(record) or ''
        
        url = ''
        if search_criteria['by_url']:
            url_value = record.extract_url() or ''
            url = urllib.parse.urlparse(url_value).hostname
            url = url[:30] if url else ''
        
        owner = shared_record.owner if shared_record else ''
        if not owner:
            owner = (context.auth.auth_context.username 
                    if context.auth and context.auth.auth_context else '')
        
        shares = self._get_shares_string(shared_record, owner)
        
        row = [group_num + 1, title, login]
        if search_criteria['by_url']:
            row.append(url)
        row.extend([record_uid, owner, shares])
        
        return row

    def _get_shares_string(self, shared_record, owner):
        """Get shares string for display."""
        if not shared_record:
            return ''
        
        perms = {k: p for k, p in shared_record.permissions.items()}
        keys = list(perms.keys())
        keys.sort()
        perms = [perms.get(k) for k in keys]
        return ', '.join([p.to_name for p in perms if owner != p.to_name])

    def _remove_duplicates(self, dupe_info, col_headers, dupe_uids, 
                          kwargs, dry_run, logging_fn, context):
        """Remove duplicate records."""
        def confirm_removal():
            prompt_title = (f'\nThe following duplicate '
                          f'{"records have" if len(dupe_uids) > 1 else "record has"} '
                          f'been marked for removal:\n')
            indices = (idx + 1 for idx in range(len(dupe_info)))
            prompt_report = prompt_title + '\n' + tabulate(dupe_info, col_headers, showindex=indices)
            prompt_msg = prompt_report + '\n\nDo you wish to proceed?'
            answer = input(f"{prompt_msg} (y/n): ").strip().lower()
            return answer == 'y'

        if kwargs.get('force') or confirm_removal():
            logging_fn(f'Deleting {len(dupe_uids)} records...')
            if not dry_run:
                rm_cmd = record_edit.RecordDeleteCommand()
                rm_cmd.execute(context, records=list(dupe_uids), force=True)
            else:
                logging.info('In dry-run mode: no actual records removed '
                           '(exclude --dry-run flag to disable)')
        else:
            print('Duplicate record removal aborted. No records removed.')

    
    
    