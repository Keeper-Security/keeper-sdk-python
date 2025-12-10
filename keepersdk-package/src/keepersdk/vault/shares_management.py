import json
import logging
from enum import Enum
from typing import Optional

from .. import crypto, utils
from ..proto import folder_pb2, record_pb2
from ..vault import vault_online, vault_utils, share_management_utils
from ..enterprise import enterprise_data


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


logger = logging.getLogger()


TIMESTAMP_MILLISECONDS_FACTOR = 1000

def set_expiration_fields(obj, expiration):
    """Set expiration and timerNotificationType fields on proto object if expiration is provided."""
    if isinstance(expiration, int):
        if expiration > 0:
            obj.expiration = expiration * TIMESTAMP_MILLISECONDS_FACTOR
            obj.timerNotificationType = record_pb2.NOTIFY_OWNER
        elif expiration < 0:
            obj.expiration = -1


class RecordShares():
    
    @staticmethod
    def cancel_share(vault: vault_online.VaultOnline, emails: list[str]):
        for email in emails:
            request = {
                'command': 'cancel_share',
                'to_email': email
            }
            vault.keeper_auth.execute_auth_command(request=request)
        vault.sync_down()
    
    @staticmethod
    def prep_request(vault: vault_online.VaultOnline,
                    emails: list[str],
                    action: str,
                    uid_or_name: str,
                    share_expiration: int,
                    dry_run: bool,
                    enterprise: enterprise_data.EnterpriseData,
                    enterprise_access: bool = False,
                    recursive: bool = False,
                    can_edit: bool = False,
                    can_share: bool = False):
        
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
                rs = share_management_utils.try_resolve_path(vault, uid_or_name)
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
            if enterprise_access:
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
                except Exception as e:
                    logger.error(f'Error checking share admin status: {e}')

        if record_uid is None and folder_uid is None and shared_folder_uid is None:
            raise ValueError('Enter name or uid of existing record or shared folder')
        
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
                raise ValueError('--recursive parameter is required')
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
            raise ValueError('There are no records to share selected')

        if action == 'owner' and len(emails) > 1:
            raise ValueError('You can transfer ownership to a single account only')

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
            raise ValueError('Nothing to do.')

        # Load records in shared folders
        if shared_folder_uid:
            if isinstance(shared_folder_uid, str):
                share_management_utils.load_records_in_shared_folder(vault=vault, shared_folder_uid=shared_folder_uid, record_uids=record_uids)
            elif isinstance(shared_folder_uid, list):
                for sf_uid in shared_folder_uid:
                    share_management_utils.load_records_in_shared_folder(vault=vault, shared_folder_uid=sf_uid, record_uids=record_uids)

        # Get share information for records not in cache
        not_owned_records = {} if is_share_admin else None
        share_info = share_management_utils.get_record_shares(vault=vault, record_uids=list(record_uids), is_share_admin=False)
        if share_info and not_owned_records is not None:
            for record_info in share_info:
                record_uid = record_info.get('record_uid')
                if record_uid:
                    not_owned_records[record_uid] = record_info

        # Build the request
        rq = record_pb2.RecordShareUpdateRequest()
        existing_shares = {}
        
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

            record_path = share_management_utils.resolve_record_share_path(vault=vault, enterprise=enterprise, record_uid=record_uid)
            
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
                        else:
                            ro.editable = bool(can_edit)
                            ro.shareable = bool(can_share)
                            set_expiration_fields(ro, share_expiration)
                    elif email in existing_shares:
                        current = existing_shares[email]
                        if action == ShareAction.OWNER.value:
                            ro.transfer = True
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
    def send_requests(vault: vault_online.VaultOnline, requests: record_pb2.RecordShareUpdateRequest):
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
                
                success_status = []
                failed_status = []
                statuses = getattr(response, attr_name)
                for status_record in statuses:
                    record_uid = utils.base64_url_encode(status_record.recordUid)
                    status = status_record.status
                    email = status_record.username
                    
                    if status == 'success':
                        success_status.append(
                            f'Record "{record_uid}" access permissions has been {success_verb} user \'{email}\''
                        )
                    else:
                        failed_status.append(
                            f'Failed to {failure_verb} record "{record_uid}" access permissions for user \'{email}\': {status_record.message}'
                        )
                return success_status, failed_status
        
        for request in requests:
            # Process request in batches until all records are handled
            success_responses = []
            failed_responses = []
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
                
                success_response, failed_response = process_response_statuses(response)
                success_responses.extend(success_response)
                failed_responses.extend(failed_response)
            
            return success_responses, failed_responses

class FolderShares():
    
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
                rq.defaultManageRecords = folder_pb2.BOOLEAN_TRUE if mr == ManagePermission.ON.value else folder_pb2.BOOLEAN_FALSE
            else:
                rq.defaultManageRecords = folder_pb2.BOOLEAN_NO_CHANGE
            if mu is not None:
                rq.defaultManageUsers = folder_pb2.BOOLEAN_TRUE if mu == ManagePermission.ON.value else folder_pb2.BOOLEAN_FALSE
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
                rss = vault.keeper_auth.execute_auth_rest(rest_endpoint=ApiUrl.SHARE_FOLDER_UPDATE.value, request=rqs, response_type=folder_pb2.SharedFolderUpdateV3ResponseV2, payload_version=1)
                if rss and rss.sharedFoldersUpdateV3Response:
                    success_status = [str]
                    failed_status = [str]
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
                                            success_status.append('Team share \'%s\' %s', team.name,
                                                            'added' if attr == 'sharedFolderAddTeamStatus' else
                                                            'updated' if attr == 'sharedFolderUpdateTeamStatus' else
                                                            'removed')
                                        else:
                                            failed_status.append('Team share \'%s\' failed', team.name)

                        for attr in (
                                'sharedFolderAddUserStatus', 'sharedFolderUpdateUserStatus',
                                'sharedFolderRemoveUserStatus'):
                            if hasattr(rs, attr):
                                statuses = getattr(rs, attr)
                                for s in statuses:
                                    username = s.username
                                    status = s.status
                                    if status == 'success':
                                        success_status.append('User share \'%s\' %s', username,
                                                        'added' if attr == 'sharedFolderAddUserStatus' else
                                                        'updated' if attr == 'sharedFolderUpdateUserStatus' else
                                                        'removed')
                                    elif status == 'invited':
                                        success_status.append('User \'%s\' invited', username)
                                    else:
                                        failed_status.append('User share \'%s\' failed', username)

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
                                        action = 'added' if attr == 'sharedFolderAddRecordStatus' else 'updated' if attr == 'sharedFolderUpdateRecordStatus' else 'removed'
                                        success_status.append(f'Record share {title} {action}')
                                    else:
                                        failed_status.append(f'Record share \'{title}\' failed')
                    return success_status, failed_status
