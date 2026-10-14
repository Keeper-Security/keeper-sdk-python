import logging
from enum import Enum
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union

from .. import crypto, utils
from ..proto import folder_pb2, record_pb2
from ..vault import vault_online, vault_types, vault_utils, share_management_utils
from ..enterprise import enterprise_types


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

# Constants
TIMESTAMP_MILLISECONDS_FACTOR = 1000
MAX_BATCH_SIZE = 990
FOLDER_CHUNK_SIZE = 999
UID_BYTE_LENGTH = 16

# Shared folder update: status returned when an "update" targets a user/team that is no
# longer a member of the shared folder on the server (local cache is stale).
SF_STALE_MEMBER_STATUS = 'doesnt_exist'
SF_STALE_RETRY_LIMIT = 1
# Record share update: statuses meaning the direct share no longer exists (e.g. it expired).
RECORD_STALE_SHARE_STATUSES = frozenset({'doesnt_exist'})

# Callback used to rebuild a shared folder request after stale members are evicted.
# (shared_folder_uid, stale_usernames, stale_team_uids) -> request | [requests] | None
SharedFolderRequestRebuilder = Callable[
    [str, List[str], List[str]],
    Union[None, folder_pb2.SharedFolderUpdateV3Request, Sequence[folder_pb2.SharedFolderUpdateV3Request]]
]

# Record type attribute names
RECORD_TYPE_ADD = 'addSharedRecord'
RECORD_TYPE_UPDATE = 'updateSharedRecord'
RECORD_TYPE_REMOVE = 'removeSharedRecord'

# Status attribute mappings
RECORD_STATUS_ATTRIBUTES = {
    'addSharedRecordStatus': ('granted to', 'grant'),
    'updateSharedRecordStatus': ('changed for', 'change'),
    'removeSharedRecordStatus': ('revoked from', 'revoke')
}

# Folder type strings
FOLDER_TYPE_SHARED_FOLDER = 'shared_folder'
FOLDER_TYPE_SHARED_FOLDER_FOLDER = 'shared_folder_folder'

def is_share_expired(expiration, now_ms: Optional[int] = None) -> bool:
    """True if a share expiration timestamp (milliseconds, int or str) is set and in the past."""
    try:
        expiration = int(expiration or 0)
    except (TypeError, ValueError):
        return False
    if expiration <= 0:
        return False
    return expiration <= (now_ms if now_ms is not None else utils.current_milli_time())


def set_expiration_fields(obj, expiration, rotate_on_expiration: bool = False):
    """Set expiration, notification, and optional rotateOnExpiration on a share proto object."""
    if isinstance(expiration, int):
        if expiration > 0:
            obj.expiration = expiration * TIMESTAMP_MILLISECONDS_FACTOR
            obj.timerNotificationType = record_pb2.NOTIFY_OWNER
            if rotate_on_expiration:
                obj.rotateOnExpiration = True
        elif expiration < 0:
            obj.expiration = -1


class RecordShares():
    
    @staticmethod
    def cancel_share(vault: vault_online.VaultOnline, emails: List[str]):
        for email in emails:
            request = {
                'command': 'cancel_share',
                'to_email': email
            }
            vault.keeper_auth.execute_auth_command(request=request)
        vault.sync_down()
    
    @staticmethod
    def _resolve_uid_or_name(vault: vault_online.VaultOnline, uid_or_name: str, record_cache: Dict, shared_folder_cache: Dict, folder_cache: Dict):
        """Resolve uid_or_name to record_uid, folder_uid, or shared_folder_uid."""
        record_uid = None
        folder_uid = None
        shared_folder_uid = None
        
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
                        if folder.folder_type == FOLDER_TYPE_SHARED_FOLDER:
                            folder_uid = folder.folder_uid
                            shared_folder_uid = folder_uid
                        elif folder.folder_type == FOLDER_TYPE_SHARED_FOLDER_FOLDER:
                            folder_uid = folder.folder_uid
                            shared_folder_uid = folder.subfolders
        
        return record_uid, folder_uid, shared_folder_uid
    
    @staticmethod
    def _check_share_admin_status(vault, uid_or_name, enterprise_access):
        """Check if user is share admin for the given UID."""
        is_share_admin = False
        record_uid = None
        
        if enterprise_access:
            try:
                uid = utils.base64_url_decode(uid_or_name)
                if isinstance(uid, bytes) and len(uid) == UID_BYTE_LENGTH:
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
        
        return is_share_admin, record_uid
    
    @staticmethod
    def _collect_record_uids(vault, record_uid, folder_uid, shared_folder_uid, 
                            record_cache, recursive):
        """Collect all record UIDs based on the resolved UIDs."""
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
        
        return record_uids
    
    @staticmethod
    def _handle_user_invitations(vault, all_users, action, dry_run):
        """Handle user invitations and filter users with available keys."""
        if not dry_run and action in (ShareAction.GRANT.value, ShareAction.OWNER.value):
            invited = vault.keeper_auth.load_user_public_keys(list(all_users), send_invites=True)
            if invited:
                for email in invited:
                    logger.warning('Share invitation has been sent to \'%s\'', email)
                logger.warning('Please repeat this command when invitation is accepted.')
                all_users.difference_update(invited)
            
            if vault.keeper_auth._key_cache:
                all_users.intersection_update(vault.keeper_auth._key_cache.keys())
        
        return all_users
    
    @staticmethod
    def _encrypt_record_key_for_user(vault, record_key, email, ro):
        """Encrypt record key for a user using their public key."""
        keys = vault.keeper_auth._key_cache[email]
        if vault.keeper_auth.auth_context.forbid_rsa and keys.ec:
            ec_key = crypto.load_ec_public_key(keys.ec)
            ro.recordKey = crypto.encrypt_ec(record_key, ec_key)
            ro.useEccKey = True
        elif not vault.keeper_auth.auth_context.forbid_rsa and keys.rsa:
            rsa_key = crypto.load_rsa_public_key(keys.rsa)
            ro.recordKey = crypto.encrypt_rsa(record_key, rsa_key)
            ro.useEccKey = False
    
    @staticmethod
    def _build_shared_record(vault, email, record_uid, record_path, action, 
                            can_edit, can_share, share_expiration, existing_shares,
                            rotate_on_expiration: bool = False):
        """Build a SharedRecord proto object for a user."""
        ro = record_pb2.SharedRecord()
        ro.toUsername = email
        ro.recordUid = utils.base64_url_decode(record_uid)
        
        if record_path:
            if 'shared_folder_uid' in record_path:
                ro.sharedFolderUid = utils.base64_url_decode(record_path['shared_folder_uid'])
            if 'team_uid' in record_path:
                ro.teamUid = utils.base64_url_decode(record_path['team_uid'])
        
        if action == ShareAction.OWNER.value:
            ro.transfer = True
        elif action == ShareAction.GRANT.value:
            if email in existing_shares:
                current = existing_shares[email]
                ro.editable = can_edit if can_edit is not None else current.get('editable')
                ro.shareable = can_share if can_share is not None else current.get('shareable')
            else:
                ro.editable = bool(can_edit)
                ro.shareable = bool(can_share)
            set_expiration_fields(ro, share_expiration, rotate_on_expiration)
        else:
            if can_share or can_edit:
                if email in existing_shares:
                    current = existing_shares[email]
                    ro.editable = False if can_edit else current.get('editable')
                    ro.shareable = False if can_share else current.get('shareable')
                set_expiration_fields(ro, share_expiration, rotate_on_expiration)
        
        return ro
    
    @staticmethod
    def _process_record_shares(vault, record_uids, all_users, action, can_edit, 
                              can_share, share_expiration, record_cache, 
                              not_owned_records, is_share_admin, enterprise,
                              rotate_on_expiration: bool = False,
                              expired_shares: Optional[Set[Tuple[str, str]]] = None):
        """Process shares for all records and users, building the request."""
        rq = record_pb2.RecordShareUpdateRequest()
        
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
            
            existing_shares = {}
            if isinstance(rec, dict):
                if 'shares' in rec:
                    shares = rec['shares']
                    if 'user_permissions' in shares:
                        for po in shares['user_permissions']:
                            username = po['username'].lower()
                            if not po.get('owner') and is_share_expired(po.get('expiration')):
                                # Expired share: server no longer has it, so grant must be sent as an add.
                                if expired_shares is not None:
                                    expired_shares.add((record_uid, username))
                                continue
                            existing_shares[username] = po
                    del rec['shares']
            
            record_path = share_management_utils.resolve_record_share_path(
                vault=vault, enterprise=enterprise, record_uid=record_uid
            )
            
            # Process each user
            for email in all_users:
                ro = RecordShares._build_shared_record(
                    vault, email, record_uid, record_path, action,
                    can_edit, can_share, share_expiration, existing_shares,
                    rotate_on_expiration,
                )
                
                if action in {ShareAction.GRANT.value, ShareAction.OWNER.value}:
                    record_uid_to_use = rec.get('record_uid', record_uid) if isinstance(rec, dict) else getattr(rec, 'record_uid', record_uid)
                    record_key = vault.vault_data.get_record_key(record_uid=record_uid_to_use)
                    if record_key and email not in existing_shares and vault.keeper_auth._key_cache and email in vault.keeper_auth._key_cache:
                        RecordShares._encrypt_record_key_for_user(vault, record_key, email, ro)
                    
                    if email in existing_shares:
                        rq.updateSharedRecord.append(ro)
                    else:
                        rq.addSharedRecord.append(ro)
                else:
                    if can_share or can_edit:
                        rq.updateSharedRecord.append(ro)
                    else:
                        rq.removeSharedRecord.append(ro)
        
        return rq
    
    @staticmethod
    def prep_request(vault: vault_online.VaultOnline,
                    emails: List[str],
                    action: str,
                    uid_or_name: str,
                    share_expiration: Optional[int],
                    dry_run: bool,
                    enterprise: enterprise_types.IEnterpriseData,
                    enterprise_access: bool = False,
                    recursive: bool = False,
                    can_edit: bool = False,
                    can_share: bool = False,
                    rotate_on_expiration: bool = False,
                    expired_shares: Optional[Set[Tuple[str, str]]] = None):
        """Prepare a record share update request.

        ``expired_shares``: optional set the caller passes in; it is filled with
        (record_uid, username) pairs whose existing direct share has expired. Pass the same set
        to :meth:`send_requests` to get "had expired" messages in the result.
        """
        # Build caches
        record_cache = {x.record_uid: x for x in vault.vault_data.records()}
        shared_folder_cache = {x.shared_folder_uid: x for x in vault.vault_data.shared_folders()}
        folder_cache = {x: x for x in getattr(vault.vault_data, '_folders', [])}
        
        # Resolve UID or name
        record_uid, folder_uid, shared_folder_uid = RecordShares._resolve_uid_or_name(
            vault, uid_or_name, record_cache, shared_folder_cache, folder_cache
        )
        
        # Check share admin status if needed
        is_share_admin = False
        if record_uid is None and folder_uid is None and shared_folder_uid is None:
            is_share_admin, record_uid = RecordShares._check_share_admin_status(
                vault, uid_or_name, enterprise_access
            )
        
        if record_uid is None and folder_uid is None and shared_folder_uid is None:
            raise ValueError('Enter name or uid of existing record or shared folder')
        
        # Collect record UIDs
        record_uids = RecordShares._collect_record_uids(
            vault, record_uid, folder_uid, shared_folder_uid, record_cache, recursive
        )
        
        if not record_uids:
            raise ValueError('There are no records to share selected')

        if rotate_on_expiration:
            if action != ShareAction.GRANT.value:
                raise ValueError('--rotate-on-expiration is only valid with --action grant')
            share_management_utils.validate_rotate_on_expiration(share_expiration, rotate_on_expiration)
            share_management_utils.validate_record_shares_rotate_on_expiration(
                vault, record_uids, rotate_on_expiration
            )
        
        if action == ShareAction.OWNER.value and len(emails) > 1:
            raise ValueError('You can transfer ownership to a single account only')
        
        # Normalize and handle user invitations
        all_users = {email.casefold() for email in emails}
        all_users = RecordShares._handle_user_invitations(vault, all_users, action, dry_run)
        
        if not all_users:
            raise ValueError('Nothing to do.')
        
        # Load records in shared folders
        if shared_folder_uid:
            if isinstance(shared_folder_uid, str):
                share_management_utils.load_records_in_shared_folder(
                    vault=vault, shared_folder_uid=shared_folder_uid, record_uids=record_uids
                )
            elif isinstance(shared_folder_uid, list):
                for sf_uid in shared_folder_uid:
                    share_management_utils.load_records_in_shared_folder(
                        vault=vault, shared_folder_uid=sf_uid, record_uids=record_uids
                    )
        
        # Get share information for records not in cache
        not_owned_records = {} if is_share_admin else None
        share_info = share_management_utils.get_record_shares(
            vault=vault, record_uids=list(record_uids), is_share_admin=False
        )
        if share_info and expired_shares is not None and action == ShareAction.GRANT.value:
            target_users = {x.lower() for x in all_users}
            for record_info in share_info:
                rec_uid = record_info.get('record_uid')
                for po in (record_info.get('shares') or {}).get('user_permissions') or []:
                    username = (po.get('username') or '').lower()
                    if (rec_uid and username in target_users and not po.get('owner')
                            and is_share_expired(po.get('expiration'))):
                        expired_shares.add((rec_uid, username))
        if share_info and not_owned_records is not None:
            for record_info in share_info:
                record_uid = record_info.get('record_uid')
                if record_uid:
                    not_owned_records[record_uid] = record_info
        
        # Build the request
        return RecordShares._process_record_shares(
            vault, record_uids, all_users, action, can_edit, can_share,
            share_expiration, record_cache, not_owned_records, is_share_admin, enterprise,
            rotate_on_expiration, expired_shares,
        )
    
    @staticmethod
    def _create_batch_request(request, max_size):
        """Create a batch request by taking items from the source request."""
        batch = record_pb2.RecordShareUpdateRequest()
        remaining = max_size
        
        record_type_attrs = [RECORD_TYPE_ADD, RECORD_TYPE_UPDATE, RECORD_TYPE_REMOVE]
        for attr_name in record_type_attrs:
            if remaining <= 0:
                break
                
            source_list = getattr(request, attr_name)
            if not source_list:
                continue
                
            items_to_take = min(remaining, len(source_list))
            target_list = getattr(batch, attr_name)
            target_list.extend(source_list[:items_to_take])
            
            del source_list[:items_to_take]
            remaining -= items_to_take
            
        return batch
    
    @staticmethod
    def _process_response_statuses(response, expired_shares: Optional[Set[Tuple[str, str]]] = None,
                                   ignore_updates: Optional[Set[Tuple[str, str]]] = None,
                                   readded: Optional[Set[Tuple[str, str]]] = None):
        """Process and log the status of each operation in the response."""
        success_status = []
        failed_status = []
        expired_shares = expired_shares or set()
        ignore_updates = ignore_updates or set()
        readded = readded or set()

        for attr_name, (success_verb, failure_verb) in RECORD_STATUS_ATTRIBUTES.items():
            if not hasattr(response, attr_name):
                continue

            statuses = getattr(response, attr_name)
            for status_record in statuses:
                record_uid = utils.base64_url_encode(status_record.recordUid)
                status = status_record.status
                email = status_record.username
                key = (record_uid, (email or '').lower())

                if attr_name == RECORD_TYPE_UPDATE + 'Status' and key in ignore_updates:
                    continue
                was_expired = key in expired_shares or key in readded

                if status == 'success':
                    if attr_name != RECORD_TYPE_REMOVE + 'Status' and was_expired:
                        success_status.append(
                            f'Record "{record_uid}" share for user \'{email}\' had expired; '
                            f'access permissions have been granted again'
                        )
                    else:
                        success_status.append(
                            f'Record "{record_uid}" access permissions has been {success_verb} user \'{email}\''
                        )
                elif attr_name == RECORD_TYPE_UPDATE + 'Status' and status in RECORD_STALE_SHARE_STATUSES:
                    reason = 'has expired' if was_expired else 'no longer exists (it has expired or was removed)'
                    failed_status.append(
                        f'Record "{record_uid}" share for user \'{email}\' {reason} and could not be renewed '
                        f'automatically; share the record again to restore access'
                    )
                elif was_expired and attr_name == RECORD_TYPE_ADD + 'Status':
                    failed_status.append(
                        f'Record "{record_uid}" share for user \'{email}\' had expired and could not be '
                        f'granted again: {status_record.message or status}'
                    )
                else:
                    failed_status.append(
                        f'Failed to {failure_verb} record "{record_uid}" access permissions for user \'{email}\': {status_record.message or status}'
                    )

        return success_status, failed_status

    @staticmethod
    def _has_pending_requests(request):
        """Check if request has any pending items."""
        return (len(request.addSharedRecord) > 0 or
                len(request.updateSharedRecord) > 0 or
                len(request.removeSharedRecord) > 0)

    @staticmethod
    def _rebuild_stale_updates_as_adds(vault: vault_online.VaultOnline, batch_request, response
                                       ) -> Tuple[Optional[record_pb2.RecordShareUpdateRequest], Set[Tuple[str, str]]]:
        """Turn updateSharedRecord entries answered with a stale status into addSharedRecord entries."""
        stale = {
            (utils.base64_url_encode(x.recordUid), (x.username or '').lower())
            for x in response.updateSharedRecordStatus if x.status in RECORD_STALE_SHARE_STATUSES
        }
        if not stale:
            return None, set()

        retry = record_pb2.RecordShareUpdateRequest()
        rebuilt: Set[Tuple[str, str]] = set()
        for ro in batch_request.updateSharedRecord:
            record_uid = utils.base64_url_encode(ro.recordUid)
            email = (ro.toUsername or '').lower()
            if (record_uid, email) not in stale:
                continue
            record_key = vault.vault_data.get_record_key(record_uid=record_uid)
            if not record_key:
                continue
            key_cache = vault.keeper_auth._key_cache
            if not key_cache or email not in key_cache:
                vault.keeper_auth.load_user_public_keys([email], send_invites=False)
                key_cache = vault.keeper_auth._key_cache
            if not key_cache or email not in key_cache:
                continue
            add = record_pb2.SharedRecord()
            add.CopyFrom(ro)
            RecordShares._encrypt_record_key_for_user(vault, record_key, email, add)
            if not add.recordKey:
                continue
            retry.addSharedRecord.append(add)
            rebuilt.add((record_uid, email))
        return (retry if rebuilt else None), rebuilt

    @staticmethod
    def send_requests(vault: vault_online.VaultOnline, requests: List[record_pb2.RecordShareUpdateRequest],
                      expired_shares: Optional[Set[Tuple[str, str]]] = None,
                      retry_stale: bool = True):
        """Send record share update requests in batches.

        ``expired_shares``: (record_uid, username) pairs from :meth:`prep_request` whose share had
        expired; used for clearer result messages.
        ``retry_stale``: if an update is rejected because the share no longer exists (e.g. expired),
        re-send it once as an add with the record key encrypted for the user.
        """
        success_responses = []
        failed_responses = []
        for request in requests:
            while RecordShares._has_pending_requests(request):
                batch_request = RecordShares._create_batch_request(request, MAX_BATCH_SIZE)

                response = vault.keeper_auth.execute_auth_rest(
                    rest_endpoint=ApiUrl.SHARE_UPDATE.value,
                    request=batch_request,
                    response_type=record_pb2.RecordShareUpdateResponse
                )
                if not response:
                    continue

                retry_rq, rebuilt = (None, set())
                if retry_stale:
                    retry_rq, rebuilt = RecordShares._rebuild_stale_updates_as_adds(vault, batch_request, response)

                success_response, failed_response = RecordShares._process_response_statuses(
                    response, expired_shares, ignore_updates=rebuilt)
                success_responses.extend(success_response)
                failed_responses.extend(failed_response)

                if retry_rq is not None:
                    for record_uid, email in sorted(rebuilt):
                        logger.info('Share of record %s for user \'%s\' no longer exists (expired); re-granting',
                                    record_uid, email)
                    retry_response = vault.keeper_auth.execute_auth_rest(
                        rest_endpoint=ApiUrl.SHARE_UPDATE.value,
                        request=retry_rq,
                        response_type=record_pb2.RecordShareUpdateResponse
                    )
                    if retry_response:
                        success_response, failed_response = RecordShares._process_response_statuses(
                            retry_response, expired_shares, readded=rebuilt)
                        success_responses.extend(success_response)
                        failed_responses.extend(failed_response)

        return success_responses, failed_responses

class FolderShares():
    
    @staticmethod
    def _convert_manage_permission(value, default_value=None):
        """Convert manage permission value to proto boolean."""
        if value is None:
            return folder_pb2.BOOLEAN_NO_CHANGE if default_value is None else folder_pb2.BOOLEAN_TRUE if default_value else folder_pb2.BOOLEAN_FALSE
        return folder_pb2.BOOLEAN_TRUE if value == ManagePermission.ON.value else folder_pb2.BOOLEAN_FALSE
    
    @staticmethod
    def _encrypt_shared_folder_key_for_user(vault, sf_key, keys, uo):
        """Encrypt shared folder key for a user."""
        if vault.keeper_auth.auth_context.forbid_rsa and keys.ec:
            ec_key = crypto.load_ec_public_key(keys.ec)
            uo.typedSharedFolderKey.encryptedKey = crypto.encrypt_ec(sf_key, ec_key)
            uo.typedSharedFolderKey.encryptedKeyType = folder_pb2.encrypted_by_public_key_ecc
        elif not vault.keeper_auth.auth_context.forbid_rsa and keys.rsa:
            rsa_key = crypto.load_rsa_public_key(keys.rsa)
            uo.typedSharedFolderKey.encryptedKey = crypto.encrypt_rsa(sf_key, rsa_key)
            uo.typedSharedFolderKey.encryptedKeyType = folder_pb2.encrypted_by_public_key
    
    @staticmethod
    def _encrypt_shared_folder_key_for_team(vault, team_sf_key, keys, to):
        """Encrypt shared folder key for a team."""
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
    
    @staticmethod
    def _initialize_request(rq, curr_sf):
        """Initialize the shared folder update request with basic fields."""
        rq.sharedFolderUid = utils.base64_url_decode(curr_sf['shared_folder_uid'])
        if 'revision' in curr_sf:
            rq.revision = curr_sf['revision']
        else:
            rq.forceUpdate = True
    
    @staticmethod
    def _process_default_account_permissions(rq, action, mr, mu, default_account):
        """Process default account permissions."""
        if default_account and action == ShareAction.GRANT.value:
            rq.defaultManageRecords = FolderShares._convert_manage_permission(mr)
            rq.defaultManageUsers = FolderShares._convert_manage_permission(mu)
    
    @staticmethod
    def _process_users(vault, rq, curr_sf, users, action, mr, mu, share_expiration,
                       rotate_on_expiration: bool = False):
        """Process user shares for the shared folder."""
        if not users:
            return

        existing_users = {}
        for user in curr_sf.get('users', []):
            username = user['username'] if isinstance(user, dict) else user.name
            if username:
                existing_users[username.casefold()] = username

        for email in users:
            current_username = existing_users.get(email.casefold(), email)
            uo = folder_pb2.SharedFolderUpdateUser()
            uo.username = current_username
            set_expiration_fields(uo, share_expiration, rotate_on_expiration)

            if email.casefold() in existing_users:
                if action == ShareAction.GRANT.value:
                    uo.manageRecords = FolderShares._convert_manage_permission(mr)
                    uo.manageUsers = FolderShares._convert_manage_permission(mu)
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
                    default_mr = curr_sf.get('default_manage_records') is True if mr is None else None
                    default_mu = curr_sf.get('default_manage_users') is True if mu is None else None
                    uo.manageRecords = FolderShares._convert_manage_permission(mr, default_mr)
                    uo.manageUsers = FolderShares._convert_manage_permission(mu, default_mu)
                    
                    sf_key = curr_sf.get('shared_folder_key_unencrypted')
                    if sf_key:
                        FolderShares._encrypt_shared_folder_key_for_user(vault, sf_key, keys, uo)
                    
                    rq.sharedFolderAddUser.append(uo)
                else:
                    logger.warning('User %s not found', email)
    
    @staticmethod
    def _process_teams(vault, rq, curr_sf, teams, action, mr, mu, share_expiration,
                       rotate_on_expiration: bool = False):
        """Process team shares for the shared folder."""
        if not teams:
            return
        
        existing_teams = {x['team_uid']: x for x in curr_sf.get('teams', [])}
        
        for team_uid in teams:
            to = folder_pb2.SharedFolderUpdateTeam()
            to.teamUid = utils.base64_url_decode(team_uid)
            set_expiration_fields(to, share_expiration, rotate_on_expiration)
            
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
                
                team_sf_key = curr_sf.get('shared_folder_key_unencrypted')
                if team_sf_key:
                    vault.keeper_auth.load_team_keys([team_uid])
                    keys = vault.keeper_auth._key_cache.get(team_uid) if vault.keeper_auth._key_cache else None
                    if keys:
                        FolderShares._encrypt_shared_folder_key_for_team(vault, team_sf_key, keys, to)
                    else:
                        continue
                else:
                    logger.info('Shared folder key is not available.')
                
                rq.sharedFolderAddTeam.append(to)
    
    @staticmethod
    def _process_default_record_permissions(rq, action, ce, cs, default_record):
        """Process default record permissions."""
        if default_record and action == ShareAction.GRANT.value:
            rq.defaultCanEdit = FolderShares._convert_manage_permission(ce)
            rq.defaultCanShare = FolderShares._convert_manage_permission(cs)
    
    @staticmethod
    def _process_records(vault, rq, curr_sf, rec_uids, action, ce, cs):
        """Process record permissions for the shared folder.

        Share expiration applies to the user/team access to the shared folder,
        not to the record entry itself. Setting expiration on
        SharedFolderUpdateRecord makes the record access time-limited and can
        cause the record to be removed from the owner's vault when the timer
        expires.
        """
        if not rec_uids:
            return
        
        existing_records = {x.record_uid for x in curr_sf.get('records', [])}
        
        for record_uid in rec_uids:
            ro = folder_pb2.SharedFolderUpdateRecord()
            ro.recordUid = utils.base64_url_decode(record_uid)

            if record_uid in existing_records:
                if action == ShareAction.GRANT.value:
                    ro.canEdit = FolderShares._convert_manage_permission(ce)
                    ro.canShare = FolderShares._convert_manage_permission(cs)
                    rq.sharedFolderUpdateRecord.append(ro)
                elif action == ShareAction.REMOVE.value:
                    rq.sharedFolderRemoveRecord.append(ro.recordUid)
            else:
                if action == ShareAction.GRANT.value:
                    default_ce = curr_sf.get('default_can_edit') is True if ce is None else None
                    default_cs = curr_sf.get('default_can_share') is True if cs is None else None
                    ro.canEdit = FolderShares._convert_manage_permission(ce, default_ce)
                    ro.canShare = FolderShares._convert_manage_permission(cs, default_cs)
                    
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
    
    @staticmethod
    def prepare_request(vault: vault_online.VaultOnline, kwargs, curr_sf, users, teams, rec_uids, *,
                        default_record=False, default_account=False,
                        share_expiration=None, rotate_on_expiration: bool = False):
        """Prepare a shared folder update request."""
        rq = folder_pb2.SharedFolderUpdateV3Request()
        FolderShares._initialize_request(rq, curr_sf)
        
        action = kwargs.get('action') or ShareAction.GRANT.value
        mr = kwargs.get('manage_records')
        mu = kwargs.get('manage_users')
        ce = kwargs.get('can_edit')
        cs = kwargs.get('can_share')
        
        FolderShares._process_default_account_permissions(rq, action, mr, mu, default_account)
        FolderShares._process_users(vault, rq, curr_sf, users, action, mr, mu, share_expiration, rotate_on_expiration)
        FolderShares._process_teams(vault, rq, curr_sf, teams, action, mr, mu, share_expiration, rotate_on_expiration)
        FolderShares._process_default_record_permissions(rq, action, ce, cs, default_record)
        FolderShares._process_records(vault, rq, curr_sf, rec_uids, action, ce, cs)
        
        return rq

    @staticmethod
    def _get_team_action_verb(attr_name):
        """Get action verb for team status attribute."""
        if attr_name == 'sharedFolderAddTeamStatus':
            return 'added'
        elif attr_name == 'sharedFolderUpdateTeamStatus':
            return 'updated'
        else:
            return 'removed'
    
    @staticmethod
    def _get_user_action_verb(attr_name):
        """Get action verb for user status attribute."""
        if attr_name == 'sharedFolderAddUserStatus':
            return 'added'
        elif attr_name == 'sharedFolderUpdateUserStatus':
            return 'updated'
        else:
            return 'removed'
    
    @staticmethod
    def _get_record_action_verb(attr_name):
        """Get action verb for record status attribute."""
        if attr_name == 'sharedFolderAddRecordStatus':
            return 'added'
        elif attr_name == 'sharedFolderUpdateRecordStatus':
            return 'updated'
        else:
            return 'removed'
    
    @staticmethod
    def _stale_member_failure(label: str, name: str, expired: Optional[bool]) -> str:
        """Message for an Update* entry the server answered with 'doesnt_exist' and that was not re-added."""
        if expired:
            return (f'{label} \'{name}\' has expired and could not be renewed automatically; '
                    f'share the folder with it again to restore access')
        return (f'{label} \'{name}\' no longer exists on the shared folder (it has expired or was removed); '
                f'share the folder with it again to restore access')

    @staticmethod
    def _readded_member_success(label: str, name: str, expired: Optional[bool]) -> str:
        if expired:
            return f'{label} \'{name}\' had expired and has been re-added'
        return f'{label} \'{name}\' was no longer on the shared folder (expired or removed) and has been re-added'

    @staticmethod
    def _process_team_statuses(rs, team_cache, success_status, failed_status,
                               ignore_update_teams: Optional[Set[str]] = None,
                               readded_teams: Optional[Dict[str, bool]] = None,
                               stale_teams: Optional[Dict[str, bool]] = None):
        """Process team status responses."""
        team_attrs = (
            'sharedFolderAddTeamStatus', 'sharedFolderUpdateTeamStatus',
            'sharedFolderRemoveTeamStatus'
        )
        readded_teams = readded_teams or {}
        stale_teams = stale_teams or {}
        for attr in team_attrs:
            if not hasattr(rs, attr):
                continue

            statuses = getattr(rs, attr)
            for t in statuses:
                team_uid = utils.base64_url_encode(t.teamUid)
                if ignore_update_teams and attr == 'sharedFolderUpdateTeamStatus' and team_uid in ignore_update_teams:
                    continue
                team = next((x for x in team_cache if x.team_uid == team_uid), None)
                team_name = team.name if team else team_uid
                status = t.status
                if status == 'success':
                    if attr == 'sharedFolderAddTeamStatus' and team_uid in readded_teams:
                        success_status.append(
                            FolderShares._readded_member_success('Team share', team_name, readded_teams[team_uid]))
                    else:
                        action_verb = FolderShares._get_team_action_verb(attr)
                        success_status.append(f'Team share \'{team_name}\' {action_verb}')
                elif attr == 'sharedFolderUpdateTeamStatus' and status == SF_STALE_MEMBER_STATUS:
                    failed_status.append(
                        FolderShares._stale_member_failure('Team share', team_name, stale_teams.get(team_uid)))
                elif attr == 'sharedFolderAddTeamStatus' and team_uid in readded_teams:
                    failed_status.append(f'Team share \'{team_name}\' had expired and could not be re-added: {status}')
                else:
                    failed_status.append(f'Team share \'{team_name}\' failed: {status}')

    @staticmethod
    def _process_user_statuses(rs, success_status, failed_status,
                               ignore_update_users: Optional[Set[str]] = None,
                               readded_users: Optional[Dict[str, bool]] = None,
                               stale_users: Optional[Dict[str, bool]] = None):
        """Process user status responses."""
        user_attrs = (
            'sharedFolderAddUserStatus', 'sharedFolderUpdateUserStatus',
            'sharedFolderRemoveUserStatus'
        )
        readded_users = readded_users or {}
        stale_users = stale_users or {}
        for attr in user_attrs:
            if not hasattr(rs, attr):
                continue

            statuses = getattr(rs, attr)
            for s in statuses:
                username = s.username
                key = (username or '').lower()
                if ignore_update_users and attr == 'sharedFolderUpdateUserStatus' and key in ignore_update_users:
                    continue
                status = s.status
                if status == 'success':
                    if attr == 'sharedFolderAddUserStatus' and key in readded_users:
                        success_status.append(
                            FolderShares._readded_member_success('User share', username, readded_users[key]))
                    else:
                        action_verb = FolderShares._get_user_action_verb(attr)
                        success_status.append(f'User share \'{username}\' {action_verb}')
                elif status == 'invited':
                    success_status.append(f'User \'{username}\' invited')
                elif attr == 'sharedFolderUpdateUserStatus' and status == SF_STALE_MEMBER_STATUS:
                    failed_status.append(
                        FolderShares._stale_member_failure('User share', username, stale_users.get(key)))
                elif attr == 'sharedFolderAddUserStatus' and key in readded_users:
                    failed_status.append(f'User share \'{username}\' had expired and could not be re-added: {status}')
                else:
                    failed_status.append(f'User share \'{username}\' failed: {status}')

    @staticmethod
    def _process_record_statuses(rs, vault, success_status, failed_status):
        """Process record status responses."""
        record_attrs = (
            'sharedFolderAddRecordStatus', 'sharedFolderUpdateRecordStatus',
            'sharedFolderRemoveRecordStatus'
        )
        for attr in record_attrs:
            if not hasattr(rs, attr):
                continue
            
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
                    action_verb = FolderShares._get_record_action_verb(attr)
                    success_status.append(f'Record share {title} {action_verb}')
                else:
                    failed_status.append(f'Record share \'{title}\' failed')
    
    @staticmethod
    def _collect_stale_members(rs) -> Tuple[List[str], List[str]]:
        """Return (usernames, team_uids) whose *update* failed with 'doesnt_exist'.

        Typical cause: the share had expired (or was removed) on the server while the local
        shared folder cache still lists the member, so we sent sharedFolderUpdateUser/Team
        instead of sharedFolderAddUser/Team.
        """
        users = [x.username for x in rs.sharedFolderUpdateUserStatus
                 if x.status == SF_STALE_MEMBER_STATUS]
        teams = [utils.base64_url_encode(x.teamUid) for x in rs.sharedFolderUpdateTeamStatus
                 if x.status == SF_STALE_MEMBER_STATUS]
        return users, teams

    @staticmethod
    def _cached_member_expiration(vault: vault_online.VaultOnline, shared_folder_uid: str
                                  ) -> Tuple[Dict[str, Tuple[str, bool]], Dict[str, bool]]:
        """Read cached membership links for a shared folder.

        Returns ({username_lower: (user_uid, expired)}, {team_uid: expired}).
        """
        users: Dict[str, Tuple[str, bool]] = {}
        teams: Dict[str, bool] = {}
        storage = vault.vault_data.storage.shared_folder_permissions
        for link in storage.get_links_by_subject(shared_folder_uid):
            expired = is_share_expired(getattr(link, 'expiration_time', 0))
            if link.user_type == vault_types.SharedFolderUserType.Team:
                teams[link.user_uid] = expired
            else:
                info = vault.vault_data.get_user_email(link.user_uid)
                if info and info.username:
                    users[info.username.lower()] = (link.user_uid, expired)
        return users, teams

    @staticmethod
    def evict_stale_members(vault: vault_online.VaultOnline, shared_folder_uid: str,
                            usernames: Iterable[str] = (), team_uids: Iterable[str] = ()
                            ) -> Tuple[Dict[str, bool], Dict[str, bool]]:
        """Remove user/team permission entries for a shared folder from the local cache.

        After eviction, ``vault.vault_data.load_shared_folder(...).user_permissions`` no longer
        contains these members, so a rebuilt request emits Add* instead of Update* entries.

        Returns ({username_lower: expired}, {team_uid: expired}) for the requested members, where
        ``expired`` is True when the cached share had an expiration time in the past.
        """
        usernames = {x.lower() for x in usernames if x}
        team_uids = {x for x in team_uids if x}
        user_result: Dict[str, bool] = {}
        team_result: Dict[str, bool] = {}
        if not usernames and not team_uids:
            return user_result, team_result

        cached_users, cached_teams = FolderShares._cached_member_expiration(vault, shared_folder_uid)
        links: List[Tuple[str, str]] = []
        for name in usernames:
            uid, expired = cached_users.get(name, (None, False))
            user_result[name] = expired
            if uid:
                links.append((shared_folder_uid, uid))
        for team_uid in team_uids:
            team_result[team_uid] = cached_teams.get(team_uid, False)
            links.append((shared_folder_uid, team_uid))

        if links:
            vault.vault_data.storage.shared_folder_permissions.delete_links(links)
            logger.debug('Evicted %d stale member(s) from shared folder %s cache',
                         len(links), shared_folder_uid)
        return user_result, team_result

    @staticmethod
    def _has_member_changes(rq: folder_pb2.SharedFolderUpdateV3Request) -> bool:
        return any(len(getattr(rq, f)) > 0 for f in (
            'sharedFolderAddUser', 'sharedFolderUpdateUser', 'sharedFolderRemoveUser',
            'sharedFolderAddTeam', 'sharedFolderUpdateTeam', 'sharedFolderRemoveTeam',
            'sharedFolderAddRecord', 'sharedFolderUpdateRecord', 'sharedFolderRemoveRecord'))

    @staticmethod
    def _rebuild_for_stale_members(vault: vault_online.VaultOnline, rs,
                                   rebuild_request: SharedFolderRequestRebuilder,
                                   users: List[str], teams: List[str]
                                   ) -> Tuple[List[folder_pb2.SharedFolderUpdateV3Request], Dict[str, bool], Dict[str, bool]]:
        """Evict stale members from cache and rebuild request(s) so they are re-added.

        Returns (requests, stale_users, stale_teams); the dicts map member -> expired flag.
        """
        shared_folder_uid = utils.base64_url_encode(rs.sharedFolderUid)
        stale_users, stale_teams = FolderShares.evict_stale_members(vault, shared_folder_uid, users, teams)
        try:
            rebuilt = rebuild_request(shared_folder_uid, users, teams)
        except Exception as e:
            logger.warning('Failed to rebuild shared folder request for %s: %s', shared_folder_uid, e)
            rebuilt = None
        if rebuilt is None:
            rebuilt = []
        elif isinstance(rebuilt, folder_pb2.SharedFolderUpdateV3Request):
            rebuilt = [rebuilt]

        result = []
        for rq in rebuilt:
            if not isinstance(rq, folder_pb2.SharedFolderUpdateV3Request) or not FolderShares._has_member_changes(rq):
                continue
            # The server has already bumped the folder revision; use it, since the cache is stale.
            if rs.revision:
                rq.revision = rs.revision
                rq.forceUpdate = False
            result.append(rq)
        return result, stale_users, stale_teams

    @staticmethod
    def build_shared_folder_info(vault: vault_online.VaultOnline, shared_folder_uid: str) -> Optional[Dict]:
        """Build the ``curr_sf`` dict for :meth:`prepare_request` from the current vault cache."""
        sh_fol = vault.vault_data.load_shared_folder(shared_folder_uid)
        if not sh_fol:
            return None
        sf_entity = vault.vault_data.storage.shared_folders.get_entity(shared_folder_uid)
        return {
            'shared_folder_uid': shared_folder_uid,
            'users': [x for x in sh_fol.user_permissions
                      if x.user_type != vault_types.SharedFolderUserType.Team],
            'teams': share_management_utils.get_shared_folder_team_permissions(sh_fol),
            'records': sh_fol.record_permissions,
            'shared_folder_key_unencrypted': vault.vault_data.get_shared_folder_key(shared_folder_uid=shared_folder_uid),
            'default_manage_users': sh_fol.default_manage_users,
            'default_manage_records': sh_fol.default_manage_records,
            'revision': sf_entity.revision if sf_entity else 0,
        }

    @staticmethod
    def make_stale_member_rebuilder(vault: vault_online.VaultOnline, kwargs: Optional[Dict] = None, *,
                                    share_expiration=None,
                                    rotate_on_expiration: bool = False) -> SharedFolderRequestRebuilder:
        """Default ``rebuild_request`` callback for :meth:`send_requests`.

        Rebuilds a request for only the stale users/teams from the (already evicted) cache, so they
        are sent as sharedFolderAddUser / sharedFolderAddTeam with freshly encrypted folder keys.
        Uses the same permission ``kwargs`` and ``share_expiration`` as the original request.
        """
        rebuild_kwargs = dict(kwargs or {})

        def rebuild(shared_folder_uid: str, users: List[str], teams: List[str]):
            action = rebuild_kwargs.get('action') or ShareAction.GRANT.value
            if action != ShareAction.GRANT.value:
                return None
            sf_info = FolderShares.build_shared_folder_info(vault, shared_folder_uid)
            if not sf_info:
                return None
            return FolderShares.prepare_request(
                vault, rebuild_kwargs, sf_info, list(users), list(teams), [],
                default_record=False, default_account=False,
                share_expiration=share_expiration,
                rotate_on_expiration=rotate_on_expiration,
            )

        return rebuild

    @staticmethod
    def send_requests(vault: vault_online.VaultOnline, partitioned_requests,
                      rebuild_request: Optional[SharedFolderRequestRebuilder] = None,
                      max_retries: int = SF_STALE_RETRY_LIMIT) -> Tuple[List[str], List[str]]:
        """Send shared folder update requests in chunks.

        If ``rebuild_request`` is supplied and the server answers an Update* entry with
        ``doesnt_exist`` (e.g. the share had expired), the stale user/team is evicted from the
        shared folder cache, the request is rebuilt via the callback (now producing Add* entries)
        and re-sent, up to ``max_retries`` times. See :meth:`make_stale_member_rebuilder`.
        """
        success_status: List[str] = []
        failed_status: List[str] = []

        pending: List[folder_pb2.SharedFolderUpdateV3Request] = []
        for requests in partitioned_requests or []:
            if isinstance(requests, folder_pb2.SharedFolderUpdateV3Request):
                pending.append(requests)
            else:
                pending.extend(requests)

        # shared_folder_uid -> {member: expired} for members re-sent as Add* in the current attempt
        readded_users: Dict[str, Dict[str, bool]] = {}
        readded_teams: Dict[str, Dict[str, bool]] = {}

        attempt = 0
        while pending:
            can_retry = rebuild_request is not None and attempt < max_retries
            retry_requests: List[folder_pb2.SharedFolderUpdateV3Request] = []
            next_readded_users: Dict[str, Dict[str, bool]] = {}
            next_readded_teams: Dict[str, Dict[str, bool]] = {}

            while pending:
                vault.auto_sync = True
                chunk = pending[:FOLDER_CHUNK_SIZE]
                pending = pending[FOLDER_CHUNK_SIZE:]

                rqs = folder_pb2.SharedFolderUpdateV3RequestV2()
                rqs.sharedFoldersUpdateV3.extend(chunk)

                rss = vault.keeper_auth.execute_auth_rest(
                    rest_endpoint=ApiUrl.SHARE_FOLDER_UPDATE.value,
                    request=rqs,
                    response_type=folder_pb2.SharedFolderUpdateV3ResponseV2,
                    payload_version=1
                )
                if not rss or not rss.sharedFoldersUpdateV3Response:
                    continue

                team_cache = vault.vault_data.teams()
                for rs in rss.sharedFoldersUpdateV3Response:
                    sf_uid = utils.base64_url_encode(rs.sharedFolderUid)
                    ignore_users: Set[str] = set()
                    ignore_teams: Set[str] = set()
                    stale_user_info: Dict[str, bool] = {}
                    stale_team_info: Dict[str, bool] = {}

                    stale_users, stale_teams = FolderShares._collect_stale_members(rs)
                    if stale_users or stale_teams:
                        if can_retry:
                            rebuilt, stale_user_info, stale_team_info = FolderShares._rebuild_for_stale_members(
                                vault, rs, rebuild_request, stale_users, stale_teams)
                            re_users = {u.username.lower() for rq in rebuilt for u in rq.sharedFolderAddUser}
                            re_teams = {utils.base64_url_encode(t.teamUid) for rq in rebuilt for t in rq.sharedFolderAddTeam}
                            if rebuilt:
                                retry_requests.extend(rebuilt)
                                # Outcome is reported from the retry response instead.
                                ignore_users.update(x.lower() for x in stale_users if x.lower() in re_users)
                                ignore_teams.update(x for x in stale_teams if x in re_teams)
                                next_readded_users.setdefault(sf_uid, {}).update(
                                    {u: stale_user_info.get(u, False) for u in ignore_users})
                                next_readded_teams.setdefault(sf_uid, {}).update(
                                    {t: stale_team_info.get(t, False) for t in ignore_teams})
                                for u in sorted(ignore_users):
                                    logger.info('Share for user \'%s\' on shared folder %s %s; re-adding',
                                                u, sf_uid, 'had expired' if stale_user_info.get(u) else 'no longer exists')
                        else:
                            cached_users, cached_teams = FolderShares._cached_member_expiration(vault, sf_uid)
                            stale_user_info = {u.lower(): cached_users.get(u.lower(), ('', False))[1] for u in stale_users}
                            stale_team_info = {t: cached_teams.get(t, False) for t in stale_teams}

                    FolderShares._process_team_statuses(
                        rs, team_cache, success_status, failed_status,
                        ignore_teams, readded_teams.get(sf_uid), stale_team_info)
                    FolderShares._process_user_statuses(
                        rs, success_status, failed_status,
                        ignore_users, readded_users.get(sf_uid), stale_user_info)
                    FolderShares._process_record_statuses(rs, vault, success_status, failed_status)

            pending = retry_requests
            readded_users, readded_teams = next_readded_users, next_readded_teams
            attempt += 1

        return success_status, failed_status
