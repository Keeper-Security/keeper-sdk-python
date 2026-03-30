import datetime
import hmac
import json
import logging
import os

from typing import Callable, Optional, List, Union, Tuple, Set, Dict
from urllib import parse

from . import ksm, record_management, shares_management, share_management_utils, vault_online, vault_record, vault_types
from .. import utils, crypto, constants
from ..enterprise import enterprise_data
from ..proto.APIRequest_pb2 import (
    GetApplicationsSummaryResponse, ApplicationShareType, GetAppInfoRequest, 
    GetAppInfoResponse, RemoveAppClientsRequest, Device, AddAppClientRequest, 
    AppShareAdd, AddAppSharesRequest, RemoveAppSharesRequest
)
from ..proto.enterprise_pb2 import GENERAL
from ..proto.record_pb2 import ApplicationAddRequest

URL_GET_SUMMARY_API = 'vault/get_applications_summary'
URL_GET_APP_INFO_API = 'vault/get_app_info'
URL_CREATE_APP_API = 'vault/application_add'

CLIENT_ADD_URL = 'vault/app_client_add'
CLIENT_REMOVE_URL = 'vault/app_client_remove'

SHARE_ADD_URL = 'vault/app_share_add'
SHARE_REMOVE_URL = 'vault/app_share_remove'

CLIENT_SHORT_ID_LENGTH = 8

MILLISECONDS_PER_SECOND = 1000

CLIENT_ID_COUNTER_BYTES = b'KEEPER_SECRETS_MANAGER_CLIENT_ID'
CLIENT_ID_DIGEST = 'sha512'

DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

def list_secrets_manager_apps(vault: vault_online.VaultOnline) -> List[ksm.SecretsManagerApp]:
    response = vault.keeper_auth.execute_auth_rest(
        URL_GET_SUMMARY_API,
        request=None,
        response_type=GetApplicationsSummaryResponse
    )

    apps_list = []
    if response and response.applicationSummary:
        for app_summary in response.applicationSummary:
            uid = utils.base64_url_encode(app_summary.appRecordUid)
            app_record = vault.vault_data.load_record(uid)
            name = app_record.title if app_record else ''
            last_access = int_to_datetime(app_summary.lastAccess)
            secrets_app = ksm.SecretsManagerApp(
                name=name,
                uid=uid,
                records=app_summary.folderRecords,
                folders=app_summary.folderShares,
                count=app_summary.clientCount,
                last_access=last_access
            )
            apps_list.append(secrets_app)

    return apps_list


def get_secrets_manager_app(vault: vault_online.VaultOnline, uid_or_name: str) -> ksm.SecretsManagerApp:
    ksm_app = next((r for r in vault.vault_data.records() if r.record_uid == uid_or_name or r.title == uid_or_name), None)
    if not ksm_app:
        raise ValueError(f'No application found with UID/Name: {uid_or_name}')

    app_infos = get_app_info(vault=vault, app_uid=ksm_app.record_uid)
    if not app_infos:
        raise ValueError('No Secrets Manager Applications returned.')

    app_info = app_infos[0]
    client_devices = [x for x in app_info.clients if x.appClientType == GENERAL]
    client_list = []
    for c in client_devices:
        client_id = utils.base64_url_encode(c.clientId)
        short_client_id = shorten_client_id(app_info.clients, client_id, CLIENT_SHORT_ID_LENGTH)
        client = ksm.ClientDevice(
            name=c.id,
            short_id=short_client_id,
            created_on=int_to_datetime(c.createdOn),
            expires_on=int_to_datetime(c.accessExpireOn),
            first_access=int_to_datetime(c.firstAccess),
            last_access=int_to_datetime(c.lastAccess),
            ip_lock=c.lockIp,
            ip_address=c.ipAddress
        )
        client_list.append(client)

    shared_secrets = []
    for share in getattr(app_info, 'shares', []):
        shared_secrets.append(handle_share_type(share, ksm_app, vault))

    records_count = len([
        s for s in getattr(app_info, 'shares', [])
        if ApplicationShareType.Name(s.shareType) == 'SHARE_TYPE_RECORD'
    ])
    folders_count = len(shared_secrets) - records_count

    return ksm.SecretsManagerApp(
        name=ksm_app.title,
        uid=ksm_app.record_uid,
        records=records_count,
        folders=folders_count,
        count=len(client_list),
        last_access=None,
        shared_secrets=shared_secrets,
        client_devices=client_list
    )


def create_secrets_manager_app(vault: vault_online.VaultOnline, name: str, force_add: Optional[bool] = False):
    
    existing_app = next((r for r in vault.vault_data.records() if r.title == name), None)
    if existing_app and not force_add:
        raise ValueError(f'Application with the same name {name} already exists. Set force to true to add Application with same name')

    app_record_data = {
        'title': name,
        'type': 'app'
    }

    data_json = json.dumps(app_record_data)
    record_key_unencrypted = utils.generate_aes_key()
    record_key_encrypted = crypto.encrypt_aes_v2(record_key_unencrypted, vault.keeper_auth.auth_context.data_key)

    app_record_uid_str = utils.generate_uid()
    app_record_uid = utils.base64_url_decode(app_record_uid_str)

    rdata = bytes(data_json, 'utf-8')
    rdata = crypto.encrypt_aes_v2(rdata, record_key_unencrypted)

    client_modified_time = utils.current_milli_time()

    ra = ApplicationAddRequest()
    ra.app_uid = app_record_uid
    ra.record_key = record_key_encrypted
    ra.client_modified_time = client_modified_time
    ra.data = rdata

    vault.keeper_auth.execute_auth_rest(request=ra, rest_endpoint=URL_CREATE_APP_API, response_type=None)
    
    app_uid_str = utils.base64_url_encode(ra.app_uid)
    return app_uid_str


def remove_secrets_manager_app(vault: vault_online.VaultOnline, uid_or_name: str, force: Optional[bool] = False):
    
    app = get_secrets_manager_app(vault=vault, uid_or_name=uid_or_name)
    
    if (app.records != 0 or app.folders != 0 or app.count != 0) and not force:
        raise ValueError('Cannot remove application with clients, shared record, shared folder. Force remove to proceed')
    
    record_obj = vault_types.RecordPath(folder_uid=None, record_uid=app.uid)
    
    record_management.delete_vault_objects(vault=vault, vault_objects=[record_obj])
    
    return app.uid


def share_secrets_manager_app(vault: vault_online.VaultOnline, enterprise: enterprise_data.EnterpriseData, 
                               app_uid: str, emails: List[str], action: str, can_edit: bool, can_share: bool) -> Tuple[List, List]:

    request = shares_management.RecordShares.prep_request(
        vault=vault, emails=emails, action=action, uid_or_name=app_uid, 
        share_expiration=None, dry_run=False, enterprise=enterprise, enterprise_access=True, 
        recursive=False, can_edit=can_edit, can_share=can_share
    )
    
    success_responses, failed_responses = shares_management.RecordShares.send_requests(vault=vault, requests=[request])

    vault.sync_down()

    removed = action == 'remove'

    success_responses_content, failed_responses_content = _update_shares_user_permissions(vault=vault, enterprise=enterprise, uid=app_uid, removed=removed)
    return success_responses.extend(success_responses_content), failed_responses.extend(failed_responses_content)  


def _update_shares_user_permissions(vault: vault_online.VaultOnline, enterprise: enterprise_data.EnterpriseData, uid: str, removed: bool) -> Tuple[List, List]:
    
    # Get user permissions for the app
    user_perms = _get_app_user_permissions(vault=vault, uid=uid)
    
    # Get app info and shared secrets
    app_infos = get_app_info(vault=vault, app_uid=uid)
    app_info = app_infos[0]
    if not app_info:
        return [], []
        
    # Separate shared records and folders
    shared_recs, shared_folders = _separate_shared_items(
        vault, app_info.shares
    )
    
    # Create share requests for users that need updates
    return _process_share_updates(
        vault, enterprise, user_perms, shared_recs, shared_folders, removed
    )


def _get_app_user_permissions(vault: vault_online.VaultOnline, uid: str) -> List:
    """Get user permissions for the application."""
    share_info = share_management_utils.get_record_shares(vault=vault, record_uids=[uid], is_share_admin=False)
    user_perms = []
    if share_info:
        for record_info in share_info:
            if record_info.get('record_uid') == uid:
                user_perms = record_info.get('shares', {}).get('user_permissions', [])
                break
    return user_perms


def _separate_shared_items(vault: vault_online.VaultOnline, shared_secrets):
    """Separate shared secrets into records and folders."""
    shared_recs = []
    shared_folders = []
    
    for share in shared_secrets:
        uid_str = utils.base64_url_encode(share.secretUid)
        share_type = ApplicationShareType.Name(share.shareType)
        
        if share_type == ApplicationShareType.SHARE_TYPE_RECORD:
            shared_recs.append(uid_str)
        elif share_type == ApplicationShareType.SHARE_TYPE_FOLDER:
            shared_folders.append(uid_str)
    
    if shared_recs:
        share_management_utils.get_record_shares(
            vault=vault, 
            record_uids=shared_recs, 
            is_share_admin=False
        )
        
    return shared_recs, shared_folders


def _process_share_updates(vault: vault_online.VaultOnline, enterprise: enterprise_data.EnterpriseData, 
                            user_perms: List, shared_recs: List, shared_folders: List, removed: bool) -> Tuple[List, List]:
    """Process share updates for users."""
    app_users_map = _categorize_app_users(vault, user_perms)
    
    sf_requests, rec_requests = _build_share_requests(
        vault, enterprise, app_users_map, shared_recs, shared_folders, removed
    )
    
    return _send_share_requests(vault, sf_requests, rec_requests)


def _categorize_app_users(vault: vault_online.VaultOnline, user_perms: List) -> Dict:
    """Categorize users into admins and viewers."""
    current_username = vault.keeper_auth.auth_context.username
    admins = [
        up.get('username') for up in user_perms 
        if up.get('editable') and up.get('username') != current_username
    ]
    viewers = [
        up.get('username') for up in user_perms 
        if not up.get('editable')
    ]
    return dict(admins=admins, viewers=viewers)


def _build_share_requests(vault: vault_online.VaultOnline, enterprise: enterprise_data.EnterpriseData,
                            app_users_map: Dict, shared_recs: List, shared_folders: List,
                            removed: bool) -> Tuple:
    """Build share requests for folders and records."""
    sf_requests = []
    rec_requests = []
    all_share_uids = shared_recs + shared_folders
    
    for users in app_users_map.values():
        users_needing_update = [
            u for u in users 
            if _user_needs_update(vault, u, all_share_uids, removed)
        ]
        
        if not users_needing_update:
            continue
            
        folder_requests = _create_folder_share_requests(
            vault, shared_folders, users_needing_update, removed
        )
        if folder_requests:
            sf_requests.append(folder_requests)
        
        record_requests = _create_record_share_requests(
            vault, enterprise, shared_recs, users_needing_update, removed
        )
        rec_requests.extend(record_requests)
    
    return sf_requests, rec_requests


def _send_share_requests(vault: vault_online.VaultOnline, sf_requests: List, rec_requests: List) -> Tuple[List, List]:
    """Send share requests to the server."""
    success_responses = []
    failed_responses = []
    if sf_requests:
        success_responses, failed_responses = shares_management.FolderShares.send_requests(vault, sf_requests)
    if rec_requests:
        success_responses_rec, failed_responses_rec = shares_management.RecordShares.send_requests(vault, rec_requests)
        success_responses.extend(success_responses_rec)
        failed_responses.extend(failed_responses_rec)
    
    vault.sync_down()
    return success_responses, failed_responses


def _user_needs_update(vault: vault_online.VaultOnline, user: str, share_uids: List, removed: bool) -> bool:
    """Check if a user needs share permission updates."""
    record_permissions = _get_record_permissions(vault, share_uids)
    record_cache = {x.record_uid: x for x in vault.vault_data.records()}
    
    for share_uid in share_uids:
        share_user_permissions = _get_share_user_permissions(
            vault, share_uid, record_cache, record_permissions
        )
        
        user_permissions_set = {
            up.get('username') for up in share_user_permissions 
            if isinstance(up, dict)
        }
        
        if user not in user_permissions_set:
            return True
    return False


def _get_record_permissions(vault: vault_online.VaultOnline, share_uids: List) -> Dict:
    """Get record permissions for given share UIDs."""
    record_share_info = share_management_utils.get_record_shares(
        vault=vault, 
        record_uids=share_uids, 
        is_share_admin=False
    )
    
    record_permissions = {}
    if record_share_info:
        for record_info in record_share_info:
            record_uid = record_info.get('record_uid')
            if record_uid:
                record_permissions[record_uid] = (
                    record_info.get('shares', {}).get('user_permissions', [])
                )
    return record_permissions


def _get_share_user_permissions(vault: vault_online.VaultOnline, share_uid: str, 
                                record_cache: Dict, record_permissions: Dict) -> List:
    """Get user permissions for a share (record or folder)."""
    is_record_share = share_uid in record_cache
    
    if is_record_share:
        return record_permissions.get(share_uid, [])
    
    shared_folder_obj = vault.vault_data.load_shared_folder(shared_folder_uid=share_uid)
    if shared_folder_obj and shared_folder_obj.user_permissions:
        return shared_folder_obj.user_permissions
    
    return []


def _create_folder_share_requests(vault: vault_online.VaultOnline, shared_folders: List,
                                users: List, removed: bool) -> List:
    """Create folder share requests."""
    if not shared_folders:
        return []
        
    sf_action = 'remove' if removed else 'grant'
    requests = []
    
    for folder_uid in shared_folders:
        for user in users:
            if _user_needs_update(vault, user, [folder_uid], removed):
                request = _build_folder_share_request(
                    vault, folder_uid, user, sf_action
                )
                requests.append(request)
    
    return requests


def _build_folder_share_request(vault: vault_online.VaultOnline, folder_uid: str, 
                                user: str, action: str) -> Dict:
    """Build a single folder share request."""
    shared_folder = vault.vault_data.load_shared_folder(folder_uid)
    shared_folder_revision = vault.vault_data.storage.shared_folders.get_entity(folder_uid).revision
    sf_unencrypted_key = vault.vault_data.get_shared_folder_key(shared_folder_uid=folder_uid)
    
    sf_info = {
        'shared_folder_uid': folder_uid,
        'users': shared_folder.user_permissions,
        'teams': [],
        'records': shared_folder.record_permissions,
        'shared_folder_key_unencrypted': sf_unencrypted_key,
        'default_manage_users': shared_folder.default_can_share,
        'default_manage_records': shared_folder.default_can_edit,
        'revision': shared_folder_revision
    }
    
    return shares_management.FolderShares.prepare_request(
        vault=vault,
        kwargs={'action': action},
        curr_sf=sf_info,
        users=[user],
        teams=[],
        rec_uids=[],
        default_record=False,
        default_account=False,
        share_expiration=-1
    )


def _create_record_share_requests(vault: vault_online.VaultOnline, enterprise: enterprise_data.EnterpriseData, shared_recs: List,
                                users: List, removed: bool) -> List:
    """Create record share requests."""
    if not shared_recs or not vault:
        return []
        
    rec_action = 'remove' if removed else 'grant'
    requests = []
    
    for record_uid in shared_recs:
        for user in users:
            if _user_needs_update(vault, user, [record_uid], removed):
                request = shares_management.RecordShares.prep_request(
                    vault=vault,
                    emails=[user],
                    action=rec_action,
                    uid_or_name=record_uid,
                    share_expiration=-1,
                    dry_run=False,
                    enterprise=enterprise,
                    can_edit=False,
                    can_share=False
                )
                requests.append(request)
    
    return requests


def get_app_info(vault: vault_online.VaultOnline, app_uid: Union[str, List[str]]) -> List:
    rq = GetAppInfoRequest()
    
    if isinstance(app_uid, str):
        app_uid = [app_uid]
    
    for uid in app_uid:
        rq.appRecordUid.append(utils.base64_url_decode(uid))
    
    rs = vault.keeper_auth.execute_auth_rest(
        request=rq, 
        rest_endpoint=URL_GET_APP_INFO_API, 
        response_type=GetAppInfoResponse
        )
    return rs.appInfo


def shorten_client_id(all_clients, original_id, number_of_characters):
    new_id = original_id[:number_of_characters]
    res = [x for x in all_clients if utils.base64_url_encode(x.clientId).startswith(new_id)]
    if len(res) == 1 or new_id == original_id:
        return new_id
    return shorten_client_id(all_clients, original_id, number_of_characters + 1)


def int_to_datetime(timestamp: int) -> datetime.datetime:
    return datetime.datetime.fromtimestamp(timestamp / 1000) if timestamp and timestamp != 0 else None


def handle_share_type(share, ksm_app, vault: vault_online.VaultOnline):
    uid_str = utils.base64_url_encode(share.secretUid)
    share_type = ApplicationShareType.Name(share.shareType)
    editable_status = share.editable

    if share_type == 'SHARE_TYPE_RECORD':
        return ksm.SharedSecretsInfo(type='RECORD', uid=uid_str, name=ksm_app.title, permissions=editable_status)
    
    elif share_type == 'SHARE_TYPE_FOLDER':
        cached_sf = next((f for f in vault.vault_data.folders() if f.folder_uid == uid_str), None)
        if cached_sf:
            return ksm.SharedSecretsInfo(type='FOLDER', uid=uid_str, name=cached_sf.name, permissions=editable_status)
        
    else:
        return None


class KSMClientManagement:

    @staticmethod
    def add_client_to_ksm_app(
            vault: vault_online.VaultOnline,
            uid: str,
            client_name: str,
            count: int,
            index: int,
            unlock_ip: bool,
            first_access_expire_duration_ms: int,
            access_expire_in_ms: Optional[int],
            master_key: bytes,
            server: str) -> Dict:
        """Generate a single client device and return token info and output string."""
        
        # Generate secret and client ID
        secret_bytes = os.urandom(32)
        client_id = KSMClientManagement._generate_client_id(secret_bytes)
        
        encrypted_master_key = crypto.encrypt_aes_v2(master_key, secret_bytes)
        
        # Create and send request
        device = KSMClientManagement._create_client_request(
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
        token_with_prefix = KSMClientManagement._generate_token_with_prefix(
            secret_bytes=secret_bytes,
            server=server
        )
        
        output_string = KSMClientManagement._create_output_string(
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
        return hmac.new(
            secret_bytes, 
            CLIENT_ID_COUNTER_BYTES, 
            CLIENT_ID_DIGEST
        ).digest()

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
        abbrev = KSMClientManagement._get_abbrev_by_host(server)
        
        if abbrev:
            return f'{abbrev}:{token}'
        else:
            tmp_server = server if server.startswith(('http://', 'https://')) else f"https://{server}"
            
            return f'{parse.urlparse(tmp_server).netloc.lower()}:{token}'
    

    @staticmethod
    def _get_abbrev_by_host(host: str) -> Optional[str]:
        # Return abbreviation of the Keeper's public host

        if host.startswith('https:'):
            host = parse.urlparse(host).netloc    # https://keepersecurity.com/api/v2/ --> keepersecurity.com

        keys = [k for k, v in constants.KEEPER_PUBLIC_HOSTS.items() if v == host]
        if keys:
            return keys[0]
        return None

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
        
        exp_date_str = KSMClientManagement._format_timestamp(
            first_access_expire_duration_ms
        )
        output_lines.append(f'Token Expires On: {exp_date_str}')
        
        app_expire_on_str = (
            KSMClientManagement._format_timestamp(access_expire_in_ms)
            if access_expire_in_ms else "Never"
        )
        output_lines.append(f'App Access Expires on: {app_expire_on_str}')
        
        return '\n'.join(output_lines)

    @staticmethod
    def _format_timestamp(timestamp_ms: int) -> str:
        """Format timestamp in milliseconds to date string."""
        try:
            return datetime.datetime.fromtimestamp(
                timestamp_ms / MILLISECONDS_PER_SECOND
            ).strftime(DATE_FORMAT)
        except (OSError, ValueError):
            return 'Invalid timestamp'

    @staticmethod
    def remove_clients_from_ksm_app(vault: vault_online.VaultOnline, uid: str, client_names_and_ids: List[str], callable: Callable = None):
        """Remove client devices from a KSM application."""
        client_hashes = KSMClientManagement._convert_to_client_hashes(
            vault, uid, client_names_and_ids
        )

        found_clients_count = len(client_hashes)
        if found_clients_count == 0:
            raise ValueError('No Client Devices found with given name or ID\n')
        
        if callable:
            if not KSMClientManagement._confirm_remove_clients(found_clients_count, callable):
                raise ValueError('User did not confirm removal of clients')

        KSMClientManagement._send_remove_client_request(vault, uid, client_hashes)

    @staticmethod
    def _convert_to_client_hashes(vault: vault_online.VaultOnline, uid: str, 
                                    client_names_and_ids: List[str]) -> List[bytes]:
        """Convert client names/IDs to client ID hashes."""
        exact_matches, partial_matches = KSMClientManagement._categorize_client_matches(
            client_names_and_ids
        )
        
        app_infos = get_app_info(vault=vault, app_uid=uid)
        app_info = app_infos[0]
        client_id_hashes_bytes = []
        
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

    @staticmethod
    def _categorize_client_matches(client_names_and_ids: List[str]) -> Tuple[Set, Set]:
        """Categorize client names/IDs into exact and partial matches."""
        exact_matches = set()
        partial_matches = set()
        
        for name in client_names_and_ids:
            if len(name) >= CLIENT_SHORT_ID_LENGTH:
                partial_matches.add(name)
            else:
                exact_matches.add(name)
        
        return exact_matches, partial_matches

    @staticmethod
    def _confirm_remove_clients(clients_count: int, callable: Callable) -> bool:
        """Confirm removal of clients."""
        return callable(clients_count)

    @staticmethod
    def _send_remove_client_request(vault: vault_online.VaultOnline, uid: str, 
                                    client_hashes: List[bytes]) -> None:
        """Send remove client request to server."""
        request = RemoveAppClientsRequest()
        request.appRecordUid = utils.base64_url_decode(uid)
        request.clients.extend(client_hashes)
        vault.keeper_auth.execute_auth_rest(rest_endpoint=CLIENT_REMOVE_URL, request=request)


class KSMShareManagement:

    @staticmethod
    def add_secrets_to_ksm_app(vault: vault_online.VaultOnline, enterprise:enterprise_data.EnterpriseData, app_uid: str, master_key: bytes,
                    secret_uids: List[str], is_editable: bool = False) -> List:
        """Share secrets with a KSM application."""

        app_shares, added_secret_info = KSMShareManagement._process_all_secrets(
            vault, secret_uids, master_key, is_editable
        )

        if not added_secret_info:
            raise ValueError("No valid secrets found to share.")

        KSMShareManagement._send_share_request(
            vault, app_uid, app_shares
        )

        vault.sync_down()

        _update_shares_user_permissions(vault, enterprise, app_uid, removed=False)

        return added_secret_info

    @staticmethod
    def _process_all_secrets(vault: vault_online.VaultOnline, secret_uids: List[str],
                            master_key: bytes, is_editable: bool) -> Tuple[List, List]:
        """Process all secrets and build share requests."""
        app_shares = []
        added_secret_info = []

        for secret_uid in secret_uids:
            share_info = KSMShareManagement._process_secret(
                vault, secret_uid, master_key, is_editable
            )
            
            if share_info:
                app_shares.append(share_info['app_share'])
                added_secret_info.append(share_info['secret_info'])

        return app_shares, added_secret_info

    @staticmethod
    def _process_secret(vault: vault_online.VaultOnline, secret_uid: str, 
                              master_key: bytes, is_editable: bool) -> Optional[Dict]:
        """Process a single secret and create share request."""
        secret_info = KSMShareManagement._get_secret_info(vault, secret_uid)
        
        if not secret_info:
            return None

        share_key_decrypted, share_type, secret_type_name = secret_info
        
        if not share_key_decrypted:
            logging.warning(f"Could not retrieve key for secret {secret_uid}")
            return None

        app_share = KSMShareManagement._build_app_share(
            secret_uid, share_key_decrypted, master_key, share_type, is_editable
        )

        return {
            'app_share': app_share,
            'secret_info': (secret_uid, secret_type_name)
        }

    @staticmethod
    def _get_secret_info(vault: vault_online.VaultOnline, secret_uid: str) -> Optional[Tuple]:
        """Get secret information (key, type, name) for a given UID."""
        is_record = secret_uid in vault.vault_data._records
        is_shared_folder = secret_uid in vault.vault_data._shared_folders

        if is_record:
            return KSMShareManagement._get_record_secret_info(vault, secret_uid)
        elif is_shared_folder:
            return KSMShareManagement._get_folder_secret_info(vault, secret_uid)
        else:
            KSMShareManagement._log_invalid_secret_warning(secret_uid)
            return None

    @staticmethod
    def _get_record_secret_info(vault: vault_online.VaultOnline, secret_uid: str) -> Optional[Tuple]:
        """Get secret info for a record."""
        record = vault.vault_data.load_record(record_uid=secret_uid)
        if not isinstance(record, vault_record.TypedRecord):
            raise ValueError("Unable to share application secret, only typed records can be shared")
        
        share_key_decrypted = vault.vault_data.get_record_key(record_uid=secret_uid)
        share_type = ApplicationShareType.SHARE_TYPE_RECORD
        secret_type_name = 'Record'
        
        return share_key_decrypted, share_type, secret_type_name

    @staticmethod
    def _get_folder_secret_info(vault: vault_online.VaultOnline, secret_uid: str) -> Tuple:
        """Get secret info for a shared folder."""
        share_key_decrypted = vault.vault_data.get_shared_folder_key(shared_folder_uid=secret_uid)
        share_type = ApplicationShareType.SHARE_TYPE_FOLDER
        secret_type_name = 'Shared Folder'
        
        return share_key_decrypted, share_type, secret_type_name

    @staticmethod
    def _log_invalid_secret_warning(secret_uid: str) -> None:
        """Log warning for invalid secret UID."""
        logging.warning(
            f"UID='{secret_uid}' is not a Record nor Shared Folder. "
            "Only individual records or Shared Folders can be added to the application. "
        )

    @staticmethod
    def _build_app_share(secret_uid: str, share_key_decrypted: bytes, master_key: bytes,
                        share_type: int, is_editable: bool) -> AppShareAdd:
        """Build AppShareAdd object."""
        app_share = AppShareAdd()
        app_share.secretUid = utils.base64_url_decode(secret_uid)
        app_share.shareType = share_type
        app_share.encryptedSecretKey = crypto.encrypt_aes_v2(share_key_decrypted, master_key)
        app_share.editable = is_editable
        return app_share

    @staticmethod
    def _send_share_request(vault: vault_online.VaultOnline, app_uid: str, 
                          app_shares: List) -> bool:
        """Send the share request to the server."""
        request = KSMShareManagement._build_share_request(app_uid, app_shares)

        vault.keeper_auth.execute_auth_rest(rest_endpoint=SHARE_ADD_URL, request=request)
        return True

    @staticmethod
    def _build_share_request(app_uid: str, app_shares: List) -> AddAppSharesRequest:
        """Build share request object."""
        request = AddAppSharesRequest()
        request.appRecordUid = utils.base64_url_decode(app_uid)
        request.shares.extend(app_shares)
        return request

    @staticmethod
    def remove_secrets_from_ksm_app(vault: vault_online.VaultOnline, app_uid: str, 
                    secret_uids: List[str]) -> None:
        """Send remove share request to server."""
        request = RemoveAppSharesRequest()
        request.appRecordUid = utils.base64_url_decode(app_uid)
        request.shares.extend(utils.base64_url_decode(uid) for uid in secret_uids)
        vault.keeper_auth.execute_auth_rest(rest_endpoint=SHARE_REMOVE_URL, request=request)