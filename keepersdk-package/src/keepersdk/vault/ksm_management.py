import datetime
import json
from typing import Optional

from . import vault_online, ksm, record_management, vault_types
from ..proto.APIRequest_pb2 import GetApplicationsSummaryResponse, ApplicationShareType, GetAppInfoRequest, GetAppInfoResponse
from ..proto.enterprise_pb2 import GENERAL
from ..proto.record_pb2 import ApplicationAddRequest
from .. import utils, crypto

URL_GET_SUMMARY_API = 'vault/get_applications_summary'
URL_GET_APP_INFO_API = 'vault/get_app_info'
URL_CREATE_APP_API = 'vault/application_add'
CLIENT_SHORT_ID_LENGTH = 8


def list_secrets_manager_apps(vault: vault_online.VaultOnline) -> list[ksm.SecretsManagerApp]:
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


def get_app_info(vault: vault_online.VaultOnline, app_uid: str | list[str]) -> list:
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