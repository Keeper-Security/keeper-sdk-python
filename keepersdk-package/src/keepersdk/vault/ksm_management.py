import datetime
import time

from . import vault_online, ksm
from ..proto import APIRequest_pb2
from ..proto.APIRequest_pb2 import GetApplicationsSummaryResponse, ApplicationShareType, GetAppInfoRequest, GetAppInfoResponse
from ..proto.enterprise_pb2 import GENERAL
from .. import utils

URL_GET_SUMMARY_API = 'vault/get_applications_summary'
URL_GET_APP_INFO_API = 'vault/get_app_info'
CLIENT_SHORT_ID_LENGTH = 8


def list_secrets_manager_apps(vault: vault_online.VaultOnline) -> list[ksm.SecretsManagerApp]:
    response = vault.keeper_auth.execute_auth_rest(
        URL_GET_SUMMARY_API,
        request=None,
        response_type=GetApplicationsSummaryResponse
    )

    apps_list = []
    for app_summary in response.applicationSummary:
        uid = utils.base64_url_encode(app_summary.appRecordUid)
        app_record = vault.vault_data.load_record(uid)
        name = getattr(app_record, 'title', '') if app_record else ''
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

    records_count = sum(
        1 for s in getattr(app_info, 'shares', []) 
        if ApplicationShareType.Name(s.shareType) == 'SHARE_TYPE_RECORD'
        )
    
    folders_count = sum(
        1 for s in getattr(app_info, 'shares', []) 
        if ApplicationShareType.Name(s.shareType) == 'SHARE_TYPE_FOLDER'
        )

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


def get_app_info(vault: vault_online.VaultOnline, app_uid):
    rq = GetAppInfoRequest()
    rq.appRecordUid.append(utils.base64_url_decode(app_uid))
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
        return ksm.SharedSecretsInfo(type='UNKOWN SHARE TYPE', uid=uid_str, name=ksm_app.title, permissions=editable_status)