from base64 import b32decode
import datetime
import fnmatch
import hashlib
import hmac
import json
import re
from typing import Iterator, List, Optional
from urllib import parse

from keepersdk import crypto, utils
from keepersdk.helpers.keeper_dag.constants import PAM_CONFIGURATIONS
from keepersdk.proto.enterprise_pb2 import GetSharingAdminsRequest, GetSharingAdminsResponse
from keepersdk.proto.router_pb2 import RouterRotationInfo
from keepersdk.proto.pam_pb2 import PAMGenericUidRequest
from keepersdk.vault import vault_online, vault_record, vault_types, vault_utils, share_management_utils

from ..commands.base import CommandError
from ..params import KeeperParams
from .. import api
from . import folder_utils

logger = api.get_logger()

GET_SHARE_ADMINS = 'enterprise/get_sharing_admins'


def is_record_uid(value: str) -> bool:
    if not value:
        return False
    try:
        return len(utils.base64_url_decode(value)) == 16
    except Exception:
        return False


def try_load_record_on_demand(vault: Optional[vault_online.VaultOnline], record_uid: str) -> bool:
    if vault is None:
        return False
    return share_management_utils.try_load_record_on_demand(vault, record_uid)


def try_resolve_single_record(record_name: Optional[str], context: KeeperParams) -> Optional[vault_record.KeeperRecordInfo]:
    if context.vault is None:
        raise CommandError('Vault is not initialized. Login to initialize the vault.')
    if not record_name:
        return None

    record_info = context.vault.vault_data.get_record(record_name)
    if record_info:
        return record_info

    if is_record_uid(record_name):
        try_load_record_on_demand(context.vault, record_name)
        record_info = context.vault.vault_data.get_record(record_name)
        if record_info:
            return record_info

    folder, name = folder_utils.try_resolve_path(context, record_name)
    if name:
        name = name.casefold()
        for record_uid in folder.records:
            record_info = context.vault.vault_data.get_record(record_uid)
            if record_info and record_info.title.casefold() == name:
                return record_info
    return None


def resolve_records(pattern: str, context: KeeperParams, *, recursive: bool=False) -> Iterator[str]:
    if context.vault is None:
        raise CommandError('Vault is not initialized. Login to initialize the vault.')
    record_info = context.vault.vault_data.get_record(pattern)
    if record_info:
        yield record_info.record_uid
        return

    folder = context.vault.vault_data.get_folder(pattern)
    if folder:
        pattern = ''
    else:
        folder, pattern = folder_utils.try_resolve_path(context, pattern)

    if pattern:
        regex = re.compile(fnmatch.translate(pattern), re.IGNORECASE).match
        for record_uid in folder.records:
            record_info = context.vault.vault_data.get_record(record_uid)
            if record_info and regex(record_info.title):
                yield record_uid
    else:
        folders: List[vault_types.Folder] = []
        def add_folder(f: vault_types.Folder) -> None:
            folders.append(f)
        if recursive:
            vault_utils.traverse_folder_tree(context.vault.vault_data, folder, add_folder)
        else:
            add_folder(folder)
        for folder in folders:
            yield from folder.records


def default_confirm(prompt: str) -> bool:
    return input(f"{prompt} (y/n): ").strip().lower() == 'y'


def get_totp_code(url, offset=None):
    comp = parse.urlparse(url)
    if comp.scheme == 'otpauth':
        params = dict(parse.parse_qsl(comp.query))
        
        secret = params.get('secret')
        algorithm = params.get('algorithm', 'SHA1')
        digits = int(params['digits']) if 'digits' in params else 6
        period = int(params['period']) if 'period' in params else 30
        if secret:
            tm_base = int(datetime.datetime.now().timestamp())
            tm = tm_base / period
            if isinstance(offset, int):
                tm += offset
            alg = algorithm.lower()
            if alg in hashlib.__dict__:
                reminder = len(secret) % 8
                if reminder in {2, 4, 5, 7}:
                    padding = '=' * (8 - reminder)
                    secret += padding
                key = bytes(b32decode(secret))
                msg = int(tm).to_bytes(8, byteorder='big')
                hash = hashlib.__dict__[alg]
                hm = hmac.new(key, msg=msg, digestmod=hash)
                digest = hm.digest()
                offset = digest[-1] & 0x0f
                base = bytearray(digest[offset:offset + 4])
                base[0] = base[0] & 0x7f
                code_int = int.from_bytes(base, byteorder='big')
                code = str(code_int % (10 ** digits))
                if len(code) < digits:
                    code = code.rjust(digits, '0')
                return code, period - (tm_base % period), period
            else:
                raise Exception(f'Unsupported hash algorithm: {algorithm}')


def get_share_admins_for_record(vault: vault_online.VaultOnline, record_uid: str):
    try:
        request = GetSharingAdminsRequest()
        request.recordUid = utils.base64_url_decode(record_uid)
        response = vault.keeper_auth.execute_auth_rest(rest_endpoint=GET_SHARE_ADMINS, request=request, response_type= GetSharingAdminsResponse)
        admins = [x.email for x in response.userProfileExts if x.isShareAdminForRequestedObject]
    except Exception as e:
        logger.debug(e)
        return

    return admins


def resolve_record(context: KeeperParams, name: str) -> str:
    record_uid = None
    vault = context.vault
    if name in vault.vault_data._records:
        return name
    else:
        rs = folder_utils.try_resolve_path(context, name)
        if rs is not None:
            folder, name = rs
            if folder is not None and name is not None:
                if folder.records:
                    for uid in folder.records:
                        r = vault.vault_data.get_record(record_uid=uid)
                        if r.title.lower() == name.lower():
                            return uid
    if record_uid is None:
        raise CommandError(f'Record not found: {name}')


def record_rotation_get(vault: vault_online.VaultOnline, record_uid_bytes: bytes) -> RouterRotationInfo:

    rq = PAMGenericUidRequest()
    rq.uid = record_uid_bytes

    rotation_info_rs = vault.keeper_auth.execute_auth_rest(rest_endpoint='pam/get_rotation_info', request=rq, response_type=RouterRotationInfo)

    return rotation_info_rs


PAM_CONFIGURATION_RECORD_TYPES = PAM_CONFIGURATIONS


def pam_configurations_get_all(vault: vault_online.VaultOnline):
    return list(vault.vault_data.find_records(
        criteria=None,
        record_type=PAM_CONFIGURATION_RECORD_TYPES,
        record_version=6,
    ))


def pam_decrypt_configuration_data(pam_config_v6_record):
    data = pam_config_v6_record.get('data')
    record_key_unencrypted = pam_config_v6_record.get('record_key_unencrypted')
    data_unencrypted_bytes = crypto.decrypt_aes_v2(
        utils.base64_url_decode(data),
        record_key_unencrypted
    )

    data_unencrypted_json_str = utils.base64_url_encode(data_unencrypted_bytes)
    data_unencrypted_dict = json.loads(data_unencrypted_json_str)

    return data_unencrypted_dict
