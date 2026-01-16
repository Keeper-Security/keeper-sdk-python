from ..proto import APIRequest_pb2
from ..vault import vault_online

def get_two_fa_list(vault: vault_online.VaultOnline) -> APIRequest_pb2.TwoFactorListResponse:
    response = vault.keeper_auth.execute_auth_rest(
        rest_endpoint='authentication/2fa_list',
        request=None,
        response_type=APIRequest_pb2.TwoFactorListResponse
    )
    return response


def add_two_fa_method(
    vault: vault_online.VaultOnline,
    channel_type: APIRequest_pb2.TwoFactorChannelType,
    channel_uid: bytes,
    channel_name: str = '',
    phone_number: str = '',
    duo_push_type: APIRequest_pb2.TwoFactorPushType = APIRequest_pb2.TWO_FA_PUSH_NONE
) -> APIRequest_pb2.TwoFactorAddResponse:

    rq = APIRequest_pb2.TwoFactorAddRequest()
    rq.channelType = channel_type
    rq.channel_uid = channel_uid
    rq.channelName = channel_name
    rq.phoneNumber = phone_number
    rq.duoPushType = duo_push_type
    
    response = vault.keeper_auth.execute_auth_rest(
        rest_endpoint='authentication/2fa_add',
        request=rq,
        response_type=APIRequest_pb2.TwoFactorAddResponse
    )
    return response


def validate_two_fa_method(
    vault: vault_online.VaultOnline,
    channel_uid: bytes,
    value_type: APIRequest_pb2.TwoFactorValueType,
    value: str,
    expire_in: APIRequest_pb2.TwoFactorExpiration = APIRequest_pb2.TWO_FA_EXP_IMMEDIATELY
) -> None:

    rq = APIRequest_pb2.TwoFactorValidateRequest()
    rq.channel_uid = channel_uid
    rq.valueType = value_type
    rq.value = value
    rq.expireIn = expire_in
    
    vault.keeper_auth.execute_auth_rest(
        rest_endpoint='authentication/2fa_add_validate',
        request=rq,
        response_type=None
    )

def delete_two_fa_method(vault: vault_online.VaultOnline, channel_uid: bytes) -> None:
    rq = APIRequest_pb2.TwoFactorDeleteRequest()
    rq.channel_uid = channel_uid
    vault.keeper_auth.execute_auth_rest(
        rest_endpoint='authentication/2fa_delete',
        request=rq,
        response_type=None
    )