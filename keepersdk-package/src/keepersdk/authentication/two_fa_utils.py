from ..proto import APIRequest_pb2
from ..vault import vault_online

# REST endpoint constants
REST_ENDPOINT_2FA_LIST = 'authentication/2fa_list'
REST_ENDPOINT_2FA_ADD = 'authentication/2fa_add'
REST_ENDPOINT_2FA_ADD_VALIDATE = 'authentication/2fa_add_validate'
REST_ENDPOINT_2FA_DELETE = 'authentication/2fa_delete'

DEFAULT_DUO_PUSH_TYPE = APIRequest_pb2.TWO_FA_PUSH_NONE
DEFAULT_EXPIRE_IN = APIRequest_pb2.TWO_FA_EXP_IMMEDIATELY


def get_two_fa_list(vault: vault_online.VaultOnline) -> APIRequest_pb2.TwoFactorListResponse:
    """Retrieve the list of two-factor authentication methods."""
    return vault.keeper_auth.execute_auth_rest(
        rest_endpoint=REST_ENDPOINT_2FA_LIST,
        request=None,
        response_type=APIRequest_pb2.TwoFactorListResponse
    )


def add_two_fa_method(
    vault: vault_online.VaultOnline,
    channel_type: APIRequest_pb2.TwoFactorChannelType,
    channel_uid: bytes,
    channel_name: str = '',
    phone_number: str = '',
    duo_push_type: APIRequest_pb2.TwoFactorPushType = DEFAULT_DUO_PUSH_TYPE
) -> APIRequest_pb2.TwoFactorAddResponse:
    """Add a new two-factor authentication method."""
    request = APIRequest_pb2.TwoFactorAddRequest()
    request.channelType = channel_type
    request.channel_uid = channel_uid
    request.channelName = channel_name
    request.phoneNumber = phone_number
    request.duoPushType = duo_push_type
    
    return vault.keeper_auth.execute_auth_rest(
        rest_endpoint=REST_ENDPOINT_2FA_ADD,
        request=request,
        response_type=APIRequest_pb2.TwoFactorAddResponse
    )


def validate_two_fa_method(
    vault: vault_online.VaultOnline,
    channel_uid: bytes,
    value_type: APIRequest_pb2.TwoFactorValueType,
    value: str,
    expire_in: APIRequest_pb2.TwoFactorExpiration = DEFAULT_EXPIRE_IN
) -> None:
    """Validate a two-factor authentication method."""
    request = APIRequest_pb2.TwoFactorValidateRequest()
    request.channel_uid = channel_uid
    request.valueType = value_type
    request.value = value
    request.expireIn = expire_in
    
    vault.keeper_auth.execute_auth_rest(
        rest_endpoint=REST_ENDPOINT_2FA_ADD_VALIDATE,
        request=request,
        response_type=None
    )


def delete_two_fa_method(vault: vault_online.VaultOnline, channel_uid: bytes) -> None:
    """Delete a two-factor authentication method."""
    request = APIRequest_pb2.TwoFactorDeleteRequest()
    request.channel_uid = channel_uid
    
    vault.keeper_auth.execute_auth_rest(
        rest_endpoint=REST_ENDPOINT_2FA_DELETE,
        request=request,
        response_type=None
    )