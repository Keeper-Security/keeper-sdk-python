
from ..proto import APIRequest_pb2, AccountSummary_pb2
from . import keeper_auth
from .. import crypto, errors

def load_account_summary(auth: keeper_auth.KeeperAuth) -> AccountSummary_pb2.AccountSummaryElements:
    rq = AccountSummary_pb2.AccountSummaryRequest()
    rq.summaryVersion = 1
    account_summary = auth.execute_auth_rest('login/account_summary', rq,
                                             response_type=AccountSummary_pb2.AccountSummaryElements)
    assert account_summary is not None
    return account_summary


def register_data_key_for_device(auth: keeper_auth.KeeperAuth) -> bool:
    device_key = auth.auth_context.device_private_key
    assert device_key is not None
    rq = APIRequest_pb2.RegisterDeviceDataKeyRequest()
    rq.encryptedDeviceToken = auth.auth_context.device_token
    rq.encryptedDeviceDataKey = crypto.encrypt_ec(auth.auth_context.data_key, device_key.public_key())
    try:
        auth.execute_auth_rest('authentication/register_encrypted_data_key_for_device', rq)
    except errors.KeeperApiError as kae:
        if kae.result_code == 'device_data_key_exists':
            return False
        raise kae
    return True


def rename_device(auth: keeper_auth.KeeperAuth, new_name: str):
    rq = APIRequest_pb2.DeviceUpdateRequest()
    rq.clientVersion = auth.keeper_endpoint.client_version
    # rq.deviceStatus = proto.DEVICE_OK
    rq.deviceName = new_name
    rq.encryptedDeviceToken = auth.auth_context.device_token

    auth.execute_auth_rest('authentication/update_device', rq)


def set_user_setting(auth: keeper_auth.KeeperAuth, name: str, value: str) -> None:
    # Available setting names:
    #   - logout_timer
    #   - persistent_login
    #   - ip_disable_auto_approve

    rq = APIRequest_pb2.UserSettingRequest()
    rq.setting = name
    rq.value = value
    auth.execute_auth_rest('setting/set_user_setting', rq)
