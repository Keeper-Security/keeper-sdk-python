import abc
import json
from typing import Callable, Optional, List

from urllib.parse import urlparse, urlunparse, quote_plus

from google.protobuf.json_format import MessageToDict

from . import auth, configuration, notifications, endpoint
from .auth_types import (channel_keeper_to_sdk, tfa_channel_info_keeper_to_sdk,
                         tfa_action_sdk_to_keeper, duo_capability_to_sdk, duration_sdk_to_keeper,
                         tfa_value_type_for_channel)

from .. import utils, crypto, errors
from ..proto import APIRequest_pb2, AccountSummary_pb2, breachwatch_pb2, push_pb2, ssocloud_pb2


class LoginContext:
    def __init__(self):
        self.username = ''
        self.passwords = []
        self.clone_code = b''
        self.device_token = b''
        self.device_private_key = None
        self.device_public_key = None
        self.message_session_uid = crypto.get_random_bytes(16)
        self.account_type = auth.AccountAuthType.Regular
        self.sso_login_info = None  # type: Optional[auth.SsoLoginInfo]


def ensure_device_token_loaded(login_auth, context):  # type: (auth.LoginAuth, LoginContext) -> None
    logger = utils.get_logger()
    attempt = 0
    context.clone_code = ''

    config = login_auth.keeper_endpoint.get_configuration_storage().get()
    server = login_auth.keeper_endpoint.server
    while attempt < 6:
        attempt += 1

        if context.device_token and context.device_private_key and context.device_public_key:
            device_token = utils.base64_url_encode(context.device_token)
            dc = config.devices().get(device_token)
            if dc:
                dsc = dc.get_server_info().get(server)
                if dsc:
                    clone_code = dsc.get_clone_code()
                    if clone_code:
                        context.clone_code = utils.base64_url_decode(clone_code)
                    return
            else:
                dc = configuration.DeviceConfiguration(device_token)
                dc.private_key = utils.base64_url_encode(crypto.unload_ec_private_key(context.device_private_key))
                dc.public_key = utils.base64_url_encode(crypto.unload_ec_public_key(context.device_public_key))
                config.devices().put(dc)
            try:
                register_device_in_region(login_auth, dc)
                dc = configuration.DeviceConfiguration(dc)
                dsc = configuration.DeviceServerConfiguration(server)
                dc.get_server_info().put(dsc)
                login_auth.keeper_endpoint.get_configuration_storage().put(config)
                return
            except Exception as e:
                logger.debug('Register device in region error: %s', e)
                config.devices().delete(device_token)
        else:
            if context.username:
                uc = config.users().get(context.username)
                if uc:
                    last_device = uc.get_last_device()
                    if last_device:
                        device_token = last_device.get_device_token()
                        if device_token:
                            dc = config.devices().get(device_token)
                            if dc:
                                try:
                                    context.device_token = utils.base64_url_decode(dc.get_device_token())
                                    context.device_private_key = crypto.load_ec_private_key(
                                        utils.base64_url_decode(dc.get_private_key()))
                                    context.device_public_key = crypto.load_ec_public_key(
                                        utils.base64_url_decode(dc.get_public_key()))
                                    continue
                                except Exception as e:
                                    logger.debug('Load device key error: %s', e)
                                    config.devices().delete(dc.get_device_token())
                        uc = configuration.UserConfiguration(uc)
                        uc.last_device = None
                        config.users().put(uc)

            dc = next((x for x in config.devices().list()), None)
            if dc:
                try:
                    context.device_token = \
                        utils.base64_url_decode(dc.get_device_token())
                    context.device_private_key = \
                        crypto.load_ec_private_key(utils.base64_url_decode(dc.get_private_key()))
                    context.device_public_key = \
                        crypto.load_ec_public_key(utils.base64_url_decode(dc.get_public_key()))
                except Exception as e:
                    logger.debug('Load device key error: %s', e)
                    config.devices().delete(dc.get_device_token())
            else:
                dc = register_device(login_auth)
                context.device_token = utils.base64_url_decode(dc.get_device_token())
                context.device_private_key = crypto.load_ec_private_key(utils.base64_url_decode(dc.get_private_key()))
                context.device_public_key = crypto.load_ec_public_key(utils.base64_url_decode(dc.get_public_key()))
                config.devices().put(dc)
                login_auth.keeper_endpoint.get_configuration_storage().put(config)
                return


def register_device_in_region(login_auth, device_config):
    # type: (auth.LoginAuth, configuration.IDeviceConfiguration) -> None
    rq = APIRequest_pb2.RegisterDeviceInRegionRequest()
    rq.encryptedDeviceToken = utils.base64_url_decode(device_config.get_device_token())
    rq.clientVersion = login_auth.keeper_endpoint.client_version
    rq.deviceName = login_auth.keeper_endpoint.device_name
    rq.devicePublicKey = utils.base64_url_decode(device_config.get_public_key())

    try:
        login_auth.execute_rest('authentication/register_device_in_region', rq)
    except errors.KeeperApiError as kae:
        if 'exists' != kae.result_code:
            raise kae
    except errors.InvalidDeviceTokenError as idt:
        if 'public key already exists' != idt.message:
            raise idt


def register_device(login_auth):   # type: (auth.LoginAuth) -> configuration.DeviceConfiguration
    private_key, public_key = crypto.generate_ec_key()
    device_public_key = crypto.unload_ec_public_key(public_key)
    device_private_key = crypto.unload_ec_private_key(private_key)

    rq = APIRequest_pb2.DeviceRegistrationRequest()
    rq.clientVersion = login_auth.keeper_endpoint.client_version
    rq.deviceName = login_auth.keeper_endpoint.device_name
    rq.devicePublicKey = device_public_key

    device = login_auth.execute_rest('authentication/register_device', rq, response_type=APIRequest_pb2.Device)
    dc = configuration.DeviceConfiguration(utils.base64_url_encode(device.encryptedDeviceToken))
    dc.public_key = utils.base64_url_encode(device_public_key)
    dc.private_key = utils.base64_url_encode(device_private_key)
    dsc = configuration.DeviceServerConfiguration(login_auth.keeper_endpoint.server)
    dc.get_server_info().put(dsc)
    return dc


def redirect_to_region(login_auth, region_host):  # type: (auth.LoginAuth, str) -> None
    keeper_endpoint = login_auth.keeper_endpoint
    keeper_endpoint.server = region_host
    if login_auth.on_region_changed:
        login_auth.on_region_changed(region_host)


def ensure_push_notifications(login_auth, login_context):
    # type: (auth.LoginAuth, LoginContext) -> None
    if login_auth.push_notifications:
        return

    rq = push_pb2.WssConnectionRequest()
    rq.messageSessionUid = login_context.message_session_uid
    rq.encryptedDeviceToken = login_context.device_token
    rq.deviceTimeStamp = utils.current_milli_time()

    login_auth.push_notifications = login_auth.keeper_endpoint.connect_to_push_server(rq.SerializeToString())


def start_login(login_auth, login_context, method=APIRequest_pb2.EXISTING_ACCOUNT, new_login=False):
    # type: (auth.LoginAuth, LoginContext, int, bool) -> None
    if new_login:
        login_auth.resume_session = False

    rq = APIRequest_pb2.StartLoginRequest()
    rq.clientVersion = login_auth.keeper_endpoint.client_version
    rq.encryptedDeviceToken = login_context.device_token
    rq.loginType = APIRequest_pb2.ALTERNATE if login_auth.alternate_password else APIRequest_pb2.NORMAL
    rq.loginMethod = method
    rq.messageSessionUid = login_context.message_session_uid
    rq.forceNewLogin = new_login

    if login_context.clone_code and login_auth.resume_session and method == APIRequest_pb2.EXISTING_ACCOUNT:
        rq.cloneCode = login_context.clone_code
    else:
        rq.username = login_context.username

    process_start_login(login_auth, login_context, rq)


def resume_login(login_auth, login_context, login_token, method=APIRequest_pb2.EXISTING_ACCOUNT):
    # type: (auth.LoginAuth, LoginContext, bytes, APIRequest_pb2.LoginMethod.ValueType) -> None
    rq = APIRequest_pb2.StartLoginRequest()
    rq.clientVersion = login_auth.keeper_endpoint.client_version
    rq.encryptedDeviceToken = login_context.device_token
    rq.encryptedLoginToken = login_token
    rq.username = login_context.username
    rq.loginMethod = method
    rq.messageSessionUid = login_context.message_session_uid

    process_start_login(login_auth, login_context, rq)


def get_session_token_scope(session_token_type):   # type: (int) -> auth.SessionTokenRestriction
    if session_token_type == APIRequest_pb2.ACCOUNT_RECOVERY:
        return auth.SessionTokenRestriction.AccountRecovery
    if session_token_type == APIRequest_pb2.SHARE_ACCOUNT:
        return auth.SessionTokenRestriction.ShareAccount
    if session_token_type == APIRequest_pb2.ACCEPT_INVITE:
        return auth.SessionTokenRestriction.AcceptInvite
    if session_token_type in [APIRequest_pb2.PURCHASE, APIRequest_pb2.RESTRICT]:
        return auth.SessionTokenRestriction.AccountExpired
    return auth.SessionTokenRestriction.Unrestricted


def store_configuration(login_auth, login_context):  # type: (auth.LoginAuth, LoginContext) -> None
    config = login_auth.keeper_endpoint.get_configuration_storage().get()
    config.set_last_login(login_context.username)
    config.set_last_server(login_auth.keeper_endpoint.server)

    device_token = utils.base64_url_encode(login_context.device_token)
    iuc = config.users().get(login_context.username)
    uc = None  # type: Optional[configuration.UserConfiguration]
    if not iuc:
        uc = configuration.UserConfiguration(login_context.username)
        uc.server = login_auth.keeper_endpoint.server
        uc.last_device = configuration.UserDeviceConfiguration(device_token)
    else:
        udc = iuc.get_last_device()
        if not udc or udc.get_device_token() != device_token:
            uc = configuration.UserConfiguration(iuc)
            uc.last_device = configuration.UserDeviceConfiguration(device_token)
    if uc:
        config.users().put(uc)

    isc = config.servers().get(login_auth.keeper_endpoint.server)
    sc = None   # type: Optional[configuration.ServerConfiguration]
    if not isc:
        sc = configuration.ServerConfiguration(login_auth.keeper_endpoint.server)
        sc.server_key_id = login_auth.keeper_endpoint.get_server_key_id()
    if sc:
        config.servers().put(sc)

    idc = config.devices().get(device_token)
    if not idc:
        dc = configuration.DeviceConfiguration(device_token)
        dc.public_key = crypto.unload_ec_public_key(login_context.device_public_key)
        dc.private_key = crypto.unload_ec_private_key(login_context.device_private_key)
    else:
        dc = configuration.DeviceConfiguration(idc)
    idsc = dc.get_server_info().get(login_auth.keeper_endpoint.server)
    dsc = configuration.DeviceServerConfiguration(idsc if idsc else login_auth.keeper_endpoint.server)
    dsc.clone_code = utils.base64_url_encode(login_context.clone_code)
    dc.get_server_info().put(dsc)
    config.devices().put(dc)

    login_auth.keeper_endpoint.get_configuration_storage().put(config)


class ConnectedLoginStep(auth.LoginStepConnected):
    def __init__(self, keeper_auth):
        self._keeper_auth = keeper_auth

    def keeper_auth(self):
        return self._keeper_auth


def on_logged_in(login_auth, login_context, response, on_decrypt_data_key):
    # type: (auth.LoginAuth, LoginContext, APIRequest_pb2.LoginResponse, Callable[[bytes], bytes]) -> None
    login_context.username = response.primaryUsername
    login_context.clone_code = response.cloneCode
    store_configuration(login_auth, login_context)

    auth_context = auth.AuthContext()
    auth_context.username = login_context.username
    auth_context.session_token = response.encryptedSessionToken
    auth_context.session_token_restriction = get_session_token_scope(response.sessionTokenType)
    auth_context.data_key = on_decrypt_data_key(response.encryptedDataKey)

    keeper_auth = auth.KeeperAuth(login_auth.keeper_endpoint, auth_context)
    post_login(keeper_auth)

    if auth_context.session_token_restriction == auth.SessionTokenRestriction.Unrestricted:
        ensure_push_notifications(login_auth, login_context)
        if isinstance(login_auth.push_notifications, notifications.KeeperPushNotifications):
            login_auth.push_notifications.send_to_push_channel(auth_context.session_token, False)
        keeper_auth.push_notifications = login_auth.push_notifications
        login_auth.push_notifications = None

    login_auth.login_step = ConnectedLoginStep(keeper_auth)


class DeviceApprovalStep(auth.LoginStepDeviceApproval):
    def __init__(self, login_auth, login_context, login_token):  # type: (auth.LoginAuth, LoginContext, bytes) -> None
        self._login_auth = login_auth
        self._login_context = login_context
        self._login_token = login_token
        self._email_sent = False
        if login_auth.push_notifications:
            login_auth.push_notifications.register_callback(self.push_handler)

    def push_handler(self, event):   # type: (dict) -> bool
        if not isinstance(event, dict):
            return False
        token = None
        if 'event' in event and event['event'] == 'received_totp':
            token = self._login_token
            if 'encryptedLoginToken' in event:
                token = utils.base64_url_decode(event['encryptedLoginToken'])
        elif 'message' in event and event['message'] == 'device_approved':
            if event.get('approved', False):
                token = self._login_token
        elif 'command' in event and event['command'] == 'device_verified':
            token = self._login_token
        if token:
            resume_login(self._login_auth, self._login_context, token)

        return False

    def send_push(self, channel):
        if channel == auth.DeviceApprovalChannel.Email:
            rq = APIRequest_pb2.DeviceVerificationRequest()
            rq.username = self._login_context.username
            rq.clientVersion = self._login_auth.keeper_endpoint.client_version
            rq.encryptedDeviceToken = self._login_context.device_token
            rq.messageSessionUid = self._login_context.message_session_uid
            rq.verificationChannel = 'email_resend' if self._email_sent else 'email'

            self._login_auth.execute_rest('authentication/request_device_verification', rq)
            self._email_sent = True
        elif channel in {auth.DeviceApprovalChannel.KeeperPush, auth.DeviceApprovalChannel.TwoFactor}:
            rq = APIRequest_pb2.TwoFactorSendPushRequest()
            rq.encryptedLoginToken = self._login_token
            rq.pushType = APIRequest_pb2.TwoFactorPushType.TWO_FA_PUSH_KEEPER \
                if channel == auth.DeviceApprovalChannel.KeeperPush \
                else APIRequest_pb2.TwoFactorPushType.TWO_FA_PUSH_NONE

            self._login_auth.execute_rest('authentication/2fa_send_push', rq)

    def send_code(self, channel, code):
        if channel == auth.DeviceApprovalChannel.Email:
            rq = APIRequest_pb2.ValidateDeviceVerificationCodeRequest()
            rq.username = self._login_context.username
            rq.clientVersion = self._login_auth.keeper_endpoint.client_version
            rq.encryptedDeviceToken = self._login_context.device_token
            rq.messageSessionUid = self._login_context.message_session_uid
            rq.verificationCode = code

            self._login_auth.execute_rest('authentication/validate_device_verification_code', rq)
            resume_login(self._login_auth, self._login_context, self._login_token)

        elif channel == auth.DeviceApprovalChannel.TwoFactor:
            rq = APIRequest_pb2.TwoFactorValidateRequest()
            rq.encryptedLoginToken = self._login_token
            rq.valueType = APIRequest_pb2.TWO_FA_CODE_NONE
            rq.value = code

            rs = self._login_auth.execute_rest('authentication/2fa_validate', rq,
                                               response_type=APIRequest_pb2.TwoFactorValidateResponse)
            resume_login(self._login_auth, self._login_context, rs.encryptedLoginToken if rs else self._login_token)

    def resume(self):
        if self._login_auth.login_step is self:
            resume_login(self._login_auth, self._login_context, self._login_token)

    def close(self):
        if self._login_auth.push_notifications:
            self._login_auth.push_notifications.remove_callback(self.push_handler)


def on_device_approval_required(login_auth, login_context, response):
    # type: (auth.LoginAuth, LoginContext, APIRequest_pb2.LoginResponse) -> None

    ensure_push_notifications(login_auth, login_context)
    login_auth.login_step = DeviceApprovalStep(login_auth, login_context, response.encryptedLoginToken)


def post_login(keeper_auth):   # type: (auth.KeeperAuth) -> None
    rq = AccountSummary_pb2.AccountSummaryRequest()
    rq.summaryVersion = 1

    rs = keeper_auth.execute_auth_rest('login/account_summary', rq,
                                       response_type=AccountSummary_pb2.AccountSummaryElements)

    keeper_auth.auth_context.settings.update(MessageToDict(rs.settings))
    keeper_auth.auth_context.license.update(MessageToDict(rs.license))
    enf = MessageToDict(rs.Enforcements)
    if 'strings' in enf:
        strs = {x['key']: x['value'] for x in enf['strings'] if 'key' in x and 'value' in x}
        keeper_auth.auth_context.enforcements.update(strs)
    if 'booleans' in enf:
        bools = {x['key']: x.get('value', False) for x in enf['booleans'] if 'key' in x}
        keeper_auth.auth_context.enforcements.update(bools)
    if 'longs' in enf:
        longs = {x['key']: x['value'] for x in enf['longs'] if 'key' in x and 'value' in x}
        keeper_auth.auth_context.enforcements.update(longs)
    if 'jsons' in enf:
        jsons = {x['key']: x['value'] for x in enf['jsons'] if 'key' in x and 'value' in x}
        keeper_auth.auth_context.enforcements.update(jsons)
    keeper_auth.auth_context.is_enterprise_admin = rs.isEnterpriseAdmin
    if rs.clientKey:
        keeper_auth.auth_context.client_key = crypto.decrypt_aes_v1(rs.clientKey, keeper_auth.auth_context.data_key)
    if rs.keysInfo.encryptedPrivateKey:
        rsa_private_key = crypto.decrypt_aes_v1(rs.keysInfo.encryptedPrivateKey, keeper_auth.auth_context.data_key)
        keeper_auth.auth_context.rsa_private_key = crypto.load_rsa_private_key(rsa_private_key)
    if rs.keysInfo.encryptedEccPrivateKey:
        ec_private_key = crypto.decrypt_aes_v2(rs.keysInfo.encryptedEccPrivateKey, keeper_auth.auth_context.data_key)
        keeper_auth.auth_context.ec_private_key = crypto.load_ec_private_key(ec_private_key)
    if rs.keysInfo.eccPublicKey:
        keeper_auth.auth_context.ec_public_key = crypto.load_ec_public_key(rs.keysInfo.eccPublicKey)

    if keeper_auth.auth_context.session_token_restriction == auth.SessionTokenRestriction.Unrestricted:
        if keeper_auth.auth_context.license.get('accountType', 0) == 2:
            try:
                e_rs = keeper_auth.execute_auth_rest('enterprise/get_enterprise_public_key', None,
                                                     response_type=breachwatch_pb2.EnterprisePublicKeyResponse)
                if e_rs.enterpriseECCPublicKey:
                    keeper_auth.auth_context.enterprise_ec_public_key = \
                        crypto.load_ec_public_key(e_rs.enterpriseECCPublicKey)
                if e_rs.enterprisePublicKey:
                    keeper_auth.auth_context.enterprise_rsa_public_key = \
                        crypto.load_rsa_public_key(e_rs.enterprisePublicKey)

            except Exception as e:
                logger = utils.get_logger()
                logger.debug('Get enterprise public key error: %s', e)


class TwoFactorStep(auth.LoginStepTwoFactor):
    def __init__(self, login_auth, login_context, login_token, channels):
        # type: (auth.LoginAuth, LoginContext, bytes, List[APIRequest_pb2.TwoFactorChannelInfo]) -> None
        super(TwoFactorStep, self).__init__()
        self._login_auth = login_auth
        self._login_context = login_context
        self._login_token = login_token
        self._channels = channels
        self._last_push_channel_uid = None
        if login_auth.push_notifications:
            login_auth.push_notifications.register_callback(self.push_handler)

    def push_handler(self, event):
        if 'event' in event:
            command = event['event']
            if command == 'received_totp':
                if 'encryptedLoginToken' in event:
                    token = utils.base64_url_decode(event['encryptedLoginToken'])
                    resume_login(self._login_auth, self._login_context, token)
                elif 'passcode' in event:
                    if self._last_push_channel_uid:
                        self.send_code(self._last_push_channel_uid, event['passcode'])
        return False

    def get_channels(self):
        return [tfa_channel_info_keeper_to_sdk(x) for x in self._channels]

    def get_channel_push_actions(self, channel_uid):
        channel = self.get_channel_by_uid(channel_uid)
        if channel:
            channel_type = channel_keeper_to_sdk(channel.channelType)
            if channel_type == auth.TwoFactorChannel.TextMessage:
                return [auth.TwoFactorPushAction.TextMessage]
            if channel_type == auth.TwoFactorChannel.KeeperDNA:
                return [auth.TwoFactorPushAction.KeeperDna]
            if channel_type == auth.TwoFactorChannel.DuoSecurity:
                return [y for y in (duo_capability_to_sdk(x) for x in channel.capabilities) if y]
        return []

    def send_push(self, channel_uid, action):
        channel = self.get_channel_by_uid(channel_uid)
        if not channel:
            raise errors.KeeperError(f'Channel \"{utils.base64_url_encode(channel_uid)}\" not found')
        rq = APIRequest_pb2.TwoFactorSendPushRequest()
        rq.encryptedLoginToken = self._login_token
        rq.pushType = tfa_action_sdk_to_keeper(action)
        rq.channel_uid = channel_uid
        if action in {auth.TwoFactorPushAction.DuoPush, auth.TwoFactorPushAction.KeeperDna}:
            rq.expireIn = duration_sdk_to_keeper(self.duration)
        self._login_auth.execute_rest('authentication/2fa_send_push', rq)
        self._last_push_channel_uid = channel_uid

    def send_code(self, channel_uid, code):
        channel = self.get_channel_by_uid(channel_uid)
        if not channel:
            raise errors.KeeperError(f'Channel \"{utils.base64_url_encode(channel_uid)}\" not found')

        rq = APIRequest_pb2.TwoFactorValidateRequest()
        rq.encryptedLoginToken = self._login_token
        rq.channel_uid = channel_uid
        rq.expireIn = duration_sdk_to_keeper(self.duration)
        rq.valueType = tfa_value_type_for_channel(channel_keeper_to_sdk(channel.channelType))
        rq.value = code
        rs = self._login_auth.execute_rest('authentication/2fa_validate', rq,
                                           response_type=APIRequest_pb2.TwoFactorValidateResponse)
        if rs:
            resume_login(self._login_auth, self._login_context, rs.encryptedLoginToken)

    def resume(self):
        if self._login_auth.login_step is self:
            resume_login(self._login_auth, self._login_context, self._login_token)

    def get_channel_by_uid(self, channel_uid):
        return next((x for x in self._channels if x.channel_uid == channel_uid), None)

    def close(self):
        if self._login_auth.push_notifications:
            self._login_auth.push_notifications.remove_all()


def on_requires_2fa(login_auth, login_context, response):
    # type: (auth.LoginAuth, LoginContext, APIRequest_pb2.LoginResponse) -> None
    ensure_push_notifications(login_auth, login_context)
    login_auth.login_step = TwoFactorStep(login_auth, login_context, response.encryptedLoginToken,
                                          list(response.channels))


class PasswordLoginStep(auth.LoginStepPassword):
    def __init__(self, login_auth, login_context, login_token, salt):
        # type: (auth.LoginAuth, LoginContext, bytes, APIRequest_pb2.Salt) -> None
        super(PasswordLoginStep, self).__init__()
        self._login_auth = login_auth
        self._login_context = login_context
        self._login_token = login_token
        self._salt = salt

    def verify_password(self, password):
        salt = self._salt.salt
        iterations = self._salt.iterations
        rq = APIRequest_pb2.ValidateAuthHashRequest()
        rq.passwordMethod = APIRequest_pb2.ENTERED
        rq.encryptedLoginToken = self._login_token
        rq.authResponse = crypto.derive_keyhash_v1(password, salt, iterations)

        rs = self._login_auth.execute_rest('authentication/validate_auth_hash', rq,
                                           response_type=APIRequest_pb2.LoginResponse)

        def decrypt_data_key(encrypted_data_key):
            if rs.encryptedDataKeyType == APIRequest_pb2.BY_ALTERNATE:
                key = crypto.derive_keyhash_v2('data_key', password, salt, iterations)
                return crypto.decrypt_aes_v2(encrypted_data_key, key)
            return utils.decrypt_encryption_params(encrypted_data_key, password)

        on_logged_in(self._login_auth, self._login_context, rs, decrypt_data_key)

    def verify_biometric_key(self, biometric_key):
        rq = APIRequest_pb2.ValidateAuthHashRequest()
        rq.passwordMethod = APIRequest_pb2.BIOMETRICS
        rq.encryptedLoginToken = self._login_token
        rq.authResponse = crypto.create_bio_auth_hash(biometric_key)

        rs = self._login_auth.execute_rest('authentication/validate_auth_hash', rq,
                                           response_type=APIRequest_pb2.LoginResponse)
        on_logged_in(self._login_auth, self._login_context, rs, lambda x: crypto.decrypt_aes_v2(x, biometric_key))


def on_requires_auth_hash(login_auth, login_context, response):
    # type: (auth.LoginAuth, LoginContext, APIRequest_pb2.LoginResponse) -> None
    salt = next((x for x in response.salt
                 if x.name.lower() == ('alternate' if login_auth.alternate_password else 'master')), None)
    if not salt:
        salt = response.salt[0]

    password_step = PasswordLoginStep(login_auth, login_context, response.encryptedLoginToken, salt)
    while login_context.passwords:
        password = login_context.passwords.pop()
        try:
            password_step.verify_password(password)
            if not isinstance(login_auth.login_step, auth.LoginStepPassword):
                return
        except:
            pass
    login_auth.login_step = password_step


class SsoTokenLoginStep(auth.LoginStepSsoToken, abc.ABC):
    def __init__(self, login_auth, login_context, sso_info, login_token):
        # type: (auth.LoginAuth, LoginContext, auth.SsoLoginInfo, bytes) -> None
        super(SsoTokenLoginStep, self).__init__()
        self._login_auth = login_auth
        self._login_context = login_context
        self._sso_info = sso_info
        self._login_token = login_token
        self._login_url = ''

    @property
    def is_cloud_sso(self):
        return self._sso_info.is_cloud

    @property
    def is_provider_login(self):
        return False if self._login_context.username else True

    @property
    def login_name(self):
        if self._login_context.username:
            return self._login_context.username
        else:
            return self._sso_info.sso_provider

    @property
    def sso_login_url(self):
        return self._login_url

    def login_with_password(self):
        if self._login_context.username:
            self._login_auth.alternate_password = True
            self._login_context.account_type = auth.AccountAuthType.Regular
            start_login(self._login_auth, self._login_context)


class CloudSsoTokenLoginStep(SsoTokenLoginStep):
    def __init__(self, login_auth, login_context, sso_info, login_token):
        super(CloudSsoTokenLoginStep, self).__init__(login_auth, login_context, sso_info, login_token)
        self.transmission_key = utils.generate_aes_key()
        rq = ssocloud_pb2.SsoCloudRequest()
        rq.clientVersion = login_auth.keeper_endpoint.client_version
        rq.embedded = True
        transmission_key = utils.generate_aes_key()
        api_rq = endpoint.prepare_api_request(
            login_auth.keeper_endpoint.get_server_key_id(), transmission_key, rq.SerializeToString())
        url_comp = list(urlparse(sso_info.sso_url))
        url_comp[3] = f'payload={quote_plus(utils.base64_url_encode(api_rq.SerializeToString()))}'
        self._login_url = urlunparse(url_comp)

    def set_sso_token(self, token_str):
        token = crypto.decrypt_aes_v2(utils.base64_url_decode(token_str), self.transmission_key)
        rs = ssocloud_pb2.SsoCloudResponse()
        rs.ParseFromString(token)
        self._login_context.username = rs.email
        self._sso_info.sso_provider = rs.providerName
        self._sso_info.idp_session_id = rs.idpSessionId
        self._login_context.sso_login_info = self._sso_info

        ensure_device_token_loaded(self._login_auth, self._login_context)
        lt = rs.encryptedLoginToken or self._login_token
        if lt:
            resume_login(self._login_auth, self._login_context, lt, method=APIRequest_pb2.AFTER_SSO)
        else:
            start_login(self._login_auth, self._login_context, method=APIRequest_pb2.AFTER_SSO, new_login=False)


class OnPremisesSsoTokenLoginStep(SsoTokenLoginStep):
    def __init__(self, login_auth, login_context, sso_info, login_token):
        super(OnPremisesSsoTokenLoginStep, self).__init__(login_auth, login_context, sso_info, login_token)
        self._private_key, self._public_key = crypto.generate_rsa_key()
        pub = crypto.unload_rsa_public_key(self._public_key)
        url_comp = list(urlparse(sso_info.sso_url))
        url_comp[3] = f'key={quote_plus(utils.base64_url_encode(pub))}&embedded'
        self._login_url = urlunparse(url_comp)

    def set_sso_token(self, token_str):
        token = json.loads(token_str)
        if 'email' in token:
            self._login_context.username = token['email']
        if 'provider_name' in token:
            self._sso_info.sso_provider = token['provider_name']
        if 'session_id' in token:
            self._sso_info.idp_session_id = token['session_id']
        for key in ('password', 'new_password'):
            if key in token:
                password = crypto.decrypt_rsa(utils.base64_url_decode(token[key]), self._private_key)
                self._login_context.passwords.append(password)
        self._login_context.sso_login_info = self._sso_info

        lt = self._login_token
        if 'login_token' in token:
            lt = utils.base64_url_decode(token['login_token'])
        if lt:
            resume_login(self._login_auth, self._login_context, lt, method=APIRequest_pb2.AFTER_SSO)
        else:
            start_login(self._login_auth, self._login_context, method=APIRequest_pb2.AFTER_SSO, new_login=False)


def on_sso_redirect(login_auth, login_context, sso_info, login_token=None):
    # type: (auth.LoginAuth, LoginContext, auth.SsoLoginInfo, Optional[bytes]) -> None
    login_context.account_type = auth.AccountAuthType.CloudSso \
        if sso_info.is_cloud else auth.AccountAuthType.OnsiteSso

    login_auth.login_step = CloudSsoTokenLoginStep(login_auth, login_context, sso_info, login_token) \
        if sso_info.is_cloud else OnPremisesSsoTokenLoginStep(login_auth, login_context, sso_info, login_token)


class SsoDataKeyLoginStep(auth.LoginStepSsoDataKey):
    def __init__(self, login_auth, login_context, login_token):
        # type: (auth.LoginAuth, LoginContext, bytes) -> None
        super(SsoDataKeyLoginStep, self).__init__()
        self._login_auth = login_auth
        self._login_context = login_context
        self._login_token = login_token
        if login_auth.push_notifications:
            login_auth.push_notifications.register_callback(self.push_handler)

    def push_handler(self, event):   # type: (dict) -> bool
        if event.get('message', '') == 'device_approved':
            if event.get('approved', False):
                resume_login(self._login_auth, self._login_context, self._login_token)
        elif event.get('command', '') == 'device_verified':
            resume_login(self._login_auth, self._login_context, self._login_token)
        return False

    def request_data_key(self, channel):
        if channel == auth.DataKeyShareChannel.KeeperPush:
            rq = APIRequest_pb2.TwoFactorSendPushRequest()
            rq.pushType = APIRequest_pb2.TWO_FA_PUSH_KEEPER
            rq.encryptedLoginToken = self._login_token
            self._login_auth.execute_rest('authentication/2fa_send_push', rq)
        elif channel == auth.DataKeyShareChannel.AdminApproval:
            rq = APIRequest_pb2.DeviceVerificationRequest()
            rq.username = self._login_context.username
            rq.clientVersion = self._login_auth.keeper_endpoint.client_version
            rq.encryptedDeviceToken = self._login_context.device_token
            rq.messageSessionUid = self._login_context.message_session_uid
            rs = self._login_auth.execute_rest('authentication/request_device_admin_approval', rq,
                                               response_type=APIRequest_pb2.DeviceVerificationResponse)
            if rs and rs.deviceStatus == APIRequest_pb2.DEVICE_OK:
                resume_login(self._login_auth, self._login_context, self._login_token)

    def close(self):
        if self._login_auth.push_notifications:
            self._login_auth.push_notifications.remove_callback(self.push_handler)


def on_request_data_key(login_auth, login_context, login_token):
    # type: (auth.LoginAuth, LoginContext, bytes) -> None
    ensure_push_notifications(login_auth, login_context)
    login_auth.login_step = SsoDataKeyLoginStep(login_auth, login_context, login_token)


def process_start_login(login_auth, login_context, request):
    # type: (auth.LoginAuth, LoginContext, APIRequest_pb2.StartLoginRequest) -> None
    response = login_auth.execute_rest('authentication/start_login', request,
                                       response_type=APIRequest_pb2.LoginResponse)
    if response.loginState == APIRequest_pb2.LOGGED_IN:
        on_logged_in(login_auth, login_context, response,
                     lambda x: crypto.decrypt_ec(x, login_context.device_private_key))
        return
    if response.loginState == APIRequest_pb2.REQUIRES_USERNAME:
        resume_login(login_auth, login_context, response.encryptedLoginToken)
        return
    if response.loginState == APIRequest_pb2.DEVICE_APPROVAL_REQUIRED:
        on_device_approval_required(login_auth, login_context, response)
        return
    if response.loginState == APIRequest_pb2.REQUIRES_2FA:
        on_requires_2fa(login_auth, login_context, response)
        return
    if response.loginState == APIRequest_pb2.REQUIRES_AUTH_HASH:
        on_requires_auth_hash(login_auth, login_context, response)
        return
    if response.loginState in {APIRequest_pb2.REDIRECT_CLOUD_SSO, APIRequest_pb2.REDIRECT_ONSITE_SSO}:
        sso_login_info = auth.SsoLoginInfo()
        sso_login_info.is_cloud = response.loginState == APIRequest_pb2.REDIRECT_CLOUD_SSO
        sso_login_info.sso_url = response.url
        on_sso_redirect(login_auth, login_context, sso_login_info, response.encryptedLoginToken)
        return
    if response.loginState == APIRequest_pb2.REQUIRES_DEVICE_ENCRYPTED_DATA_KEY:
        on_request_data_key(login_auth, login_context, response.encryptedLoginToken)
        return
    if response.loginState in {APIRequest_pb2.DEVICE_ACCOUNT_LOCKED, APIRequest_pb2.DEVICE_LOCKED}:
        raise errors.InvalidDeviceTokenError(response.message)
    message = f'State {APIRequest_pb2.LoginState.Name(response.loginState)}: Not implemented: {response.message}'
    login_auth.login_step = auth.LoginStepError('not_implemented', message)
