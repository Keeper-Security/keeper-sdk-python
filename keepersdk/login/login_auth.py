#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2023 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import abc
import enum
import json
from typing import Type, Optional, List, Callable, Dict, Any, Sequence

from google.protobuf.json_format import MessageToDict
from urllib.parse import urlparse, urlunparse, quote_plus
from cryptography.hazmat.primitives.asymmetric import ec

from . import endpoint, configuration, notifications, auth
from .. import crypto, utils, errors
from ..proto import APIRequest_pb2, AccountSummary_pb2, breachwatch_pb2, push_pb2, ssocloud_pb2


class ILoginStep(abc.ABC):
    def close(self):    # type: () -> None
        pass

    def is_final(self):  # type: () -> bool
        return False


class LoginStepDeviceApproval(ILoginStep, abc.ABC):
    @abc.abstractmethod
    def send_push(self, channel):
        pass

    @abc.abstractmethod
    def send_code(self, channel, code):
        pass

    @abc.abstractmethod
    def resume(self):
        pass


class LoginStepTwoFactor(ILoginStep, abc.ABC):
    def __init__(self):
        self.duration = TwoFactorDuration.EveryLogin

    @abc.abstractmethod
    def get_channels(self):
        pass

    @abc.abstractmethod
    def get_channel_push_actions(self, channel_uid):
        pass

    @abc.abstractmethod
    def send_push(self, channel_uid, action):
        pass

    @abc.abstractmethod
    def send_code(self, channel_uid, code):
        pass

    @abc.abstractmethod
    def resume(self):
        pass


class LoginStepSsoDataKey(ILoginStep, abc.ABC):
    @staticmethod
    def get_channels():   # type: () -> Sequence[DataKeyShareChannel]
        return DataKeyShareChannel.KeeperPush, DataKeyShareChannel.AdminApproval

    @abc.abstractmethod
    def request_data_key(self, channel):   # type: (DataKeyShareChannel) -> None
        pass


class LoginStepPassword(ILoginStep, abc.ABC):
    @abc.abstractmethod
    def verify_password(self, password):   # type: (str) -> None
        pass

    @abc.abstractmethod
    def verify_biometric_key(self, biometric_key):  # type: (bytes) -> None
        pass


class LoginStepError(ILoginStep):
    def __init__(self, code, message):    # type: (str, str) -> None
        self.code = code         # type: str
        self.message = message   # type: str

    def is_final(self):
        return True


class LoginStepSsoToken(ILoginStep, abc.ABC):
    @abc.abstractmethod
    def set_sso_token(self, token):   # type: (str) -> None
        pass

    @abc.abstractmethod
    def login_with_password(self):    # type: () -> None
        pass

    @property
    @abc.abstractmethod
    def is_cloud_sso(self):    # type: () -> bool
        pass

    @property
    @abc.abstractmethod
    def is_provider_login(self):    # type: () -> bool
        pass

    @property
    @abc.abstractmethod
    def login_name(self):    # type: () -> str
        pass

    @property
    @abc.abstractmethod
    def sso_login_url(self):    # type: () -> str
        pass


class AccountAuthType(enum.Enum):
    Regular = 1
    CloudSso = 2
    OnsiteSso = 3
    ManagedCompany = 4


class DeviceApprovalChannel(enum.Enum):
    Email = enum.auto()
    KeeperPush = enum.auto()
    TwoFactor = enum.auto()


class TwoFactorDuration(enum.Enum):
    EveryLogin = enum.auto()
    EveryDay = enum.auto()
    Every30Days = enum.auto()
    Forever = enum.auto()


class TwoFactorChannel(enum.Enum):
    Other = enum.auto()
    Authenticator = enum.auto()
    TextMessage = enum.auto()
    DuoSecurity = enum.auto()
    RSASecurID = enum.auto()
    KeeperDNA = enum.auto()
    SecurityKey = enum.auto()
    Backup = enum.auto()


class TwoFactorPushAction(enum.Enum):
    DuoPush = enum.auto()
    DuoTextMessage = enum.auto()
    DuoVoiceCall = enum.auto()
    TextMessage = enum.auto()
    KeeperDna = enum.auto()


class DataKeyShareChannel(enum.Enum):
    KeeperPush = enum.auto()
    AdminApproval = enum.auto()


class TwoFactorChannelInfo:
    def __init__(self):          # type: () -> None
        self.channel_type = TwoFactorChannel.Other    # type: TwoFactorChannel
        self.channel_name = ''   # type: str
        self.channel_uid = b''   # type: bytes
        self.phone = None        # type: Optional[str]
        self.max_expiration = TwoFactorDuration.EveryLogin   # type: TwoFactorDuration


class SsoLoginInfo:
    def __init__(self):          # type: () -> None
        self.is_cloud = False
        self.sso_provider = ''
        self.sso_url = ''
        self.idp_session_id = ''


class LoginContext:
    def __init__(self):                 # type: () -> None
        self.username = ''              # type: str
        self.passwords = []             # type: List[str]
        self.clone_code = b''           # type: bytes
        self.device_token = b''         # type: bytes
        self.device_private_key = None  # type: Optional[ec.EllipticCurvePrivateKey]
        self.device_public_key = None   # type: Optional[ec.EllipticCurvePublicKey]
        self.message_session_uid = crypto.get_random_bytes(16)
        self.account_type = AccountAuthType.Regular
        self.sso_login_info = None  # type: Optional[SsoLoginInfo]


class LoginAuth:
    def __init__(self, keeper_endpoint):     # type: (endpoint.KeeperEndpoint) -> None
        self.keeper_endpoint = keeper_endpoint
        self.alternate_password = False
        self.resume_session = False
        self.on_next_step = None             # type: Optional[Callable[[], None]]
        self.on_region_changed = None        # type: Optional[Callable[[str], None]]
        self._login_step = LoginStepReady()  # type: ILoginStep
        self.push_notifications = None       # type: Optional[notifications.FanOut[Dict[str, Any]]]

    @property
    def login_step(self):   # type: () -> ILoginStep
        return self._login_step

    @login_step.setter
    def login_step(self, value):  # type: (ILoginStep) -> None
        if isinstance(value, ILoginStep):
            if self._login_step:
                self._login_step.close()
            self._login_step = value
            if self.on_next_step:
                self.on_next_step()

    def execute_rest(self, rest_endpoint, request, response_type=None):
        # type: (str, Optional[endpoint.TRQ], Optional[Type[endpoint.TRS]]) -> Optional[endpoint.TRS]
        return self.keeper_endpoint.execute_rest(rest_endpoint, request, response_type)

    def login(self, username, *passwords):  # type: (str, str) -> None
        login_context = LoginContext()
        login_context.username = configuration.adjust_username(username)
        login_context.passwords.extend(passwords)
        config = self.keeper_endpoint.get_configuration_storage().get()
        uc = config.users().get(login_context.username)
        if uc:
            pwd = uc.password
            if pwd:
                login_context.passwords.append(pwd)
            us = uc.server
            if us:
                if us != self.keeper_endpoint.server:
                    self.keeper_endpoint.server = us
        try:
            try:
                _ensure_device_token_loaded(self, login_context)
                _start_login(self, login_context)
            except errors.RegionRedirectError as rr:
                _redirect_to_region(self, rr.region_host)
                _ensure_device_token_loaded(self, login_context)
                _start_login(self, login_context)
        except errors.KeeperApiError as kae:
            self.login_step = LoginStepError(kae.result_code, kae.message)
        except Exception as e:
            self.login_step = LoginStepError('unknown_error', str(e))


class LoginStepReady(ILoginStep):
    pass


class LoginStepConnected(ILoginStep, abc.ABC):
    @abc.abstractmethod
    def keeper_auth(self):
        pass

    def is_final(self):
        return True


def _channel_keeper_to_sdk(channel_type):      # type: (int) -> TwoFactorChannel
    if channel_type == APIRequest_pb2.TWO_FA_CT_TOTP:
        return TwoFactorChannel.Authenticator
    if channel_type == APIRequest_pb2.TWO_FA_CT_SMS:
        return TwoFactorChannel.TextMessage
    if channel_type == APIRequest_pb2.TWO_FA_CT_DUO:
        return TwoFactorChannel.DuoSecurity
    if channel_type == APIRequest_pb2.TWO_FA_CT_RSA:
        return TwoFactorChannel.RSASecurID
    if channel_type == APIRequest_pb2.TWO_FA_CT_WEBAUTHN:
        return TwoFactorChannel.SecurityKey
    if channel_type == APIRequest_pb2.TWO_FA_CT_DNA:
        return TwoFactorChannel.KeeperDNA
    if channel_type == APIRequest_pb2.TWO_FA_CT_BACKUP:
        return TwoFactorChannel.Backup
    return TwoFactorChannel.Other


def _duration_keeper_to_sdk(duration):       # type: (int) -> TwoFactorDuration
    if duration in {APIRequest_pb2.TWO_FA_EXP_IMMEDIATELY, APIRequest_pb2.TWO_FA_EXP_5_MINUTES}:
        return TwoFactorDuration.EveryLogin
    if duration in {APIRequest_pb2.TWO_FA_EXP_12_HOURS, APIRequest_pb2.TWO_FA_EXP_24_HOURS}:
        return TwoFactorDuration.EveryDay
    if duration == APIRequest_pb2.TWO_FA_EXP_30_DAYS:
        return TwoFactorDuration.Every30Days
    return TwoFactorDuration.Forever


def _duration_sdk_to_keeper(duration):       # type: (TwoFactorDuration) -> int
    if duration == TwoFactorDuration.EveryLogin:
        return APIRequest_pb2.TWO_FA_EXP_IMMEDIATELY
    if duration == TwoFactorDuration.EveryDay:
        return APIRequest_pb2.TWO_FA_EXP_24_HOURS
    if duration == TwoFactorDuration.Every30Days:
        return APIRequest_pb2.TWO_FA_EXP_30_DAYS
    if duration == TwoFactorDuration.Forever:
        return APIRequest_pb2.TWO_FA_EXP_NEVER
    return APIRequest_pb2.TWO_FA_EXP_IMMEDIATELY


def duo_capability_to_sdk(capability):
    if capability == 'push':
        return TwoFactorPushAction.DuoPush
    if capability == 'sms':
        return TwoFactorPushAction.DuoTextMessage
    if capability == 'phone':
        return TwoFactorPushAction.DuoVoiceCall
    return ''


def tfa_action_sdk_to_keeper(action):   # type: (TwoFactorPushAction) -> int
    if action == TwoFactorPushAction.DuoPush:
        return APIRequest_pb2.TWO_FA_PUSH_DUO_PUSH
    if action == TwoFactorPushAction.DuoTextMessage:
        return APIRequest_pb2.TWO_FA_PUSH_DUO_TEXT
    if action == TwoFactorPushAction.DuoVoiceCall:
        return APIRequest_pb2.TWO_FA_PUSH_DUO_CALL
    if action == TwoFactorPushAction.TextMessage:
        return APIRequest_pb2.TWO_FA_PUSH_SMS
    if action == TwoFactorPushAction.KeeperDna:
        return APIRequest_pb2.TWO_FA_PUSH_KEEPER
    return APIRequest_pb2.TWO_FA_PUSH_NONE


def tfa_value_type_for_channel(channel_type):   # type: (TwoFactorChannel) -> int
    if channel_type == TwoFactorChannel.Authenticator:
        return APIRequest_pb2.TWO_FA_CODE_TOTP
    if channel_type == TwoFactorChannel.TextMessage:
        return APIRequest_pb2.TWO_FA_CODE_SMS
    if channel_type == TwoFactorChannel.DuoSecurity:
        return APIRequest_pb2.TWO_FA_CODE_DUO
    if channel_type == TwoFactorChannel.RSASecurID:
        return APIRequest_pb2.TWO_FA_CODE_RSA
    if channel_type == TwoFactorChannel.SecurityKey:
        return APIRequest_pb2.TWO_FA_RESP_WEBAUTHN
    if channel_type == TwoFactorChannel.KeeperDNA:
        return APIRequest_pb2.TWO_FA_CODE_DNA
    return APIRequest_pb2.TWO_FA_CODE_NONE


def _tfa_channel_info_keeper_to_sdk(channel_info):
    # type: (APIRequest_pb2.TwoFactorChannelInfo) -> TwoFactorChannelInfo
    info = TwoFactorChannelInfo()
    info.channel_type = _channel_keeper_to_sdk(channel_info.channelType)
    info.channel_uid = channel_info.channel_uid
    info.channel_name = channel_info.channelName
    info.phone = channel_info.phoneNumber
    info.max_expiration = _duration_keeper_to_sdk(channel_info.maxExpiration)

    return info


def _ensure_device_token_loaded(login_auth, context):  # type: (LoginAuth, LoginContext) -> None
    logger = utils.get_logger()
    attempt = 0
    context.clone_code = b''

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
                    clone_code = dsc.clone_code
                    if clone_code:
                        context.clone_code = utils.base64_url_decode(clone_code)
                    return
            else:
                dc = configuration.DeviceConfiguration(device_token)
                dc.private_key = utils.base64_url_encode(crypto.unload_ec_private_key(context.device_private_key))
                dc.public_key = utils.base64_url_encode(crypto.unload_ec_public_key(context.device_public_key))
                config.devices().put(dc)
            try:
                _register_device_in_region(login_auth, dc)
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
                    last_device = uc.last_device
                    if isinstance(last_device, configuration.IUserDeviceConfiguration):
                        device_token = last_device.device_token
                        if device_token:
                            dc = config.devices().get(device_token)
                            if dc:
                                try:
                                    context.device_token = utils.base64_url_decode(dc.device_token)
                                    context.device_private_key = crypto.load_ec_private_key(
                                        utils.base64_url_decode(dc.private_key))
                                    context.device_public_key = crypto.load_ec_public_key(
                                        utils.base64_url_decode(dc.public_key))
                                    continue
                                except Exception as e:
                                    logger.debug('Load device key error: %s', e)
                                    config.devices().delete(dc.device_token)
                        uc = configuration.UserConfiguration(uc)
                        uc.last_device = None
                        config.users().put(uc)

            dc = next((x for x in config.devices().list()), None)
            if dc:
                try:
                    context.device_token = \
                        utils.base64_url_decode(dc.device_token)
                    context.device_private_key = \
                        crypto.load_ec_private_key(utils.base64_url_decode(dc.private_key))
                    context.device_public_key = \
                        crypto.load_ec_public_key(utils.base64_url_decode(dc.public_key))
                except Exception as e:
                    logger.debug('Load device key error: %s', e)
                    config.devices().delete(dc.device_token)
            else:
                dc = _register_device(login_auth)
                context.device_token = utils.base64_url_decode(dc.device_token)
                context.device_private_key = crypto.load_ec_private_key(utils.base64_url_decode(dc.private_key))
                context.device_public_key = crypto.load_ec_public_key(utils.base64_url_decode(dc.public_key))
                config.devices().put(dc)
                login_auth.keeper_endpoint.get_configuration_storage().put(config)
                return


def _register_device_in_region(login_auth, device_config):
    # type: (LoginAuth, configuration.IDeviceConfiguration) -> None
    rq = APIRequest_pb2.RegisterDeviceInRegionRequest()
    rq.encryptedDeviceToken = utils.base64_url_decode(device_config.device_token)
    rq.clientVersion = login_auth.keeper_endpoint.client_version
    rq.deviceName = login_auth.keeper_endpoint.device_name
    rq.devicePublicKey = utils.base64_url_decode(device_config.public_key)

    try:
        login_auth.execute_rest('authentication/register_device_in_region', rq)
    except errors.KeeperApiError as kae:
        if 'exists' != kae.result_code:
            raise kae
    except errors.InvalidDeviceTokenError as idt:
        if 'public key already exists' != idt.message:
            raise idt


def _register_device(login_auth):   # type: (LoginAuth) -> configuration.DeviceConfiguration
    private_key, public_key = crypto.generate_ec_key()
    device_public_key = crypto.unload_ec_public_key(public_key)
    device_private_key = crypto.unload_ec_private_key(private_key)

    rq = APIRequest_pb2.DeviceRegistrationRequest()
    rq.clientVersion = login_auth.keeper_endpoint.client_version
    rq.deviceName = login_auth.keeper_endpoint.device_name
    rq.devicePublicKey = device_public_key

    device = login_auth.execute_rest('authentication/register_device', rq, response_type=APIRequest_pb2.Device)
    assert device is not None
    dc = configuration.DeviceConfiguration(utils.base64_url_encode(device.encryptedDeviceToken))
    dc.public_key = utils.base64_url_encode(device_public_key)
    dc.private_key = utils.base64_url_encode(device_private_key)
    dsc = configuration.DeviceServerConfiguration(login_auth.keeper_endpoint.server)
    dc.get_server_info().put(dsc)
    return dc


def _start_login(login_auth, login_context, method=APIRequest_pb2.EXISTING_ACCOUNT, new_login=False):
    # type: (LoginAuth, LoginContext, APIRequest_pb2.LoginMethod, bool) -> None
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

    _process_start_login(login_auth, login_context, rq)


def _resume_login(login_auth, login_context, login_token, method=APIRequest_pb2.EXISTING_ACCOUNT):
    # type: (LoginAuth, LoginContext, bytes, APIRequest_pb2.LoginMethod) -> None
    rq = APIRequest_pb2.StartLoginRequest()
    rq.clientVersion = login_auth.keeper_endpoint.client_version
    rq.encryptedDeviceToken = login_context.device_token
    rq.encryptedLoginToken = login_token
    rq.username = login_context.username
    rq.loginMethod = method
    rq.messageSessionUid = login_context.message_session_uid

    _process_start_login(login_auth, login_context, rq)


def _process_start_login(login_auth, login_context, request):
    # type: (LoginAuth, LoginContext, APIRequest_pb2.StartLoginRequest) -> None
    response = login_auth.execute_rest(
        'authentication/start_login', request, response_type=APIRequest_pb2.LoginResponse)
    assert response is not None
    if response.loginState == APIRequest_pb2.LOGGED_IN:
        assert login_context.device_private_key is not None

        def decrypt_with_device_key(encrypted_data_key):
            return crypto.decrypt_ec(encrypted_data_key, login_context.device_private_key)
        _on_logged_in(login_auth, login_context, response, decrypt_with_device_key)
        return
    if response.loginState == APIRequest_pb2.REQUIRES_USERNAME:
        _resume_login(login_auth, login_context, response.encryptedLoginToken)
        return
    if response.loginState == APIRequest_pb2.DEVICE_APPROVAL_REQUIRED:
        _on_device_approval_required(login_auth, login_context, response)
        return
    if response.loginState == APIRequest_pb2.REQUIRES_2FA:
        _on_requires_2fa(login_auth, login_context, response)
        return
    if response.loginState == APIRequest_pb2.REQUIRES_AUTH_HASH:
        _on_requires_auth_hash(login_auth, login_context, response)
        return
    if response.loginState in {APIRequest_pb2.REDIRECT_CLOUD_SSO, APIRequest_pb2.REDIRECT_ONSITE_SSO}:
        sso_login_info = SsoLoginInfo()
        sso_login_info.is_cloud = response.loginState == APIRequest_pb2.REDIRECT_CLOUD_SSO
        sso_login_info.sso_url = response.url
        _on_sso_redirect(login_auth, login_context, sso_login_info, response.encryptedLoginToken)
        return
    if response.loginState == APIRequest_pb2.REQUIRES_DEVICE_ENCRYPTED_DATA_KEY:
        _on_request_data_key(login_auth, login_context, response.encryptedLoginToken)
        return
    if response.loginState in {APIRequest_pb2.DEVICE_ACCOUNT_LOCKED, APIRequest_pb2.DEVICE_LOCKED}:
        raise errors.InvalidDeviceTokenError(response.message)
    message = f'State {APIRequest_pb2.LoginState.keys()[response.loginState]}: Not implemented: {response.message}'
    login_auth.login_step = LoginStepError('not_implemented', message)


def _store_configuration(login_auth, login_context):  # type: (LoginAuth, LoginContext) -> None
    config = login_auth.keeper_endpoint.get_configuration_storage().get()
    config.last_login = login_context.username
    config.last_server = login_auth.keeper_endpoint.server

    device_token = utils.base64_url_encode(login_context.device_token)
    iuc = config.users().get(login_context.username)
    uc = None  # type: Optional[configuration.UserConfiguration]
    if not iuc:
        uc = configuration.UserConfiguration(login_context.username)
        uc.server = login_auth.keeper_endpoint.server
        uc.last_device = configuration.UserDeviceConfiguration(device_token)
    else:
        udc = iuc.last_device
        if not udc or udc.device_token != device_token:
            uc = configuration.UserConfiguration(iuc)
            uc.last_device = configuration.UserDeviceConfiguration(device_token)
    if uc:
        config.users().put(uc)

    isc = config.servers().get(login_auth.keeper_endpoint.server)
    sc = None   # type: Optional[configuration.ServerConfiguration]
    if not isc:
        sc = configuration.ServerConfiguration(login_auth.keeper_endpoint.server)
        sc.server_key_id = login_auth.keeper_endpoint.server_key_id
    if sc:
        config.servers().put(sc)

    idc = config.devices().get(device_token)
    if not idc:
        dc = configuration.DeviceConfiguration(device_token)
        assert login_context.device_public_key is not None
        dc.public_key = crypto.unload_ec_public_key(login_context.device_public_key)
        assert login_context.device_private_key is not None
        dc.private_key = crypto.unload_ec_private_key(login_context.device_private_key)
    else:
        dc = configuration.DeviceConfiguration(idc)
    idsc = dc.get_server_info().get(login_auth.keeper_endpoint.server)
    dsc = configuration.DeviceServerConfiguration(idsc if idsc else login_auth.keeper_endpoint.server)
    dsc.clone_code = utils.base64_url_encode(login_context.clone_code)
    dc.get_server_info().put(dsc)
    config.devices().put(dc)

    login_auth.keeper_endpoint.get_configuration_storage().put(config)


def _redirect_to_region(login_auth, region_host):  # type: (LoginAuth, str) -> None
    keeper_endpoint = login_auth.keeper_endpoint
    keeper_endpoint.server = region_host
    if login_auth.on_region_changed:
        login_auth.on_region_changed(region_host)


def _ensure_push_notifications(login_auth, login_context):    # type: (LoginAuth, LoginContext) -> None
    if login_auth.push_notifications:
        return

    rq = push_pb2.WssConnectionRequest()
    rq.messageSessionUid = login_context.message_session_uid
    rq.encryptedDeviceToken = login_context.device_token
    rq.deviceTimeStamp = utils.current_milli_time()

    login_auth.push_notifications = login_auth.keeper_endpoint.connect_to_push_server(rq.SerializeToString())


def _get_session_token_scope(session_token_type):   # type: (int) -> auth.SessionTokenRestriction
    if session_token_type == APIRequest_pb2.ACCOUNT_RECOVERY:
        return auth.SessionTokenRestriction.AccountRecovery
    if session_token_type == APIRequest_pb2.SHARE_ACCOUNT:
        return auth.SessionTokenRestriction.ShareAccount
    if session_token_type == APIRequest_pb2.ACCEPT_INVITE:
        return auth.SessionTokenRestriction.AcceptInvite
    if session_token_type in [APIRequest_pb2.PURCHASE, APIRequest_pb2.RESTRICT]:
        return auth.SessionTokenRestriction.AccountExpired
    return auth.SessionTokenRestriction.Unrestricted


def _on_device_approval_required(login_auth, login_context, response):
    # type: (LoginAuth, LoginContext, APIRequest_pb2.LoginResponse) -> None

    _ensure_push_notifications(login_auth, login_context)
    login_auth.login_step = _DeviceApprovalStep(login_auth, login_context, response.encryptedLoginToken)


def _on_request_data_key(login_auth, login_context, login_token):
    # type: (LoginAuth, LoginContext, bytes) -> None
    _ensure_push_notifications(login_auth, login_context)
    login_auth.login_step = _SsoDataKeyLoginStep(login_auth, login_context, login_token)


def _on_requires_auth_hash(login_auth, login_context, response):
    # type: (LoginAuth, LoginContext, APIRequest_pb2.LoginResponse) -> None
    salt = next((x for x in response.salt
                 if x.name.lower() == ('alternate' if login_auth.alternate_password else 'master')), None)
    if not salt:
        salt = response.salt[0]

    password_step = _PasswordLoginStep(login_auth, login_context, response.encryptedLoginToken, salt)
    while login_context.passwords:
        password = login_context.passwords.pop()
        try:
            password_step.verify_password(password)
            if not isinstance(login_auth.login_step, LoginStepPassword):
                return
        except:
            pass
    login_auth.login_step = password_step


def _on_requires_2fa(login_auth, login_context, response):
    # type: (LoginAuth, LoginContext, APIRequest_pb2.LoginResponse) -> None
    _ensure_push_notifications(login_auth, login_context)
    login_auth.login_step = _TwoFactorStep(
        login_auth, login_context, response.encryptedLoginToken, list(response.channels))


def _post_login(logged_auth):   # type: (auth.KeeperAuth) -> None
    rq = AccountSummary_pb2.AccountSummaryRequest()
    rq.summaryVersion = 1

    rs = logged_auth.execute_auth_rest(
        'login/account_summary', rq, response_type=AccountSummary_pb2.AccountSummaryElements)
    assert rs is not None
    logged_auth.auth_context.settings.update(MessageToDict(rs.settings))
    logged_auth.auth_context.license.update(MessageToDict(rs.license))
    enf = MessageToDict(rs.Enforcements)
    if 'strings' in enf:
        strs = {x['key']: x['value'] for x in enf['strings'] if 'key' in x and 'value' in x}
        logged_auth.auth_context.enforcements.update(strs)
    if 'booleans' in enf:
        bools = {x['key']: x.get('value', False) for x in enf['booleans'] if 'key' in x}
        logged_auth.auth_context.enforcements.update(bools)
    if 'longs' in enf:
        longs = {x['key']: x['value'] for x in enf['longs'] if 'key' in x and 'value' in x}
        logged_auth.auth_context.enforcements.update(longs)
    if 'jsons' in enf:
        jsons = {x['key']: x['value'] for x in enf['jsons'] if 'key' in x and 'value' in x}
        logged_auth.auth_context.enforcements.update(jsons)
    logged_auth.auth_context.is_enterprise_admin = rs.isEnterpriseAdmin
    if rs.clientKey:
        logged_auth.auth_context.client_key = crypto.decrypt_aes_v1(rs.clientKey, logged_auth.auth_context.data_key)
    if rs.keysInfo.encryptedPrivateKey:
        rsa_private_key = crypto.decrypt_aes_v1(rs.keysInfo.encryptedPrivateKey, logged_auth.auth_context.data_key)
        logged_auth.auth_context.rsa_private_key = crypto.load_rsa_private_key(rsa_private_key)
    if rs.keysInfo.encryptedEccPrivateKey:
        ec_private_key = crypto.decrypt_aes_v2(rs.keysInfo.encryptedEccPrivateKey, logged_auth.auth_context.data_key)
        logged_auth.auth_context.ec_private_key = crypto.load_ec_private_key(ec_private_key)
    if rs.keysInfo.eccPublicKey:
        logged_auth.auth_context.ec_public_key = crypto.load_ec_public_key(rs.keysInfo.eccPublicKey)

    if logged_auth.auth_context.session_token_restriction == auth.SessionTokenRestriction.Unrestricted:
        if logged_auth.auth_context.license.get('accountType', 0) == 2:
            try:
                e_rs = logged_auth.execute_auth_rest('enterprise/get_enterprise_public_key', None,
                                                     response_type=breachwatch_pb2.EnterprisePublicKeyResponse)
                assert e_rs is not None
                if e_rs.enterpriseECCPublicKey:
                    logged_auth.auth_context.enterprise_ec_public_key = \
                        crypto.load_ec_public_key(e_rs.enterpriseECCPublicKey)
                if e_rs.enterprisePublicKey:
                    logged_auth.auth_context.enterprise_rsa_public_key = \
                        crypto.load_rsa_public_key(e_rs.enterprisePublicKey)

            except Exception as e:
                logger = utils.get_logger()
                logger.debug('Get enterprise public key error: %s', e)


def _on_logged_in(login_auth, login_context, response, on_decrypt_data_key):
    # type: (LoginAuth, LoginContext, APIRequest_pb2.LoginResponse, Callable[[bytes], bytes]) -> None
    login_context.username = response.primaryUsername
    login_context.clone_code = response.cloneCode
    _store_configuration(login_auth, login_context)

    auth_context = auth.AuthContext()
    auth_context.username = login_context.username
    auth_context.session_token = response.encryptedSessionToken
    auth_context.session_token_restriction = _get_session_token_scope(response.sessionTokenType)
    auth_context.data_key = on_decrypt_data_key(response.encryptedDataKey)

    logged_auth = auth.KeeperAuth(login_auth.keeper_endpoint, auth_context)
    _post_login(logged_auth)

    if auth_context.session_token_restriction == auth.SessionTokenRestriction.Unrestricted:
        _ensure_push_notifications(login_auth, login_context)
        if isinstance(login_auth.push_notifications, notifications.KeeperPushNotifications):
            login_auth.push_notifications.send_to_push_channel(auth_context.session_token, False)
        logged_auth.push_notifications = login_auth.push_notifications
        login_auth.push_notifications = None

    login_auth.login_step = _ConnectedLoginStep(logged_auth)


def _on_sso_redirect(login_auth, login_context, sso_info, login_token=None):
    # type: (LoginAuth, LoginContext, SsoLoginInfo, Optional[bytes]) -> None
    login_context.account_type = AccountAuthType.CloudSso \
        if sso_info.is_cloud else AccountAuthType.OnsiteSso

    login_auth.login_step = _CloudSsoTokenLoginStep(login_auth, login_context, sso_info, login_token) \
        if sso_info.is_cloud else _OnPremisesSsoTokenLoginStep(login_auth, login_context, sso_info, login_token)


class _ConnectedLoginStep(LoginStepConnected):
    def __init__(self, keeper_auth):
        self._keeper_auth = keeper_auth

    def keeper_auth(self):
        return self._keeper_auth


class _DeviceApprovalStep(LoginStepDeviceApproval):
    def __init__(self, login_auth, login_context, login_token):  # type: (LoginAuth, LoginContext, bytes) -> None
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
            _resume_login(self._login_auth, self._login_context, token)

        return False

    def send_push(self, channel):
        if channel == DeviceApprovalChannel.Email:
            rq = APIRequest_pb2.DeviceVerificationRequest()
            rq.username = self._login_context.username
            rq.clientVersion = self._login_auth.keeper_endpoint.client_version
            rq.encryptedDeviceToken = self._login_context.device_token
            rq.messageSessionUid = self._login_context.message_session_uid
            rq.verificationChannel = 'email_resend' if self._email_sent else 'email'

            self._login_auth.execute_rest('authentication/request_device_verification', rq)
            self._email_sent = True
        elif channel in {DeviceApprovalChannel.KeeperPush, DeviceApprovalChannel.TwoFactor}:
            rq = APIRequest_pb2.TwoFactorSendPushRequest()
            rq.encryptedLoginToken = self._login_token
            rq.pushType = APIRequest_pb2.TwoFactorPushType.TWO_FA_PUSH_KEEPER \
                if channel == DeviceApprovalChannel.KeeperPush \
                else APIRequest_pb2.TwoFactorPushType.TWO_FA_PUSH_NONE

            self._login_auth.execute_rest('authentication/2fa_send_push', rq)

    def send_code(self, channel, code):
        if channel == DeviceApprovalChannel.Email:
            rq = APIRequest_pb2.ValidateDeviceVerificationCodeRequest()
            rq.username = self._login_context.username
            rq.clientVersion = self._login_auth.keeper_endpoint.client_version
            rq.encryptedDeviceToken = self._login_context.device_token
            rq.messageSessionUid = self._login_context.message_session_uid
            rq.verificationCode = code

            self._login_auth.execute_rest('authentication/validate_device_verification_code', rq)
            _resume_login(self._login_auth, self._login_context, self._login_token)

        elif channel == DeviceApprovalChannel.TwoFactor:
            rq = APIRequest_pb2.TwoFactorValidateRequest()
            rq.encryptedLoginToken = self._login_token
            rq.valueType = APIRequest_pb2.TWO_FA_CODE_NONE
            rq.value = code

            rs = self._login_auth.execute_rest(
                'authentication/2fa_validate', rq, response_type=APIRequest_pb2.TwoFactorValidateResponse)
            _resume_login(self._login_auth, self._login_context, rs.encryptedLoginToken if rs else self._login_token)

    def resume(self):
        if self._login_auth.login_step is self:
            _resume_login(self._login_auth, self._login_context, self._login_token)

    def close(self):
        if self._login_auth.push_notifications:
            self._login_auth.push_notifications.remove_callback(self.push_handler)


class _SsoDataKeyLoginStep(LoginStepSsoDataKey):
    def __init__(self, login_auth, login_context, login_token):
        # type: (LoginAuth, LoginContext, bytes) -> None
        super(_SsoDataKeyLoginStep, self).__init__()
        self._login_auth = login_auth
        self._login_context = login_context
        self._login_token = login_token
        if login_auth.push_notifications:
            login_auth.push_notifications.register_callback(self.push_handler)

    def push_handler(self, event):   # type: (dict) -> bool
        if event.get('message', '') == 'device_approved':
            if event.get('approved', False):
                _resume_login(self._login_auth, self._login_context, self._login_token)
        elif event.get('command', '') == 'device_verified':
            _resume_login(self._login_auth, self._login_context, self._login_token)
        return False

    def request_data_key(self, channel):
        if channel == DataKeyShareChannel.KeeperPush:
            rq = APIRequest_pb2.TwoFactorSendPushRequest()
            rq.pushType = APIRequest_pb2.TWO_FA_PUSH_KEEPER
            rq.encryptedLoginToken = self._login_token
            self._login_auth.execute_rest('authentication/2fa_send_push', rq)
        elif channel == DataKeyShareChannel.AdminApproval:
            rq = APIRequest_pb2.DeviceVerificationRequest()
            rq.username = self._login_context.username
            rq.clientVersion = self._login_auth.keeper_endpoint.client_version
            rq.encryptedDeviceToken = self._login_context.device_token
            rq.messageSessionUid = self._login_context.message_session_uid
            rs = self._login_auth.execute_rest('authentication/request_device_admin_approval', rq,
                                               response_type=APIRequest_pb2.DeviceVerificationResponse)
            if rs and rs.deviceStatus == APIRequest_pb2.DEVICE_OK:
                _resume_login(self._login_auth, self._login_context, self._login_token)

    def close(self):
        if self._login_auth.push_notifications:
            self._login_auth.push_notifications.remove_callback(self.push_handler)


class _SsoTokenLoginStep(LoginStepSsoToken, abc.ABC):
    def __init__(self, login_auth, login_context, sso_info, login_token):
        # type: (LoginAuth, LoginContext, SsoLoginInfo, bytes) -> None
        super(_SsoTokenLoginStep, self).__init__()
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
            self._login_context.account_type = AccountAuthType.Regular
            _start_login(self._login_auth, self._login_context)


class _CloudSsoTokenLoginStep(_SsoTokenLoginStep):
    def __init__(self, login_auth, login_context, sso_info, login_token):
        super(_CloudSsoTokenLoginStep, self).__init__(login_auth, login_context, sso_info, login_token)
        self.transmission_key = utils.generate_aes_key()
        rq = ssocloud_pb2.SsoCloudRequest()
        rq.clientVersion = login_auth.keeper_endpoint.client_version
        rq.embedded = True
        transmission_key = utils.generate_aes_key()
        api_rq = endpoint.prepare_api_request(
            login_auth.keeper_endpoint.server_key_id, transmission_key, rq.SerializeToString())
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

        _ensure_device_token_loaded(self._login_auth, self._login_context)
        lt = rs.encryptedLoginToken or self._login_token
        if lt:
            _resume_login(self._login_auth, self._login_context, lt, method=APIRequest_pb2.AFTER_SSO)
        else:
            _start_login(self._login_auth, self._login_context, method=APIRequest_pb2.AFTER_SSO, new_login=False)


class _OnPremisesSsoTokenLoginStep(_SsoTokenLoginStep):
    def __init__(self, login_auth, login_context, sso_info, login_token):
        super(_OnPremisesSsoTokenLoginStep, self).__init__(login_auth, login_context, sso_info, login_token)
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
                self._login_context.passwords.append(password.decode())
        self._login_context.sso_login_info = self._sso_info

        lt = self._login_token
        if 'login_token' in token:
            lt = utils.base64_url_decode(token['login_token'])
        if lt:
            _resume_login(self._login_auth, self._login_context, lt, method=APIRequest_pb2.AFTER_SSO)
        else:
            _start_login(self._login_auth, self._login_context, method=APIRequest_pb2.AFTER_SSO, new_login=False)


class _PasswordLoginStep(LoginStepPassword):
    def __init__(self, login_auth, login_context, login_token, salt):
        # type: (LoginAuth, LoginContext, bytes, APIRequest_pb2.Salt) -> None
        super(_PasswordLoginStep, self).__init__()
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

        rs = self._login_auth.execute_rest(
            'authentication/validate_auth_hash', rq, response_type=APIRequest_pb2.LoginResponse)

        def decrypt_data_key(encrypted_data_key):
            if rs.encryptedDataKeyType == APIRequest_pb2.BY_ALTERNATE:
                key = crypto.derive_keyhash_v2('data_key', password, salt, iterations)
                return crypto.decrypt_aes_v2(encrypted_data_key, key)
            return utils.decrypt_encryption_params(encrypted_data_key, password)

        _on_logged_in(self._login_auth, self._login_context, rs, decrypt_data_key)

    def verify_biometric_key(self, biometric_key):
        rq = APIRequest_pb2.ValidateAuthHashRequest()
        rq.passwordMethod = APIRequest_pb2.BIOMETRICS
        rq.encryptedLoginToken = self._login_token
        rq.authResponse = crypto.create_bio_auth_hash(biometric_key)

        rs = self._login_auth.execute_rest(
            'authentication/validate_auth_hash', rq, response_type=APIRequest_pb2.LoginResponse)
        _on_logged_in(self._login_auth, self._login_context, rs, lambda x: crypto.decrypt_aes_v2(x, biometric_key))


class _TwoFactorStep(LoginStepTwoFactor):
    def __init__(self, login_auth, login_context, login_token, channels):
        # type: (LoginAuth, LoginContext, bytes, List[APIRequest_pb2.TwoFactorChannelInfo]) -> None
        super(_TwoFactorStep, self).__init__()
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
                    _resume_login(self._login_auth, self._login_context, token)
                elif 'passcode' in event:
                    if self._last_push_channel_uid:
                        self.send_code(self._last_push_channel_uid, event['passcode'])
        return False

    def get_channels(self):
        return [_tfa_channel_info_keeper_to_sdk(x) for x in self._channels]

    def get_channel_push_actions(self, channel_uid):
        channel = self.get_channel_by_uid(channel_uid)
        if channel:
            channel_type = _channel_keeper_to_sdk(channel.channelType)
            if channel_type == TwoFactorChannel.TextMessage:
                return [TwoFactorPushAction.TextMessage]
            if channel_type == TwoFactorChannel.KeeperDNA:
                return [TwoFactorPushAction.KeeperDna]
            if channel_type == TwoFactorChannel.DuoSecurity:
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
        if action in {TwoFactorPushAction.DuoPush, TwoFactorPushAction.KeeperDna}:
            rq.expireIn = _duration_sdk_to_keeper(self.duration)
        self._login_auth.execute_rest('authentication/2fa_send_push', rq)
        self._last_push_channel_uid = channel_uid

    def send_code(self, channel_uid, code):
        channel = self.get_channel_by_uid(channel_uid)
        if not channel:
            raise errors.KeeperError(f'Channel \"{utils.base64_url_encode(channel_uid)}\" not found')

        rq = APIRequest_pb2.TwoFactorValidateRequest()
        rq.encryptedLoginToken = self._login_token
        rq.channel_uid = channel_uid
        rq.expireIn = _duration_sdk_to_keeper(self.duration)
        rq.valueType = tfa_value_type_for_channel(_channel_keeper_to_sdk(channel.channelType))
        rq.value = code
        rs = self._login_auth.execute_rest('authentication/2fa_validate', rq,
                                           response_type=APIRequest_pb2.TwoFactorValidateResponse)
        if rs:
            _resume_login(self._login_auth, self._login_context, rs.encryptedLoginToken)

    def resume(self):
        if self._login_auth.login_step is self:
            _resume_login(self._login_auth, self._login_context, self._login_token)

    def get_channel_by_uid(self, channel_uid):
        return next((x for x in self._channels if x.channel_uid == channel_uid), None)

    def close(self):
        if self._login_auth.push_notifications:
            self._login_auth.push_notifications.remove_all()
