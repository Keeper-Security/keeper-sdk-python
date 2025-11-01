import abc
import dataclasses
import enum
import json
from typing import Type, Optional, List, Callable, Dict, Any, Sequence
from urllib.parse import urlparse, urlunparse, quote_plus

from cryptography.hazmat.primitives.asymmetric import ec
from google.protobuf.json_format import MessageToDict

from . import endpoint, configuration, keeper_auth, auth_utils, notifications, push_notifications
from .. import crypto, utils, errors
from ..proto import APIRequest_pb2, breachwatch_pb2, ssocloud_pb2


class ILoginStep(abc.ABC):
    def close(self):
        pass

    def is_final(self):
        return False


class DeviceApprovalChannel(enum.Enum):
    Email = enum.auto()
    KeeperPush = enum.auto()
    TwoFactor = enum.auto()


class TwoFactorDuration(enum.IntEnum):
    EveryLogin = enum.auto()
    Every12Hours = enum.auto()
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


class LoginStepDeviceApproval(ILoginStep, abc.ABC):
    @abc.abstractmethod
    def send_push(self, channel: DeviceApprovalChannel) -> None:
        pass

    @abc.abstractmethod
    def send_code(self, channel: DeviceApprovalChannel, code: str) -> None:
        pass

    @abc.abstractmethod
    def resume(self) -> None:
        pass


class TwoFactorChannelInfo:
    def __init__(self) -> None:
        self.channel_type: TwoFactorChannel = TwoFactorChannel.Other
        self.channel_name: str = ''
        self.channel_uid: bytes = b''
        self.phone: Optional[str] = None
        self.max_expiration: TwoFactorDuration = TwoFactorDuration.EveryLogin
        self.challenge: str = ''


class LoginStepTwoFactor(ILoginStep, abc.ABC):
    def __init__(self) -> None:
        self.duration: TwoFactorDuration = TwoFactorDuration.EveryLogin

    @abc.abstractmethod
    def get_channels(self) -> Sequence[TwoFactorChannelInfo]:
        pass

    @abc.abstractmethod
    def get_channel_push_actions(self, channel_uid: bytes) -> Sequence[TwoFactorPushAction]:
        pass

    @abc.abstractmethod
    def send_push(self, channel_uid: bytes, action: TwoFactorPushAction) -> None:
        pass

    @abc.abstractmethod
    def send_code(self, channel_uid: bytes, code: str) -> None:
        pass

    @abc.abstractmethod
    def resume(self) -> None:
        pass


class LoginStepSsoDataKey(ILoginStep, abc.ABC):
    @staticmethod
    def get_channels() -> Sequence[DataKeyShareChannel]:
        return DataKeyShareChannel.KeeperPush, DataKeyShareChannel.AdminApproval

    @abc.abstractmethod
    def request_data_key(self, channel: DataKeyShareChannel) -> None:
        pass

    @abc.abstractmethod
    def resume(self) -> None:
        pass


class LoginStepPassword(ILoginStep, abc.ABC):
    @property
    @abc.abstractmethod
    def username(self) -> str:
        pass

    @abc.abstractmethod
    def verify_password(self, password: str) -> None:
        pass

    @abc.abstractmethod
    def verify_biometric_key(self, biometric_key: bytes) -> None:
        pass


class LoginStepError(ILoginStep):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message

    def is_final(self) -> bool:
        return True


class LoginStepSsoToken(ILoginStep, abc.ABC):
    @abc.abstractmethod
    def set_sso_token(self, token: str) -> None:
        pass

    @abc.abstractmethod
    def login_with_password(self) -> None:
        pass

    @property
    @abc.abstractmethod
    def is_cloud_sso(self) -> bool:
        pass

    @property
    @abc.abstractmethod
    def is_provider_login(self) -> bool:
        pass

    @property
    @abc.abstractmethod
    def login_name(self) -> str:
        pass

    @property
    @abc.abstractmethod
    def sso_login_url(self) -> str:
        pass


class AccountAuthType(enum.Enum):
    Regular = 1
    CloudSso = 2
    OnsiteSso = 3
    ManagedCompany = 4


class LoginContext:
    def __init__(self) -> None:
        self.username = ''
        self.passwords: List[str] = []
        self.clone_code = b''
        self.device_token = b''
        self.device_private_key: Optional[ec.EllipticCurvePrivateKey] = None
        self.message_session_uid: bytes = crypto.get_random_bytes(16)
        self.account_type: AccountAuthType = AccountAuthType.Regular
        self.sso_login_info: Optional[keeper_auth.SsoLoginInfo] = None
        self.biometric: Optional[bool] = False


class LoginAuth:
    def __init__(self, keeper_endpoint: endpoint.KeeperEndpoint) -> None:
        self.keeper_endpoint = keeper_endpoint
        self._context: Optional[LoginContext] = None
        self.alternate_password = False
        self.resume_session = False
        self.on_next_step: Optional[Callable[[], None]] = None
        self.on_region_changed: Optional[Callable[[str], None]] = None
        self._login_step: ILoginStep = LoginStepReady()
        self.push_notifications: Optional[notifications.FanOut[Dict[str, Any]]] = None

    @property
    def context(self):
        return self._context

    @property
    def login_step(self):
        return self._login_step

    @login_step.setter
    def login_step(self, value: ILoginStep) -> None:
        if isinstance(value, ILoginStep):
            if self._login_step:
                self._login_step.close()
            self._login_step = value
            if self.on_next_step:
                self.on_next_step()

    def execute_rest(self, rest_endpoint: str, request: Optional[endpoint.TRQ],
                     response_type: Optional[Type[endpoint.TRS]] = None) -> Optional[endpoint.TRS]:
        return self.keeper_endpoint.execute_rest(rest_endpoint, request, response_type)

    def login(self, username: str, *passwords: str) -> None:
        self._context = LoginContext()
        self.context.username = configuration.adjust_username(username)
        self.context.passwords.extend(passwords)
        config = self.keeper_endpoint.get_configuration_storage().get()
        uc = config.users().get(self.context.username)
        if uc:
            pwd = uc.password
            if pwd:
                self.context.passwords.append(pwd)
            us = uc.server
            if us:
                if us != self.keeper_endpoint.server:
                    self.keeper_endpoint.server = us
        try:
            try:
                _ensure_device_token_loaded(self)
                _start_login(self)
            except errors.RegionRedirectError as rr:
                _redirect_to_region(self, rr.region_host)
                _ensure_device_token_loaded(self)
                _start_login(self)
        except errors.KeeperApiError as kae:
            self.login_step = LoginStepError(kae.result_code, kae.message)
        except Exception as e:
            self.login_step = LoginStepError('unknown_error', str(e))

    def close(self) -> None:
        self.login_step = LoginStepReady()
        self._context = None

        if self.push_notifications:
            if not self.push_notifications.is_completed:
                self.push_notifications.shutdown()
            self.push_notifications = None


class LoginStepReady(ILoginStep):
    pass


class LoginStepConnected(ILoginStep, abc.ABC):
    @abc.abstractmethod
    def take_keeper_auth(self) -> keeper_auth.KeeperAuth:
        pass

    def is_final(self):
        return True


@dataclasses.dataclass
class TwoFactorChannelMapping:
    sdk: TwoFactorChannel
    proto: APIRequest_pb2.TwoFactorChannelType
    value: APIRequest_pb2.TwoFactorValueType


TwoFactorChannels: List[TwoFactorChannelMapping] = [
    TwoFactorChannelMapping(sdk=TwoFactorChannel.Authenticator, proto=APIRequest_pb2.TWO_FA_CT_TOTP,
                            value=APIRequest_pb2.TWO_FA_CODE_TOTP),
    TwoFactorChannelMapping(sdk=TwoFactorChannel.TextMessage, proto=APIRequest_pb2.TWO_FA_CT_SMS,
                            value=APIRequest_pb2.TWO_FA_CODE_SMS),
    TwoFactorChannelMapping(sdk=TwoFactorChannel.DuoSecurity, proto=APIRequest_pb2.TWO_FA_CT_DUO,
                            value=APIRequest_pb2.TWO_FA_CODE_DUO),
    TwoFactorChannelMapping(sdk=TwoFactorChannel.RSASecurID, proto=APIRequest_pb2.TWO_FA_CT_RSA,
                            value=APIRequest_pb2.TWO_FA_CODE_RSA),
    TwoFactorChannelMapping(sdk=TwoFactorChannel.SecurityKey, proto=APIRequest_pb2.TWO_FA_CT_WEBAUTHN,
                            value=APIRequest_pb2.TWO_FA_RESP_WEBAUTHN),
    TwoFactorChannelMapping(sdk=TwoFactorChannel.KeeperDNA, proto=APIRequest_pb2.TWO_FA_CT_DNA,
                            value=APIRequest_pb2.TWO_FA_CODE_DNA),
    TwoFactorChannelMapping(sdk=TwoFactorChannel.Backup, proto=APIRequest_pb2.TWO_FA_CT_BACKUP,
                            value=APIRequest_pb2.TWO_FA_CODE_NONE),
]


def _channel_keeper_to_sdk(channel_type: APIRequest_pb2.TwoFactorChannelType) -> TwoFactorChannel:
    return next((x.sdk for x in TwoFactorChannels if x.proto == channel_type), TwoFactorChannel.Other)


def tfa_value_type_for_channel(channel_type: TwoFactorChannel) -> APIRequest_pb2.TwoFactorValueType:
    return next((x.value for x in TwoFactorChannels if x.sdk == channel_type), APIRequest_pb2.TWO_FA_CODE_NONE)


@dataclasses.dataclass
class TwoFactorPushMapping:
    sdk: TwoFactorPushAction
    proto: APIRequest_pb2.TwoFactorPushType


TwoFactorPushes: List[TwoFactorPushMapping] = [
    TwoFactorPushMapping(sdk=TwoFactorPushAction.DuoPush, proto=APIRequest_pb2.TWO_FA_PUSH_DUO_PUSH),
    TwoFactorPushMapping(sdk=TwoFactorPushAction.DuoTextMessage, proto=APIRequest_pb2.TWO_FA_PUSH_DUO_TEXT),
    TwoFactorPushMapping(sdk=TwoFactorPushAction.DuoVoiceCall, proto=APIRequest_pb2.TWO_FA_PUSH_DUO_CALL),
    TwoFactorPushMapping(sdk=TwoFactorPushAction.TextMessage, proto=APIRequest_pb2.TWO_FA_PUSH_SMS),
    TwoFactorPushMapping(sdk=TwoFactorPushAction.KeeperDna, proto=APIRequest_pb2.TWO_FA_PUSH_KEEPER),
]


def tfa_action_sdk_to_keeper(action: TwoFactorPushAction) -> APIRequest_pb2.TwoFactorPushType:
    return next((x.proto for x in TwoFactorPushes if x.sdk == action), APIRequest_pb2.TWO_FA_PUSH_NONE)


def duo_capability_to_sdk(capability: str) -> Optional[TwoFactorPushAction]:
    if capability == 'push':
        return TwoFactorPushAction.DuoPush
    if capability == 'sms':
        return TwoFactorPushAction.DuoTextMessage
    if capability == 'phone':
        return TwoFactorPushAction.DuoVoiceCall
    return None


@dataclasses.dataclass
class DurationMapping:
    sdk: TwoFactorDuration
    proto: APIRequest_pb2.TwoFactorExpiration


Durations: List[DurationMapping] = [
    DurationMapping(sdk=TwoFactorDuration.EveryLogin, proto=APIRequest_pb2.TWO_FA_EXP_IMMEDIATELY),
    DurationMapping(sdk=TwoFactorDuration.EveryLogin, proto=APIRequest_pb2.TWO_FA_EXP_5_MINUTES),
    DurationMapping(sdk=TwoFactorDuration.Every12Hours, proto=APIRequest_pb2.TWO_FA_EXP_12_HOURS),
    DurationMapping(sdk=TwoFactorDuration.EveryDay, proto=APIRequest_pb2.TWO_FA_EXP_24_HOURS),
    DurationMapping(sdk=TwoFactorDuration.Every30Days, proto=APIRequest_pb2.TWO_FA_EXP_30_DAYS),
    DurationMapping(sdk=TwoFactorDuration.Forever, proto=APIRequest_pb2.TWO_FA_EXP_NEVER),
]


def _duration_keeper_to_sdk(duration: APIRequest_pb2.TwoFactorExpiration) -> TwoFactorDuration:
    return next((x.sdk for x in Durations if x.proto == duration), TwoFactorDuration.EveryLogin)


def _duration_sdk_to_keeper(duration: TwoFactorDuration) -> APIRequest_pb2.TwoFactorExpiration:
    return next((x.proto for x in Durations if x.sdk == duration), APIRequest_pb2.TWO_FA_EXP_IMMEDIATELY)


def _tfa_channel_info_keeper_to_sdk(channel_info: APIRequest_pb2.TwoFactorChannelInfo) -> TwoFactorChannelInfo:
    info = TwoFactorChannelInfo()
    info.channel_type = _channel_keeper_to_sdk(channel_info.channelType)
    info.channel_uid = channel_info.channel_uid
    info.channel_name = channel_info.channelName
    info.phone = channel_info.phoneNumber
    info.max_expiration = _duration_keeper_to_sdk(channel_info.maxExpiration)
    info.challenge = channel_info.challenge
    return info


def _ensure_device_token_loaded(login: LoginAuth) -> None:
    logger = utils.get_logger()
    attempt = 0

    context = login.context
    context.clone_code = b''
    config = login.keeper_endpoint.get_configuration_storage().get()
    server = login.keeper_endpoint.server
    while attempt < 6:
        attempt += 1

        if context.device_token and context.device_private_key:
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
                config.devices().put(dc)
            try:
                _register_device_in_region(login, dc)
                dc = configuration.DeviceConfiguration(dc)
                dsc = configuration.DeviceServerConfiguration(server)
                dc.get_server_info().put(dsc)
                login.keeper_endpoint.get_configuration_storage().put(config)
                return
            except Exception as e:
                logger.debug('Register device in region error: %s', e)
                config.devices().delete(device_token)
                context.device_token = None
                context.device_private_key = None
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
                except Exception as e:
                    logger.debug('Load device key error: %s', e)
                    config.devices().delete(dc.device_token)
            else:
                dc = _register_device(login)
                context.device_token = utils.base64_url_decode(dc.device_token)
                context.device_private_key = crypto.load_ec_private_key(utils.base64_url_decode(dc.private_key))
                config.devices().put(dc)
                login.keeper_endpoint.get_configuration_storage().put(config)
                return


def _register_device_in_region(login_auth: LoginAuth, device_config: configuration.IDeviceConfiguration) -> None:
    rq = APIRequest_pb2.RegisterDeviceInRegionRequest()
    rq.encryptedDeviceToken = utils.base64_url_decode(device_config.device_token)
    rq.clientVersion = login_auth.keeper_endpoint.client_version
    rq.deviceName = login_auth.keeper_endpoint.device_name
    private_key = utils.base64_url_decode(device_config.private_key)
    pk = crypto.load_ec_private_key(private_key)
    rq.devicePublicKey = crypto.unload_ec_public_key(pk.public_key())

    try:
        login_auth.execute_rest('authentication/register_device_in_region', rq)
    # except errors.KeeperApiError as kae:
    #     if 'exists' != kae.result_code:
    #         raise kae
    except errors.InvalidDeviceTokenError as idt:
        if 'public key already exists' != idt.message:
            raise idt


def _register_device(login_auth: LoginAuth) -> configuration.DeviceConfiguration:
    private_key, public_key = crypto.generate_ec_key()
    device_private_key = crypto.unload_ec_private_key(private_key)

    rq = APIRequest_pb2.DeviceRegistrationRequest()
    rq.clientVersion = login_auth.keeper_endpoint.client_version
    rq.deviceName = login_auth.keeper_endpoint.device_name
    rq.devicePublicKey = crypto.unload_ec_public_key(public_key)

    device = login_auth.execute_rest('authentication/register_device', rq, response_type=APIRequest_pb2.Device)
    assert device is not None
    dc = configuration.DeviceConfiguration(utils.base64_url_encode(device.encryptedDeviceToken))
    dc.private_key = utils.base64_url_encode(device_private_key)
    dsc = configuration.DeviceServerConfiguration(login_auth.keeper_endpoint.server)
    dc.get_server_info().put(dsc)
    return dc


def _start_login(login: LoginAuth, method: APIRequest_pb2.LoginMethod = APIRequest_pb2.EXISTING_ACCOUNT,
                 new_login: bool=False) -> None:
    if new_login:
        login.resume_session = False

    rq = APIRequest_pb2.StartLoginRequest()
    rq.clientVersion = login.keeper_endpoint.client_version
    rq.encryptedDeviceToken = login.context.device_token
    rq.loginType = APIRequest_pb2.ALTERNATE if login.alternate_password else APIRequest_pb2.NORMAL
    rq.loginMethod = method
    rq.messageSessionUid = login.context.message_session_uid
    rq.forceNewLogin = new_login

    if login.context.clone_code and login.resume_session and method == APIRequest_pb2.EXISTING_ACCOUNT:
        rq.cloneCode = login.context.clone_code
    else:
        rq.username = login.context.username

    _process_start_login(login, rq)


def _resume_login(login: LoginAuth, login_token: bytes,
                  method: APIRequest_pb2.LoginMethod = APIRequest_pb2.EXISTING_ACCOUNT) -> None:
    rq = APIRequest_pb2.StartLoginRequest()
    rq.clientVersion = login.keeper_endpoint.client_version
    rq.encryptedDeviceToken = login.context.device_token
    rq.encryptedLoginToken = login_token
    rq.username = login.context.username
    rq.loginMethod = method
    rq.messageSessionUid = login.context.message_session_uid

    _process_start_login(login, rq)


def _process_start_login(login: LoginAuth, request: APIRequest_pb2.StartLoginRequest) -> None:
    response = login.execute_rest(
        'authentication/start_login', request, response_type=APIRequest_pb2.LoginResponse)
    assert response is not None
    if response.loginState == APIRequest_pb2.LOGGED_IN:
        assert login.context.device_private_key is not None

        def decrypt_with_device_key(encrypted_data_key):
            return crypto.decrypt_ec(encrypted_data_key, login.context.device_private_key)
        _on_logged_in(login, response, decrypt_with_device_key)
        if login.context.biometric:
            utils.get_logger().info('Successfully authenticated with Biometric Login')
        elif login.context.sso_login_info is None:
            utils.get_logger().info('Successfully authenticated with Persistent Login')
        else:
            utils.get_logger().info('Successfully authenticated with %s SSO',
                                    'Cloud' if login.context.sso_login_info.is_cloud else 'On-Premises')
    elif response.loginState == APIRequest_pb2.REQUIRES_USERNAME:
        _resume_login(login, response.encryptedLoginToken)
    elif response.loginState == APIRequest_pb2.REGION_REDIRECT:
        raise errors.RegionRedirectError(response.stateSpecificValue, '')
    elif response.loginState == APIRequest_pb2.DEVICE_APPROVAL_REQUIRED:
        _on_device_approval_required(login, response)
    elif response.loginState == APIRequest_pb2.REQUIRES_2FA:
        _on_requires_2fa(login, response)
    elif response.loginState == APIRequest_pb2.REQUIRES_AUTH_HASH:
        _on_requires_auth_hash(login, response)
    elif response.loginState in (APIRequest_pb2.REDIRECT_CLOUD_SSO, APIRequest_pb2.REDIRECT_ONSITE_SSO):
        sso_login_info = keeper_auth.SsoLoginInfo()
        sso_login_info.is_cloud = response.loginState == APIRequest_pb2.REDIRECT_CLOUD_SSO
        sso_login_info.sso_url = response.url
        _on_sso_redirect(login, sso_login_info, response.encryptedLoginToken)
    elif response.loginState == APIRequest_pb2.REQUIRES_DEVICE_ENCRYPTED_DATA_KEY:
        _on_request_data_key(login, response.encryptedLoginToken)
    elif response.loginState in (APIRequest_pb2.DEVICE_ACCOUNT_LOCKED, APIRequest_pb2.DEVICE_LOCKED):
        raise errors.InvalidDeviceTokenError(response.message)
    else:
        state = APIRequest_pb2.LoginState.Name(response.loginState)  # type: ignore
        message = f'State {state}: Not implemented: {response.message}'
        login.login_step = LoginStepError('not_implemented', message)


def _store_configuration(login: LoginAuth) -> None:
    config = login.keeper_endpoint.get_configuration_storage().get()
    config.last_login = login.context.username
    config.last_server = login.keeper_endpoint.server

    device_token = utils.base64_url_encode(login.context.device_token)
    iuc = config.users().get(login.context.username)
    uc: Optional[configuration.UserConfiguration] = None
    if not iuc:
        uc = configuration.UserConfiguration(login.context.username)
        uc.server = login.keeper_endpoint.server
        uc.last_device = configuration.UserDeviceConfiguration(device_token)
    else:
        udc = iuc.last_device
        if not udc or udc.device_token != device_token:
            uc = configuration.UserConfiguration(iuc)
            uc.last_device = configuration.UserDeviceConfiguration(device_token)
    if uc:
        config.users().put(uc)

    isc = config.servers().get(login.keeper_endpoint.server)
    sc: Optional[configuration.ServerConfiguration] = None
    if not isc:
        sc = configuration.ServerConfiguration(login.keeper_endpoint.server)
        sc.server_key_id = login.keeper_endpoint.server_key_id
    elif isc.server_key_id != login.keeper_endpoint.server_key_id:
        sc = configuration.ServerConfiguration(login.keeper_endpoint.server)
        sc.server_key_id = login.keeper_endpoint.server_key_id
    if sc:
        config.servers().put(sc)

    idc = config.devices().get(device_token)
    if not idc:
        dc = configuration.DeviceConfiguration(device_token)
        assert login.context.device_private_key is not None
        dc.private_key = crypto.unload_ec_private_key(login.context.device_private_key)
    else:
        dc = configuration.DeviceConfiguration(idc)
    idsc = dc.get_server_info().get(login.keeper_endpoint.server)
    dsc = configuration.DeviceServerConfiguration(idsc if idsc else login.keeper_endpoint.server)
    dsc.clone_code = utils.base64_url_encode(login.context.clone_code)
    dc.get_server_info().put(dsc)
    config.devices().put(dc)

    login.keeper_endpoint.get_configuration_storage().put(config)


def _redirect_to_region(login: LoginAuth, region_host: str) -> None:
    keeper_endpoint = login.keeper_endpoint
    keeper_endpoint.server = region_host
    if login.on_region_changed:
        login.on_region_changed(region_host)


def _ensure_push_notifications(login: LoginAuth) -> None:
    if login.push_notifications:
        return

    keeper_pushes = push_notifications.KeeperPushNotifications()
    transmission_key = utils.generate_aes_key()
    url = login.keeper_endpoint.get_push_url(transmission_key, login.context.device_token, login.context.message_session_uid)
    keeper_pushes.connect_to_push_channel(url, transmission_key)
    login.push_notifications = keeper_pushes


def _get_session_token_scope(session_token_type: APIRequest_pb2.SessionTokenType) -> keeper_auth.SessionTokenRestriction:
    if session_token_type == APIRequest_pb2.SessionTokenType.ACCOUNT_RECOVERY:
        return keeper_auth.SessionTokenRestriction.AccountRecovery
    if session_token_type == APIRequest_pb2.SessionTokenType.SHARE_ACCOUNT:
        return keeper_auth.SessionTokenRestriction.ShareAccount
    if session_token_type == APIRequest_pb2.SessionTokenType.ACCEPT_INVITE:
        return keeper_auth.SessionTokenRestriction.AcceptInvite
    if session_token_type in [APIRequest_pb2.SessionTokenType.PURCHASE, APIRequest_pb2.SessionTokenType.RESTRICT]:
        return keeper_auth.SessionTokenRestriction.AccountExpired
    return keeper_auth.SessionTokenRestriction.Unrestricted


def _on_device_approval_required(login: LoginAuth, response: APIRequest_pb2.LoginResponse) -> None:
    _ensure_push_notifications(login)
    login.login_step = _DeviceApprovalStep(login, response.encryptedLoginToken)


def _on_request_data_key(login: LoginAuth, login_token: bytes) -> None:
    _ensure_push_notifications(login)
    login.login_step = _SsoDataKeyLoginStep(login, login_token)


def _on_requires_auth_hash(login: LoginAuth, response: APIRequest_pb2.LoginResponse) -> None:
    if len(response.salt) == 0:
        login.login_step = LoginStepError(
            'account-recovery-required',
            'Your account requires account recovery in order to use a Master Password authentication method.\n' +
            'Account recovery (Forgot Password) is available in the Web Vault or Enterprise Console.')
        return

    salt = next((x for x in response.salt
                 if x.name.lower() == ('alternate' if login.alternate_password else 'master')), None)
    if not salt:
        salt = response.salt[0]

    password_step = _PasswordLoginStep(login, response.encryptedLoginToken, salt)
    while login.context.passwords:
        password = login.context.passwords.pop()
        if password:
            try:
                password_step.verify_password(password)
                if not isinstance(login.login_step, LoginStepPassword):
                    return
            except Exception as e:
                utils.get_logger().debug('Cannot verify a provided password: %s', e)
    login.login_step = password_step


def _on_requires_2fa(login: LoginAuth, response: APIRequest_pb2.LoginResponse):
    _ensure_push_notifications(login)
    login.login_step = _TwoFactorStep(login, response.encryptedLoginToken, list(response.channels))


def _post_login(logged_auth: keeper_auth.KeeperAuth) -> None:
    rs = auth_utils.load_account_summary(logged_auth)

    assert rs is not None
    if rs.license.enterpriseId:
        logged_auth.auth_context.enterprise_id = rs.license.enterpriseId
    logged_auth.auth_context.forbid_rsa = rs.forbidKeyType2
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

    if logged_auth.auth_context.session_token_restriction == keeper_auth.SessionTokenRestriction.Unrestricted:
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


def _on_logged_in(login: LoginAuth, response: APIRequest_pb2.LoginResponse,
                  on_decrypt_data_key: Callable[[bytes], bytes]) -> None:
    login.context.username = response.primaryUsername
    login.context.clone_code = response.cloneCode
    _store_configuration(login)

    auth_context = keeper_auth.AuthContext()
    auth_context.username = login.context.username
    auth_context.account_uid = response.accountUid
    auth_context.session_token = response.encryptedSessionToken
    auth_context.session_token_restriction = _get_session_token_scope(response.sessionTokenType)
    auth_context.data_key = on_decrypt_data_key(response.encryptedDataKey)
    auth_context.sso_login_info = login.context.sso_login_info
    auth_context.device_token = login.context.device_token
    auth_context.device_private_key = login.context.device_private_key
    auth_context.message_session_uid = login.context.message_session_uid

    keeper_endpoint = login.keeper_endpoint
    # Create push_notifications if not provided (for testing or custom implementations)
    push_notif = login.push_notifications if login.push_notifications is not None else push_notifications.KeeperPushNotifications()
    logged_auth = keeper_auth.KeeperAuth(keeper_endpoint, auth_context, push_notifications=push_notif)
    _post_login(logged_auth)

    # Start push notifications if unrestricted and using KeeperPushNotifications
    if auth_context.session_token_restriction == keeper_auth.SessionTokenRestriction.Unrestricted:
        if isinstance(push_notif, push_notifications.KeeperPushNotifications):
            push_notif.start_push_server(logged_auth)

    login.login_step = _ConnectedLoginStep(logged_auth)
    logged_auth.on_idle()


def _on_sso_redirect(login: LoginAuth, sso_info: keeper_auth.SsoLoginInfo, login_token: Optional[bytes]=None) -> None:
    login.context.account_type = AccountAuthType.CloudSso if sso_info.is_cloud else AccountAuthType.OnsiteSso

    login.login_step = _CloudSsoTokenLoginStep(login, sso_info, login_token) \
        if sso_info.is_cloud else _OnPremisesSsoTokenLoginStep(login, sso_info, login_token)


class _ConnectedLoginStep(LoginStepConnected):
    def __init__(self, auth: keeper_auth.KeeperAuth) -> None:
        self._keeper_auth: Optional[keeper_auth.KeeperAuth] = auth

    def take_keeper_auth(self):
        if self._keeper_auth:
            auth = self._keeper_auth
            self._keeper_auth = None
            return auth
        else:
            raise ValueError('Already taken')


class _DeviceApprovalStep(LoginStepDeviceApproval):
    def __init__(self, login: LoginAuth, login_token: bytes):
        self._login = login
        self._login_token = login_token
        self._email_sent = False
        if login.push_notifications:
            login.push_notifications.register_callback(self.push_handler)

    def push_handler(self, event: Dict[str, Any]):
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
            _resume_login(self._login, token)

        return False

    def send_push(self, channel: DeviceApprovalChannel) -> None:
        if channel == DeviceApprovalChannel.Email:
            rq_email = APIRequest_pb2.DeviceVerificationRequest()
            rq_email.username = self._login.context.username
            rq_email.clientVersion = self._login.keeper_endpoint.client_version
            rq_email.encryptedDeviceToken = self._login.context.device_token
            rq_email.messageSessionUid = self._login.context.message_session_uid
            rq_email.verificationChannel = 'email_resend' if self._email_sent else 'email'

            self._login.execute_rest('authentication/request_device_verification', rq_email)
            self._email_sent = True
        elif channel in {DeviceApprovalChannel.KeeperPush, DeviceApprovalChannel.TwoFactor}:
            rq_tfa = APIRequest_pb2.TwoFactorSendPushRequest()
            rq_tfa.encryptedLoginToken = self._login_token
            rq_tfa.pushType = APIRequest_pb2.TwoFactorPushType.TWO_FA_PUSH_KEEPER \
                if channel == DeviceApprovalChannel.KeeperPush \
                else APIRequest_pb2.TwoFactorPushType.TWO_FA_PUSH_NONE

            self._login.execute_rest('authentication/2fa_send_push', rq_tfa)

    def send_code(self, channel: DeviceApprovalChannel, code: str) -> None:
        if channel == DeviceApprovalChannel.Email:
            rq_email = APIRequest_pb2.ValidateDeviceVerificationCodeRequest()
            rq_email.username = self._login.context.username
            rq_email.clientVersion = self._login.keeper_endpoint.client_version
            rq_email.encryptedDeviceToken = self._login.context.device_token
            rq_email.messageSessionUid = self._login.context.message_session_uid
            rq_email.verificationCode = code

            self._login.execute_rest('authentication/validate_device_verification_code', rq_email)
            _resume_login(self._login, self._login_token)

        elif channel == DeviceApprovalChannel.TwoFactor:
            rq_tfa = APIRequest_pb2.TwoFactorValidateRequest()
            rq_tfa.encryptedLoginToken = self._login_token
            rq_tfa.valueType = APIRequest_pb2.TWO_FA_CODE_NONE
            rq_tfa.value = code

            rs = self._login.execute_rest(
                'authentication/2fa_validate', rq_tfa, response_type=APIRequest_pb2.TwoFactorValidateResponse)
            _resume_login(self._login, rs.encryptedLoginToken if rs else self._login_token)

    def resume(self):
        if self._login.login_step is self:
            _resume_login(self._login, self._login_token)

    def close(self):
        if self._login.push_notifications:
            self._login.push_notifications.remove_callback(self.push_handler)


class _SsoDataKeyLoginStep(LoginStepSsoDataKey):
    def __init__(self, login: LoginAuth, login_token: bytes):
        super(_SsoDataKeyLoginStep, self).__init__()
        self._login = login
        self._login_token = login_token
        if login.push_notifications:
            login.push_notifications.register_callback(self.push_handler)

    def push_handler(self, event: Dict[str, Any]):
        if event.get('message', '') == 'device_approved':
            if event.get('approved', False):
                _resume_login(self._login, self._login_token)
        elif event.get('command', '') == 'device_verified':
            _resume_login(self._login, self._login_token)
        return False

    def request_data_key(self, channel: DataKeyShareChannel):
        if channel == DataKeyShareChannel.KeeperPush:
            rq_push = APIRequest_pb2.TwoFactorSendPushRequest()
            rq_push.pushType = APIRequest_pb2.TWO_FA_PUSH_KEEPER
            rq_push.encryptedLoginToken = self._login_token
            self._login.execute_rest('authentication/2fa_send_push', rq_push)
        elif channel == DataKeyShareChannel.AdminApproval:
            rq_admin = APIRequest_pb2.DeviceVerificationRequest()
            rq_admin.username = self._login.context.username
            rq_admin.clientVersion = self._login.keeper_endpoint.client_version
            rq_admin.encryptedDeviceToken = self._login.context.device_token
            rq_admin.messageSessionUid = self._login.context.message_session_uid
            rs = self._login.execute_rest('authentication/request_device_admin_approval', rq_admin,
                                          response_type=APIRequest_pb2.DeviceVerificationResponse)
            if rs and rs.deviceStatus == APIRequest_pb2.DEVICE_OK:
                _resume_login(self._login, self._login_token)

    def resume(self) -> None:
        if self._login.login_step is self:
            _resume_login(self._login, self._login_token)

    def close(self):
        if self._login.push_notifications:
            self._login.push_notifications.remove_callback(self.push_handler)


class _SsoTokenLoginStep(LoginStepSsoToken, abc.ABC):
    def __init__(self, login: LoginAuth, sso_info: keeper_auth.SsoLoginInfo, login_token: Optional[bytes]):
        super(_SsoTokenLoginStep, self).__init__()
        self._login = login
        self._sso_info = sso_info
        self._login_token = login_token
        self._login_url = ''

    @property
    def is_cloud_sso(self):
        return self._sso_info.is_cloud

    @property
    def is_provider_login(self):
        return False if self._login.context.username else True

    @property
    def login_name(self):
        if self._login.context.username:
            return self._login.context.username
        else:
            return self._sso_info.sso_provider

    @property
    def sso_login_url(self):
        return self._login_url

    def login_with_password(self):
        if self._login.context.username:
            self._login.alternate_password = True
            self._login.context.account_type = AccountAuthType.Regular
            _start_login(self._login)


class _CloudSsoTokenLoginStep(_SsoTokenLoginStep):
    def __init__(self, login: LoginAuth, sso_info: keeper_auth.SsoLoginInfo, login_token: Optional[bytes]):
        super(_CloudSsoTokenLoginStep, self).__init__(login, sso_info, login_token)
        self.transmission_key = utils.generate_aes_key()
        rq = ssocloud_pb2.SsoCloudRequest()
        rq.messageSessionUid = crypto.get_random_bytes(16)
        rq.clientVersion = login.keeper_endpoint.client_version
        rq.dest = 'commander'
        rq.forceLogin = False
        rq.detached = True
        api_rq = endpoint.prepare_api_request(
            login.keeper_endpoint.server_key_id, self.transmission_key, rq.SerializeToString())
        url_comp = list(urlparse(sso_info.sso_url))
        url_comp[4] = f'payload={quote_plus(utils.base64_url_encode(api_rq.SerializeToString()))}'
        self._login_url = urlunparse(url_comp)

    def set_sso_token(self, token_str: str):
        token = crypto.decrypt_aes_v2(utils.base64_url_decode(token_str), self.transmission_key)
        rs = ssocloud_pb2.SsoCloudResponse()
        rs.ParseFromString(token)
        self._login.context.username = rs.email
        self._sso_info.sso_provider = rs.providerName
        self._sso_info.idp_session_id = rs.idpSessionId
        self._login.context.sso_login_info = self._sso_info

        _ensure_device_token_loaded(self._login)
        lt = rs.encryptedLoginToken or self._login_token
        if lt:
            _resume_login(self._login, lt, method=APIRequest_pb2.AFTER_SSO)
        else:
            _start_login(self._login, method=APIRequest_pb2.AFTER_SSO, new_login=False)


class _OnPremisesSsoTokenLoginStep(_SsoTokenLoginStep):
    def __init__(self, login: LoginAuth, sso_info: keeper_auth.SsoLoginInfo, login_token: Optional[bytes]):
        super(_OnPremisesSsoTokenLoginStep, self).__init__(login, sso_info, login_token)
        self._private_key, self._public_key = crypto.generate_rsa_key()
        pub = crypto.unload_rsa_public_key(self._public_key)
        url_comp = list(urlparse(sso_info.sso_url))
        url_comp[3] = f'key={quote_plus(utils.base64_url_encode(pub))}&embedded'
        self._login_url = urlunparse(url_comp)

    def set_sso_token(self, token_str: str):
        token = json.loads(token_str)
        if 'email' in token:
            self._login.context.username = token['email']
        if 'provider_name' in token:
            self._sso_info.sso_provider = token['provider_name']
        if 'session_id' in token:
            self._sso_info.idp_session_id = token['session_id']
        for key in ('password', 'new_password'):
            if key in token:
                password = crypto.decrypt_rsa(utils.base64_url_decode(token[key]), self._private_key)
                self._login.context.passwords.append(password.decode())
        self._login.context.sso_login_info = self._sso_info

        lt = self._login_token
        if 'login_token' in token:
            lt = utils.base64_url_decode(token['login_token'])
        if lt:
            _resume_login(self._login, lt, method=APIRequest_pb2.AFTER_SSO)
        else:
            _start_login(self._login, method=APIRequest_pb2.AFTER_SSO, new_login=False)


class _PasswordLoginStep(LoginStepPassword):
    def __init__(self, login: LoginAuth, login_token: bytes, salt: APIRequest_pb2.Salt):
        super(_PasswordLoginStep, self).__init__()
        self._login = login
        self._login_token = login_token
        self._salt = salt

    @property
    def username(self) -> str:
        return self._login.context.username

    def verify_password(self, password):
        salt = self._salt.salt
        iterations = self._salt.iterations
        rq = APIRequest_pb2.ValidateAuthHashRequest()
        rq.passwordMethod = APIRequest_pb2.ENTERED
        rq.encryptedLoginToken = self._login_token
        rq.authResponse = crypto.derive_keyhash_v1(password, salt, iterations)

        rs = self._login.execute_rest(
            'authentication/validate_auth_hash', rq, response_type=APIRequest_pb2.LoginResponse)

        def decrypt_data_key(encrypted_data_key):
            if rs.encryptedDataKeyType == APIRequest_pb2.BY_ALTERNATE:
                key = crypto.derive_keyhash_v2('data_key', password, salt, iterations)
                return crypto.decrypt_aes_v2(encrypted_data_key, key)
            return utils.decrypt_encryption_params(encrypted_data_key, password)

        _on_logged_in(self._login, rs, decrypt_data_key)
        utils.get_logger().info('Successfully authenticated with Master Password')

    def verify_biometric_key(self, biometric_key):
        rq = APIRequest_pb2.ValidateAuthHashRequest()
        rq.passwordMethod = APIRequest_pb2.BIOMETRICS
        rq.encryptedLoginToken = self._login_token
        rq.authResponse = crypto.create_bio_auth_hash(biometric_key)

        rs = self._login.execute_rest(
            'authentication/validate_auth_hash', rq, response_type=APIRequest_pb2.LoginResponse)
        _on_logged_in(self._login, rs, lambda x: crypto.decrypt_aes_v2(x, biometric_key))
        utils.get_logger().info('Successfully authenticated with Biometrics')


class _TwoFactorStep(LoginStepTwoFactor):
    def __init__(self, login: LoginAuth, login_token: bytes,
                 channels: List[APIRequest_pb2.TwoFactorChannelInfo]) -> None:
        super(_TwoFactorStep, self).__init__()
        self._login = login
        self._login_token = login_token
        self._channels = channels
        self._last_push_channel_uid = None
        if login.push_notifications:
            login.push_notifications.register_callback(self.push_handler)

    def push_handler(self, event):
        if 'event' in event:
            command = event['event']
            if command == 'received_totp':
                if 'encryptedLoginToken' in event:
                    token = utils.base64_url_decode(event['encryptedLoginToken'])
                    _resume_login(self._login, token)
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
        self._login.execute_rest('authentication/2fa_send_push', rq)
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
        rs = self._login.execute_rest('authentication/2fa_validate', rq,
                                      response_type=APIRequest_pb2.TwoFactorValidateResponse)
        if rs:
            _resume_login(self._login, rs.encryptedLoginToken)

    def resume(self):
        if self._login.login_step is self:
            _resume_login(self._login, self._login_token)

    def get_channel_by_uid(self, channel_uid):
        return next((x for x in self._channels if x.channel_uid == channel_uid), None)

    def close(self):
        if self._login.push_notifications:
            self._login.push_notifications.remove_all()
