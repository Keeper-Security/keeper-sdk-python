#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import abc
import concurrent.futures
import enum
import time
from typing import Optional, Dict, Any, Type, TypeVar, List, Callable, Sequence

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from google.protobuf.message import Message

from . import configuration, endpoint, notifications
from .. import errors


class SessionTokenRestriction(enum.IntFlag):
    Unrestricted = 1 << 0
    AccountRecovery = 1 << 1
    ShareAccount = 1 << 2
    AcceptInvite = 1 << 3
    AccountExpired = 1 << 4


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


class SsoLoginInfo:
    def __init__(self):
        self.is_cloud = False
        self.sso_provider = ''
        self.sso_url = ''
        self.idp_session_id = ''


class AuthContext:
    def __init__(self):
        self.username = ''
        self.session_token = b''
        self.session_token_restriction = SessionTokenRestriction.Unrestricted
        self.data_key = b''
        self.client_key = b''
        self.rsa_private_key = None              # type: Optional[RSAPrivateKey]
        self.ec_private_key = None               # type: Optional[EllipticCurvePrivateKey]
        self.enterprise_rsa_public_key = None    # type: Optional[RSAPublicKey]
        self.enterprise_ec_public_key = None     # type: Optional[EllipticCurvePublicKey]
        self.is_enterprise_admin = False
        self.enforcements = {}   # type: Dict[str, Any]
        self.settings = {}       # type: Dict[str, Any]
        self.license = {}        # type: Dict[str, Any]


class AsyncExecutor:
    def __init__(self):
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=2)

    def execute_async(self, fn, *args, **kwargs):
        return self._executor.submit(fn, *args, **kwargs)

    def close(self):
        if self._executor:
            self._executor.shutdown(wait=False)
            self._executor = None


TRQ = TypeVar('TRQ', bound=Message)
TRS = TypeVar('TRS', bound=Message)


class KeeperAuth(AsyncExecutor):
    def __init__(self, keeper_endpoint, auth_context):
        AsyncExecutor.__init__(self)
        self.keeper_endpoint = keeper_endpoint
        self.auth_context = auth_context
        self.push_notifications = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):  # type: () -> None
        if self.push_notifications and not self.push_notifications.is_completed:
            self.push_notifications.shutdown()

        AsyncExecutor.close(self)

    def execute_auth_rest(self, rest_endpoint, request, response_type=None):
        # type: (str, Optional[TRQ], Optional[Type[TRS]]) -> Optional[TRS]
        return self.keeper_endpoint.execute_rest(
            rest_endpoint, request, response_type=response_type, session_token=self.auth_context.session_token)

    def execute_auth_command(self, request, throw_on_error=True):
        # type: (Dict[str, Any], bool) -> Dict[str, Any]
        request['username'] = self.auth_context.username
        response = self.keeper_endpoint.v2_execute(
            request, session_token=self.auth_context.session_token)
        if throw_on_error and response.get('result') != 'success':
            raise errors.KeeperApiError(response.get('result_code'), response.get('message'))
        return response

    def execute_batch(self, requests):  # type: (List[str, Any]) -> List[Dict[str, Any]]

        responses = []
        if not requests:
            return responses

        chunk_size = 98
        queue = requests.copy()
        while len(queue) > 0:
            chunk = queue[:chunk_size]
            queue = queue[chunk_size:]

            rq = {
                'command': 'execute',
                'requests': chunk
            }
            rs = self.execute_auth_command(rq)
            results = rs['results']
            if isinstance(results, list) and len(results) > 0:
                responses.extend(results)
                if len(results) < len(chunk):
                    queue = chunk[len(results):] + queue

                if len(results) > 50:
                    time.sleep(5)

        return responses


class ILoginStep(abc.ABC):
    def close(self):    # type: () -> None
        pass

    def is_final(self):  # type: () -> bool
        return False


class LoginAuth:
    def __init__(self, keeper_endpoint):   # type: (endpoint.KeeperEndpoint) -> None
        self.keeper_endpoint = keeper_endpoint
        self.alternate_password = False
        self.resume_session = False
        self.on_next_step = None          # type: Optional[Callable[[], None]]
        self.on_region_changed = None     # type: Optional[Callable[[str], None]]
        self._login_step = LoginStepReady()  # type: ILoginStep
        self.push_notifications = None    # type: Optional[notifications.FanOut[Dict[str, any]]]

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
        # type: (str, Optional[TRQ], Optional[Type[TRS]]) -> Optional[TRS]
        return self.keeper_endpoint.execute_rest(rest_endpoint, request, response_type)

    def login(self, username, *passwords):  # type: (str, str) -> None
        from . import auth_extensions
        login_context = auth_extensions.LoginContext()
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
                auth_extensions.ensure_device_token_loaded(self, login_context)
                auth_extensions.start_login(self, login_context)
            except errors.RegionRedirectError as rr:
                auth_extensions.redirect_to_region(self, rr.region_host)
                auth_extensions.ensure_device_token_loaded(self, login_context)
                auth_extensions.start_login(self, login_context)
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


class TwoFactorChannelInfo:
    def __init__(self):
        self.channel_type = TwoFactorChannel.Other    # type: TwoFactorChannel
        self.channel_name = ''   # type: str
        self.channel_uid = b''   # type: bytes
        self.phone = None        # type: Optional[str]
        self.max_expiration = TwoFactorDuration.EveryLogin   # type: TwoFactorDuration


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


class DataKeyShareChannel(enum.Enum):
    KeeperPush = enum.auto()
    AdminApproval = enum.auto()


class LoginStepSsoDataKey(ILoginStep, abc.ABC):
    def get_channels(self):   # type: () -> Sequence[DataKeyShareChannel]
        return DataKeyShareChannel.KeeperPush, DataKeyShareChannel.AdminApproval

    @abc.abstractmethod
    def request_data_key(self, channel):   # type: (DataKeyShareChannel) -> None
        pass
