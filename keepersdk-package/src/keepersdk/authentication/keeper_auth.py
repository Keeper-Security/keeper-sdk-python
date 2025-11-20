from __future__ import annotations

import abc
import enum
import json
import logging
import time
from typing import Optional, Dict, Any, List, Type, Set, Iterable, Union

import attrs
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from google.protobuf.json_format import MessageToJson, MessageToDict

from . import endpoint, notifications
from .. import errors, utils, crypto
from ..proto import AccountSummary_pb2, APIRequest_pb2, breachwatch_pb2, push_pb2


class IKeeperAuth(abc.ABC):
    @property
    @abc.abstractmethod
    def keeper_auth(self)-> KeeperAuth:
        pass


class SessionTokenRestriction(enum.IntFlag):
    Unrestricted = 1 << 0
    AccountRecovery = 1 << 1
    ShareAccount = 1 << 2
    AcceptInvite = 1 << 3
    AccountExpired = 1 << 4


class SsoLoginInfo:
    def __init__(self):
        self.is_cloud = False
        self.sso_provider = ''
        self.sso_url = ''
        self.idp_session_id = ''


@attrs.define(kw_only=True)
class UserKeys:
    aes: Optional[bytes] = None
    rsa: Optional[bytes] = None
    ec: Optional[bytes] = None


class AuthContext:
    def __init__(self) -> None:
        self.username = ''
        self.account_uid: bytes = b''
        self.session_token: bytes = b''
        self.session_token_restriction: SessionTokenRestriction = SessionTokenRestriction.Unrestricted
        self.data_key: bytes = b''
        self.client_key: bytes = b''
        self.rsa_private_key: Optional[RSAPrivateKey] = None
        self.ec_private_key: Optional[EllipticCurvePrivateKey] = None
        self.ec_public_key: Optional[EllipticCurvePublicKey] = None
        self.enterprise_rsa_public_key: Optional[RSAPublicKey] = None
        self.enterprise_ec_public_key: Optional[EllipticCurvePublicKey] = None
        self.is_enterprise_admin = False
        self.is_mc_superadmin = False
        self.enterprise_id: Optional[int] = None
        self.enforcements: Dict[str, Any] = {}
        self.settings: Dict[str, Any] = {}
        self.license: Dict[str, Any] = {}
        self.sso_login_info: Optional[SsoLoginInfo] = None
        self.device_token: bytes = b''
        self.device_private_key: Optional[EllipticCurvePrivateKey] = None
        self.forbid_rsa: bool = False
        self.message_session_uid: bytes = b''


class TimeToKeepalive:
    def __init__(self, auth_context: AuthContext):
        self.time_of_last_activity = time.time() / 60.0
        self._logout_timeout_min = 60
        lt = auth_context.settings.get('logoutTimer')
        if isinstance(lt, str):
            if lt.isdigit():
                lt = int(lt)
        if isinstance(lt, (int, float)):
            self._logout_timeout_min = int(lt / (1000 * 60))
        if 'longs' in auth_context.enforcements:
            longs = auth_context.enforcements['longs']
            timeout = next((x.get('value') for x in longs if x.get('key') == 'logout_timer_desktop'), None)
            if isinstance(timeout, (int, float)):
                self._logout_timeout_min = int(timeout)
        self.update_time_of_last_activity()

    def update_time_of_last_activity(self):
        self.time_of_last_activity = time.time() / 60.0

    def check_keepalive(self) -> bool:
        now = time.time() / 60.0
        return (now - self.time_of_last_activity) > (self._logout_timeout_min * 0.3)


class KeeperAuth:
    def __init__(self, keeper_endpoint: endpoint.KeeperEndpoint, auth_context: AuthContext) -> None:
        self.keeper_endpoint = keeper_endpoint
        self.auth_context = auth_context
        self.push_notifications: Optional[notifications.FanOut[Dict[str, Any]]] = None
        self._ttk: Optional[TimeToKeepalive] = None
        self._key_cache: Optional[Dict[str, UserKeys]] = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self) -> None:
        if self.push_notifications and not self.push_notifications.is_completed:
            self.push_notifications.shutdown()
        self.push_notifications = None

    def _update_ttk(self):
        if self._ttk:
            self._ttk.update_time_of_last_activity()

    def on_idle(self):
        if self._ttk is None:
            self._ttk = TimeToKeepalive(self.auth_context)

        if self._ttk.check_keepalive():
            self.execute_auth_rest('keep_alive', None)

    def execute_auth_rest(self, rest_endpoint: str,
                          request: Optional[endpoint.TRQ],
                          *,
                          response_type: Optional[Type[endpoint.TRS]]=None,
                          payload_version: Optional[int]=None
                          ) -> Optional[endpoint.TRS]:
        result = self.keeper_endpoint.execute_rest(
            rest_endpoint, request, response_type=response_type, session_token=self.auth_context.session_token,
            payload_version=payload_version)
        self._update_ttk()
        return result

    def execute_auth_command(self, request: Dict[str, Any], throw_on_error=True) -> Dict[str, Any]:
        request['username'] = self.auth_context.username
        response = self.keeper_endpoint.v2_execute(request, session_token=self.auth_context.session_token)
        if response is None:
            raise errors.KeeperApiError('server_error', 'JSON response is empty')
        if throw_on_error and response.get('result') != 'success':
            raise errors.KeeperApiError(response.get('result_code') or '', response.get('message') or '')
        self._update_ttk()
        return response

    def execute_batch(self, requests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        responses: List[Dict[str, Any]] = []
        if not requests:
            return responses

        sleep_interval = 0
        chunk_size = 200
        queue = requests.copy()
        while len(queue) > 0:
            if sleep_interval > 0:
                time.sleep(sleep_interval)
                sleep_interval = 0

            chunk = queue[:chunk_size]
            queue = queue[chunk_size:]
            rq = {
                'command': 'execute',
                'requests': chunk
            }
            rs = self.execute_auth_command(rq)
            results = rs.get('results')
            if isinstance(results, list) and len(results) > 0:
                error_status = results[-1]
                throttled = error_status.get('result') != 'success' and error_status.get('result_code') == 'throttled'
                if throttled:
                    sleep_interval = 10
                    results.pop()
                responses.extend(results)

                if len(results) < len(chunk):
                    queue = chunk[len(results):] + queue
        return responses

    def execute_router(self, path: str,  request: Optional[endpoint.TRQ], *,
                       response_type: Optional[Type[endpoint.TRS]]=None) -> Optional[endpoint.TRS]:
        logger = utils.get_logger()
        if logger.level <= logging.DEBUG:
            js = MessageToJson(request) if request else ''
            logger.debug('>>> [RQ] \"%s\": %s', path, js)
        payload = request.SerializeToString() if request else None
        rs_bytes = self.keeper_endpoint.execute_router_rest(
            path, session_token=self.auth_context.session_token, payload=payload)
        if response_type:
            response = response_type()
            if rs_bytes:
                response.ParseFromString(rs_bytes)
            if logger.level <= logging.DEBUG:
                js = MessageToJson(response)
                logger.debug('>>> [RS] \"%s\": %s', path, js)

            return response
        return None

    def execute_router_json(self, path: str,  request: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        logger = utils.get_logger()
        payload: Optional[bytes] = None
        if isinstance(request, dict):
            js = json.dumps(request)
            payload = js.encode('utf-8')
            if logger.level <= logging.DEBUG:
                logger.debug('>>> [RQ] \"%s\": %s', path, js)

        rs_bytes = self.keeper_endpoint.execute_router_rest(
            path, session_token=self.auth_context.session_token, payload=payload)
        if rs_bytes:
            response = json.loads(rs_bytes)
            if logger.level <= logging.DEBUG:
                logger.debug('>>> [RS] \"%s\": %s', path, rs_bytes.decode('utf-8'))

            return response

    def load_user_public_keys(self, emails: Iterable[str], send_invites: bool = False) -> Optional[List[str]]:
        s: Set[str] = set((x.casefold() for x in emails))
        if self._key_cache is not None:
            s.difference_update(self._key_cache.keys())
        if not s:
            return None

        public_key_rq = APIRequest_pb2.GetPublicKeysRequest()
        public_key_rq.usernames.extend(s)
        need_share_accept = []
        rs = self.execute_auth_rest(
            'vault/get_public_keys', public_key_rq, response_type=APIRequest_pb2.GetPublicKeysResponse)
        assert rs is not None
        if self._key_cache is None:
            self._key_cache = {}

        for pk in rs.keyResponses:
            email = pk.username
            if pk.errorCode in ['', 'success']:
                rsa = pk.publicKey
                ec = pk.publicEccKey
                self._key_cache[email] = UserKeys(rsa=rsa, ec=ec)
            elif pk.errorCode == 'no_active_share_exist':
                need_share_accept.append(pk.username)
        if len(need_share_accept) > 0 and send_invites:
            for email in need_share_accept:
                send_invite_rq = APIRequest_pb2.SendShareInviteRequest()
                send_invite_rq.email = email
                try:
                    self.execute_auth_rest('vault/send_share_invite', send_invite_rq)
                except Exception as e:
                    utils.get_logger().debug('Share invite failed: %s', e)
            return need_share_accept

    def load_team_keys(self, team_uids: Iterable[str]) -> None:
        s = set(team_uids)
        if self._key_cache is not None:
            s.difference_update(self._key_cache.keys())
        if not s:
            return

        if self._key_cache is None:
            self._key_cache = {}

        utils.get_logger().debug('Loading %d team keys', len(s))
        uids_to_load = list(s)

        while len(uids_to_load) > 0:
            uids = uids_to_load[:90]
            uids_to_load = uids_to_load[90:]
            rq = {
                'command': 'team_get_keys',
                'teams': uids
            }
            rs = self.execute_auth_command(rq)
            if 'keys' in rs:
                for tk in rs['keys']:
                    if 'key' in tk:
                        team_uid = tk['team_uid']
                        try:
                            aes: Optional[bytes] = None
                            rsa: Optional[bytes] = None
                            ec: Optional[bytes] = None
                            encrypted_key = utils.base64_url_decode(tk['key'])
                            key_type = tk['type']
                            if key_type == 1:
                                aes = crypto.decrypt_aes_v1(encrypted_key, self.auth_context.data_key)
                            elif key_type == 2:
                                assert self.auth_context.rsa_private_key is not None
                                aes = crypto.decrypt_rsa(encrypted_key, self.auth_context.rsa_private_key)
                            elif key_type == 3:
                                aes = crypto.decrypt_aes_v2(encrypted_key, self.auth_context.data_key)
                            elif key_type == 4:
                                assert self.auth_context.ec_private_key is not None
                                aes = crypto.decrypt_ec(encrypted_key, self.auth_context.ec_private_key)
                            elif key_type == -3:
                                rsa = encrypted_key
                            elif key_type == -1:
                                ec = encrypted_key
                            self._key_cache[team_uid] = UserKeys(aes=aes,rsa=rsa, ec=ec)
                        except Exception as e:
                            utils.get_logger().debug(e)

    def get_user_keys(self, username: str) -> Optional[UserKeys]:
        if self._key_cache:
            return self._key_cache.get(username)
        return None

    def get_team_keys(self, team_uid: str) -> Optional[UserKeys]:
        if self._key_cache:
            return self._key_cache.get(team_uid)
        return None

    def post_login(self) -> None:
        rs = load_account_summary(self)

        assert rs is not None
        if rs.license.enterpriseId:
            self.auth_context.enterprise_id = rs.license.enterpriseId
        self.auth_context.forbid_rsa = rs.forbidKeyType2
        self.auth_context.settings.update(MessageToDict(rs.settings))
        self.auth_context.license.update(MessageToDict(rs.license))
        enf = MessageToDict(rs.Enforcements)
        if 'strings' in enf:
            strs = {x['key']: x['value'] for x in enf['strings'] if 'key' in x and 'value' in x}
            self.auth_context.enforcements.update(strs)
        if 'booleans' in enf:
            bools = {x['key']: x.get('value', False) for x in enf['booleans'] if 'key' in x}
            self.auth_context.enforcements.update(bools)
        if 'longs' in enf:
            longs = {x['key']: x['value'] for x in enf['longs'] if 'key' in x and 'value' in x}
            self.auth_context.enforcements.update(longs)
        if 'jsons' in enf:
            jsons = {x['key']: x['value'] for x in enf['jsons'] if 'key' in x and 'value' in x}
            self.auth_context.enforcements.update(jsons)
        self.auth_context.is_enterprise_admin = rs.isEnterpriseAdmin
        if rs.clientKey:
            self.auth_context.client_key = crypto.decrypt_aes_v1(rs.clientKey, self.auth_context.data_key)
        if rs.keysInfo.encryptedPrivateKey:
            rsa_private_key = crypto.decrypt_aes_v1(rs.keysInfo.encryptedPrivateKey, self.auth_context.data_key)
            self.auth_context.rsa_private_key = crypto.load_rsa_private_key(rsa_private_key)
        if rs.keysInfo.encryptedEccPrivateKey:
            ec_private_key = crypto.decrypt_aes_v2(rs.keysInfo.encryptedEccPrivateKey, self.auth_context.data_key)
            self.auth_context.ec_private_key = crypto.load_ec_private_key(ec_private_key)
        if rs.keysInfo.eccPublicKey:
            self.auth_context.ec_public_key = crypto.load_ec_public_key(rs.keysInfo.eccPublicKey)

        if self.auth_context.session_token_restriction == SessionTokenRestriction.Unrestricted:
            if self.auth_context.license.get('accountType', 0) == 2:
                try:
                    e_rs = self.execute_auth_rest('enterprise/get_enterprise_public_key', None,
                                                         response_type=breachwatch_pb2.EnterprisePublicKeyResponse)
                    assert e_rs is not None
                    if e_rs.enterpriseECCPublicKey:
                        self.auth_context.enterprise_ec_public_key = \
                            crypto.load_ec_public_key(e_rs.enterpriseECCPublicKey)
                    if e_rs.enterprisePublicKey:
                        self.auth_context.enterprise_rsa_public_key = \
                            crypto.load_rsa_public_key(e_rs.enterprisePublicKey)

                except Exception as e:
                    logger = utils.get_logger()
                    logger.debug('Get enterprise public key error: %s', e)


def load_account_summary(auth: KeeperAuth) -> AccountSummary_pb2.AccountSummaryElements:
    rq = AccountSummary_pb2.AccountSummaryRequest()
    rq.summaryVersion = 1
    account_summary = auth.execute_auth_rest('login/account_summary', rq,
                                             response_type=AccountSummary_pb2.AccountSummaryElements)
    assert account_summary is not None
    return account_summary


def register_data_key_for_device(auth: KeeperAuth) -> bool:
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

def rename_device(auth: KeeperAuth, new_name: str):
    rq = APIRequest_pb2.DeviceUpdateRequest()
    rq.clientVersion = auth.keeper_endpoint.client_version
    # rq.deviceStatus = proto.DEVICE_OK
    rq.deviceName = new_name
    rq.encryptedDeviceToken = auth.auth_context.device_token

    auth.execute_auth_rest('authentication/update_device', rq)


def set_user_setting(auth: KeeperAuth, name: str, value: str) -> None:
    # Available setting names:
    #   - logout_timer
    #   - persistent_login
    #   - ip_disable_auto_approve

    rq = APIRequest_pb2.UserSettingRequest()
    rq.setting = name
    rq.value = value
    auth.execute_auth_rest('setting/set_user_setting', rq)


class KeeperPushNotifications(notifications.BasePushNotifications):
    def __init__(self, auth: KeeperAuth) -> None:
        super().__init__()
        self.auth: KeeperAuth = auth
        self.transmission_key = utils.generate_aes_key()

    def on_messaged_received(self, message: Union[str, bytes]):
        if isinstance(message, bytes):
            if self.transmission_key:
                decrypted_data = crypto.decrypt_aes_v2(message, self.transmission_key)
            else:
                decrypted_data = message
            rs = push_pb2.WssClientResponse()
            rs.ParseFromString(decrypted_data)
            self.push(json.loads(rs.message))

    async def on_connected(self):
        await self.send_message(utils.base64_url_encode(self.auth.auth_context.session_token))

    def get_connection_parameters(self) -> Optional[notifications.PushConnectionParameters]:
        self.auth.execute_auth_rest('keep_alive', None)
        push_url = self.auth.keeper_endpoint.get_push_url(
            self.transmission_key, self.auth.auth_context.device_token, self.auth.auth_context.message_session_uid)
        params = notifications.PushConnectionParameters(url=push_url)
        return params