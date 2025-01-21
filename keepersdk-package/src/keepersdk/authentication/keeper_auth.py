from __future__ import annotations

import abc
import asyncio
import enum
import json
import logging
import time
from typing import Optional, Dict, Any, List, Type, Set, Iterable

import attrs
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from google.protobuf.json_format import MessageToJson

from . import endpoint, notifications
from .. import errors, utils, crypto, background
from ..proto import APIRequest_pb2


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
        self.account_uid = b''
        self.session_token = b''
        self.session_token_restriction: SessionTokenRestriction = SessionTokenRestriction.Unrestricted
        self.data_key = b''
        self.client_key = b''
        self.rsa_private_key: Optional[RSAPrivateKey] = None
        self.ec_private_key: Optional[EllipticCurvePrivateKey] = None
        self.ec_public_key: Optional[EllipticCurvePublicKey] = None
        self.enterprise_rsa_public_key: Optional[RSAPublicKey] = None
        self.enterprise_ec_public_key: Optional[EllipticCurvePublicKey] = None
        self.is_enterprise_admin = False
        self.enterprise_id: Optional[int] = None
        self.enforcements: Dict[str, Any] = {}
        self.settings: Dict[str, Any] = {}
        self.license: Dict[str, Any] = {}
        self.sso_login_info: Optional[SsoLoginInfo] = None
        self.device_token = b''
        self.device_private_key: Optional[EllipticCurvePrivateKey] = None
        self.forbid_rsa = False
        self.session_token = b''
        self.message_session_uid = b''


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
        self._push_notifications = notifications.KeeperPushNotifications()
        self._ttk: Optional[TimeToKeepalive] = None
        self._key_cache: Optional[Dict[str, UserKeys]] = None
        self._use_pushes = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    @property
    def push_notifications(self) -> notifications.FanOut[Dict[str, Any]]:
        return self._push_notifications

    def close(self) -> None:
        if self.push_notifications and not self.push_notifications.is_completed:
            self.stop_pushes()

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
                                rsa = encrypted_key
                            elif key_type == 4:
                                assert self.auth_context.ec_private_key is not None
                                aes = crypto.decrypt_ec(encrypted_key, self.auth_context.ec_private_key)
                            elif key_type == -3:
                                aes = crypto.decrypt_aes_v2(encrypted_key, self.auth_context.data_key)
                            elif key_type == -4:
                                ec = encrypted_key
                            self._key_cache[team_uid] = UserKeys(aes=aes,rsa=rsa, ec=ec)
                        except Exception as e:
                            utils.get_logger().debug(e)

    def get_user_keys(self, username: str) -> Optional[UserKeys]:
        if self._key_cache:
            return self._key_cache.get(username)

    def get_team_keys(self, team_uid: str) -> Optional[UserKeys]:
        if self._key_cache:
            return self._key_cache.get(team_uid)

    async def _push_server_guard(self):
        transmission_key = utils.generate_aes_key()
        self._use_pushes = True
        try:
            while self._use_pushes:
                self.execute_auth_rest('keep_alive', None)
                url = self.keeper_endpoint.get_push_url(
                    transmission_key, self.auth_context.device_token, self.auth_context.message_session_uid)
                await self._push_notifications.main_loop(url, transmission_key, self.auth_context.session_token)
        except Exception as e:
            utils.get_logger().debug(e)
        finally:
            self._use_pushes = False
            
    @property
    def use_pushes(self) -> bool:
        return self._use_pushes

    def start_pushes(self):
        asyncio.run_coroutine_threadsafe(self._push_server_guard(), loop=background.get_loop())

    def stop_pushes(self):
        self._use_pushes = False
        self._push_notifications.shutdown()
