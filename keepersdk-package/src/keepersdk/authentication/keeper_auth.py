import concurrent.futures
import enum
import time
from typing import Optional, Dict, Any, List, Type

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from . import endpoint, notifications
from .. import errors


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

class _AsyncExecutor:
    def __init__(self) -> None:
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=2)

    def execute_async(self, fn, *args, **kwargs):
        return self._executor.submit(fn, *args, **kwargs)

    def close(self):
        if self._executor:
            self._executor.shutdown(wait=False)
            self._executor = None

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

class KeeperAuth(_AsyncExecutor):
    def __init__(self, keeper_endpoint: endpoint.KeeperEndpoint, auth_context: AuthContext) -> None:
        _AsyncExecutor.__init__(self)
        self.keeper_endpoint = keeper_endpoint
        self.auth_context = auth_context
        self.push_notifications: Optional[notifications.FanOut[Dict[str, Any]]] = None
        self._ttk: Optional[TimeToKeepalive] = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self) -> None:
        if self.push_notifications and not self.push_notifications.is_completed:
            self.push_notifications.shutdown()

        _AsyncExecutor.close(self)

    def _update_ttk(self):
        if self._ttk:
            self._ttk.update_time_of_last_activity()

    def on_idle(self):
        if self._ttk is None:
            self._ttk = TimeToKeepalive(self.auth_context)

        if self._ttk.check_keepalive():
            self.execute_auth_rest('keep_alive', None)

    def execute_auth_rest(self, rest_endpoint: str, request: Optional[endpoint.TRQ],
                          response_type: Optional[Type[endpoint.TRS]]=None) -> Optional[endpoint.TRS]:
        result = self.keeper_endpoint.execute_rest(
            rest_endpoint, request, response_type=response_type, session_token=self.auth_context.session_token)
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
            results = rs['results']
            if isinstance(results, list) and len(results) > 0:
                if len(results) < len(chunk):
                    queue = chunk[len(results):] + queue
                last_index = len(results) - 1
                last_status = results[last_index]
                if last_status.get('result') != 'success' and last_status.get('result_code') == 'throttled':
                    results.pop()
                    queue.insert(0, chunk[last_index])
                    sleep_interval = 10

                responses.extend(results)

        self._update_ttk()
        return responses
