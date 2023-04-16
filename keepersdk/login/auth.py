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


class AuthContext:
    def __init__(self):          # type: () -> None
        self.username = ''
        self.session_token = b''
        self.session_token_restriction = SessionTokenRestriction.Unrestricted
        self.data_key = b''
        self.client_key = b''
        self.rsa_private_key = None              # type: Optional[RSAPrivateKey]
        self.ec_private_key = None               # type: Optional[EllipticCurvePrivateKey]
        self.ec_public_key = None                # type: Optional[EllipticCurvePublicKey]
        self.enterprise_rsa_public_key = None    # type: Optional[RSAPublicKey]
        self.enterprise_ec_public_key = None     # type: Optional[EllipticCurvePublicKey]
        self.is_enterprise_admin = False
        self.enforcements = {}                   # type: Dict[str, Any]
        self.settings = {}                       # type: Dict[str, Any]
        self.license = {}                        # type: Dict[str, Any]


class _AsyncExecutor:
    def __init__(self):   # type: () -> None
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=2)

    def execute_async(self, fn, *args, **kwargs):
        return self._executor.submit(fn, *args, **kwargs)

    def close(self):
        if self._executor:
            self._executor.shutdown(wait=False)
            self._executor = None


class KeeperAuth(_AsyncExecutor):
    def __init__(self, keeper_endpoint, auth_context):   # type: (endpoint.KeeperEndpoint, AuthContext) -> None
        _AsyncExecutor.__init__(self)
        self.keeper_endpoint = keeper_endpoint
        self.auth_context = auth_context
        self.push_notifications = None      # type: Optional[notifications.FanOut[Dict[str, Any]]]

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):  # type: () -> None
        if self.push_notifications and not self.push_notifications.is_completed:
            self.push_notifications.shutdown()

        _AsyncExecutor.close(self)

    def execute_auth_rest(self, rest_endpoint, request, response_type=None):
        # type: (str, Optional[endpoint.TRQ], Optional[Type[endpoint.TRS]]) -> Optional[endpoint.TRS]
        return self.keeper_endpoint.execute_rest(
            rest_endpoint, request, response_type=response_type, session_token=self.auth_context.session_token)

    def execute_auth_command(self, request, throw_on_error=True):
        # type: (Dict[str, Any], bool) -> Dict[str, Any]
        request['username'] = self.auth_context.username
        response = self.keeper_endpoint.v2_execute(request, session_token=self.auth_context.session_token)
        if response is None:
            raise errors.KeeperApiError('server_error', 'JSON response is empty')
        if throw_on_error and response.get('result') != 'success':
            raise errors.KeeperApiError(response.get('result_code'), response.get('message'))
        return response

    def execute_batch(self, requests):  # type: (List[Dict[str, Any]]) -> List[Dict[str, Any]]
        responses = []   # type: List[Dict[str, Any]]
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
