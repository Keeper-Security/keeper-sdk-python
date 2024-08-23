from typing import Iterator, Tuple, Optional, List, Dict, Union, Iterable

from . import endpoint, configuration, keeper_auth
from .. import crypto, utils, constants
from ..proto import breachwatch_pb2


class BreachWatch:
    def __init__(self, auth: keeper_auth.KeeperAuth) -> None:
        keeper_endpoint = auth.keeper_endpoint
        us_server = ''
        for region in constants.KEEPER_PUBLIC_HOSTS.values():
            if keeper_endpoint.server.endswith(region):
                us_server = keeper_endpoint.server.replace(region, constants.DEFAULT_KEEPER_SERVER)
                break
        if not us_server:
            us_server = keeper_endpoint.server

        self.endpoint = endpoint.KeeperEndpoint(configuration.InMemoryConfigurationStorage(), us_server)

        rs = auth.execute_auth_rest('breachwatch/initialize', None,
                                    response_type=breachwatch_pb2.BreachWatchTokenResponse)

        self.domain_token = b''
        self.email_token = b''
        self.password_token = b''

        if rs:
            if rs.clientEncrypted:
                enc_token = rs.breachWatchToken
                breach_watch_token = crypto.decrypt_aes_v2(enc_token, auth.auth_context.data_key)
            else:
                breach_watch_token = rs.breachWatchToken
                enc_token = crypto.encrypt_aes_v2(breach_watch_token, auth.auth_context.data_key)
                rq = breachwatch_pb2.BreachWatchTokenRequest()
                rq.breachWatchToken = enc_token
                auth.execute_auth_rest('breachwatch/save_token', rq)

            token_rq = breachwatch_pb2.BreachWatchTokenRequest()
            token_rq.breachWatchToken = breach_watch_token
            token_rs = auth.execute_auth_rest('breachwatch/anonymize_token', token_rq, response_type=breachwatch_pb2.AnonymizedTokenResponse)
            assert token_rs is not None
            self.domain_token = token_rs.domainToken
            self.email_token = token_rs.emailToken
            self.password_token = token_rs.passwordToken

        self.send_audit_events = False

    def scan_passwords(self,
                       passwords: Iterable[Union[str, Tuple[str, Optional[bytes]]]]
                       ) -> Iterator[Tuple[str, Optional[breachwatch_pb2.HashStatus]]]:
        logger = utils.get_logger()
        results: Dict[str, breachwatch_pb2.HashStatus] = {}
        bw_hashes: Dict[bytes, str] = {}
        bw_euids: Dict[bytes, bytes] = {}
        for x in passwords:
            password: str
            euid: Optional[bytes] = None
            if isinstance(x, str):
                password = x
                euid = None
            elif isinstance(x, (tuple, list)) and len(x) == 2:
                password = x[0]
                if isinstance(x[1], bytes):
                    euid = x[1]
            else:
                logger.debug('Invalid password entry')
                continue

            score = utils.password_score(password)
            bw_hash = utils.breach_watch_hash(password)
            if score >= 40:
                bw_hashes[bw_hash] = password
                if euid:
                    bw_euids[bw_hash] = euid
            else:
                status = breachwatch_pb2.HashStatus()
                status.hash1 = bw_hash
                status.breachDetected = True
                results[password] = status
        if len(bw_hashes) > 0:
            logger.info('Breachwatch: %d password(s) to scan', len(bw_hashes))
            hashes: List[breachwatch_pb2.HashCheck] = []
            for bw_hash in bw_hashes:
                check = breachwatch_pb2.HashCheck()
                check.hash1 = bw_hash
                if bw_hash in bw_euids:
                    check.euid = bw_euids[bw_hash]
                hashes.append(check)

            while len(hashes) > 0:
                chunk = hashes[:500]
                hashes = hashes[500:]

                rq = breachwatch_pb2.BreachWatchStatusRequest()
                rq.anonymizedToken = self.password_token
                rq.hashCheck.extend(chunk)

                rs = self.endpoint.execute_rest(
                    'breachwatch/status', rq, response_type=breachwatch_pb2.BreachWatchStatusResponse)
                assert rs is not None
                for status in rs.hashStatus:
                    results[bw_hashes[status.hash1]] = status

        for password in results:
            yield password, results.get(password)

    def delete_euids(self, euids: List[bytes]):
        while euids:
            chunk = euids[:999]
            euids = euids[999:]
            rq = breachwatch_pb2.BreachWatchStatusRequest()
            rq.anonymizedToken = self.password_token
            rq.removedEuid.extend(chunk)
            self.endpoint.execute_rest('breachwatch/status', rq)
