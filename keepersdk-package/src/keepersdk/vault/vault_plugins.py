import abc
import base64
import enum
import json
import threading
from typing import Iterable, Dict, List, Optional, Any, Set
from urllib.parse import urlparse

from . import vault_data, vault_extensions, vault_record
from .. import utils, crypto
from ..authentication import keeper_auth, breachwatch
from ..proto import client_pb2, breachwatch_pb2, record_pb2, APIRequest_pb2


class IVaultData(abc.ABC):
    @property
    @abc.abstractmethod
    def vault_data(self)-> vault_data.VaultData:
        pass

    @abc.abstractmethod
    def request_sync(self)-> None:
        pass

    @property
    @abc.abstractmethod
    def lock(self)-> threading.Lock:
        pass


class IClientAuditEventPlugin(IVaultData, abc.ABC):
    @abc.abstractmethod
    def schedule_audit_event(self, name: str, **kwargs) -> None:
        pass

    @abc.abstractmethod
    def send_client_audit_events(self) -> None:
        pass


class PendingShareAction(enum.Enum):
    ACCEPT = 1
    DENY = 2
    IGNORE = 3

class IPendingSharePlugin(abc.ABC):
    @abc.abstractmethod
    def pending_shares(self) -> Iterable[str]:
        pass

    @abc.abstractmethod
    def set_pending_shares(self, shares: Iterable[str]) -> None:
        pass

    @abc.abstractmethod
    def resolve_pending_shares(self, shares: Iterable[str], action: PendingShareAction) -> None:
        pass

class IAuditDataPlugin(IVaultData, abc.ABC):
    @abc.abstractmethod
    def schedule_audit_data(self, record_uids: Iterable[str]) -> None:
        pass

    @abc.abstractmethod
    def send_audit_data(self) -> None:
        pass


class IBreachWatchPlugin(abc.ABC):
    @abc.abstractmethod
    def scan_and_store_record_status(self, record_uid: str,
                                     record_key: bytes,
                                     password: str) -> Optional[client_pb2.BWPassword]:
        pass


class ISecurityAuditPlugin(abc.ABC):
    @abc.abstractmethod
    def set_reused_passwords(self, count: int, revision: int) -> None:
        pass

    @abc.abstractmethod
    def send_reused_passwords(self):
        pass

    @abc.abstractmethod
    def schedule_security_data(self, record_uid: str, strength: int, url: Optional[str], bw_status: Optional[int]) -> None:
        pass

    @abc.abstractmethod
    def schedule_security_data_delete(self, record_uid: str) -> None:
        pass

    @abc.abstractmethod
    def send_security_audit_data(self) -> None:
        pass

# IMPLEMENTATIONS

class SecurityAuditPlugin(ISecurityAuditPlugin, IVaultData, keeper_auth.IKeeperAuth, abc.ABC):
    def __init__(self) -> None:
        super(SecurityAuditPlugin, self).__init__()
        self._reused_password_count = 0
        self._reused_password_revision = 0
        self._security_audit_requests: Dict[str, APIRequest_pb2.SecurityData] = {}

    def set_reused_passwords(self, count: int, revision: int) -> None:
        self._reused_password_count = count
        self._reused_password_revision = revision

    def send_reused_passwords(self):
        # TODO
        pass

    def schedule_security_data(self, record_uid: str, strength: int, url: Optional[str], bw_status: Optional[int]) -> None:
        if self.keeper_auth.auth_context.enterprise_rsa_public_key is not None:
            record_info = self.vault_data.get_record(record_uid)
            if record_info and (record_info.flags & vault_record.RecordFlags.IsOwner):
                sec_data = APIRequest_pb2.SecurityData()
                data: Dict[str, Any] = {
                    'strength': strength
                }
                if isinstance(bw_status, int):
                    data['bw_result'] = bw_status
                else:
                    data['bw_result'] = int(client_pb2.BWStatus.GOOD)

                if isinstance(url, str):
                    parse_results = urlparse(url)
                    domain = parse_results.hostname or parse_results.path
                    if domain:
                        # truncate domain string if needed to avoid reaching RSA encryption data size limitation
                        data['domain'] = domain[:200]
                sec_data.uid = utils.base64_url_decode(record_uid)
                sec_data.data = crypto.encrypt_rsa(
                    json.dumps(data).encode('utf-8'), self.keeper_auth.auth_context.enterprise_rsa_public_key)
                with self.lock:
                    self._security_audit_requests[record_uid] = sec_data

    def schedule_security_data_delete(self, record_uid: str) -> None:
        record_info = self.vault_data.get_record(record_uid)
        if record_info and (record_info.flags & vault_record.RecordFlags.IsOwner):
            sec_data = APIRequest_pb2.SecurityData()
            sec_data.uid = utils.base64_url_decode(record_uid)

            with self.lock:
                self._security_audit_requests[record_uid] = sec_data

    def send_security_audit_data(self) -> None:
        sds: List[APIRequest_pb2.SecurityData] = []
        with self.lock:
            if len(self._security_audit_requests) == 0:
                return
            if len(self._security_audit_requests) < 900:
                sds.extend(self._security_audit_requests.values())
                self._security_audit_requests.clear()
            else:
                record_uids = list(self._security_audit_requests.keys())[:900]
                for record_uid in record_uids:
                    sds.append(self._security_audit_requests.pop(record_uid))

        if len(sds) > 0:
            update_rq = APIRequest_pb2.SecurityDataRequest()
            update_rq.recordSecurityData.extend(sds)
            self.keeper_auth.execute_auth_rest('enterprise/update_security_data', update_rq)

class AuditDataPlugin(IAuditDataPlugin, keeper_auth.IKeeperAuth, abc.ABC):
    def __init__(self) -> None:
        super(AuditDataPlugin, self).__init__()
        self._pending_audit_data: Set[str] = set()

    def schedule_audit_data(self, record_uids: Iterable[str]) -> None:
        if not self.keeper_auth.auth_context.enterprise_ec_public_key:
            return

        with self.lock:
            self._pending_audit_data.update(record_uids)

    def send_audit_data(self) -> None:
        if self._pending_audit_data is None:
            return
        if len(self._pending_audit_data) == 0:
            return
        if self.keeper_auth.auth_context.enterprise_ec_public_key is None:
            return

        uids: List[str] = []
        with self.lock:
            if len(self._pending_audit_data) < 900:
                uids.extend(self._pending_audit_data)
                self._pending_audit_data.clear()
            else:
                record_uids = list(self._pending_audit_data)
                uids = record_uids[:900]
                for record_uid in uids:
                    self._pending_audit_data.remove(record_uid)

        rqs: List[record_pb2.RecordAddAuditData] = []
        for record_uid in uids:
            record_info = self.vault_data.get_record(record_uid)
            kr = self.vault_data.load_record(record_uid)
            if record_info and kr:
                audit_data = vault_extensions.extract_audit_data(kr)
                if audit_data:
                    record_audit_rq = record_pb2.RecordAddAuditData()
                    record_audit_rq.record_uid = utils.base64_url_decode(record_uid)
                    record_audit_rq.revision = record_info.revision
                    record_audit_rq.data = crypto.encrypt_ec(
                        json.dumps(audit_data).encode('utf-8'), self.keeper_auth.auth_context.enterprise_ec_public_key)
                    rqs.append(record_audit_rq)

        if len(rqs) > 0:
            audit_rq = record_pb2.AddAuditDataRequest()
            audit_rq.records.extend(rqs)
            self.keeper_auth.execute_auth_rest('vault/record_add_audit_data', audit_rq)


class PendingSharePlugin(IPendingSharePlugin, keeper_auth.IKeeperAuth, abc.ABC):
    def __init__(self) -> None:
        super(PendingSharePlugin, self).__init__()
        self._pending_shares: Dict[str, bool] = {}

    def pending_shares(self) -> Iterable[str]:
        return (x for x, y in self._pending_shares.items() if y is True)

    def set_pending_shares(self, shares: Iterable[str]) -> None:
        for email in shares:
            if email not in self._pending_shares:
                self._pending_shares[email] = True

    def resolve_pending_shares(self, shares: Iterable[str], action: PendingShareAction):
        if action == PendingShareAction.IGNORE:
            for email in shares:
                if email in self._pending_shares:
                    self._pending_shares[email] = False
            return

        rqs = [{
            'command': 'accept_share' if action == PendingShareAction.ACCEPT else 'cancel_share',
            'from_email': email
        } for email in shares]

        rss = self.keeper_auth.execute_batch(rqs)
        for rq, rs in zip(rqs, rss):
            email = rq['from_email']
            if email in self._pending_shares:
                del self._pending_shares[email]
            if rs.get('result') != 'success':
                pass


class ClientAuditEventPlugin(IClientAuditEventPlugin, keeper_auth.IKeeperAuth, abc.ABC):
    def __init__(self) -> None:
        super(ClientAuditEventPlugin, self).__init__()
        self._pending_audit_events: List[Dict[str, Any]] = []

    def schedule_audit_event(self, name: str, **kwargs) -> None:
        with self.lock:
            self._pending_audit_events.append({
                'audit_event_type': name,
                'inputs': {x: kwargs[x] for x in kwargs
                           if x in ('record_uid', 'file_format', 'attachment_id', 'to_username')}
            })

    def send_client_audit_events(self) -> None:
        if self._pending_audit_events is None:
            return
        if len(self._pending_audit_events) == 0:
            return

        rq: Dict[str, Any] = {
            'command': 'audit_event_client_logging',
        }
        with self.lock:
            rq['item_logs'] = self._pending_audit_events[:99]
            self._pending_audit_events = self._pending_audit_events[99:]

        self.keeper_auth.execute_auth_command(rq)


class BreachWatchPlugin(IBreachWatchPlugin, IVaultData, keeper_auth.IKeeperAuth, abc.ABC):
    def __init__(self) -> None:
        super(BreachWatchPlugin, self).__init__()
        self._breach_watch: Optional[breachwatch.BreachWatch] = None

    @property
    def breach_watch(self) -> Optional[breachwatch.BreachWatch]:
        if not self._breach_watch:
            try:
                self._breach_watch = breachwatch.BreachWatch(self.keeper_auth)
            except Exception as e:
                utils.get_logger().warning('Initialize BreachWatch error: %s', e)
        return self._breach_watch

    def scan_and_store_record_status(self, record_uid: str, record_key: bytes, password: str) -> Optional[client_pb2.BWPassword]:
        if not password:
            return None

        vault = self.vault_data
        logger = utils.get_logger()
        bw_record = vault.storage.breach_watch_records.get_entity(record_uid)
        euid: Optional[bytes] = None
        if record_key and bw_record:
            data_obj: Optional[Dict[str, Any]] = None
            try:
                data = crypto.decrypt_aes_v2(bw_record.data, record_key)
                data_obj = json.loads(data.decode())
            except Exception as e:
                logger.debug('BreachWatch data record \"%s\" decrypt error: %s', record_uid, e)

            if data_obj and 'passwords' in data_obj:
                password = next((x for x in data_obj['passwords'] if x.get('value', '') == password), '')
                if password:    # password has not been changed
                    return None
                euid = next((base64.b64decode(x['euid']) for x in data_obj['passwords'] if 'euid' in x), None)

        hash_status: Optional[breachwatch_pb2.HashStatus] = None
        bw = self.breach_watch
        if bw is None:
            return None
        hs = next(bw.scan_passwords(((password, euid),)), (password, hash_status))
        if isinstance(hs, tuple) and len(hs) == 2:
            _, hash_status = hs

        bwrq = breachwatch_pb2.BreachWatchRecordRequest()
        bwrq.recordUid = utils.base64_url_decode(record_uid)
        bwrq.breachWatchInfoType = breachwatch_pb2.RECORD
        bwrq.updateUserWhoScanned = True
        bw_password = client_pb2.BWPassword()
        bw_password.value = password
        bw_password.status = client_pb2.WEAK if hash_status and hash_status.breachDetected else client_pb2.GOOD
        bw_password.euid = hash_status.euid if hash_status else b''
        bw_data = client_pb2.BreachWatchData()
        bw_data.passwords.append(bw_password)
        data = bw_data.SerializeToString()
        try:
            bwrq.encryptedData = crypto.encrypt_aes_v2(data, record_key)
            rq = breachwatch_pb2.BreachWatchUpdateRequest()
            rq.breachWatchRecordRequest.append(bwrq)
            rs = self.keeper_auth.execute_auth_rest('breachwatch/update_record_data', rq,
                                                    response_type=breachwatch_pb2.BreachWatchUpdateResponse)
            assert rs is not None
            status = rs.breachWatchRecordStatus[0]
            if status.reason:
                raise Exception(status.reason)
        except Exception as e:
            logger.warning('BreachWatch: %s', str(e))

        return bw_password
