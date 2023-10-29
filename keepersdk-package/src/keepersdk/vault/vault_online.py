import abc
import enum
import json
import threading
import concurrent.futures
from typing import Optional, Any, Dict, Union, List, Iterable

from . import sync_down, vault_extensions
from .. import crypto, utils
from ..proto import record_pb2
from .vault_record import PasswordRecord, TypedRecord
from . import vault_data, vault_storage, storage_types
from ..authentication import keeper_auth


class VaultOnline(vault_data.VaultData, storage_types.IPendingShares):
    def __init__(self, auth: keeper_auth.KeeperAuth, storage: vault_storage.IVaultStorage) -> None:
        super(VaultOnline, self).__init__(auth.auth_context.client_key, storage)
        self._keeper_auth = auth
        self._auto_sync = False
        self._sync_down_lock = threading.Lock()
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        self._sync_record_types = True
        self._pending_audit_data: Optional[Dict[str, record_pb2.RecordAddAuditData]] = None
        self._pending_audit_events: List[Dict[str, Any]] = []
        self.sync_requested = False
        self.auto_sync = True    # call setter
        self._pending_shares: Dict[str, bool] = {}

    def close(self):
        self.auto_sync = False
        super(VaultOnline, self).close()

    @property
    def keeper_auth(self) -> keeper_auth.KeeperAuth:
        return self._keeper_auth

    @property
    def auto_sync(self) -> bool:
        return self._auto_sync

    @auto_sync.setter
    def auto_sync(self, value: bool) -> None:
        if value != self._auto_sync:
            self._auto_sync = value
            if self._keeper_auth.push_notifications:
                self._keeper_auth.push_notifications.remove_callback(self.on_notification_received)
                if value:
                    self._keeper_auth.push_notifications.register_callback(self.on_notification_received)

    def on_notification_received(self, event: Dict[str, Any]) -> Optional[bool]:
        if isinstance(event, dict):
            if event.get('event', '') == 'sync':
                if event.get('sync', False):
                    with self._sync_down_lock:
                        self.sync_requested = True
            return False

    def sync_down(self, force=False):
        with self._sync_down_lock:
            if force:
                self.storage.clear()
            changes = sync_down.sync_down_request(
                self._keeper_auth, self.storage, sync_record_types=self._sync_record_types)
            self.sync_requested = False
            self._sync_record_types = False
            self.rebuild_data(changes)

    @staticmethod
    def process_add_audit_data_response(fut: concurrent.futures.Future) -> None:
        if fut.done() and not fut.cancelled():
            e = fut.exception(0)
            if e:
                utils.get_logger().debug('Store audit data error: %s', e)

    @staticmethod
    def process_audit_event_response(fut: concurrent.futures.Future) -> None:
        if fut.done() and not fut.cancelled():
            e = fut.exception(0)
            if e:
                utils.get_logger().debug('Store audit event error: %s', e)

    def run_pending_jobs(self):
        rqs = []
        with self._sync_down_lock:
            if self._pending_audit_data:
                if len(self._pending_audit_data) < 900:
                    rqs.extend(self._pending_audit_data.values())
                    self._pending_audit_data.clear()
                else:
                    record_uids = list(self._pending_audit_data.keys())
                    record_uids = record_uids[:900]
                    for record_uid in record_uids:
                        rqs.append(self._pending_audit_data.pop(record_uid))

        if len(rqs) > 0:
            audit_rq = record_pb2.AddAuditDataRequest()
            audit_rq.records.extend(rqs)
            fut = self._keeper_auth.execute_async(
                self._keeper_auth.execute_auth_rest, 'vault/record_add_audit_data', audit_rq)
            fut.add_done_callback(VaultOnline.process_add_audit_data_response)

        rqs.clear()
        with self._sync_down_lock:
            if self._pending_audit_events:
                if len(self._pending_audit_events) < 90:
                    rqs.extend(self._pending_audit_events)
                    self._pending_audit_events.clear()
                else:
                    batch = self._pending_audit_events[:90]
                    rqs.extend(batch)
                    self._pending_audit_events = self._pending_audit_events[90:]
                rq = {
                    'command': 'audit_event_client_logging',
                    'item_logs': rqs
                }
                fut = self._keeper_auth.execute_async(self._keeper_auth.execute_auth_command, rq)
                fut.add_done_callback(VaultOnline.process_audit_event_response)

    def schedule_audit_data(self, record: Union[PasswordRecord, TypedRecord], revision: int) -> None:
        ent_ec_public_key = self._keeper_auth.auth_context.enterprise_ec_public_key
        if ent_ec_public_key:
            audit_data = vault_extensions.extract_audit_data(record)
            if audit_data:
                record_audit_rq = record_pb2.RecordAddAuditData()
                record_audit_rq.record_uid = utils.base64_url_decode(record.record_uid)
                record_audit_rq.revision = revision
                record_audit_rq.data = crypto.encrypt_ec(
                    json.dumps(audit_data).encode('utf-8'), ent_ec_public_key)
                with self._sync_down_lock:
                    if self._pending_audit_data is None:
                        self._pending_audit_data = {}
                    self._pending_audit_data[record.record_uid] = record_audit_rq

    def schedule_audit_event(self, name: str, **kwargs) -> None:
        if self._keeper_auth.auth_context.enterprise_ec_public_key:
            with self._sync_down_lock:
                if self._pending_audit_events is None:
                    self._pending_audit_events = []
                self._pending_audit_events.append({
                    'audit_event_type': name,
                    'inputs': {x: kwargs[x] for x in kwargs
                               if x in ('record_uid', 'file_format', 'attachment_id', 'to_username')}
                })

    def pending_shares(self) -> Iterable[str]:
        return (x for x, y in self._pending_shares.items() if y is True)

    def set_pending_shares(self, shares: Iterable[str]) -> None:
        for email in shares:
            if email not in self._pending_shares:
                self._pending_shares[email] = True

    def resolve_pending_shares(self, shares: Iterable[str], action: storage_types.PendingShareAction):
        if action == storage_types.PendingShareAction.IGNORE:
            for email in shares:
                if email in self._pending_shares:
                    self._pending_shares[email] = False
            return

        rqs = [
            {
                'command': 'accept_share' if action == storage_types.PendingShareAction.ACCEPT else 'cancel_share',
                'from_email': email
            } for email in shares]

        rss = self.keeper_auth.execute_batch(rqs)
        for rq, rs in zip(rqs, rss):
            email = rq['from_email']
            if email in self._pending_shares:
                del self._pending_shares[email]
            if rs.get('result') != 'success':
                pass





