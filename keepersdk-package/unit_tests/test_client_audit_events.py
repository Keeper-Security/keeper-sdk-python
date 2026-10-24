import unittest
from unittest.mock import MagicMock

import data_vault
from keepersdk import crypto
from keepersdk.vault import vault_online, memory_storage


def get_enterprise_vault() -> vault_online.VaultOnline:
    auth = data_vault.get_connected_auth()
    auth.auth_context.enterprise_ec_public_key = crypto.generate_ec_key()[1]
    auth.execute_auth_command = MagicMock(return_value={'result': 'success'})
    vault = vault_online.get_vault_online(auth, memory_storage.InMemoryVaultStorage())
    vault.auto_sync = False
    return vault


def sent_events(vault: vault_online.VaultOnline):
    events = []
    for call in vault.keeper_auth.execute_auth_command.call_args_list:
        rq = call.args[0]
        if rq.get('command') == 'audit_event_client_logging':
            events.extend(rq['item_logs'])
    return events


class TestClientAuditEvents(unittest.TestCase):
    def test_record_access_events_are_sent(self):
        vault = get_enterprise_vault()
        self.addCleanup(vault.close)
        caep = vault.client_audit_event_plugin()
        caep.schedule_audit_event('open_record', record_uid='uid1')
        caep.schedule_audit_event('copy_password', record_uid='uid1')
        caep.schedule_audit_event('revealed_password', record_uid='uid1')
        vault.flush_client_audit_events()

        self.assertEqual(sent_events(vault), [
            {'audit_event_type': 'open_record', 'inputs': {'record_uid': 'uid1'}},
            {'audit_event_type': 'copy_password', 'inputs': {'record_uid': 'uid1'}},
            {'audit_event_type': 'revealed_password', 'inputs': {'record_uid': 'uid1'}},
        ])

    def test_send_drains_queue_in_chunks(self):
        vault = get_enterprise_vault()
        self.addCleanup(vault.close)
        caep = vault.client_audit_event_plugin()
        for i in range(250):
            caep.schedule_audit_event('open_record', record_uid=f'uid{i}')
        vault.flush_client_audit_events()

        calls = vault.keeper_auth.execute_auth_command.call_args_list
        self.assertEqual([len(c.args[0]['item_logs']) for c in calls], [99, 99, 52])
        self.assertEqual(len(sent_events(vault)), 250)

    def test_close_flushes_pending_events(self):
        vault = get_enterprise_vault()
        vault.client_audit_event_plugin().schedule_audit_event('open_record', record_uid='uid1')
        vault.close()

        self.assertEqual(sent_events(vault), [{'audit_event_type': 'open_record', 'inputs': {'record_uid': 'uid1'}}])

    def test_flush_with_empty_queue_sends_nothing(self):
        vault = get_enterprise_vault()
        self.addCleanup(vault.close)
        vault.flush_client_audit_events()

        vault.keeper_auth.execute_auth_command.assert_not_called()

    def test_personal_vault_is_noop(self):
        auth = data_vault.get_connected_auth()
        auth.execute_auth_command = MagicMock(return_value={'result': 'success'})
        vault = vault_online.get_vault_online(auth, memory_storage.InMemoryVaultStorage())
        vault.auto_sync = False
        self.assertIsNone(vault.client_audit_event_plugin())

        vault.flush_client_audit_events()
        vault.close()

        auth.execute_auth_command.assert_not_called()
