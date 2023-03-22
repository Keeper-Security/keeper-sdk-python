import unittest
from unittest.mock import MagicMock

from vault import vault_online, sync_down, memory_storage
from proto import record_pb2
import data_vault


def get_sync_down_auth():
    auth = data_vault.get_connected_auth()

    def sync_down_mock(rq, throw=True):
        command = rq['command']
        if command == 'sync_down':
            return data_vault.sync_down_response()
        raise Exception(f'Command \"{command}\" not supported')
    mock = MagicMock()
    mock.side_effect = sync_down_mock
    auth.execute_auth_command = mock

    def get_record_types_mock(endpoint, request, response_type=None):
        if endpoint == 'vault/get_record_types':
            rs = record_pb2.RecordTypesResponse()
            rs.standardCounter = 1
            rt = record_pb2.RecordType()
            rt.scope = record_pb2.RecordTypeScope.RT_STANDARD
            rt.recordTypeId = 1
            rt.content = data_vault.RecordTypes
            rs.recordTypes.append(rt)
            return rs
        raise Exception(f'Endpoint \"{endpoint}\" not supported')

    mock = MagicMock()
    mock.side_effect = get_record_types_mock
    auth.execute_auth_rest = mock
    return auth


def get_populated_vault():   # type: () -> vault_online.VaultOnline
    vault = vault_online.VaultOnline(get_sync_down_auth(), memory_storage.InMemoryVaultStorage())
    vault.sync_down()
    if isinstance(vault.keeper_auth.execute_auth_command, MagicMock):
        vault.keeper_auth.execute_auth_command.side_effect = None
    return vault


class VaultTestCase(unittest.TestCase):
    def test_vault_storage(self):
        auth = get_sync_down_auth()
        vs = memory_storage.InMemoryVaultStorage()
        sync_down.sync_down_command(auth, vs, False)

        records = list(vs.records.get_all())
        self.assertTrue(len(records) > 0)
        shared_folders = list(vs.shared_folders.get_all())
        self.assertTrue(len(shared_folders) > 0)
        teams = list(vs.teams.get_all())
        self.assertTrue(len(teams) > 0)

    def test_delete_owned_record(self):
        vault = get_populated_vault()

        record_uid = next((x.record_uid for x in vault.storage.records.get_all() if not x.shared))
        self.assertIsInstance(vault.keeper_auth.execute_auth_command, MagicMock)
        mock = vault.keeper_auth.execute_auth_command    # type: MagicMock
        mock.return_value = {
            'result': 'success',
            'revision': 201,
            'removed_records': [record_uid]
        }
        vault.sync_down()
        records = list(vault.storage.record_keys.get_links_for_subject(record_uid))
        self.assertEqual(len(records), 0)

    def test_delete_team(self):
        vault = get_populated_vault()
        orig_team_count = vault.team_count
        orig_sf_count = vault.shared_folder_count
        self.assertTrue(orig_team_count > 0)
        team_uid = next((x.team_uid for x in vault.teams()), None)
        self.assertIsNotNone(team_uid)
        self.assertIsInstance(vault.keeper_auth.execute_auth_command, MagicMock)
        mock = vault.keeper_auth.execute_auth_command    # type: MagicMock
        mock.return_value = {
            'result': 'success',
            'revision': 201,
            'removed_teams': [team_uid]
        }
        vault.sync_down()
        self.assertTrue(vault.team_count < orig_team_count)
        self.assertIsNone(vault.get_team(team_uid))
        self.assertTrue(vault.shared_folder_count < orig_sf_count)

    def test_delete_shared_folder(self):
        vault = get_populated_vault()
        orig_sf_count = vault.shared_folder_count
        self.assertTrue(orig_sf_count > 0)
        shared_folder_uid = next(x.shared_folder_uid for x in vault.shared_folders() if x.teams == 0)
        self.assertIsNotNone(shared_folder_uid)
        self.assertIsInstance(vault.keeper_auth.execute_auth_command, MagicMock)
        mock = vault.keeper_auth.execute_auth_command    # type: MagicMock
        mock.return_value = {
            'result': 'success',
            'revision': 201,
            'removed_shared_folders': [shared_folder_uid]
        }
        vault.sync_down()
        self.assertTrue(vault.shared_folder_count < orig_sf_count)
        self.assertIsNone(vault.get_shared_folder(shared_folder_uid))
