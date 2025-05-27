import unittest
from typing import Callable, Dict
from unittest.mock import MagicMock

import data_vault
from keepersdk import crypto, utils
from keepersdk.proto import record_pb2
from keepersdk.vault import vault_online, sync_down, memory_storage, record_type_management
from keepersdk.proto import SyncDown_pb2


def get_sync_down_auth():
    auth = data_vault.get_connected_auth()

    def sync_down_mock(endpoint, rq, response_type):
        if endpoint == 'vault/sync_down':
            return data_vault.sync_down_response()
        elif endpoint == 'vault/get_record_types':
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
    mock.side_effect = sync_down_mock
    auth.execute_auth_rest = mock
    return auth


def get_populated_vault() -> vault_online.VaultOnline:
    vault = vault_online.VaultOnline(get_sync_down_auth(), memory_storage.InMemoryVaultStorage())
    vault.sync_down()
    if isinstance(vault.keeper_auth.execute_auth_rest, MagicMock):
        vault.keeper_auth.execute_auth_rest.side_effect = None
    return vault


class VaultTestCase(unittest.TestCase):
    def test_vault_storage(self):
        auth = get_sync_down_auth()
        vs = memory_storage.InMemoryVaultStorage()
        sync_down.sync_down_request(auth, vs, sync_record_types=False)

        records = list(vs.records.get_all_entities())
        self.assertTrue(len(records) > 0)
        shared_folders = list(vs.shared_folders.get_all_entities())
        self.assertTrue(len(shared_folders) > 0)
        teams = list(vs.teams.get_all_entities())
        self.assertTrue(len(teams) > 0)
        nsds = list(vs.non_shared_data.get_all_entities())
        self.assertTrue(len(nsds) > 0)

    @staticmethod
    def get_execute_rest(responses: Dict) -> Callable:
        def execute_auth_rest(endpoint, request, response_type):
            if endpoint in responses:
                value = responses.pop(endpoint)
                if isinstance(value, list):
                    rs = value.pop(0)
                    if len(value) > 0:
                        responses[endpoint] = value
                    value = rs
                if value is not None:
                    return value
            return NotImplementedError()
        return execute_auth_rest

    def test_delete_owned_record(self):
        vault = get_populated_vault()

        record_uid = next((x.record_uid for x in vault.vault_data.storage.records.get_all_entities() if not x.shared))
        self.assertIsInstance(vault.keeper_auth.execute_auth_rest, MagicMock)
        mock: MagicMock = vault.keeper_auth.execute_auth_rest
        rs = SyncDown_pb2.SyncDownResponse()
        rs.continuationToken = crypto.get_random_bytes(16)
        rs.hasMore = False
        rs.cacheStatus = SyncDown_pb2.CacheStatus.KEEP
        rs.removedRecords.append(utils.base64_url_decode(record_uid))
        mock.side_effect = self.get_execute_rest({'vault/sync_down': rs})

        vault.sync_down()
        records = list(vault.vault_data.storage.record_keys.get_links_by_subject(record_uid))
        self.assertEqual(len(records), 0)

    def test_delete_team(self):
        vault = get_populated_vault()
        orig_team_count = vault.vault_data.team_count
        orig_sf_count = vault.vault_data.shared_folder_count
        self.assertTrue(orig_team_count > 0)
        team_uid = next((x.team_uid for x in vault.vault_data.teams()), None)
        self.assertIsNotNone(team_uid)
        rs = SyncDown_pb2.SyncDownResponse()
        rs.continuationToken = crypto.get_random_bytes(16)
        rs.hasMore = False
        rs.cacheStatus = SyncDown_pb2.CacheStatus.KEEP
        rs.removedTeams.append(utils.base64_url_decode(team_uid))
        self.assertIsInstance(vault.keeper_auth.execute_auth_rest, MagicMock)
        mock: MagicMock = vault.keeper_auth.execute_auth_rest
        mock.side_effect = self.get_execute_rest({'vault/sync_down': rs})

        vault.sync_down()
        self.assertTrue(vault.vault_data.team_count < orig_team_count)
        self.assertIsNone(vault.vault_data.get_team(team_uid))
        self.assertTrue(vault.vault_data.shared_folder_count < orig_sf_count)

    def test_delete_shared_folder(self):
        vault = get_populated_vault()
        orig_sf_count = vault.vault_data.shared_folder_count
        self.assertTrue(orig_sf_count > 0)
        shared_folder_uid = next(x.shared_folder_uid for x in vault.vault_data.shared_folders() if x.teams == 0)
        self.assertIsNotNone(shared_folder_uid)
        self.assertIsInstance(vault.keeper_auth.execute_auth_rest, MagicMock)
        rs = SyncDown_pb2.SyncDownResponse()
        rs.continuationToken = crypto.get_random_bytes(16)
        rs.hasMore = False
        rs.cacheStatus = SyncDown_pb2.CacheStatus.KEEP
        rs.removedSharedFolders.append(utils.base64_url_decode(shared_folder_uid))
        self.assertIsInstance(vault.keeper_auth.execute_auth_rest, MagicMock)
        mock: MagicMock = vault.keeper_auth.execute_auth_rest
        mock.side_effect = self.get_execute_rest({'vault/sync_down': rs})

        vault.sync_down()
        self.assertTrue(vault.vault_data.shared_folder_count < orig_sf_count)
        self.assertIsNone(vault.vault_data.get_shared_folder(shared_folder_uid))


class CreateCustomRecordTypeTestCase(unittest.TestCase):
    def setUp(self):
        self.vault = MagicMock()
        self.vault.keeper_auth.execute_auth_rest = MagicMock()
        self.vault.keeper_auth.auth_context.is_enterprise_admin = True

    def test_successful_creation(self):
        title = "TestType"
        fields = [{"$ref": "login"}]
        description = "A test type"
        record_type_management.record_types.FieldTypes = {"login": {}}
        self.vault.keeper_auth.execute_auth_rest.return_value = record_pb2.RecordTypeModifyResponse()
        result = record_type_management.create_custom_record_type(self.vault, title, fields, description)
        self.assertIsInstance(result, record_pb2.RecordTypeModifyResponse)
        self.vault.keeper_auth.execute_auth_rest.assert_called_once_with(
            'vault/record_type_add',
            unittest.mock.ANY,
            response_type=record_pb2.RecordTypeModifyResponse
        )

    def test_not_enterprise_admin(self):
        self.vault.keeper_auth.auth_context.is_enterprise_admin = False
        with self.assertRaises(ValueError) as cm:
            record_type_management.create_custom_record_type(self.vault, "Title", [{"$ref": "login"}], "desc")
        self.assertIn("restricted to Keeper Enterprise administrators", str(cm.exception))

    def test_missing_fields(self):
        with self.assertRaises(ValueError) as cm:
            record_type_management.create_custom_record_type(self.vault, "Title", [], "desc")
        self.assertIn("At least one field", str(cm.exception))

    def test_missing_ref(self):
        record_type_management.record_types.FieldTypes = {"login": {}}
        with self.assertRaises(ValueError) as cm:
            record_type_management.create_custom_record_type(self.vault, "Title", [{}], "desc")
        self.assertIn("Each field must contain a '$ref'", str(cm.exception))

    def test_invalid_field_name(self):
        record_type_management.record_types.FieldTypes = {"login": {}}
        with self.assertRaises(ValueError) as cm:
            record_type_management.create_custom_record_type(self.vault, "Title", [{"$ref": "not_a_field"}], "desc")
        self.assertIn("is not a valid RecordField", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
