from unittest import TestCase, mock

from keepersdk.vault import Vault

from data_vault import VaultEnvironment, get_connected_auth_context, get_sync_down_response, get_vault
from helper import KeeperApiHelper

vault_env = VaultEnvironment()


class TestSyncDown(TestCase):

    def setUp(self):
        self.communicate_mock = mock.patch('keepersdk.auth.Auth.execute_auth_command').start()
        self.communicate_mock.side_effect = KeeperApiHelper.communicate_command

    def tearDown(self):
        mock.patch.stopall()

    def test_full_sync(self):
        self.communicate_mock.side_effect = None
        self.communicate_mock.return_value = get_sync_down_response()

        auth = get_connected_auth_context()
        vault = Vault(auth)

        self.assertEqual(vault.record_count, 3)
        self.assertEqual(vault.shared_folder_count, 1)
        self.assertEqual(vault.team_count, 1)

    def test_sync_remove_owned_records(self):
        vault = get_vault()
        len_before = vault.record_count

        records_to_delete = [x.record_uid for x in vault.get_all_records() if x.owner and not x.shared]

        def sync_down_removed_records(rq):
            self.assertEqual(rq['command'], 'sync_down')
            return {
                'revision': vault_env.revision + 1,
                'removed_records': records_to_delete
            }

        KeeperApiHelper.communicate_expect([sync_down_removed_records])
        vault.sync_down()
        self.assertTrue(KeeperApiHelper.is_expect_empty())

        self.assertEqual(vault.record_count, len_before - len(records_to_delete))

    def test_sync_remove_team(self):
        vault = get_vault()
        teams_to_delete = [x.team_uid for x in vault.get_all_teams()]

        def sync_down_removed_teams(rq):
            self.assertEqual(rq['command'], 'sync_down')
            return {
                'revision': vault_env.revision + 1,
                'removed_teams': teams_to_delete
            }

        KeeperApiHelper.communicate_expect([sync_down_removed_teams])
        vault.sync_down()
        self.assertTrue(KeeperApiHelper.is_expect_empty())

        self.assertEqual(vault.record_count, 3)
        self.assertEqual(vault.team_count, 0)

    def test_sync_remove_shared_folder_then_team(self):
        vault = get_vault()
        sf_to_delete = [x.shared_folder_uid for x in vault.get_all_shared_folders()]

        def sync_down_removed_shared_folders(rq):
            self.assertEqual(rq['command'], 'sync_down')
            return {
                'revision': vault_env.revision + 1,
                'removed_shared_folders': sf_to_delete
            }

        KeeperApiHelper.communicate_expect([sync_down_removed_shared_folders])
        vault.sync_down()
        self.assertTrue(KeeperApiHelper.is_expect_empty())

        self.assertEqual(vault.record_count, 3)
        self.assertEqual(vault.shared_folder_count, 1)
        self.assertEqual(vault.team_count, 1)

        teams_to_delete = [x.team_uid for x in vault.get_all_teams()]

        def sync_down_removed_teams(rq):
            self.assertEqual(rq['command'], 'sync_down')
            return {
                'revision': vault_env.revision + 1,
                'removed_teams': teams_to_delete
            }

        KeeperApiHelper.communicate_expect([sync_down_removed_teams])
        vault.sync_down()
        self.assertTrue(KeeperApiHelper.is_expect_empty())

        self.assertEqual(vault.record_count, 2)
        self.assertEqual(vault.shared_folder_count, 0)
        self.assertEqual(vault.team_count, 0)

    def test_sync_remove_team_shared_folder(self):
        vault = get_vault()
        teams_to_delete = [x.team_uid for x in vault.get_all_teams()]
        sf_to_delete = [x.shared_folder_uid for x in vault.get_all_shared_folders()]

        def sync_down_removed_teams_and_shared_folders(rq):
            self.assertEqual(rq['command'], 'sync_down')
            return {
                'revision': vault_env.revision + 1,
                'removed_shared_folders': sf_to_delete,
                'removed_teams': teams_to_delete
            }

        KeeperApiHelper.communicate_expect([sync_down_removed_teams_and_shared_folders])
        vault.sync_down()
        self.assertTrue(KeeperApiHelper.is_expect_empty())

        self.assertEqual(vault.record_count, 2)
        self.assertEqual(vault.shared_folder_count, 0)
        self.assertEqual(vault.team_count, 0)
