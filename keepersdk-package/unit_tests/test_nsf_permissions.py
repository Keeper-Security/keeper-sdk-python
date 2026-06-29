import unittest
from unittest.mock import MagicMock

from keepersdk import utils
from keepersdk.proto import folder_pb2
from keepersdk.vault import memory_nsf_storage, nsf_common, nsf_storage_types as nsf


class TestNsfPermissions(unittest.TestCase):
    def _vault(self, *, username='alice@example.com', account_uid=None):
        vault = MagicMock()
        vault.keeper_auth.auth_context.username = username
        vault.keeper_auth.auth_context.account_uid = account_uid or utils.base64_url_decode(
            utils.generate_uid())
        return vault

    def test_folder_share_denied_for_viewer(self):
        folder_uid = utils.generate_uid()
        account_uid = utils.generate_uid()
        storage = memory_nsf_storage.InMemoryNSFStorage()
        storage.folder_accesses.put_links([
            nsf.NSFFolderAccess(
                folder_uid=folder_uid,
                access_type_uid=account_uid,
                access_type=int(folder_pb2.AT_USER),
                permissions_json='{"canUpdateAccess":false,"canViewRecords":true}',
            ),
        ])
        vault = self._vault(account_uid=utils.base64_url_decode(account_uid))
        vault.nsf_data.storage = storage

        with self.assertRaisesRegex(ValueError, 'permission to share'):
            nsf_common.require_nsf_folder_share_permission(vault, folder_uid)

    def test_folder_share_allowed_for_share_manager(self):
        folder_uid = utils.generate_uid()
        account_uid = utils.generate_uid()
        storage = memory_nsf_storage.InMemoryNSFStorage()
        storage.folder_accesses.put_links([
            nsf.NSFFolderAccess(
                folder_uid=folder_uid,
                access_type_uid=account_uid,
                access_type=int(folder_pb2.AT_USER),
                permissions_json='{"canUpdateAccess":true}',
            ),
        ])
        vault = self._vault(account_uid=utils.base64_url_decode(account_uid))
        vault.nsf_data.storage = storage

        nsf_common.require_nsf_folder_share_permission(vault, folder_uid)

    def test_folder_share_allowed_for_owner_row(self):
        folder_uid = utils.generate_uid()
        account_uid = utils.generate_uid()
        storage = memory_nsf_storage.InMemoryNSFStorage()
        storage.folders.put_entities([nsf.NSFFolder(
            folder_uid=folder_uid,
            owner_account_uid=account_uid,
            owner_username='alice@example.com',
        )])
        vault = self._vault(account_uid=utils.base64_url_decode(account_uid))
        vault.nsf_data.storage = storage

        nsf_common.require_nsf_folder_share_permission(vault, folder_uid)

    def test_record_share_denied_without_permission(self):
        record_uid = utils.generate_uid()
        account_uid = utils.generate_uid()
        storage = memory_nsf_storage.InMemoryNSFStorage()
        storage.record_accesses.put_links([
            nsf.NSFRecordAccess(
                record_uid=record_uid,
                access_type_uid=account_uid,
                can_update_access=False,
            ),
        ])
        vault = self._vault(account_uid=utils.base64_url_decode(account_uid))
        vault.nsf_data.storage = storage

        with self.assertRaisesRegex(ValueError, 'permission to share'):
            nsf_common.require_nsf_record_share_permission(vault, record_uid)

    def test_record_access_inheritance_helpers(self):
        record_uid = utils.generate_uid()
        vault = self._vault()
        from unittest.mock import patch
        api_access = [{
            'record_uid': record_uid,
            'accessor_name': 'alice@example.com',
            'access_type': 'AT_USER',
            'inherited': True,
            'owner': False,
        }]
        with patch.object(
                nsf_common, 'collect_nsf_record_accessors', return_value=api_access):
            accesses = nsf_common.find_record_user_accesses(
                vault, record_uid, 'alice@example.com')
            self.assertTrue(nsf_common.record_user_has_inherited_access(accesses))
            self.assertFalse(nsf_common.record_user_has_direct_access(accesses))

    def test_folder_inherit_detection(self):
        parent_uid = utils.generate_uid()
        folder_uid = utils.generate_uid()
        storage = memory_nsf_storage.InMemoryNSFStorage()
        storage.folders.put_entities([
            nsf.NSFFolder(
                folder_uid=parent_uid,
                inherit_user_permissions=int(folder_pb2.BOOLEAN_TRUE),
            ),
            nsf.NSFFolder(
                folder_uid=folder_uid,
                parent_uid=parent_uid,
                inherit_user_permissions=int(folder_pb2.BOOLEAN_TRUE),
            ),
        ])
        vault = self._vault()
        vault.nsf_data.storage = storage

        self.assertTrue(nsf_common.folder_inherits_parent_permissions(vault, folder_uid))

        storage.folders.put_entities([
            nsf.NSFFolder(
                folder_uid=folder_uid,
                parent_uid=parent_uid,
                inherit_user_permissions=int(folder_pb2.BOOLEAN_FALSE),
            ),
        ])
        self.assertFalse(nsf_common.folder_inherits_parent_permissions(vault, folder_uid))


class TestEncryptForTeam(unittest.TestCase):
    def test_prefer_asymmetric_then_aes_fallback(self):
        from keepersdk.authentication.keeper_auth import UserKeys
        from keepersdk import crypto

        folder_key = utils.generate_aes_key()
        team_aes = utils.generate_aes_key()
        keys = UserKeys(aes=team_aes, rsa=None, ec=None)
        encrypted, key_type = nsf_common.encrypt_for_team(
            folder_key, keys, forbid_rsa=False)
        self.assertEqual(crypto.decrypt_aes_v1(encrypted, team_aes), folder_key)
        self.assertEqual(key_type, folder_pb2.encrypted_by_data_key)

    def test_invalid_aes_size_is_not_used_as_fallback(self):
        from keepersdk.authentication.keeper_auth import UserKeys

        keys = UserKeys(aes=b'x' * 480, rsa=None, ec=None)
        with self.assertRaisesRegex(ValueError, 'No public key found for team'):
            nsf_common.encrypt_for_team(
                utils.generate_aes_key(), keys, forbid_rsa=False)


if __name__ == '__main__':
    unittest.main()
