"""Team RSA private key wrapping, and NSF folder keys validated against folder data."""

import json
import unittest
from unittest.mock import MagicMock, Mock, patch

from keepersdk import crypto, utils
from keepersdk.proto import folder_pb2
from keepersdk.vault import memory_nsf_storage, nsf_crypto, nsf_data, nsf_management, nsf_storage_types as nsf
from keepersdk.vault import storage_types, vault_data


class TeamRsaPrivateKeyTest(unittest.TestCase):
    def setUp(self):
        self.team_key = utils.generate_aes_key()
        private_key, _ = crypto.generate_rsa_key()
        self.private_key_der = crypto.unload_rsa_private_key(private_key)

    def test_gcm_wrapped_key(self):
        wrapped = crypto.encrypt_aes_v2(self.private_key_der, self.team_key)
        self.assertEqual(vault_data.decrypt_team_rsa_private_key(wrapped, self.team_key), self.private_key_der)

    def test_legacy_cbc_wrapped_key(self):
        wrapped = crypto.encrypt_aes_v1(self.private_key_der, self.team_key)
        self.assertEqual(vault_data.decrypt_team_rsa_private_key(wrapped, self.team_key), self.private_key_der)

    def test_wrong_team_key_does_not_return_private_key(self):
        wrapped = crypto.encrypt_aes_v2(self.private_key_der, self.team_key)
        # Usually raises; the CBC fallback can occasionally return garbage instead.
        try:
            result = vault_data.decrypt_team_rsa_private_key(wrapped, utils.generate_aes_key())
        except Exception:
            return
        self.assertNotEqual(result, self.private_key_der)

    def test_team_with_gcm_wrapped_rsa_key_loads(self):
        storage_team = storage_types.StorageTeam()
        storage_team.team_uid = utils.generate_uid()
        storage_team.name = 'Team'
        storage_team.rsa_private_key = crypto.encrypt_aes_v2(self.private_key_der, self.team_key)

        team = vault_data.load_keeper_team(storage_team, self.team_key)

        self.assertIsNotNone(team.rsa_private_key)
        self.assertEqual(crypto.unload_rsa_private_key(team.rsa_private_key), self.private_key_der)


def _auth():
    ctx = Mock()
    ctx.data_key = utils.generate_aes_key()
    ctx.rsa_private_key = None
    ctx.ec_private_key = None
    return ctx


def _b64(data: bytes, key: bytes) -> str:
    return utils.base64_url_encode(crypto.encrypt_aes_v2(data, key))


class FolderKeyValidationTest(unittest.TestCase):
    def setUp(self):
        self.storage = memory_nsf_storage.InMemoryNSFStorage()
        self.auth = _auth()

    def _folder(self, name, folder_key, parent_uid=''):
        folder_uid = utils.generate_uid()
        self.storage.folders.put_entities([nsf.NSFFolder(
            folder_uid=folder_uid, parent_uid=parent_uid,
            data=_b64(json.dumps({'name': name}).encode(), folder_key))])
        return folder_uid

    def _user_key_link(self, folder_uid, wrapped_key):
        self.storage.folder_keys.put_links([nsf.NSFFolderKey(
            folder_uid=folder_uid, parent_uid='', folder_key=_b64(wrapped_key, self.auth.data_key),
            encrypted_by=int(folder_pb2.ENCRYPTED_BY_USER_KEY))])

    def test_wrong_key_is_rejected_and_folder_access_used(self):
        folder_key = utils.generate_aes_key()
        folder_uid = self._folder('Shared', folder_key)
        # The FolderKey entry unwraps cleanly but to a key that does not open the folder data.
        self._user_key_link(folder_uid, utils.generate_aes_key())
        self.storage.folder_accesses.put_links([nsf.NSFFolderAccess(
            folder_uid=folder_uid, access_type_uid=utils.generate_uid(), access_type=int(folder_pb2.AT_USER),
            folder_key_encrypted=_b64(folder_key, self.auth.data_key))])

        keys = nsf_crypto.decrypt_folder_keys(self.storage, self.auth)

        self.assertEqual(keys[folder_uid], folder_key)

    def test_wrong_key_is_not_cached(self):
        folder_uid = self._folder('Shared', utils.generate_aes_key())
        self._user_key_link(folder_uid, utils.generate_aes_key())

        self.assertNotIn(folder_uid, nsf_crypto.decrypt_folder_keys(self.storage, self.auth))

    def test_wrong_access_entry_is_skipped_for_next_one(self):
        folder_key = utils.generate_aes_key()
        folder_uid = self._folder('Shared', folder_key)
        for key in (utils.generate_aes_key(), folder_key):
            self.storage.folder_accesses.put_links([nsf.NSFFolderAccess(
                folder_uid=folder_uid, access_type_uid=utils.generate_uid(), access_type=int(folder_pb2.AT_USER),
                folder_key_encrypted=_b64(key, self.auth.data_key))])

        self.assertEqual(nsf_crypto.decrypt_folder_keys(self.storage, self.auth)[folder_uid], folder_key)

    def test_folder_without_data_accepts_key(self):
        folder_key = utils.generate_aes_key()
        folder_uid = utils.generate_uid()
        self.storage.folders.put_entities([nsf.NSFFolder(folder_uid=folder_uid, parent_uid='', data='')])
        self._user_key_link(folder_uid, folder_key)

        self.assertEqual(nsf_crypto.decrypt_folder_keys(self.storage, self.auth)[folder_uid], folder_key)

    def test_parent_key_prefers_folder_hierarchy_parent(self):
        old_parent_key, new_parent_key, child_key = (utils.generate_aes_key() for _ in range(3))
        old_parent = self._folder('Old parent', old_parent_key)
        new_parent = self._folder('New parent', new_parent_key)
        for uid, key in ((old_parent, old_parent_key), (new_parent, new_parent_key)):
            self._user_key_link(uid, key)
        # After a move the folder's hierarchy points at the new parent, but the key
        # entry still names the old one; the key is wrapped by the new parent's key.
        child = self._folder('Child', child_key, parent_uid=new_parent)
        self.storage.folder_keys.put_links([nsf.NSFFolderKey(
            folder_uid=child, parent_uid=old_parent, folder_key=_b64(child_key, new_parent_key),
            encrypted_by=int(folder_pb2.ENCRYPTED_BY_PARENT_KEY))])

        self.assertEqual(nsf_crypto.decrypt_folder_keys(self.storage, self.auth)[child], child_key)

    def test_parent_key_falls_back_to_key_entry_parent(self):
        parent_key, child_key = utils.generate_aes_key(), utils.generate_aes_key()
        parent = self._folder('Parent', parent_key)
        self._user_key_link(parent, parent_key)
        child = self._folder('Child', child_key, parent_uid=utils.generate_uid())
        self.storage.folder_keys.put_links([nsf.NSFFolderKey(
            folder_uid=child, parent_uid=parent, folder_key=_b64(child_key, parent_key),
            encrypted_by=int(folder_pb2.ENCRYPTED_BY_PARENT_KEY))])

        self.assertEqual(nsf_crypto.decrypt_folder_keys(self.storage, self.auth)[child], child_key)

    def test_failed_parent_key_falls_back_to_folder_access(self):
        parent_key, child_key = utils.generate_aes_key(), utils.generate_aes_key()
        parent = self._folder('Parent', parent_key)
        self._user_key_link(parent, parent_key)
        child = self._folder('Child', child_key, parent_uid=parent)
        # The PARENT_KEY entry is wrapped with an unrelated key; folderAccesses has the real one.
        self.storage.folder_keys.put_links([nsf.NSFFolderKey(
            folder_uid=child, parent_uid=parent, folder_key=_b64(child_key, utils.generate_aes_key()),
            encrypted_by=int(folder_pb2.ENCRYPTED_BY_PARENT_KEY))])
        self.storage.folder_accesses.put_links([nsf.NSFFolderAccess(
            folder_uid=child, access_type_uid=utils.generate_uid(), access_type=int(folder_pb2.AT_USER),
            folder_key_encrypted=_b64(child_key, self.auth.data_key))])

        self.assertEqual(nsf_crypto.decrypt_folder_keys(self.storage, self.auth)[child], child_key)


class ListUndecryptedFolderTest(unittest.TestCase):
    def test_folder_without_key_is_not_listed(self):
        view = MagicMock()
        view.folders.return_value = [
            nsf_data.NSFFolderNode(folder_uid='F1', name='Readable', folder_key=utils.generate_aes_key()),
            nsf_data.NSFFolderNode(folder_uid='F2', name='(NSF Folder)', folder_key=None),
        ]
        with patch('keepersdk.vault.nsf_management._nsf_view', return_value=view):
            rows = nsf_management.list_nsf_items(MagicMock(), include_folders=True, include_records=False)

        self.assertEqual([r.uid for r in rows], ['F1'])


if __name__ == '__main__':
    unittest.main()
