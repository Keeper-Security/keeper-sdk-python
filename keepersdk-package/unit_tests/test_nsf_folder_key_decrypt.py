"""Unit tests for NSF folder key / name decrypt (team + shared paths)."""

import json
import unittest
from unittest.mock import Mock

from keepersdk import crypto, utils
from keepersdk.proto import folder_pb2
from keepersdk.vault import nsf_crypto, nsf_storage_types as nsf, memory_nsf_storage


def _auth(data_key=None):
    ctx = Mock()
    ctx.data_key = data_key or utils.generate_aes_key()
    ctx.rsa_private_key = None
    ctx.ec_private_key = None
    return ctx


def _put_folder(storage, name, folder_key, parent_uid=''):
    folder_uid = utils.generate_uid()
    data_b64 = utils.base64_url_encode(
        crypto.encrypt_aes_v2(json.dumps({'name': name}).encode('utf-8'), folder_key)
    )
    storage.folders.put_entities([
        nsf.NSFFolder(
            folder_uid=folder_uid,
            parent_uid=parent_uid,
            data=data_b64,
        ),
    ])
    return folder_uid


class TestNsfFolderKeyDecrypt(unittest.TestCase):

    def test_user_key_owner_path(self):
        storage = memory_nsf_storage.InMemoryNSFStorage()
        auth = _auth()
        folder_key = utils.generate_aes_key()
        folder_uid = _put_folder(storage, 'Owner Folder', folder_key)
        storage.folder_keys.put_links([
            nsf.NSFFolderKey(
                folder_uid=folder_uid,
                parent_uid='',
                folder_key=utils.base64_url_encode(
                    crypto.encrypt_aes_v2(folder_key, auth.data_key)
                ),
                encrypted_by=int(folder_pb2.ENCRYPTED_BY_USER_KEY),
            ),
        ])

        keys = nsf_crypto.decrypt_folder_keys(storage, auth)
        name = nsf_crypto.decrypt_folder_name(
            storage.folders.get_entity(folder_uid).data, keys[folder_uid]
        )
        self.assertEqual(name, 'Owner Folder')

    def test_team_key_via_folder_access(self):
        storage = memory_nsf_storage.InMemoryNSFStorage()
        auth = _auth()
        team_uid = utils.generate_uid()
        team_aes = utils.generate_aes_key()
        folder_key = utils.generate_aes_key()
        folder_uid = _put_folder(storage, 'Team Shared NSF', folder_key)
        storage.folder_keys.put_links([
            nsf.NSFFolderKey(
                folder_uid=folder_uid,
                parent_uid='',
                folder_key='',
                encrypted_by=int(folder_pb2.ENCRYPTED_BY_TEAM_KEY),
            ),
        ])
        storage.folder_accesses.put_links([
            nsf.NSFFolderAccess(
                folder_uid=folder_uid,
                access_type_uid=team_uid,
                access_type=int(folder_pb2.AT_TEAM),
                folder_key_encrypted=utils.base64_url_encode(
                    crypto.encrypt_aes_v2(folder_key, team_aes)
                ),
                folder_key_type=int(folder_pb2.encrypted_by_data_key_gcm),
            ),
        ])
        teams = {
            team_uid: nsf_crypto.TeamKeyMaterial(team_key=team_aes),
        }

        keys = nsf_crypto.decrypt_folder_keys(storage, auth, teams=teams)
        self.assertIn(folder_uid, keys)
        name = nsf_crypto.decrypt_folder_name(
            storage.folders.get_entity(folder_uid).data, keys[folder_uid]
        )
        self.assertEqual(name, 'Team Shared NSF')

    def test_team_key_fails_without_team_materials(self):
        storage = memory_nsf_storage.InMemoryNSFStorage()
        auth = _auth()
        team_uid = utils.generate_uid()
        team_aes = utils.generate_aes_key()
        folder_key = utils.generate_aes_key()
        folder_uid = _put_folder(storage, 'Hidden', folder_key)
        storage.folder_keys.put_links([
            nsf.NSFFolderKey(
                folder_uid=folder_uid,
                parent_uid='',
                folder_key='',
                encrypted_by=int(folder_pb2.ENCRYPTED_BY_TEAM_KEY),
            ),
        ])
        storage.folder_accesses.put_links([
            nsf.NSFFolderAccess(
                folder_uid=folder_uid,
                access_type_uid=team_uid,
                access_type=int(folder_pb2.AT_TEAM),
                folder_key_encrypted=utils.base64_url_encode(
                    crypto.encrypt_aes_v2(folder_key, team_aes)
                ),
                folder_key_type=int(folder_pb2.encrypted_by_data_key_gcm),
            ),
        ])

        keys = nsf_crypto.decrypt_folder_keys(storage, auth, teams={})
        self.assertNotIn(folder_uid, keys)

    def test_parent_key_without_parent_falls_back_to_team_access(self):
        storage = memory_nsf_storage.InMemoryNSFStorage()
        auth = _auth()
        team_uid = utils.generate_uid()
        team_aes = utils.generate_aes_key()
        folder_key = utils.generate_aes_key()
        parent_uid = utils.generate_uid()
        folder_uid = _put_folder(storage, 'Child Shared', folder_key, parent_uid=parent_uid)
        storage.folder_keys.put_links([
            nsf.NSFFolderKey(
                folder_uid=folder_uid,
                parent_uid=parent_uid,
                folder_key=utils.base64_url_encode(
                    crypto.encrypt_aes_v2(folder_key, utils.generate_aes_key())
                ),
                encrypted_by=int(folder_pb2.ENCRYPTED_BY_PARENT_KEY),
            ),
        ])
        storage.folder_accesses.put_links([
            nsf.NSFFolderAccess(
                folder_uid=folder_uid,
                access_type_uid=team_uid,
                access_type=int(folder_pb2.AT_TEAM),
                folder_key_encrypted=utils.base64_url_encode(
                    crypto.encrypt_aes_v2(folder_key, team_aes)
                ),
                folder_key_type=int(folder_pb2.encrypted_by_data_key_gcm),
            ),
        ])
        teams = {team_uid: nsf_crypto.TeamKeyMaterial(team_key=team_aes)}

        keys = nsf_crypto.decrypt_folder_keys(storage, auth, teams=teams)
        name = nsf_crypto.decrypt_folder_name(
            storage.folders.get_entity(folder_uid).data, keys[folder_uid]
        )
        self.assertEqual(name, 'Child Shared')

    def test_user_access_fallback(self):
        storage = memory_nsf_storage.InMemoryNSFStorage()
        auth = _auth()
        folder_key = utils.generate_aes_key()
        folder_uid = _put_folder(storage, 'Access Shared', folder_key)
        storage.folder_keys.put_links([
            nsf.NSFFolderKey(
                folder_uid=folder_uid,
                parent_uid='',
                folder_key=utils.base64_url_encode(
                    crypto.encrypt_aes_v2(folder_key, utils.generate_aes_key())
                ),
                encrypted_by=int(folder_pb2.ENCRYPTED_BY_USER_KEY),
            ),
        ])
        storage.folder_accesses.put_links([
            nsf.NSFFolderAccess(
                folder_uid=folder_uid,
                access_type_uid=utils.generate_uid(),
                access_type=int(folder_pb2.AT_USER),
                folder_key_encrypted=utils.base64_url_encode(
                    crypto.encrypt_aes_v2(folder_key, auth.data_key)
                ),
                folder_key_type=int(folder_pb2.encrypted_by_data_key_gcm),
            ),
        ])

        keys = nsf_crypto.decrypt_folder_keys(storage, auth)
        name = nsf_crypto.decrypt_folder_name(
            storage.folders.get_entity(folder_uid).data, keys[folder_uid]
        )
        self.assertEqual(name, 'Access Shared')


if __name__ == '__main__':
    unittest.main()
