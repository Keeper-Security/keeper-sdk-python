"""Sync-down after an NSF folder move must re-parent the folder, not add a second key link."""

import json
import unittest
from unittest.mock import Mock

from keepersdk import crypto, utils
from keepersdk.proto import SyncDown_pb2, folder_pb2
from keepersdk.vault import memory_nsf_storage, nsf_storage_types as nsf, nsf_sync
from keepersdk.vault.nsf_data import NSFData

PARENT = int(folder_pb2.FolderKeyEncryptionType.ENCRYPTED_BY_PARENT_KEY)
USER = int(folder_pb2.FolderKeyEncryptionType.ENCRYPTED_BY_USER_KEY)


def _auth():
    ctx = Mock()
    ctx.data_key = utils.generate_aes_key()
    ctx.rsa_private_key = None
    ctx.ec_private_key = None
    return ctx


class TestNsfFolderMoveSync(unittest.TestCase):

    def setUp(self):
        self.auth = _auth()
        self.storage = memory_nsf_storage.InMemoryNSFStorage()
        self.keys = {}
        # A (root) -> B ;  C (root)
        self.a = self._add('A', None)
        self.b = self._add('B', self.a)
        self.c = self._add('C', None)

    def _add(self, name, parent_uid):
        uid = utils.generate_uid()
        key = utils.generate_aes_key()
        self.keys[uid] = key
        wrap = self.keys[parent_uid] if parent_uid else self.auth.data_key
        enc = utils.base64_url_encode(crypto.encrypt_aes_v2(key, wrap))
        data = utils.base64_url_encode(crypto.encrypt_aes_v2(json.dumps({'name': name}).encode(), key))
        self.storage.folders.put_entities([nsf.NSFFolder(
            folder_uid=uid, parent_uid=parent_uid or '', data=data, folder_key=enc)])
        self.storage.folder_keys.put_links([nsf.NSFFolderKey(
            folder_uid=uid, parent_uid=parent_uid or '', folder_key=enc,
            encrypted_by=PARENT if parent_uid else USER)])
        return uid

    def _move_msg(self, folder_uid, new_parent_uid):
        wrap = self.keys[new_parent_uid] if new_parent_uid else self.auth.data_key
        msg = SyncDown_pb2.KeeperDriveData()
        fk = msg.folderKeys.add()
        fk.folderUid = utils.base64_url_decode(folder_uid)
        if new_parent_uid:
            fk.parentUid = utils.base64_url_decode(new_parent_uid)
        fk.folderKey = crypto.encrypt_aes_v2(self.keys[folder_uid], wrap)
        fk.encryptedBy = PARENT if new_parent_uid else USER
        return msg

    def test_move_under_new_parent(self):
        nsf_sync.apply_nsf_proto_message(self._move_msg(self.b, self.c), self.storage)

        links = list(self.storage.folder_keys.get_links_by_subject(self.b))
        self.assertEqual([l.parent_uid for l in links], [self.c])
        self.assertEqual(self.storage.folders.get_entity(self.b).parent_uid, self.c)

        view = NSFData(self.storage, self.auth)
        self.assertEqual(view.get_folder(self.b).parent_uid, self.c)
        self.assertEqual(view.get_folder(self.b).name, 'B')
        self.assertIn(self.b, view.get_folder(self.c).subfolder_uids)
        self.assertNotIn(self.b, view.get_folder(self.a).subfolder_uids)

    def test_move_to_root(self):
        nsf_sync.apply_nsf_proto_message(self._move_msg(self.b, None), self.storage)

        links = list(self.storage.folder_keys.get_links_by_subject(self.b))
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0].encrypted_by, USER)
        view = NSFData(self.storage, self.auth)
        self.assertIsNone(view.get_folder(self.b).parent_uid)
        self.assertEqual(view.get_folder(self.b).name, 'B')
        self.assertNotIn(self.b, view.get_folder(self.a).subfolder_uids)


if __name__ == '__main__':
    unittest.main()
