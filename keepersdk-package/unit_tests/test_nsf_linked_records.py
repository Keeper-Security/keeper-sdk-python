"""Unit tests for NSF records reachable only through a record link (e.g. file attachments)."""

import json
import unittest
from unittest.mock import Mock

from keepersdk import crypto, utils
from keepersdk.proto import folder_pb2
from keepersdk.vault import memory_nsf_storage, nsf_crypto, nsf_data, nsf_storage_types as nsf


def _auth():
    ctx = Mock()
    ctx.data_key = utils.generate_aes_key()
    ctx.rsa_private_key = None
    ctx.ec_private_key = None
    return ctx


def _encrypt_b64(data: bytes, key: bytes) -> str:
    return utils.base64_url_encode(crypto.encrypt_aes_v2(data, key))


class NsfLinkedRecordsTest(unittest.TestCase):
    def setUp(self):
        self.storage = memory_nsf_storage.InMemoryNSFStorage()
        self.auth = _auth()

        # A folder shared with the caller, holding a parent record the caller can open.
        self.folder_uid = utils.generate_uid()
        self.folder_key = utils.generate_aes_key()
        self.storage.folders.put_entities([nsf.NSFFolder(
            folder_uid=self.folder_uid, parent_uid='',
            data=_encrypt_b64(json.dumps({'name': 'Shared'}).encode(), self.folder_key))])
        self.storage.folder_keys.put_links([nsf.NSFFolderKey(
            folder_uid=self.folder_uid, parent_uid='',
            folder_key=_encrypt_b64(self.folder_key, self.auth.data_key),
            encrypted_by=int(folder_pb2.ENCRYPTED_BY_USER_KEY))])

        self.parent_uid, self.parent_key = self._put_record('Parent record')
        self.storage.record_keys.put_links([nsf.NSFRecordKey(
            record_uid=self.parent_uid, folder_uid=self.folder_uid,
            record_key=_encrypt_b64(self.parent_key, self.folder_key),
            folder_key_encryption_type=int(folder_pb2.ENCRYPTED_BY_PARENT_KEY))])
        self.storage.folder_records.put_links([nsf.NSFFolderRecord(
            folder_uid=self.folder_uid, record_uid=self.parent_uid)])

    def _put_record(self, title):
        record_uid = utils.generate_uid()
        record_key = utils.generate_aes_key()
        self.storage.records.put_entities([nsf.NSFRecord(
            record_uid=record_uid, version=3,
            data=_encrypt_b64(json.dumps({'title': title}).encode(), record_key))])
        return record_uid, record_key

    def _link(self, parent_uid, parent_key, child_uid, child_key, *, cbc=False):
        wrapped = crypto.encrypt_aes_v1(child_key, parent_key) if cbc else crypto.encrypt_aes_v2(child_key, parent_key)
        self.storage.record_links.put_links([nsf.NSFRecordLink(
            parent_record_uid=parent_uid, child_record_uid=child_uid,
            record_key=utils.base64_url_encode(wrapped))])

    def _rebuild(self):
        return nsf_data.NSFData(self.storage, self.auth)

    def test_attachment_shared_through_parent_record_is_decrypted(self):
        # The file has no record key and no folder entry of its own: only the parent link.
        file_uid, file_key = self._put_record('report.xlsx')
        self._link(self.parent_uid, self.parent_key, file_uid, file_key)

        entry = self._rebuild().get_record(file_uid)

        self.assertIsNotNone(entry)
        self.assertEqual(entry.record_key, file_key)
        self.assertEqual(json.loads(entry.decrypted_data)['title'], 'report.xlsx')

    def test_chain_of_links_resolves_in_any_order(self):
        child_uid, child_key = self._put_record('child')
        grandchild_uid, grandchild_key = self._put_record('grandchild')
        # Stored child-first so a single pass would miss the grandchild.
        self._link(child_uid, child_key, grandchild_uid, grandchild_key)
        self._link(self.parent_uid, self.parent_key, child_uid, child_key)

        view = self._rebuild()

        self.assertEqual(view.get_record(child_uid).record_key, child_key)
        self.assertEqual(view.get_record(grandchild_uid).record_key, grandchild_key)

    def test_cbc_wrapped_link_key_is_decrypted(self):
        file_uid, file_key = self._put_record('legacy.pdf')
        self._link(self.parent_uid, self.parent_key, file_uid, file_key, cbc=True)

        self.assertEqual(self._rebuild().get_record(file_uid).record_key, file_key)

    def test_bad_link_key_is_skipped_without_breaking_other_records(self):
        file_uid, file_key = self._put_record('report.xlsx')
        self._link(self.parent_uid, utils.generate_aes_key(), file_uid, file_key)

        view = self._rebuild()

        self.assertIsNone(view.get_record(file_uid))
        self.assertIsNotNone(view.get_record(self.parent_uid))

    def test_link_without_decryptable_parent_is_skipped(self):
        unknown_parent_uid = utils.generate_uid()
        file_uid, file_key = self._put_record('report.xlsx')
        self._link(unknown_parent_uid, utils.generate_aes_key(), file_uid, file_key)

        keys = nsf_crypto.decrypt_record_keys(self.storage, {self.folder_uid: self.folder_key}, self.auth)

        self.assertNotIn(file_uid, keys)
        self.assertIn(self.parent_uid, keys)

    def test_own_record_key_takes_precedence_over_link(self):
        file_uid, file_key = self._put_record('mine.xlsx')
        self.storage.record_keys.put_links([nsf.NSFRecordKey(
            record_uid=file_uid, folder_uid=self.folder_uid,
            record_key=_encrypt_b64(file_key, self.folder_key),
            folder_key_encryption_type=int(folder_pb2.ENCRYPTED_BY_PARENT_KEY))])
        self._link(self.parent_uid, self.parent_key, file_uid, utils.generate_aes_key())

        self.assertEqual(self._rebuild().get_record(file_uid).record_key, file_key)

    def test_attachment_of_parent_outside_any_folder_is_purged(self):
        # The parent's key is still in storage, but the parent left every folder.
        self.storage.folder_records.delete_links([(self.folder_uid, self.parent_uid)])
        file_uid, file_key = self._put_record('report.xlsx')
        self._link(self.parent_uid, self.parent_key, file_uid, file_key)

        view = self._rebuild()

        self.assertIsNone(view.get_record(self.parent_uid))
        self.assertIsNone(view.get_record(file_uid))


if __name__ == '__main__':
    unittest.main()
