from unittest import TestCase

from keepersdk import crypto, utils
from keepersdk.vault import storage_types, memory_storage
from keepersdk.storage import types


class TestMemoryStorage(TestCase):
    def test_entity_storage(self) -> None:
        record_storage: types.IEntityStorage[storage_types.StorageRecord, str] = memory_storage.InMemoryEntityStorage()
        record_key_storage: types.ILinkStorage[
            storage_types.StorageRecordKey, str, str] = memory_storage.InMemoryLinkStorage()
        record = storage_types.StorageRecord()
        record.record_uid = utils.generate_uid()
        record.revision = 3232323
        record.data = b'DATA'
        record.owner = True
        record.version = 2

        record_storage.put_entities((record,))

        client_key = utils.generate_aes_key()
        record_key = utils.generate_aes_key()

        link = storage_types.StorageRecordKey()
        link.record_uid = record.record_uid
        link.shared_folder_uid = 'Personal UID'
        link.key_type = storage_types.KeyType.DataKey
        link.record_key = crypto.encrypt_aes_v2(record_key, client_key)
        link.can_edit = True

        record_key_storage.put_links((link,))

        recs = list(record_storage.get_all())
        self.assertEqual(len(recs), 1)
        self.assertEqual(record.record_uid, recs[0].record_uid)
        self.assertEqual(record.owner, recs[0].owner)
        self.assertEqual(record.revision, recs[0].revision)

        links = list(record_key_storage.get_links_for_subject(record.record_uid))
        self.assertEqual(len(links), 1)
        self.assertEqual(link.record_uid, links[0].record_uid)
