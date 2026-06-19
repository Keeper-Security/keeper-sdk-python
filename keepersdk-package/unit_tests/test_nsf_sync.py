import unittest

from keepersdk import utils
from keepersdk.proto import SyncDown_pb2
from keepersdk.vault import nsf_sync, nsf_storage_types as nsf, memory_nsf_storage


class TestNSFSync(unittest.TestCase):
    def test_removed_folder_records_proto_uses_folder_record_key_fields(self):
        """Proto removedFolderRecords are FolderRecordKey (snake_case fields)."""
        storage = memory_nsf_storage.InMemoryNSFStorage()
        folder_uid = utils.generate_uid()
        record_uid = utils.generate_uid()
        storage.folder_records.put_links([
            nsf.NSFFolderRecord(folder_uid=folder_uid, record_uid=record_uid),
        ])
        self.assertEqual(len(list(storage.folder_records.get_links_by_subject(folder_uid))), 1)

        nsf_msg = SyncDown_pb2.KeeperDriveData()
        removed = nsf_msg.removedFolderRecords.add()
        removed.folder_uid = utils.base64_url_decode(folder_uid)
        removed.record_uid = utils.base64_url_decode(record_uid)
        nsf_sync.apply_nsf_proto_message(nsf_msg, storage, None)

        self.assertEqual(len(list(storage.folder_records.get_links_by_subject(folder_uid))), 0)


if __name__ == '__main__':
    unittest.main()
