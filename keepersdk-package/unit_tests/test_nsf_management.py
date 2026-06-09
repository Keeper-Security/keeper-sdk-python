import unittest

from keepersdk.vault import nsf_sync, memory_nsf_storage, nsf_management
from keepersdk.vault.nsf_data import NSFData
class _FakeVault:
    def __init__(self, view: NSFData) -> None:
        self.nsf_data = view
        self.sync_requested = False

    def run_pending_jobs(self) -> None:
        pass


class TestNsfManagement(unittest.TestCase):
    def test_list_and_resolve_from_cache(self):
        nsf = memory_nsf_storage.InMemoryNSFStorage()
        nsf_sync.apply_nsf_data_dict(
            nsf,
            {
                'folders': [{'folderUid': 'F1', 'parentUid': '', 'data': '', 'type': 1,
                             'inheritUserPermissions': 0, 'folderKey': '',
                             'ownerInfo': {'accountUid': 'a', 'username': 'u'},
                             'dateCreated': 1, 'lastModified': 2}],
                'folderRecords': [{'folderUid': 'F1', 'recordMetadata': {'recordUid': 'R1'},
                                   'folderKeyEncryptionType': 0}],
                'records': [{'recordUid': 'R1', 'revision': 1, 'version': 1, 'shared': False,
                             'clientModifiedTime': 0, 'fileSize': 0, 'thumbnailSize': 0}],
                'recordData': [{'recordUid': 'R1', 'user': {'accountUid': 'a', 'username': 'u'},
                                'data': ''}],
            },
        )
        view = NSFData(nsf)
        vault = _FakeVault(view)

        rows = nsf_management.list_nsf_items(vault)
        self.assertEqual(len(rows), 2)
        self.assertEqual(nsf_management.resolve_nsf_folder_uid(vault, 'F1'), 'F1')
        self.assertIsNone(nsf_management.resolve_nsf_record_uid(vault, 'missing'))

    def test_find_child_folder_and_build_removals(self):
        nsf = memory_nsf_storage.InMemoryNSFStorage()
        nsf_sync.apply_nsf_data_dict(
            nsf,
            {
                'folders': [
                    {'folderUid': 'P1', 'parentUid': '', 'data': '', 'type': 1,
                     'inheritUserPermissions': 0, 'folderKey': '',
                     'ownerInfo': {'accountUid': 'a', 'username': 'u'},
                     'dateCreated': 1, 'lastModified': 2},
                    {'folderUid': 'C1', 'parentUid': 'P1', 'data': '', 'type': 1,
                     'inheritUserPermissions': 0, 'folderKey': '',
                     'ownerInfo': {'accountUid': 'a', 'username': 'u'},
                     'dateCreated': 1, 'lastModified': 2},
                ],
                'records': [{'recordUid': 'R1', 'revision': 1, 'version': 1, 'shared': False,
                             'clientModifiedTime': 0, 'fileSize': 0, 'thumbnailSize': 0}],
                'recordData': [{'recordUid': 'R1', 'user': {'accountUid': 'a', 'username': 'u'},
                                'data': ''}],
                'folderRecords': [{'folderUid': 'P1', 'recordMetadata': {'recordUid': 'R1'},
                                   'folderKeyEncryptionType': 0}],
            },
        )
        view = NSFData(nsf)
        vault = _FakeVault(view)
        removals = nsf_management.build_nsf_record_removals(
            vault, ['R1'], operation_type='owner-trash')
        self.assertEqual(len(removals), 1)
        self.assertEqual(removals[0]['record_uid'], 'R1')


if __name__ == '__main__':
    unittest.main()
