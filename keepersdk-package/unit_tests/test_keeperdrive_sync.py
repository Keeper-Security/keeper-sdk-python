import json
import os
import sqlite3
import unittest

from keepersdk import utils
from keepersdk.proto import SyncDown_pb2, folder_pb2, record_pb2
from keepersdk.vault import keeperdrive_data, keeperdrive_sync, keeperdrive_storage_types as kd, memory_keeperdrive_storage, sqlite_storage, storage_types


class TestKeeperDriveSync(unittest.TestCase):
    def test_coerce_int_folder_usage_type_enum_name(self):
        self.assertEqual(keeperdrive_sync._coerce_int('UT_NORMAL'), int(folder_pb2.UT_NORMAL))
        self.assertEqual(keeperdrive_sync._coerce_int(1), 1)

    def test_dict_to_folder_accepts_enum_name(self):
        folder = keeperdrive_sync._dict_to_folder({
            'folderUid': 'F1',
            'parentUid': 'P',
            'data': 'd',
            'type': 'UT_NORMAL',
            'inheritUserPermissions': 1,
            'folderKey': 'k',
            'ownerInfo': {'accountUid': 'a', 'username': 'u'},
            'dateCreated': 1,
            'lastModified': 2,
        })
        self.assertEqual(folder.folder_type, int(folder_pb2.UT_NORMAL))

    def test_keeper_drive_data_rebuild_after_sync(self):
        conn = sqlite3.connect(':memory:')
        vault = sqlite_storage.SqliteVaultStorage(lambda: conn, b'owner')
        kd = vault.keeper_drive
        view = keeperdrive_data.KeeperDriveData(kd)
        keeperdrive_sync.apply_keeper_drive_data_dict(
            kd,
            {'folders': [{'folderUid': 'F1', 'parentUid': 'P', 'data': 'd', 'type': 1,
                          'inheritUserPermissions': 0, 'folderKey': 'k',
                          'ownerInfo': {'accountUid': 'a', 'username': 'u'},
                          'dateCreated': 1, 'lastModified': 2}]},
        )
        self.assertEqual(len(list(kd.folders.get_all_entities())), 1)
        view.rebuild_data(keeperdrive_data.KeeperDriveRebuildTask(True))
        self.assertEqual(view.folder_count, 0)
        conn.close()

    def test_apply_keeperdrive_sync_down_sample(self):
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
        path = os.path.join(root, 'keeperdrive_sync_down.txt')
        with open(path, 'r', encoding='utf-8') as f:
            payload = json.load(f)

        conn = sqlite3.connect(':memory:')
        owner = b'owner-test'
        vault = sqlite_storage.SqliteVaultStorage(lambda: conn, owner)
        kd = vault.keeper_drive
        assert kd is not None
        keeperdrive_sync.apply_keeper_drive_from_full_sync_json(kd, payload)

        inner = payload['keeperDriveData']
        self.assertEqual(len(list(kd.folders.get_all_entities())), len(inner['folders']))
        self.assertEqual(len(list(kd.records.get_all_entities())), len(inner['records']))

        f0 = kd.folders.get_entity(inner['folders'][0]['folderUid'])
        assert f0 is not None
        self.assertEqual(f0.owner_username, inner['folders'][0]['ownerInfo']['username'])

        conn.close()

    def test_revoked_and_removed_sync_down_delete_main_tables(self):
        """Revoked/removed sync-down payloads delete rows from main tables only."""
        kd = memory_keeperdrive_storage.InMemoryKeeperDriveStorage()
        keeperdrive_sync.apply_keeper_drive_data_dict(
            kd,
            {
                'folders': [{'folderUid': 'F1', 'parentUid': '', 'data': 'd', 'type': 1,
                             'inheritUserPermissions': 0, 'folderKey': 'k',
                             'ownerInfo': {'accountUid': 'a', 'username': 'u'},
                             'dateCreated': 1, 'lastModified': 2}],
                'folderAccesses': [{'folderUid': 'F1', 'accessTypeUid': 'A1', 'accessType': 1,
                                    'accessRoleType': 0, 'inherited': False, 'hidden': False,
                                    'deniedAccess': False, 'dateCreated': 1, 'lastModified': 2}],
                'folderRecords': [{'folderUid': 'F1', 'recordMetadata': {'recordUid': 'R1'},
                                   'folderKeyEncryptionType': 0}],
                'records': [{'recordUid': 'R1', 'revision': 1, 'version': 1, 'shared': False,
                             'clientModifiedTime': 0, 'fileSize': 0, 'thumbnailSize': 0}],
                'recordLinks': [{'parentRecordUid': 'P1', 'childRecordUid': 'C1',
                                 'recordKey': 'k', 'revision': 1}],
                'recordAccesses': [{'recordUid': 'R1', 'accessTypeUid': 'A2', 'accessType': 1,
                                    'accessRoleType': 0, 'owner': True, 'inherited': False,
                                    'hidden': False, 'deniedAccess': False,
                                    'canViewTitle': True, 'canEdit': True, 'canView': True,
                                    'canListAccess': True, 'canUpdateAccess': True,
                                    'canDelete': True, 'canChangeOwnership': True,
                                    'canRequestAccess': True, 'canApproveAccess': True,
                                    'dateCreated': 1, 'lastModified': 2}],
            },
        )
        self.assertIsNotNone(kd.folders.get_entity('F1'))
        self.assertEqual(len(list(kd.folder_accesses.get_links_by_subject('F1'))), 1)
        self.assertEqual(len(list(kd.folder_records.get_links_by_subject('F1'))), 1)
        self.assertEqual(len(list(kd.record_links.get_all_links())), 1)
        self.assertEqual(len(list(kd.record_accesses.get_links_by_subject('R1'))), 1)

        keeperdrive_sync.apply_keeper_drive_data_dict(
            kd,
            {
                'revokedFolderAccesses': [{'folderUid': 'F1', 'actorUid': 'A1'}],
                'removedFolderRecords': [{'folderUid': 'F1', 'recordUid': 'R1'}],
                'removedRecordLinks': [{'parentRecordUid': 'P1', 'childRecordUid': 'C1'}],
                'revokedRecordAccesses': [{'recordUid': 'R1', 'actorUid': 'A2'}],
                'removedFolders': ['F1'],
            },
        )
        self.assertIsNone(kd.folders.get_entity('F1'))
        self.assertEqual(len(list(kd.folder_accesses.get_links_by_subject('F1'))), 1)
        self.assertEqual(len(list(kd.folder_records.get_links_by_subject('F1'))), 0)
        self.assertEqual(len(list(kd.record_links.get_all_links())), 0)
        self.assertEqual(len(list(kd.record_accesses.get_links_by_subject('R1'))), 0)

    def test_removed_folder_records_proto_uses_folder_record_key_fields(self):
        """Proto removedFolderRecords are FolderRecordKey (snake_case fields)."""
        storage = memory_keeperdrive_storage.InMemoryKeeperDriveStorage()
        folder_uid = utils.generate_uid()
        record_uid = utils.generate_uid()
        storage.folder_records.put_links([
            kd.KDFolderRecord(folder_uid=folder_uid, record_uid=record_uid),
        ])
        self.assertEqual(len(list(storage.folder_records.get_links_by_subject(folder_uid))), 1)

        kd_msg = SyncDown_pb2.KeeperDriveData()
        removed = kd_msg.removedFolderRecords.add()
        removed.folder_uid = utils.base64_url_decode(folder_uid)
        removed.record_uid = utils.base64_url_decode(record_uid)
        keeperdrive_sync.apply_keeper_drive_proto_message(kd_msg, storage, None)

        self.assertEqual(len(list(storage.folder_records.get_links_by_subject(folder_uid))), 0)

    def test_vault_clear_wipes_drive_tables(self):
        """``SqliteVaultStorage.clear`` clears vault and Keeper Drive rows in the same database."""
        conn = sqlite3.connect(':memory:')
        owner = b'vault-owner'
        vault = sqlite_storage.SqliteVaultStorage(lambda: conn, owner)
        kd = vault.keeper_drive

        vault.user_settings.store(storage_types.UserSettings(continuation_token=b'x'))
        keeperdrive_sync.apply_keeper_drive_data_dict(
            kd,
            {'folders': [{'folderUid': 'F1', 'parentUid': 'P', 'data': 'd', 'type': 1,
                          'inheritUserPermissions': 0, 'folderKey': 'k',
                          'ownerInfo': {'accountUid': 'a', 'username': 'u'},
                          'dateCreated': 1, 'lastModified': 2}]},
        )
        self.assertIsNotNone(kd.folders.get_entity('F1'))

        vault.clear()
        self.assertIsNone(vault.user_settings.load())
        self.assertIsNone(kd.folders.get_entity('F1'))

        conn.close()


if __name__ == '__main__':
    unittest.main()
