import json
import unittest
from unittest.mock import Mock, patch

from keepersdk import crypto, utils
from keepersdk.proto import record_pb2, remove_pb2, trashcan_sync_pb2
from keepersdk.vault import trash_management


class TestNsfTrashManagement(unittest.TestCase):

    def setUp(self):
        trash_management.TrashManagement.clear_nsf_trashcan_cache()
        self.addCleanup(trash_management.TrashManagement.clear_nsf_trashcan_cache)

    def _vault(self, data_key=None, username='user@company.com'):
        vault = Mock()
        vault.keeper_auth.auth_context.username = username
        vault.keeper_auth.auth_context.data_key = data_key or utils.generate_aes_key()
        vault.keeper_auth.auth_context.rsa_private_key = None
        vault.keeper_auth.auth_context.ec_private_key = None
        vault.nsf_data = None
        return vault

    def test_nsf_trash_sync_decrypts_and_caches_items(self):
        data_key = utils.generate_aes_key()
        folder_key = utils.generate_aes_key()
        record_key = utils.generate_aes_key()
        folder_uid = utils.generate_uid()
        record_uid = utils.generate_uid()
        trashcan_uid = utils.generate_uid()

        response = trashcan_sync_pb2.TrashcanSyncResponse(sync_point=17, has_more=False)
        folder = response.trashcan_data.trashcan_folders.add()
        folder.folder_uid = utils.base64_url_decode(folder_uid)
        folder.trashcan_uid = utils.base64_url_decode(trashcan_uid)
        folder.folder_key = crypto.encrypt_aes_v2(folder_key, data_key)
        folder.folder_key_type = record_pb2.ENCRYPTED_BY_DATA_KEY_GCM
        folder.date_deleted = 1234

        record = response.trashcan_data.trashcan_records.add()
        record.record_uid = utils.base64_url_decode(record_uid)
        record.trashcan_uid = utils.base64_url_decode(trashcan_uid)
        record.date_deleted = 5678
        record.folder_record_key.folder_uid = utils.base64_url_decode(folder_uid)
        record.folder_record_key.record_uid = utils.base64_url_decode(record_uid)
        record.folder_record_key.record_key = crypto.encrypt_aes_v2(record_key, data_key)
        record.folder_record_key.record_key_type = record_pb2.ENCRYPTED_BY_DATA_KEY_GCM

        vault = self._vault(data_key)
        vault.keeper_auth.execute_auth_rest.return_value = response

        trash_management.TrashManagement._ensure_nsf_trashcan_synced(vault)
        records = trash_management.TrashManagement.nsf_trashcan_record_cache
        folders = trash_management.TrashManagement.nsf_trashcan_folder_cache

        self.assertEqual(records[record_uid]['record_key_unencrypted'], record_key)
        self.assertEqual(records[record_uid]['folder_uid'], folder_uid)
        self.assertEqual(folders[folder_uid]['folder_key_unencrypted'], folder_key)
        self.assertEqual(trash_management.TrashManagement.nsf_trashcan_sync_point, 17)
        self.assertEqual(vault.keeper_auth.execute_auth_rest.call_count, 1)

    def test_nsf_trash_sync_removes_deleted_cache_entries(self):
        record_uid = utils.generate_uid()
        folder_uid = utils.generate_uid()
        trash_management.TrashManagement.nsf_trashcan_record_cache[record_uid] = {'record_uid': record_uid}
        trash_management.TrashManagement.nsf_trashcan_folder_cache[folder_uid] = {'folder_uid': folder_uid}

        response = trashcan_sync_pb2.TrashcanSyncResponse(sync_point=22, has_more=False)
        removed_record = response.trashcan_data.removed_trashcan_records.add()
        removed_record.record_uid = utils.base64_url_decode(record_uid)
        removed_folder = response.trashcan_data.removed_trashcan_folders.add()
        removed_folder.folder_uid = utils.base64_url_decode(folder_uid)

        vault = self._vault()
        vault.keeper_auth.execute_auth_rest.return_value = response
        trash_management.TrashManagement._ensure_nsf_trashcan_synced(vault)

        self.assertNotIn(record_uid, trash_management.TrashManagement.nsf_trashcan_record_cache)
        self.assertNotIn(folder_uid, trash_management.TrashManagement.nsf_trashcan_folder_cache)

    def test_restore_nsf_record_uses_target_folder_key(self):
        data_key = utils.generate_aes_key()
        target_key = utils.generate_aes_key()
        record_key = utils.generate_aes_key()
        record_uid = utils.generate_uid()
        source_folder_uid = utils.generate_uid()
        target_folder_uid = utils.generate_uid()

        nsf_records = {
            record_uid: {
                'record_uid': record_uid,
                'folder_uid': source_folder_uid,
                'record_key_unencrypted': record_key,
            }
        }
        nsf_folders = {}
        response = remove_pb2.TrashcanRestoreResponse()
        result = response.results.add()
        result.item_uid = utils.base64_url_decode(record_uid)
        result.item_type = remove_pb2.RESTORE_ITEM_RECORD
        result.status = remove_pb2.RS_SUCCESS

        vault = self._vault(data_key)
        vault.nsf_data = Mock()
        vault.keeper_auth.execute_auth_rest.return_value = response

        with patch.object(trash_management.nsf_management, '_get_folder_key', return_value=target_key):
            restored = trash_management._execute_nsf_restoration(
                vault, {record_uid}, set(), nsf_records, nsf_folders,
                target_folder_uid=target_folder_uid)

        self.assertEqual(restored, {record_uid})
        request = vault.keeper_auth.execute_auth_rest.call_args.args[1]
        self.assertEqual(request.target_folder_uid, utils.base64_url_decode(target_folder_uid))
        self.assertEqual(len(request.records), 1)
        self.assertEqual(request.records[0].record_uid, utils.base64_url_decode(record_uid))
        self.assertEqual(
            crypto.decrypt_aes_v2(request.records[0].encrypted_record_key, target_key),
            record_key,
        )
        self.assertEqual(request.records[0].source_folder_uid, utils.base64_url_decode(source_folder_uid))

    def test_restore_nsf_groups_items_by_original_destination(self):
        data_key = utils.generate_aes_key()
        record_key_1 = utils.generate_aes_key()
        record_key_2 = utils.generate_aes_key()
        record_uid_1 = utils.generate_uid()
        record_uid_2 = utils.generate_uid()
        folder_uid_1 = utils.generate_uid()
        folder_uid_2 = utils.generate_uid()

        nsf_records = {
            record_uid_1: {'record_uid': record_uid_1, 'folder_uid': folder_uid_1, 'record_key_unencrypted': record_key_1},
            record_uid_2: {'record_uid': record_uid_2, 'folder_uid': folder_uid_2, 'record_key_unencrypted': record_key_2},
        }
        vault = self._vault(data_key)

        responses = []
        for uid in (record_uid_1, record_uid_2):
            response = remove_pb2.TrashcanRestoreResponse()
            result = response.results.add()
            result.item_uid = utils.base64_url_decode(uid)
            result.item_type = remove_pb2.RESTORE_ITEM_RECORD
            result.status = remove_pb2.RS_SUCCESS
            responses.append(response)
        vault.keeper_auth.execute_auth_rest.side_effect = responses
        vault.nsf_data = Mock()

        with patch.object(trash_management.nsf_management, '_get_folder_key',
                          return_value=utils.generate_aes_key()):
            restored = trash_management._execute_nsf_restoration(
                vault, {record_uid_1, record_uid_2}, set(), nsf_records, {})

        self.assertEqual(restored, {record_uid_1, record_uid_2})
        self.assertEqual(vault.keeper_auth.execute_auth_rest.call_count, 2)
        destinations = {
            call.args[1].target_folder_uid
            for call in vault.keeper_auth.execute_auth_rest.call_args_list
        }
        self.assertEqual(destinations, {
            utils.base64_url_decode(folder_uid_1),
            utils.base64_url_decode(folder_uid_2),
        })

    def test_restore_plan_matches_nsf_record_title(self):
        record_uid = utils.generate_uid()
        vault = self._vault()
        trash_data = {
            'deleted_records': {},
            'orphaned_records': {},
            'deleted_shared_records': {},
            'deleted_shared_folders': {},
            'nsf_records': {record_uid: {'record_uid': record_uid}},
            'nsf_folders': {},
        }
        with patch.object(
                trash_management.nsf_management,
                'get_nsf_record_details',
                return_value={'data': [{'record_uid': record_uid, 'title': 'Server One', 'type': 'login'}]}):
            plan = trash_management._create_restore_plan(['Server*'], trash_data, vault)
        self.assertEqual(plan['nsf_records_to_restore'], {record_uid})

    def test_target_folder_rejects_classic_restore(self):
        vault = self._vault()
        classic_uid = utils.generate_uid()
        trash_data = {
            'deleted_records': {classic_uid: {'record_uid': classic_uid}},
            'orphaned_records': {},
            'deleted_shared_records': {},
            'deleted_shared_folders': {},
            'nsf_records': {},
            'nsf_folders': {},
        }
        with patch.object(trash_management, '_load_trash_data', return_value=trash_data):
            with self.assertRaises(ValueError):
                trash_management.restore_trash_records(
                    vault, [classic_uid], target_folder_uid=utils.generate_uid())


    @staticmethod
    def _sync_response(sync_point=1, has_more=False, continuation_token=b''):
        return trashcan_sync_pb2.TrashcanSyncResponse(
            sync_point=sync_point, has_more=has_more, continuationToken=continuation_token)

    @staticmethod
    def _restore_response(*items):
        response = remove_pb2.TrashcanRestoreResponse()
        for uid, item_type, status in items:
            result = response.results.add()
            result.item_uid = utils.base64_url_decode(uid)
            result.item_type = item_type
            result.status = status
        return response

    def test_nsf_trash_sync_decrypts_keys_wrapped_by_folder_keys(self):
        data_key = utils.generate_aes_key()
        parent_key = utils.generate_aes_key()
        child_key = utils.generate_aes_key()
        record_key = utils.generate_aes_key()
        parent_uid = utils.generate_uid()
        child_uid = utils.generate_uid()
        record_uid = utils.generate_uid()

        response = self._sync_response()
        # Child listed before parent: decryption must not depend on response order.
        child = response.trashcan_data.trashcan_folders.add()
        child.folder_uid = utils.base64_url_decode(child_uid)
        child.parent_uid = utils.base64_url_decode(parent_uid)
        child.folder_key = crypto.encrypt_aes_v2(child_key, parent_key)
        child.folder_key_type = record_pb2.ENCRYPTED_BY_ROOT_KEY_GCM
        parent = response.trashcan_data.trashcan_folders.add()
        parent.folder_uid = utils.base64_url_decode(parent_uid)
        parent.folder_key = crypto.encrypt_aes_v2(parent_key, data_key)
        parent.folder_key_type = record_pb2.ENCRYPTED_BY_DATA_KEY_GCM
        record = response.trashcan_data.trashcan_records.add()
        record.record_uid = utils.base64_url_decode(record_uid)
        record.folder_record_key.folder_uid = utils.base64_url_decode(child_uid)
        record.folder_record_key.record_key = crypto.encrypt_aes_v2(record_key, child_key)
        record.folder_record_key.record_key_type = record_pb2.ENCRYPTED_BY_ROOT_KEY_GCM

        vault = self._vault(data_key)
        vault.keeper_auth.execute_auth_rest.return_value = response
        trash_management.TrashManagement._ensure_nsf_trashcan_synced(vault)

        folders = trash_management.TrashManagement.nsf_trashcan_folder_cache
        records = trash_management.TrashManagement.nsf_trashcan_record_cache
        self.assertEqual(folders[parent_uid]['folder_key_unencrypted'], parent_key)
        self.assertEqual(folders[child_uid]['folder_key_unencrypted'], child_key)
        self.assertEqual(records[record_uid]['record_key_unencrypted'], record_key)

    def test_nsf_trash_sync_decrypts_record_key_with_live_folder_key(self):
        folder_key = utils.generate_aes_key()
        record_key = utils.generate_aes_key()
        folder_uid = utils.generate_uid()
        record_uid = utils.generate_uid()
        response = self._sync_response()
        record = response.trashcan_data.trashcan_records.add()
        record.record_uid = utils.base64_url_decode(record_uid)
        record.folder_record_key.folder_uid = utils.base64_url_decode(folder_uid)
        record.folder_record_key.record_key = crypto.encrypt_aes_v2(record_key, folder_key)
        record.folder_record_key.record_key_type = record_pb2.ENCRYPTED_BY_ROOT_KEY_GCM

        vault = self._vault()
        vault.nsf_data = Mock()
        vault.keeper_auth.execute_auth_rest.return_value = response
        with patch.object(trash_management.nsf_management, '_get_folder_key', return_value=folder_key):
            trash_management.TrashManagement._ensure_nsf_trashcan_synced(vault)

        records = trash_management.TrashManagement.nsf_trashcan_record_cache
        self.assertEqual(records[record_uid]['record_key_unencrypted'], record_key)

    def test_nsf_trash_cache_is_reset_for_another_user(self):
        stale_uid = utils.generate_uid()
        trash_management.TrashManagement.nsf_trashcan_owner = 'first@company.com'
        trash_management.TrashManagement.nsf_trashcan_sync_point = 99
        trash_management.TrashManagement.nsf_trashcan_record_cache[stale_uid] = {'record_uid': stale_uid}

        vault = self._vault(username='second@company.com')
        vault.keeper_auth.execute_auth_rest.return_value = self._sync_response(sync_point=5)
        trash_management.TrashManagement._ensure_nsf_trashcan_synced(vault)

        request = vault.keeper_auth.execute_auth_rest.call_args.args[1]
        self.assertEqual(request.sync_point, 0)
        self.assertNotIn(stale_uid, trash_management.TrashManagement.nsf_trashcan_record_cache)
        self.assertEqual(trash_management.TrashManagement.nsf_trashcan_owner, 'second@company.com')

    def test_nsf_trash_sync_follows_continuation_token(self):
        vault = self._vault()
        vault.keeper_auth.execute_auth_rest.side_effect = [
            self._sync_response(sync_point=3, has_more=True, continuation_token=b'next'),
            self._sync_response(sync_point=4, has_more=False),
        ]
        trash_management.TrashManagement._ensure_nsf_trashcan_synced(vault)

        second_request = vault.keeper_auth.execute_auth_rest.call_args_list[1].args[1]
        self.assertEqual(second_request.continuationToken, b'next')
        self.assertEqual(trash_management.TrashManagement.nsf_trashcan_sync_point, 4)

    def test_nsf_trash_sync_stops_when_server_does_not_advance(self):
        vault = self._vault()
        vault.keeper_auth.execute_auth_rest.return_value = self._sync_response(sync_point=0, has_more=True)
        trash_management.TrashManagement._ensure_nsf_trashcan_synced(vault)
        self.assertEqual(vault.keeper_auth.execute_auth_rest.call_count, 1)

    def test_load_nsf_trashcan_tolerates_errors(self):
        vault = self._vault()
        vault.nsf_data = Mock()
        vault.keeper_auth.execute_auth_rest.side_effect = Exception('endpoint unavailable')
        with self.assertLogs(trash_management.logger, level='WARNING'):
            self.assertFalse(trash_management.TrashManagement.load_nsf_trashcan(vault))

    def test_load_nsf_trashcan_skips_vault_without_nsf(self):
        vault = self._vault()
        self.assertFalse(trash_management.TrashManagement.load_nsf_trashcan(vault))
        vault.keeper_auth.execute_auth_rest.assert_not_called()

    def test_restore_nsf_skips_items_when_target_key_unavailable(self):
        record_uid = utils.generate_uid()
        folder_uid = utils.generate_uid()
        nsf_records = {record_uid: {
            'record_uid': record_uid, 'folder_uid': folder_uid,
            'record_key_unencrypted': utils.generate_aes_key()}}
        vault = self._vault()
        vault.nsf_data = Mock()
        with patch.object(trash_management.nsf_management, '_get_folder_key',
                          side_effect=trash_management.nsf_management.NsfError('no key')):
            with self.assertLogs(trash_management.logger, level='WARNING'):
                restored = trash_management._execute_nsf_restoration(
                    vault, {record_uid}, set(), nsf_records, {})

        self.assertEqual(restored, set())
        vault.keeper_auth.execute_auth_rest.assert_not_called()

    def test_restore_nsf_restores_parent_folders_before_children_and_records(self):
        data_key = utils.generate_aes_key()
        parent_key = utils.generate_aes_key()
        child_key = utils.generate_aes_key()
        parent_uid = utils.generate_uid()
        child_uid = utils.generate_uid()
        record_uid = utils.generate_uid()
        nsf_folders = {
            child_uid: {'folder_uid': child_uid, 'parent_uid': parent_uid, 'folder_key_unencrypted': child_key},
            parent_uid: {'folder_uid': parent_uid, 'parent_uid': None, 'folder_key_unencrypted': parent_key},
        }
        nsf_records = {record_uid: {
            'record_uid': record_uid, 'folder_uid': child_uid,
            'record_key_unencrypted': utils.generate_aes_key()}}
        trash_management.TrashManagement.nsf_trashcan_folder_cache.update(nsf_folders)

        vault = self._vault(data_key)
        vault.keeper_auth.execute_auth_rest.side_effect = [
            self._restore_response((parent_uid, remove_pb2.RESTORE_ITEM_FOLDER, remove_pb2.RS_SUCCESS)),
            self._restore_response((child_uid, remove_pb2.RESTORE_ITEM_FOLDER, remove_pb2.RS_SUCCESS)),
            self._restore_response((record_uid, remove_pb2.RESTORE_ITEM_RECORD, remove_pb2.RS_NOT_IN_TRASHCAN)),
        ]
        with self.assertNoLogs(trash_management.logger, level='WARNING'):
            trash_management._execute_nsf_restoration(
                vault, {record_uid}, {parent_uid, child_uid}, nsf_records, nsf_folders)

        requests = [c.args[1] for c in vault.keeper_auth.execute_auth_rest.call_args_list]
        self.assertEqual([r.folders[0].folder_uid for r in requests[:2]],
                         [utils.base64_url_decode(parent_uid), utils.base64_url_decode(child_uid)])
        self.assertEqual(
            crypto.decrypt_aes_v2(requests[0].folders[0].encrypted_folder_key, data_key), parent_key)
        self.assertEqual(
            crypto.decrypt_aes_v2(requests[1].folders[0].encrypted_folder_key, parent_key), child_key)
        self.assertEqual(requests[2].records[0].record_uid, utils.base64_url_decode(record_uid))
        self.assertEqual(trash_management.TrashManagement.nsf_trashcan_folder_cache, {})

    def test_nsf_record_details_use_trash_keys_and_are_memoized(self):
        record_uid = utils.generate_uid()
        record_key = utils.generate_aes_key()
        nsf_records = {record_uid: {'record_uid': record_uid, 'record_key_unencrypted': record_key}}
        vault = self._vault()
        with patch.object(
                trash_management.nsf_management, 'get_nsf_record_details',
                return_value={'data': [{'record_uid': record_uid, 'title': 'Db', 'type': 'login'}]}) as details:
            first = trash_management.TrashManagement.get_nsf_trashcan_record_details(vault, nsf_records)
            second = trash_management.TrashManagement.get_nsf_trashcan_record_details(vault, nsf_records)

        self.assertEqual(first, second)
        self.assertEqual(first[record_uid]['title'], 'Db')
        details.assert_called_once()
        self.assertEqual(details.call_args.kwargs['record_keys'], {record_uid: record_key})


if __name__ == '__main__':
    unittest.main()