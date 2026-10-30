import unittest
from unittest.mock import Mock, patch

from keepersdk import utils
from keepersdk.proto import keeperdrive_convert_pb2
from keepersdk.vault import nsf_management
from keepersdk.errors import KeeperApiError


class NsfRecordConversionTests(unittest.TestCase):
    def setUp(self):
        self.uid_bytes = b'\x01' * 16
        self.uid = utils.base64_url_encode(self.uid_bytes)
        self.record_key = b'\x02' * 32
        self.vault = Mock()
        self.vault.keeper_auth.auth_context.data_key = b'\x03' * 32
        self.vault.vault_data.get_record.return_value = object()
        self.vault.vault_data.get_record_key.return_value = self.record_key
        self.vault.sync_requested = False

    @patch('keepersdk.vault.nsf_management.is_nsf_record', return_value=False)
    @patch('keepersdk.vault.nsf_management.crypto.encrypt_aes_v2', return_value=b'encrypted')
    def test_successful_conversion_sends_encrypted_keys_and_syncs(self, _encrypt, _is_nsf):
        response = keeperdrive_convert_pb2.ConvertRecordResponse()
        response.results.add(record_uid=self.uid_bytes, status=keeperdrive_convert_pb2.OK)
        self.vault.keeper_auth.execute_auth_rest.return_value = response

        results = nsf_management.convert_classic_records_to_nsf(self.vault, [self.uid])

        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].success)
        self.assertEqual(results[0].status, 'OK')
        args, kwargs = self.vault.keeper_auth.execute_auth_rest.call_args
        self.assertEqual(args[0], 'vault/records/v3/convert')
        self.assertEqual(len(args[1].records), 1)
        self.assertEqual(args[1].records[0].record_uid, self.uid_bytes)
        self.assertEqual(args[1].records[0].folder_uid, b'')
        self.assertEqual(kwargs['response_type'], keeperdrive_convert_pb2.ConvertRecordResponse)
        self.vault.run_pending_jobs.assert_called_once()

    @patch('keepersdk.vault.nsf_management.is_nsf_record', return_value=True)
    def test_already_nsf_record_is_skipped(self, _is_nsf):
        results = nsf_management.convert_classic_records_to_nsf(self.vault, [self.uid])
        self.assertTrue(results[0].skipped)
        self.assertEqual(results[0].status, 'SKIPPED_ALREADY_NSF')
        self.vault.keeper_auth.execute_auth_rest.assert_not_called()

    @patch('keepersdk.vault.nsf_management.is_nsf_record', return_value=False)
    def test_missing_classic_record_is_skipped(self, _is_nsf):
        self.vault.vault_data.get_record.return_value = None
        results = nsf_management.convert_classic_records_to_nsf(self.vault, [self.uid])
        self.assertTrue(results[0].skipped)
        self.assertEqual(results[0].status, 'SKIPPED_NOT_FOUND')
        self.vault.keeper_auth.execute_auth_rest.assert_not_called()

    def test_invalid_uid_is_skipped(self):
        results = nsf_management.convert_classic_records_to_nsf(self.vault, ['not-a-uid'])
        self.assertTrue(results[0].skipped)
        self.assertEqual(results[0].status, 'SKIPPED_INVALID_UID')
        self.vault.keeper_auth.execute_auth_rest.assert_not_called()

    @patch('keepersdk.vault.nsf_management.is_nsf_record', return_value=False)
    @patch('keepersdk.vault.nsf_management.crypto.encrypt_aes_v2', return_value=b'encrypted')
    def test_duplicate_uid_is_only_submitted_once(self, _encrypt, _is_nsf):
        response = keeperdrive_convert_pb2.ConvertRecordResponse()
        response.results.add(record_uid=self.uid_bytes, status=keeperdrive_convert_pb2.OK)
        self.vault.keeper_auth.execute_auth_rest.return_value = response
        results = nsf_management.convert_classic_records_to_nsf(self.vault, [self.uid, self.uid])
        self.assertTrue(results[0].success)
        self.assertTrue(results[1].skipped)
        self.assertEqual(results[1].status, 'SKIPPED_DUPLICATE')
        self.assertEqual(len(self.vault.keeper_auth.execute_auth_rest.call_args.args[1].records), 1)

    @patch('keepersdk.vault.nsf_management.is_nsf_record', return_value=False)
    @patch('keepersdk.vault.nsf_management.crypto.encrypt_aes_v2', return_value=b'encrypted')
    def test_batches_at_100_record_boundary(self, _encrypt, _is_nsf):
        uids = [utils.base64_url_encode(i.to_bytes(16, 'big')) for i in range(1, 102)]
        responses = []
        for chunk in (uids[:100], uids[100:]):
            response = keeperdrive_convert_pb2.ConvertRecordResponse()
            for uid in chunk:
                response.results.add(record_uid=utils.base64_url_decode(uid), status=keeperdrive_convert_pb2.OK)
            responses.append(response)
        self.vault.keeper_auth.execute_auth_rest.side_effect = responses

        results = nsf_management.convert_classic_records_to_nsf(self.vault, uids)

        self.assertEqual(len(results), 101)
        self.assertTrue(all(result.success for result in results))
        self.assertEqual(self.vault.keeper_auth.execute_auth_rest.call_count, 2)
        batch_sizes = [len(call.args[1].records) for call in self.vault.keeper_auth.execute_auth_rest.call_args_list]
        self.assertEqual(batch_sizes, [100, 1])

    @patch('keepersdk.vault.nsf_management.is_nsf_record', return_value=False)
    @patch('keepersdk.vault.nsf_management.crypto.encrypt_aes_v2', return_value=b'encrypted')
    def test_later_batch_api_error_preserves_prior_success_and_syncs(self, _encrypt, _is_nsf):
        uids = [utils.base64_url_encode(i.to_bytes(16, 'big')) for i in range(1, 102)]
        first_response = keeperdrive_convert_pb2.ConvertRecordResponse()
        for uid in uids[:100]:
            first_response.results.add(record_uid=utils.base64_url_decode(uid), status=keeperdrive_convert_pb2.OK)
        self.vault.keeper_auth.execute_auth_rest.side_effect = [
            first_response, KeeperApiError('access_denied', 'Access denied')]

        results = nsf_management.convert_classic_records_to_nsf(self.vault, uids)

        self.assertEqual(len(results), 101)
        self.assertTrue(all(result.success for result in results[:100]))
        self.assertTrue(results[100].outcome_uncertain)
        self.assertEqual(results[100].status, 'ACCESS_DENIED')
        self.vault.run_pending_jobs.assert_called_once()

    @patch('keepersdk.vault.nsf_management.is_nsf_record', return_value=False)
    @patch('keepersdk.vault.nsf_management.crypto.encrypt_aes_v2', return_value=b'encrypted')
    def test_transport_failure_marks_batch_uncertain_and_syncs(self, _encrypt, _is_nsf):
        self.vault.keeper_auth.execute_auth_rest.side_effect = OSError('connection lost')

        results = nsf_management.convert_classic_records_to_nsf(self.vault, [self.uid])

        self.assertTrue(results[0].outcome_uncertain)
        self.assertEqual(results[0].status, 'RESPONSE_UNAVAILABLE')
        self.vault.run_pending_jobs.assert_called_once()

    @patch('keepersdk.vault.nsf_management.resolve_nsf_folder_uid', return_value='AQEBAQEBAQEBAQEBAQEBAQ')
    @patch('keepersdk.vault.nsf_management.is_nsf_folder', return_value=True)
    @patch('keepersdk.vault.nsf_management._get_folder_key', return_value=b'\x04' * 32)
    @patch('keepersdk.vault.nsf_management.is_nsf_record', return_value=False)
    @patch('keepersdk.vault.nsf_management.crypto.encrypt_aes_v2', return_value=b'encrypted')
    def test_folder_destination_is_included_in_request(self, _encrypt, _is_nsf, _folder_key, _is_folder, _resolve):
        response = keeperdrive_convert_pb2.ConvertRecordResponse()
        response.results.add(record_uid=self.uid_bytes, status=keeperdrive_convert_pb2.OK)
        self.vault.keeper_auth.execute_auth_rest.return_value = response

        nsf_management.convert_classic_records_to_nsf(self.vault, [self.uid], folder_identifier='destination')

        request = self.vault.keeper_auth.execute_auth_rest.call_args.args[1]
        self.assertEqual(request.records[0].folder_uid, self.uid_bytes)
        self.assertEqual(_encrypt.call_args_list[0].args[1], b'\x04' * 32)

    @patch('keepersdk.vault.nsf_management.is_nsf_record', return_value=False)
    @patch('keepersdk.vault.nsf_management.crypto.encrypt_aes_v2', return_value=b'encrypted')
    def test_refresh_failure_is_reported_as_warning(self, _encrypt, _is_nsf):
        response = keeperdrive_convert_pb2.ConvertRecordResponse()
        response.results.add(record_uid=self.uid_bytes, status=keeperdrive_convert_pb2.OK)
        self.vault.keeper_auth.execute_auth_rest.return_value = response
        self.vault.run_pending_jobs.side_effect = RuntimeError('sync failed')

        results = nsf_management.convert_classic_records_to_nsf(self.vault, [self.uid])

        self.assertTrue(results[0].success)
        self.assertIn('Vault refresh failed', results[0].refresh_warning)


class NsfConversionDestinationTests(unittest.TestCase):
    def setUp(self):
        self.vault = Mock()
        self.folders = []
        for folder_uid, name in (('FOLDER_A', 'data234'), ('FOLDER_B', 'Data234'), ('FOLDER_C', 'unique')):
            folder = Mock(folder_uid=folder_uid)
            folder.name = name
            self.folders.append(folder)
        view = Mock()
        view.folders.return_value = self.folders
        view.get_folder.side_effect = lambda uid: next((f for f in self.folders if f.folder_uid == uid), None)
        patcher = patch('keepersdk.vault.nsf_management._nsf_view', return_value=view)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_duplicate_folder_names_require_uid(self):
        with self.assertRaises(nsf_management.NsfError) as ctx:
            nsf_management.resolve_nsf_conversion_destination(self.vault, 'data234')
        self.assertEqual(str(ctx.exception),
                         '2 NSF folders are named "data234". Use the folder UID for this operation.')

    def test_folder_is_resolved_by_unique_name_or_uid(self):
        self.assertEqual(nsf_management.resolve_nsf_conversion_destination(self.vault, 'UNIQUE'), 'FOLDER_C')
        self.assertEqual(nsf_management.resolve_nsf_conversion_destination(self.vault, 'FOLDER_A'), 'FOLDER_A')

    def test_root_and_missing_destination(self):
        self.assertEqual(nsf_management.resolve_nsf_conversion_destination(self.vault, None), '')
        self.assertEqual(nsf_management.resolve_nsf_conversion_destination(self.vault, 'My Drive'), '')
        with self.assertRaises(nsf_management.NsfError) as ctx:
            nsf_management.resolve_nsf_conversion_destination(self.vault, 'missing')
        self.assertIn('is not an NSF folder', str(ctx.exception))

    def test_conversion_is_not_sent_for_duplicate_folder_names(self):
        self.vault.keeper_auth.auth_context.data_key = b'\x03' * 32
        with self.assertRaises(nsf_management.NsfError):
            nsf_management.convert_classic_records_to_nsf(self.vault, ['UID'], folder_identifier='data234')
        self.vault.keeper_auth.execute_auth_rest.assert_not_called()


if __name__ == '__main__':
    unittest.main()
