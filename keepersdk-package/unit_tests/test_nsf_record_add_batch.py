import unittest
from typing import List
from unittest.mock import MagicMock, patch

from keepersdk import utils
from keepersdk.errors import KeeperApiError
from keepersdk.proto import record_pb2
from keepersdk.vault import nsf_management


class TestNsfRecordAddBatch(unittest.TestCase):
    def _vault(self):
        vault = MagicMock()
        vault.keeper_auth.auth_context.data_key = b'0' * 32
        vault.keeper_auth.execute_auth_rest.return_value = None
        return vault

    def _success_response(self, record_uids):
        response = record_pb2.RecordsModifyResponse()
        for uid in record_uids:
            row = response.records.add()
            row.record_uid = utils.base64_url_decode(uid)
            row.status = record_pb2.RS_SUCCESS
            row.message = ''
        return response

    @patch.object(nsf_management, 'is_nsf_folder', return_value=True)
    @patch.object(nsf_management, 'resolve_nsf_folder_uid', side_effect=lambda _v, uid: uid)
    @patch.object(nsf_management, '_get_folder_key', return_value=b'1' * 32)
    @patch.object(
        nsf_management.utils,
        'generate_uid',
        side_effect=[utils.generate_uid() for _ in range(5)],
    )
    def test_create_nsf_records_batch_single_request(self, *_mocks):
        vault = self._vault()
        expected_uids: List[str] = []

        def _execute(rest_endpoint, request, response_type=None):
            expected_uids.extend(
                utils.base64_url_encode(record.recordUid) for record in request.records)
            return self._success_response(expected_uids)

        vault.keeper_auth.execute_auth_rest.side_effect = _execute

        specs = [
            {'title': f'Record {i}', 'record_type': 'login', 'fields': {'login': f'user{i}'}}
            for i in range(3)
        ]
        results = nsf_management.create_nsf_records_batch(
            vault, specs, request_sync=False)

        self.assertEqual(len(results), 3)
        self.assertTrue(all(result.success for result in results))
        vault.keeper_auth.execute_auth_rest.assert_called_once()
        request = vault.keeper_auth.execute_auth_rest.call_args.args[1]
        self.assertEqual(len(request.records), 3)

    def test_create_nsf_records_batch_rejects_over_limit(self):
        vault = self._vault()
        specs = [
            {'title': f'Record {i}', 'record_type': 'login'}
            for i in range(nsf_management.NSF_RECORD_ADD_BATCH_LIMIT + 1)
        ]
        with self.assertRaisesRegex(ValueError, '1000'):
            nsf_management.create_nsf_records_batch(vault, specs, request_sync=False)

    @patch.object(nsf_management, 'is_nsf_folder', return_value=True)
    @patch.object(nsf_management, 'resolve_nsf_folder_uid', side_effect=lambda _v, uid: uid)
    @patch.object(nsf_management, '_get_folder_key', return_value=b'1' * 32)
    @patch.object(
        nsf_management.utils,
        'generate_uid',
        side_effect=[utils.generate_uid() for _ in range(1001)],
    )
    def test_create_nsf_records_chunks_large_input(self, generate_uid_mock, *_mocks):
        vault = self._vault()

        call_count = {'value': 0}

        def _execute(rest_endpoint, request, response_type=None):
            call_count['value'] += 1
            uids = [utils.base64_url_encode(record.recordUid) for record in request.records]
            return self._success_response(uids)

        vault.keeper_auth.execute_auth_rest.side_effect = _execute

        specs = [
            {'title': f'Record {i}', 'record_type': 'login'}
            for i in range(1001)
        ]
        results = nsf_management.create_nsf_records(vault, specs, request_sync=False)

        self.assertEqual(len(results), 1001)
        self.assertEqual(call_count['value'], 2)
        first_batch_size = vault.keeper_auth.execute_auth_rest.call_args_list[0].args[1].records
        second_batch_size = vault.keeper_auth.execute_auth_rest.call_args_list[1].args[1].records
        self.assertEqual(len(first_batch_size), 1000)
        self.assertEqual(len(second_batch_size), 1)

    @patch.object(nsf_management, 'is_nsf_folder', return_value=True)
    @patch.object(nsf_management, 'resolve_nsf_folder_uid', side_effect=lambda _v, uid: uid)
    @patch.object(nsf_management, '_get_folder_key', return_value=b'1' * 32)
    @patch.object(nsf_management.utils, 'generate_uid', return_value='AAAAAAAAAAAAAAAAAAAAAA')
    def test_create_nsf_record_raises_on_failure(self, *_mocks):
        vault = self._vault()
        response = record_pb2.RecordsModifyResponse()
        row = response.records.add()
        row.record_uid = utils.base64_url_decode('AAAAAAAAAAAAAAAAAAAAAA')
        row.status = record_pb2.RS_ACCESS_DENIED
        row.message = 'denied'
        vault.keeper_auth.execute_auth_rest.return_value = response

        with self.assertRaises(KeeperApiError):
            nsf_management.create_nsf_record(
                vault,
                title='Test',
                record_type='login',
                request_sync=False,
            )

    @patch.object(nsf_management.utils, 'generate_uid', return_value='AAAAAAAAAAAAAAAAAAAAAA')
    def test_v3_none_response_raises_no_results(self, *_mocks):
        vault = self._vault()
        vault.keeper_auth.execute_auth_rest.return_value = None

        with self.assertRaises(KeeperApiError) as ctx:
            nsf_management.create_nsf_records_batch(
                vault,
                [{'title': 'Test', 'record_type': 'login'}],
                request_sync=False,
            )
        self.assertEqual(ctx.exception.result_code, 'no_results')
        vault.keeper_auth.execute_auth_rest.assert_called_once()
        self.assertEqual(
            vault.keeper_auth.execute_auth_rest.call_args.args[0],
            'vault/records/v3/add',
        )

    def test_normalize_record_add_spec_requires_title_and_type(self):
        with self.assertRaisesRegex(nsf_management.NsfError, 'title'):
            nsf_management._normalize_record_add_spec({'record_type': 'login'})
        with self.assertRaisesRegex(nsf_management.NsfError, 'record_type'):
            nsf_management._normalize_record_add_spec({'title': 'Test'})


if __name__ == '__main__':
    unittest.main()
