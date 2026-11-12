"""Unit tests for NSF access listing: username lookup, batching, paging, empty update results."""

import unittest
from unittest.mock import MagicMock, patch

from keepersdk import utils
from keepersdk.proto import folder_access_pb2, folder_pb2, record_details_pb2, record_pb2
from keepersdk.vault import nsf_common, nsf_management


class _AccessTestBase(unittest.TestCase):
    def setUp(self):
        self.vault = MagicMock()
        for target in ('resolve_nsf_record_uid', 'resolve_nsf_folder_uid'):
            p = patch('keepersdk.vault.nsf_management.' + target, side_effect=lambda _v, u: u)
            p.start()
            self.addCleanup(p.stop)

    def _calls(self, endpoint):
        return [c for c in self.vault.keeper_auth.execute_auth_rest.call_args_list if c.args[0] == endpoint]


class FolderAccessUsernameTest(_AccessTestBase):
    def setUp(self):
        super().setUp()
        self.folder_uids = [utils.generate_uid() for _ in range(3)]
        self.user_uids = [utils.generate_uid() for _ in range(4)]

        share_objects = record_pb2.GetShareObjectsResponse()
        for i, uid in enumerate(self.user_uids):
            su = share_objects.shareEnterpriseUsers.add()
            su.userAccountUid = utils.base64_url_decode(uid)
            su.username = f'user{i}@example.com'

        def execute(endpoint, rq, **_kwargs):
            if endpoint == 'vault/get_share_objects':
                return share_objects
            rs = folder_access_pb2.GetFolderAccessResponse()
            for folder_uid_bytes in rq.folderUid:
                fr = rs.folderAccessResults.add()
                fr.folderUid = folder_uid_bytes
                for uid in self.user_uids:
                    a = fr.accessors.add()
                    a.folderUid = folder_uid_bytes
                    a.accessTypeUid = utils.base64_url_decode(uid)
                    a.accessType = folder_pb2.AT_USER
                    a.accessRoleType = folder_pb2.VIEWER
            return rs
        self.vault.keeper_auth.execute_auth_rest.side_effect = execute

    def test_share_objects_loaded_once_for_all_user_rows(self):
        result = nsf_management.get_nsf_folder_access(self.vault, self.folder_uids)

        self.assertEqual(len(self._calls('vault/get_share_objects')), 1)
        usernames = {a['username'] for r in result['results'] for a in r['accessors']}
        self.assertEqual(usernames, {f'user{i}@example.com' for i in range(4)})

    def test_resolve_usernames_false_skips_lookup(self):
        result = nsf_management.get_nsf_folder_access(self.vault, self.folder_uids, resolve_usernames=False)

        self.assertEqual(self._calls('vault/get_share_objects'), [])
        self.assertTrue(all(a['username'] is None for r in result['results'] for a in r['accessors']))

    def test_load_access_details_passes_resolve_usernames(self):
        view = MagicMock()
        view.folders.return_value = [MagicMock(folder_uid=uid) for uid in self.folder_uids]
        with patch('keepersdk.vault.nsf_management._nsf_view', return_value=view):
            nsf_management.load_nsf_access_details(self.vault, load_folder=True, resolve_usernames=False)

        self.assertEqual(self._calls('vault/get_share_objects'), [])
        self.assertEqual(view.set_nsf_folder_access_detail.call_count, 3)

    def test_lookup_failure_is_not_retried_per_row(self):
        def execute(endpoint, rq, **_kwargs):
            if endpoint == 'vault/get_share_objects':
                raise RuntimeError('throttled')
            rs = folder_access_pb2.GetFolderAccessResponse()
            fr = rs.folderAccessResults.add()
            fr.folderUid = rq.folderUid[0]
            for uid in self.user_uids:
                a = fr.accessors.add()
                a.accessTypeUid = utils.base64_url_decode(uid)
                a.accessType = folder_pb2.AT_USER
            return rs
        self.vault.keeper_auth.execute_auth_rest.side_effect = execute

        result = nsf_management.get_nsf_folder_access(self.vault, self.folder_uids[:1])

        self.assertEqual(len(self._calls('vault/get_share_objects')), 1)
        self.assertTrue(all(a['username'] is None for a in result['results'][0]['accessors']))


class FolderAccessBatchTest(_AccessTestBase):
    def test_folders_requested_in_batches_of_25(self):
        self.vault.keeper_auth.execute_auth_rest.return_value = folder_access_pb2.GetFolderAccessResponse()
        folder_uids = [utils.generate_uid() for _ in range(60)]

        nsf_management.get_nsf_folder_access(self.vault, folder_uids, resolve_usernames=False)

        sizes = [len(c.args[1].folderUid) for c in self._calls('vault/folders/v3/access')]
        self.assertEqual(sizes, [25, 25, 10])


class RecordAccessPagingTest(_AccessTestBase):
    def setUp(self):
        super().setUp()
        self.record_uid = utils.generate_uid()

    def _page(self, names, *, has_more, page_number=0, cursor='', forbidden=()):
        rs = record_details_pb2.RecordAccessResponse()
        for name in names:
            ra = rs.recordAccesses.add()
            ra.accessorInfo.name = name
            ra.data.recordUid = utils.base64_url_decode(self.record_uid)
            ra.data.accessType = folder_pb2.AT_USER
        for uid in forbidden:
            rs.forbiddenRecords.append(utils.base64_url_decode(uid))
        if has_more or page_number:
            rs.pageInfo.hasMore = has_more
            rs.pageInfo.pageNumber = page_number
            rs.pageInfo.cursorToken = cursor
        return rs

    def test_follows_pages_until_has_more_is_false(self):
        forbidden_uid = utils.generate_uid()
        self.vault.keeper_auth.execute_auth_rest.side_effect = [
            self._page(['a', 'b'], has_more=True, page_number=1, cursor='c1', forbidden=[forbidden_uid]),
            self._page(['c'], has_more=True, page_number=2, cursor='c2', forbidden=[forbidden_uid]),
            self._page(['d'], has_more=False, page_number=3),
        ]

        result = nsf_management.get_nsf_record_accesses(self.vault, [self.record_uid])

        self.assertEqual([a['accessor_name'] for a in result['record_accesses']], ['a', 'b', 'c', 'd'])
        self.assertEqual(result['forbidden_records'], [forbidden_uid])
        requests = [c.args[1] for c in self._calls('vault/records/v3/details/access')]
        self.assertFalse(requests[0].HasField('page'))
        self.assertEqual((requests[1].page.pageNumber, requests[1].page.cursorToken), (2, 'c1'))
        self.assertEqual((requests[2].page.pageNumber, requests[2].page.cursorToken), (3, 'c2'))
        self.assertEqual(requests[1].page.pageSize, 500)

    def test_single_page_response_without_page_info(self):
        self.vault.keeper_auth.execute_auth_rest.return_value = self._page(['a'], has_more=False)

        result = nsf_management.get_nsf_record_accesses(self.vault, [self.record_uid])

        self.assertEqual(len(result['record_accesses']), 1)
        self.assertEqual(len(self._calls('vault/records/v3/details/access')), 1)

    def test_page_cap_stops_endless_paging(self):
        self.vault.keeper_auth.execute_auth_rest.return_value = self._page(
            ['a'], has_more=True, page_number=1, cursor='same')

        with self.assertLogs(level='WARNING'):
            nsf_management.get_nsf_record_accesses(self.vault, [self.record_uid])

        self.assertEqual(len(self._calls('vault/records/v3/details/access')),
                         nsf_management._RECORD_ACCESS_MAX_PAGES)


class ParseFolderAccessResultTest(unittest.TestCase):
    def test_empty_response_is_not_success(self):
        result = nsf_common.parse_folder_access_result(
            folder_pb2.FolderAccessResponse(), 'F', 'user@example.com', 'Access granted')

        self.assertFalse(result['success'])
        self.assertEqual(result['status'], 'NO_RESULT')

    def test_success_row_is_success(self):
        response = folder_pb2.FolderAccessResponse()
        response.folderAccessResults.add()

        result = nsf_common.parse_folder_access_result(response, 'F', 'user@example.com', 'Access granted')

        self.assertTrue(result['success'])
        self.assertEqual(result['message'], 'Access granted')


if __name__ == '__main__':
    unittest.main()
