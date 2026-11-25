"""Unit tests for enterprise compliance reporting."""

from types import SimpleNamespace
import time
import unittest
from unittest.mock import patch

from keepersdk.enterprise.compliance import (
    ComplianceReportConfig,
    ComplianceReportGenerator,
    RecordInfo,
    SharedFolderInfo,
    permissions_to_string,
    PERMISSION_EDIT,
    PERMISSION_SHARE,
    REPORT_TYPE_HISTORY,
    REPORT_TYPE_VAULT,
)
from keepersdk.errors import KeeperApiError
from keepersdk.plugins.sox.storage_types import StorageRecordAging
from keepersdk.proto import enterprise_pb2


class _Reader:
    def __init__(self, entities=()):
        self.entities = list(entities)

    def get_all_entities(self):
        return list(self.entities)


class _Links:
    def get_all_links(self):
        return []


class _Auth:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.requests = []

    def execute_auth_rest(self, endpoint, request, response_type=None):
        self.requests.append((endpoint, request))
        return next(self.responses)


def _enterprise_data():
    user = SimpleNamespace(enterprise_user_id=42, username='User@example.com', node_id=1)
    return SimpleNamespace(
        users=_Reader([user]),
        teams=_Reader([]),
        team_users=_Links(),
        enterprise_info=SimpleNamespace(ec_private_key=None),
        root_node=SimpleNamespace(node_id=1),
    )


class ComplianceTests(unittest.TestCase):
    def test_config_rejects_conflicting_cache_modes(self):
        with self.assertRaises(ValueError):
            ComplianceReportConfig(rebuild=True, no_rebuild=True)

    def test_permissions_are_combined(self):
        self.assertEqual(permissions_to_string(PERMISSION_EDIT | PERMISSION_SHARE), 'edit,share')

    def test_preliminary_fetch_follows_continuation_token(self):
        first = enterprise_pb2.PreliminaryComplianceDataResponse(
            auditUserData=[enterprise_pb2.AuditUserData(
                enterpriseUserId=42,
                auditUserRecords=[enterprise_pb2.AuditUserRecord(recordUid=b'one')]
            )],
            hasMore=True,
            continuationToken=b'next',
        )
        second = enterprise_pb2.PreliminaryComplianceDataResponse(
            auditUserData=[enterprise_pb2.AuditUserData(
                enterpriseUserId=42,
                auditUserRecords=[enterprise_pb2.AuditUserRecord(recordUid=b'two')]
            )],
            hasMore=False,
        )
        auth = _Auth([first, second])
        generator = ComplianceReportGenerator(_enterprise_data(), auth)
        records = generator.get_preliminary_records()

        self.assertEqual(len(records), 2)
        self.assertEqual(bytes(auth.requests[1][1].continuationToken), b'next')

    def test_preliminary_fetch_rejects_missing_continuation_token(self):
        response = enterprise_pb2.PreliminaryComplianceDataResponse(hasMore=True)
        generator = ComplianceReportGenerator(_enterprise_data(), _Auth([response]))
        with self.assertRaisesRegex(RuntimeError, 'without a continuation token'):
            generator.get_preliminary_records()

    def test_shared_folder_team_uses_repeated_team_uids_field(self):
        generator = ComplianceReportGenerator(_enterprise_data(), _Auth([]))
        generator._shared_folders['Zm9sZGVy'] = SharedFolderInfo(
            folder_uid='Zm9sZGVy', records={'record': 4})
        generator._team_members['dGVhbQ'] = {42}
        response = enterprise_pb2.SharedFolderTeam(
            sharedFolderUid=b'folder', teamUids=[b'team'])

        generator._process_shared_folder_teams([response])

        self.assertIn('dGVhbQ', generator._shared_folders['Zm9sZGVy'].teams)
        self.assertEqual(generator._record_permissions[('record', 42)], 4)


class SharedFolderNameTests(unittest.TestCase):
    def test_name_comes_from_vault_data(self):
        vault_data = SimpleNamespace(get_shared_folder=lambda uid: SimpleNamespace(name='Finance'))
        generator = ComplianceReportGenerator(_enterprise_data(), _Auth([]), vault_data=vault_data)
        self.assertEqual(generator._get_shared_folder_name('SF1'), 'Finance')

    def test_falls_back_to_uid_without_vault_data(self):
        # Vault storage holds the name encrypted; it must never be shown.
        storage = SimpleNamespace(shared_folders=SimpleNamespace(
            get_entity=lambda uid: SimpleNamespace(name=b'\x8f\x01encrypted')))
        generator = ComplianceReportGenerator(_enterprise_data(), _Auth([]), vault_storage=storage)
        self.assertEqual(generator._get_shared_folder_name('SF1'), 'SF1')

    def test_unknown_folder_falls_back_to_uid(self):
        vault_data = SimpleNamespace(get_shared_folder=lambda uid: None)
        generator = ComplianceReportGenerator(_enterprise_data(), _Auth([]), vault_data=vault_data)
        self.assertEqual(generator._get_shared_folder_name('SF1'), 'SF1')


class FullComplianceBatchTests(unittest.TestCase):
    def test_batch_requests_every_user_listed_for_its_records(self):
        users = [SimpleNamespace(enterprise_user_id=uid, username=f'u{uid}@example.com', node_id=1)
                 for uid in (1, 2, 3)]
        enterprise_data = _enterprise_data()
        enterprise_data.users = _Reader(users)
        auth = _Auth([enterprise_pb2.ComplianceReportResponse()])
        generator = ComplianceReportGenerator(enterprise_data, auth)
        generator._records = {'R1': RecordInfo(record_uid='R1', record_uid_bytes=b'r1', owner_user_id=1)}
        # The preliminary data listed R1 for users 1 and 2; user 3 holds nothing.
        generator._record_permissions = {('R1', 1): 15, ('R1', 2): 15}

        generator._fetch_full_compliance_data()

        request = auth.requests[0][1]
        self.assertEqual(sorted(request.complianceReportRun.users), [1, 2])
        self.assertEqual(list(request.complianceReportRun.records), [b'r1'])


class _BatchAuth:
    """Fake ``execute_batch``: returns one prepared response per request, in call order."""

    def __init__(self, pages):
        self.pages = iter(pages)
        self.requests = []

    def execute_batch(self, requests):
        self.requests.append(requests)
        return [next(self.pages) for _ in requests]


def _rows(*uid_ts):
    return {'result': 'success',
            'audit_event_overview_report_rows': [
                {'record_uid': uid, 'last_created': ts, 'ip_address': '1.1.1.1', 'keeper_version': 'v'}
                for uid, ts in uid_ts]}


class RecordAccessEventTests(unittest.TestCase):
    def _generator(self, auth):
        generator = ComplianceReportGenerator(_enterprise_data(), auth)
        generator._build_user_lookups()
        return generator

    @patch('keepersdk.enterprise.compliance.API_EVENT_SUMMARY_ROW_LIMIT', 2)
    def test_history_pages_backwards_until_short_page(self):
        auth = _BatchAuth([_rows(('A', 300), ('B', 200)), _rows(('B', 150), ('C', 100)), _rows()])
        events = self._generator(auth)._fetch_record_access_events(REPORT_TYPE_HISTORY)

        self.assertEqual(len(auth.requests), 3)
        first, second, third = (r[0] for r in auth.requests)
        self.assertNotIn('record_uid', first['filter'])
        self.assertEqual(second['filter']['created'], {'max': 200})
        self.assertEqual(third['filter']['created'], {'max': 100})
        self.assertEqual({uid for (_, uid) in events}, {'A', 'B', 'C'})
        # The latest event wins for a record seen on two pages.
        self.assertEqual(events[('user@example.com', 'B')]['last_created'], 200)

    @patch('keepersdk.enterprise.compliance.API_EVENT_SUMMARY_ROW_LIMIT', 2)
    def test_vault_report_stops_when_all_records_found(self):
        auth = _BatchAuth([_rows(('A', 300), ('B', 200))])
        generator = self._generator(auth)
        generator._record_permissions = {('A', 42): 1, ('B', 42): 1}

        events = generator._fetch_record_access_events(REPORT_TYPE_VAULT)

        self.assertEqual(len(auth.requests), 1)
        self.assertEqual(sorted(auth.requests[0][0]['filter']['record_uid']), ['A', 'B'])
        self.assertEqual({uid for (_, uid) in events}, {'A', 'B'})

    @patch('keepersdk.enterprise.compliance.API_EVENT_SUMMARY_ROW_LIMIT', 2)
    def test_paging_that_does_not_move_backwards_stops(self):
        auth = _BatchAuth([_rows(('A', 300), ('B', 200)), _rows(('C', 200), ('D', 200))])
        with self.assertLogs(level='WARNING'):
            self._generator(auth)._fetch_record_access_events(REPORT_TYPE_HISTORY)
        self.assertEqual(len(auth.requests), 2)

    def test_failed_audit_request_raises(self):
        auth = _BatchAuth([{'result': 'fail', 'result_code': 'access_denied', 'message': 'no'}])
        with self.assertRaises(KeeperApiError):
            self._generator(auth)._fetch_record_access_events(REPORT_TYPE_HISTORY)


class RecordAccessReportTests(unittest.TestCase):
    def _generator(self, access_events):
        generator = ComplianceReportGenerator(_enterprise_data(), _Auth([]))
        generator._build_user_lookups()
        generator._records = {'R1': RecordInfo(record_uid='R1', title='One'),
                              'R2': RecordInfo(record_uid='R2', title='Two')}
        generator._record_permissions = {('R1', 42): 15}
        generator._fetch_preliminary_compliance_data = lambda *a, **k: None
        generator._fetch_full_compliance_data = lambda *a, **k: None
        generator._fetch_record_access_events = lambda report_type: access_events
        generator._fetch_aging_data = lambda uids: {}
        return generator

    def test_history_includes_past_access_without_current_permission(self):
        events = {('user@example.com', 'R2'): {'last_created': 100}}
        entries = self._generator(events).generate_record_access_report(REPORT_TYPE_HISTORY)
        self.assertEqual(sorted(e.record_uid for e in entries), ['R1', 'R2'])

    def test_vault_report_only_includes_current_access(self):
        events = {('user@example.com', 'R2'): {'last_created': 100}}
        entries = self._generator(events).generate_record_access_report(REPORT_TYPE_VAULT)
        self.assertEqual([e.record_uid for e in entries], ['R1'])


class _AgingStorage:
    def __init__(self, cached, records_dated):
        self.entities = list(cached)
        self.records_dated = records_dated
        self.dated_calls = []
        self.record_aging = SimpleNamespace(get_all_entities=lambda: list(self.entities),
                                            put_entities=self.entities.extend)

    def set_records_dated(self, ts):
        self.dated_calls.append(ts)


class _CommandAuth:
    def __init__(self):
        self.requests = []

    def execute_auth_command(self, request):
        self.requests.append(request)
        return {'audit_event_overview_report_rows': []}


class AgingCacheTests(unittest.TestCase):
    def _generator(self, storage, auth):
        return ComplianceReportGenerator(_enterprise_data(), auth, compliance_storage=storage)

    def test_partial_refresh_keeps_cache_date(self):
        fresh = int(time.time())
        storage = _AgingStorage([StorageRecordAging(record_uid='R1', created=100)], fresh)
        auth = _CommandAuth()

        data = self._generator(storage, auth)._fetch_aging_data(['R1', 'R2'])

        self.assertIsNotNone(data['R1']['created'])
        self.assertTrue(all(rq['filter']['record_uid'] == ['R2'] for rq in auth.requests))
        self.assertEqual(storage.dated_calls, [])

    def test_full_refresh_sets_cache_date(self):
        storage = _AgingStorage([], 0)
        auth = _CommandAuth()

        self._generator(storage, auth)._fetch_aging_data(['R1'])

        self.assertEqual(len(storage.dated_calls), 1)

    def test_stale_cache_is_refetched_and_redated(self):
        storage = _AgingStorage([StorageRecordAging(record_uid='R1', created=100)], 1)
        auth = _CommandAuth()

        self._generator(storage, auth)._fetch_aging_data(['R1'])

        self.assertTrue(auth.requests)
        self.assertEqual(len(storage.dated_calls), 1)


if __name__ == '__main__':
    unittest.main()
