import unittest
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from unittest.mock import MagicMock, patch

from keepersdk import errors
from keepersdk.authentication import endpoint
from keepersdk.authentication.keeper_auth import KeeperAuth, AuthContext


class TestThrottleHelpers(unittest.TestCase):
    def test_parse_wait_from_message_seconds(self):
        self.assertEqual(endpoint.parse_throttle_wait_seconds('Please wait 45 seconds'), 45)

    def test_parse_wait_from_message_minutes(self):
        self.assertEqual(endpoint.parse_throttle_wait_seconds('Retry after 2 minutes'), 120)

    def test_parse_wait_defaults_when_message_has_no_duration(self):
        self.assertEqual(
            endpoint.parse_throttle_wait_seconds('Too many requests'),
            endpoint.DEFAULT_THROTTLE_WAIT_SECONDS)

    def test_parse_wait_prefers_retry_after_header(self):
        self.assertEqual(
            endpoint.parse_throttle_wait_seconds('wait 10 seconds', {'Retry-After': '90'}),
            90)

    def test_parse_wait_accepts_retry_after_http_date(self):
        retry_at = datetime.now(timezone.utc) + timedelta(seconds=120)
        wait = endpoint.parse_throttle_wait_seconds('', {'Retry-After': format_datetime(retry_at)})
        self.assertGreaterEqual(wait, 110)
        self.assertLessEqual(wait, 120)

    def test_parse_wait_ignores_malformed_retry_after(self):
        self.assertEqual(
            endpoint.parse_throttle_wait_seconds('wait 15 seconds', {'Retry-After': 'soon'}),
            15)

    def test_parse_wait_caps_at_max(self):
        self.assertEqual(
            endpoint.parse_throttle_wait_seconds('wait 10 minutes'),
            endpoint.MAX_THROTTLE_WAIT_SECONDS)
        self.assertEqual(
            endpoint.parse_throttle_wait_seconds('', {'Retry-After': '99999'}),
            endpoint.MAX_THROTTLE_WAIT_SECONDS)

    def test_backoff_grows_exponentially(self):
        self.assertEqual(endpoint.throttle_backoff_seconds(1, 10), 30)
        self.assertEqual(endpoint.throttle_backoff_seconds(2, 10), 60)
        self.assertEqual(endpoint.throttle_backoff_seconds(3, 10), 120)
        self.assertEqual(endpoint.throttle_backoff_seconds(1, 90), 90)

    def test_is_throttle_response(self):
        self.assertTrue(endpoint.is_throttle_response(403, 'throttled'))
        self.assertTrue(endpoint.is_throttle_response(429, ''))
        self.assertFalse(endpoint.is_throttle_response(403, 'access_denied'))
        self.assertFalse(endpoint.is_throttle_response(400, ''))


class TestCommunicateKeeperThrottle(unittest.TestCase):
    def _make_endpoint(self):
        storage = MagicMock()
        storage.get.return_value = MagicMock(last_server='keepersecurity.com', servers=MagicMock(return_value={}))
        ep = endpoint.KeeperEndpoint(storage, keeper_server='keepersecurity.com')
        ep.fail_on_throttle = False
        return ep

    def _json_response(self, status_code, body, headers=None):
        rs = MagicMock()
        rs.status_code = status_code
        rs.headers = {'Content-Type': 'application/json', **(headers or {})}
        rs.json.return_value = body
        rs.reason = 'Forbidden' if status_code == 403 else 'Too Many Requests'
        rs.content = b''
        rs.text = ''
        return rs

    def _raw_response(self, status_code, reason, text='', headers=None):
        rs = MagicMock()
        rs.status_code = status_code
        rs.headers = headers or {}
        rs.reason = reason
        rs.text = text
        rs.content = b''
        rs.json.side_effect = ValueError('no json')
        return rs

    @patch('keepersdk.authentication.endpoint.time.sleep')
    @patch('keepersdk.authentication.endpoint.requests.post')
    @patch('keepersdk.authentication.endpoint.prepare_api_request')
    def test_403_throttled_retries_then_raises(self, mock_prepare, mock_post, mock_sleep):
        mock_prepare.return_value = MagicMock(SerializeToString=MagicMock(return_value=b'rq'))
        throttle_body = {'error': 'throttled', 'message': 'Please wait 1 second'}
        ok = MagicMock()
        ok.status_code = 200
        ok.headers = {}
        ok.content = b''

        # Fail twice with throttle, succeed on third
        mock_post.side_effect = [
            self._json_response(403, throttle_body),
            self._json_response(403, throttle_body),
            ok,
        ]
        ep = self._make_endpoint()
        result = ep._communicate_keeper('vault/test', b'payload')
        self.assertIsNone(result)
        self.assertEqual(mock_post.call_count, 3)
        self.assertEqual(mock_sleep.call_count, 2)

    @patch('keepersdk.authentication.endpoint.time.sleep')
    @patch('keepersdk.authentication.endpoint.requests.post')
    @patch('keepersdk.authentication.endpoint.prepare_api_request')
    def test_429_retries_then_raises(self, mock_prepare, mock_post, mock_sleep):
        mock_prepare.return_value = MagicMock(SerializeToString=MagicMock(return_value=b'rq'))
        throttle_rs = MagicMock()
        throttle_rs.status_code = 429
        throttle_rs.headers = {'Retry-After': '1'}
        throttle_rs.reason = 'Too Many Requests'
        throttle_rs.content = b''
        throttle_rs.text = ''

        mock_post.side_effect = [throttle_rs] * (endpoint.MAX_THROTTLE_RETRIES + 1)
        ep = self._make_endpoint()
        with self.assertRaises(errors.KeeperApiError) as ctx:
            ep._communicate_keeper('vault/test', b'payload')
        self.assertEqual(ctx.exception.result_code, 'throttled')
        self.assertEqual(mock_sleep.call_count, endpoint.MAX_THROTTLE_RETRIES)

    @patch('keepersdk.authentication.endpoint.requests.post')
    @patch('keepersdk.authentication.endpoint.prepare_api_request')
    def test_fail_on_throttle_raises_immediately(self, mock_prepare, mock_post):
        mock_prepare.return_value = MagicMock(SerializeToString=MagicMock(return_value=b'rq'))
        mock_post.return_value = self._json_response(403, {'error': 'throttled', 'message': 'slow down'})
        ep = self._make_endpoint()
        ep.fail_on_throttle = True
        with self.assertRaises(errors.KeeperApiError) as ctx:
            ep._communicate_keeper('vault/test', b'payload')
        self.assertEqual(ctx.exception.result_code, 'throttled')
        self.assertEqual(mock_post.call_count, 1)

    @patch('keepersdk.authentication.endpoint.requests.post')
    @patch('keepersdk.authentication.endpoint.prepare_api_request')
    def test_403_non_throttle_error_is_not_retried(self, mock_prepare, mock_post):
        mock_prepare.return_value = MagicMock(SerializeToString=MagicMock(return_value=b'rq'))
        mock_post.return_value = self._json_response(
            403, {'error': 'access_denied', 'message': 'Not permitted'})
        ep = self._make_endpoint()
        with self.assertRaises(errors.KeeperApiError) as ctx:
            ep._communicate_keeper('vault/test', b'payload')
        self.assertEqual(ctx.exception.result_code, 'access_denied')
        self.assertEqual(ctx.exception.message, 'Not permitted')
        self.assertEqual(mock_post.call_count, 1)

    @patch('keepersdk.authentication.endpoint.time.sleep')
    @patch('keepersdk.authentication.endpoint.requests.post')
    @patch('keepersdk.authentication.endpoint.prepare_api_request')
    def test_429_without_json_body_is_retried(self, mock_prepare, mock_post, mock_sleep):
        mock_prepare.return_value = MagicMock(SerializeToString=MagicMock(return_value=b'rq'))
        ok = MagicMock()
        ok.status_code = 200
        ok.headers = {}
        ok.content = b''

        mock_post.side_effect = [
            self._raw_response(429, 'Too Many Requests', '<html>rate limited</html>'),
            ok,
        ]
        ep = self._make_endpoint()
        self.assertIsNone(ep._communicate_keeper('vault/test', b'payload'))
        self.assertEqual(mock_sleep.call_count, 1)

    @patch('keepersdk.authentication.endpoint.requests.post')
    @patch('keepersdk.authentication.endpoint.prepare_api_request')
    def test_malformed_json_error_body_raises_http_error(self, mock_prepare, mock_post):
        mock_prepare.return_value = MagicMock(SerializeToString=MagicMock(return_value=b'rq'))
        rs = self._raw_response(500, 'Internal Server Error', 'not json',
                                headers={'Content-Type': 'application/json'})
        mock_post.return_value = rs
        ep = self._make_endpoint()
        with self.assertRaises(errors.KeeperApiError) as ctx:
            ep._communicate_keeper('vault/test', b'payload')
        self.assertEqual(ctx.exception.result_code, 'http_error')

    @patch('keepersdk.authentication.endpoint.requests.post')
    @patch('keepersdk.authentication.endpoint.prepare_api_request')
    def test_key_rotation_is_bounded(self, mock_prepare, mock_post):
        mock_prepare.return_value = MagicMock(SerializeToString=MagicMock(return_value=b'rq'))
        mock_post.return_value = self._json_response(401, {'error': 'key', 'key_id': 8})
        ep = self._make_endpoint()
        with self.assertRaises(errors.KeeperApiError) as ctx:
            ep._communicate_keeper('vault/test', b'payload')
        self.assertEqual(ctx.exception.result_code, 'key')
        self.assertEqual(mock_post.call_count, endpoint.MAX_KEY_RETRIES + 1)


class TestExecuteBatchThrottle(unittest.TestCase):
    @staticmethod
    def _make_auth():
        keeper_endpoint = MagicMock()
        keeper_endpoint.fail_on_throttle = False
        return KeeperAuth(keeper_endpoint, AuthContext())

    @patch('keepersdk.authentication.keeper_auth.time.sleep')
    def test_batch_throttled_retries_with_backoff(self, mock_sleep):
        auth = self._make_auth()
        throttle = {'result': 'fail', 'result_code': 'throttled', 'message': 'wait 1 second'}
        success = {'result': 'success'}

        # First chunk: one success + trailing throttle; retry returns remaining success
        auth.execute_auth_command = MagicMock(side_effect=[
            {'results': [success, throttle]},
            {'results': [success]},
        ])
        responses = auth.execute_batch([{'command': 'a'}, {'command': 'b'}])
        self.assertEqual(len(responses), 2)
        self.assertEqual(mock_sleep.call_count, 1)

    @staticmethod
    def _always_throttled(*_args, **_kwargs):
        return {'results': [{'result': 'fail', 'result_code': 'throttled', 'message': 'slow down'}]}

    @patch('keepersdk.authentication.keeper_auth.time.sleep')
    def test_batch_raises_after_max_throttle_retries(self, mock_sleep):
        auth = self._make_auth()
        auth.execute_auth_command = MagicMock(side_effect=self._always_throttled)
        with self.assertRaises(errors.KeeperApiError) as ctx:
            auth.execute_batch([{'command': 'a'}])
        self.assertEqual(ctx.exception.result_code, 'throttled')
        self.assertEqual(mock_sleep.call_count, endpoint.MAX_THROTTLE_RETRIES)

    def test_batch_fail_on_throttle_raises_immediately(self):
        auth = self._make_auth()
        auth.keeper_endpoint.fail_on_throttle = True
        auth.execute_auth_command = MagicMock(side_effect=self._always_throttled)
        with self.assertRaises(errors.KeeperApiError) as ctx:
            auth.execute_batch([{'command': 'a'}])
        self.assertEqual(ctx.exception.result_code, 'throttled')
        self.assertEqual(auth.execute_auth_command.call_count, 1)

    def test_batch_empty_results_raises_instead_of_dropping_requests(self):
        auth = self._make_auth()
        auth.execute_auth_command = MagicMock(return_value={'results': []})
        with self.assertRaises(errors.KeeperApiError) as ctx:
            auth.execute_batch([{'command': 'a'}])
        self.assertEqual(ctx.exception.result_code, 'server_error')


if __name__ == '__main__':
    unittest.main()
