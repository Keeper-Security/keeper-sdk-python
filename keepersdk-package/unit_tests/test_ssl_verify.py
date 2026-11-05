import asyncio
import os
import ssl
import tempfile
import unittest
from unittest.mock import Mock, PropertyMock, patch

import certifi

from keepersdk import utils
from keepersdk.authentication import configuration, endpoint, keeper_auth, login_auth
from keepersdk.helpers.keeper_dag.connection import commander


class SslVerifyTest(unittest.TestCase):
    def setUp(self):
        self._saved_env = {key: os.environ.get(key) for key in ('VERIFY_SSL', 'KEEPER_SSL_CERT_FILE')}
        os.environ.pop('VERIFY_SSL', None)
        os.environ.pop('KEEPER_SSL_CERT_FILE', None)
        self._saved_check = endpoint.get_certificate_check()
        utils.reset_ssl_cert_file_cache()

    def tearDown(self):
        for key, value in self._saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        endpoint.set_certificate_check(self._saved_check)
        utils.reset_ssl_cert_file_cache()

    def _cert_file(self):
        with tempfile.NamedTemporaryFile(suffix='.pem', delete=False) as cert_file:
            cert_file.write(b'fake-ca')
        self.addCleanup(os.unlink, cert_file.name)
        return cert_file.name

    def test_default_resolves_to_ca_bundle_path(self):
        verify = endpoint.get_ssl_verify()
        self.assertIsInstance(verify, str)
        self.assertTrue(os.path.exists(verify))

    def test_keeper_ssl_cert_file_custom_path(self):
        os.environ['KEEPER_SSL_CERT_FILE'] = self._cert_file()
        self.assertEqual(endpoint.get_ssl_verify(), os.environ['KEEPER_SSL_CERT_FILE'])

    def test_keeper_ssl_cert_file_certifi(self):
        os.environ['KEEPER_SSL_CERT_FILE'] = 'certifi'
        self.assertEqual(endpoint.get_ssl_verify(), certifi.where())

    def test_keeper_ssl_cert_file_none_disables_verify(self):
        os.environ['KEEPER_SSL_CERT_FILE'] = 'none'
        self.assertIs(endpoint.get_ssl_verify(), False)

    def test_certificate_check_false_disables_verify(self):
        endpoint.set_certificate_check(False)
        self.assertIs(endpoint.get_ssl_verify(), False)

    def test_legacy_verify_ssl_false_disables_verify(self):
        os.environ['VERIFY_SSL'] = 'FALSE'
        self.assertIs(endpoint.get_ssl_verify(), False)

    def test_ignore_certificate_errors_disables_verify(self):
        self.assertIs(endpoint.get_ssl_verify(ignore_certificate_errors=True), False)

    def test_resolved_bundle_is_cached_while_environment_is_unchanged(self):
        with patch('keepersdk.utils._resolve_ssl_cert_file', return_value='/ca.pem') as resolve:
            utils.get_ssl_cert_file()
            utils.get_ssl_cert_file()
        resolve.assert_called_once()

    def test_cache_follows_keeper_ssl_cert_file_changes(self):
        cert_file = self._cert_file()
        os.environ['KEEPER_SSL_CERT_FILE'] = cert_file
        self.assertEqual(utils.get_ssl_cert_file(), cert_file)
        os.environ['KEEPER_SSL_CERT_FILE'] = 'none'
        self.assertIs(utils.get_ssl_cert_file(), False)
        os.environ.pop('KEEPER_SSL_CERT_FILE')
        self.assertIsInstance(utils.get_ssl_cert_file(), str)

    def test_unreadable_cert_file_is_not_used(self):
        cert_file = self._cert_file()
        os.environ['KEEPER_SSL_CERT_FILE'] = cert_file
        with patch('os.access', return_value=False), patch('sys.stderr'):
            resolved = utils.get_ssl_cert_file()
        self.assertNotEqual(resolved, cert_file)
        self.assertIsInstance(resolved, str)

    def test_missing_cert_file_is_not_used(self):
        os.environ['KEEPER_SSL_CERT_FILE'] = '/no/such/ca.pem'
        with patch('sys.stderr'):
            resolved = utils.get_ssl_cert_file()
        self.assertNotEqual(resolved, '/no/such/ca.pem')
        self.assertIsInstance(resolved, str)

    # Precedence: any disabling setting wins over a configured CA bundle.
    def test_certificate_check_false_wins_over_custom_cert_file(self):
        os.environ['KEEPER_SSL_CERT_FILE'] = self._cert_file()
        endpoint.set_certificate_check(False)
        self.assertIs(endpoint.get_ssl_verify(), False)

    def test_verify_ssl_false_wins_over_custom_cert_file(self):
        os.environ['KEEPER_SSL_CERT_FILE'] = self._cert_file()
        os.environ['VERIFY_SSL'] = 'false'
        self.assertIs(endpoint.get_ssl_verify(), False)

    def test_server_bypass_wins_over_custom_cert_file(self):
        os.environ['KEEPER_SSL_CERT_FILE'] = self._cert_file()
        self.assertIs(endpoint.get_ssl_verify(ignore_certificate_errors=True), False)

    def test_verify_ssl_true_keeps_verification(self):
        os.environ['VERIFY_SSL'] = 'TRUE'
        self.assertIsInstance(endpoint.get_ssl_verify(), str)

    def test_server_bypass_does_not_affect_other_servers(self):
        cert_file = self._cert_file()
        os.environ['KEEPER_SSL_CERT_FILE'] = cert_file
        storage = configuration.InMemoryConfigurationStorage()
        configuration.set_server_ignore_certificate_errors(storage, 'smk.example.com', True)
        smk = endpoint.KeeperEndpoint(storage, 'smk.example.com')
        cloud = endpoint.KeeperEndpoint(storage, 'keepersecurity.com')

        self.assertIs(smk.ssl_verify, False)
        self.assertEqual(cloud.ssl_verify, cert_file)
        self.assertEqual(endpoint.get_ssl_verify(), cert_file)
        self.assertTrue(endpoint.get_certificate_check())

    def test_global_disable_applies_to_every_server(self):
        storage = configuration.InMemoryConfigurationStorage()
        configuration.set_server_ignore_certificate_errors(storage, 'smk.example.com', False)
        endpoint.set_certificate_check(False)

        self.assertIs(endpoint.KeeperEndpoint(storage, 'smk.example.com').ssl_verify, False)
        self.assertIs(endpoint.KeeperEndpoint(storage, 'keepersecurity.com').ssl_verify, False)

    def test_ssl_aware_request_uses_resolved_verify(self):
        os.environ['KEEPER_SSL_CERT_FILE'] = 'none'
        with patch('requests.request') as request:
            utils.ssl_aware_get('https://example.com')
        self.assertIs(request.call_args.kwargs['verify'], False)

    def test_endpoint_ssl_verify_honors_server_setting(self):
        storage = configuration.InMemoryConfigurationStorage()
        configuration.set_server_ignore_certificate_errors(storage, 'smk.example.com', True)

        self.assertIs(endpoint.KeeperEndpoint(storage, 'smk.example.com').ssl_verify, False)
        self.assertIsInstance(endpoint.KeeperEndpoint(storage, 'keepersecurity.com').ssl_verify, str)

    def test_login_push_honors_server_setting(self):
        keeper_endpoint = Mock(ignore_certificate_errors=True)
        push = login_auth.LoginPushNotifications(Mock(keeper_endpoint=keeper_endpoint))
        push.login = None  # cleared after connection parameters are taken
        self.assertTrue(push.get_ignore_certificate_errors())

    def _websocket_verify(self, push):
        """Run one push connection attempt and return the verify value its SSL context was built from."""
        with patch.object(endpoint, 'create_ssl_context', wraps=endpoint.create_ssl_context) as create, \
                patch('websockets.connect', side_effect=OSError('stop')):
            push.use_pushes = True
            asyncio.run(push.main_loop())
        return create.call_args.args[0]

    def test_websocket_uses_server_bypass(self):
        smk_endpoint = Mock(ignore_certificate_errors=True)
        smk_endpoint.get_push_url.return_value = 'wss://push.smk.example.com/wss'
        push = login_auth.LoginPushNotifications(Mock(keeper_endpoint=smk_endpoint))
        self.assertIs(self._websocket_verify(push), False)

    def test_websocket_verifies_server_without_bypass(self):
        cloud_endpoint = Mock(ignore_certificate_errors=False)
        cloud_endpoint.get_push_url.return_value = 'wss://push.services.keepersecurity.com/wss'
        auth = Mock(keeper_endpoint=cloud_endpoint)
        push = keeper_auth.KeeperPushNotifications(auth)
        self.assertEqual(self._websocket_verify(push), utils.get_ssl_cert_file())

    def test_dag_router_call_uses_resolved_verify(self):
        connection = object.__new__(commander.Connection)
        connection.verify_ssl = True
        connection.logger = Mock()
        response = Mock(status_code=200, content=b'ok')
        with patch.object(commander.Connection, 'dag_server_url', new_callable=PropertyMock,
                          return_value='https://connect.keepersecurity.com'), \
                patch('requests.request', return_value=response) as request:
            self.assertEqual(connection.rest_call_to_router('POST', '/api/dag/sync', agent='test'), b'ok')
        self.assertEqual(request.call_args.kwargs['verify'], endpoint.get_ssl_verify())
        self.assertEqual(request.call_args.kwargs['url'], 'https://connect.keepersecurity.com/api/dag/sync')

    def test_dag_router_call_honors_verify_ssl_false(self):
        connection = object.__new__(commander.Connection)
        connection.verify_ssl = False
        connection.logger = Mock()
        with patch.object(commander.Connection, 'dag_server_url', new_callable=PropertyMock,
                          return_value='https://connect.keepersecurity.com'), \
                patch('requests.request', return_value=Mock(status_code=200, content=b'')) as request:
            connection.rest_call_to_router('POST', 'api/dag/sync', agent='test')
        self.assertIs(request.call_args.kwargs['verify'], False)


class SslContextTest(unittest.TestCase):
    def test_verify_false_disables_certificate_checks(self):
        context = endpoint.create_ssl_context(False)
        self.assertFalse(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_NONE)

    def test_ca_bundle_path_is_loaded(self):
        context = endpoint.create_ssl_context(certifi.where())
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertGreater(context.cert_store_stats()['x509_ca'], 0)

    def test_ca_directory_is_accepted(self):
        with tempfile.TemporaryDirectory() as ca_dir:
            context = endpoint.create_ssl_context(ca_dir)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)


if __name__ == '__main__':
    unittest.main()
