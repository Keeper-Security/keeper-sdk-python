import os
import ssl
import tempfile
import unittest
from unittest.mock import Mock, patch

import certifi

from keepersdk import utils
from keepersdk.authentication import configuration, endpoint, login_auth


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

    def test_resolved_bundle_is_cached_until_reset(self):
        cert_file = self._cert_file()
        os.environ['KEEPER_SSL_CERT_FILE'] = cert_file
        self.assertEqual(utils.get_ssl_cert_file(), cert_file)
        os.environ['KEEPER_SSL_CERT_FILE'] = 'none'
        self.assertEqual(utils.get_ssl_cert_file(), cert_file)
        utils.reset_ssl_cert_file_cache()
        self.assertIs(utils.get_ssl_cert_file(), False)

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
