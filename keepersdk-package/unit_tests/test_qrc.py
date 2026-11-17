import unittest
from unittest.mock import MagicMock, Mock, patch

from cryptography.hazmat.primitives.asymmetric import ec

from keepersdk import crypto, errors, utils
from keepersdk.authentication import configuration, endpoint
from keepersdk.authentication.qrc import qrc_crypto, qrc_keys
from keepersdk.proto import APIRequest_pb2


class TestQrcCrypto(unittest.TestCase):
    def test_mlkem_key_size_is_validated_before_optional_import(self):
        with self.assertRaisesRegex(ValueError, 'public key size'):
            qrc_crypto._mlkem_encapsulation(b'bad')

    def test_qrc_key_metadata_matches_supported_cloud_hosts(self):
        self.assertEqual(qrc_keys.QRC_KEY_IDS_BY_HOST['keepersecurity.com'], 136)
        self.assertEqual(
            {key: len(value) for key, value in qrc_keys.QRC_PUBLIC_KEYS.items()},
            {107: 1568, 124: 1568, 136: 1568},
        )

    @unittest.skipUnless(qrc_crypto.is_available(), 'keeper-mlkem is not installed')
    def test_server_can_recover_transmission_key(self):
        from mlkem import MLKEM_1024_PARAMETERS, ML_KEM
        kem = ML_KEM(MLKEM_1024_PARAMETERS)
        mlkem_public, mlkem_private = kem.key_gen()
        server_ec_private, server_ec_public = crypto.generate_ec_key()
        transmission_key = utils.generate_aes_key()

        message = qrc_crypto.encrypt_transmission_key(
            transmission_key, crypto.generate_ec_key()[0], server_ec_public, mlkem_public)

        # Server side: decapsulate, ECDH with the client key, derive, decrypt.
        mlkem_secret = kem.decaps(mlkem_private, message.mlkem_encapsulated_key)
        ec_secret = server_ec_private.exchange(
            ec.ECDH(), crypto.load_ec_public_key(message.client_ec_public_key))
        hybrid_key = qrc_crypto._derive_key(
            ec_secret, mlkem_secret, crypto.unload_ec_public_key(server_ec_public),
            message.client_ec_public_key, message.mlkem_encapsulated_key)
        self.assertEqual(crypto.decrypt_aes_v2(message.encrypted_transmission_key, hybrid_key),
                         transmission_key)


class TestQrcApiRequest(unittest.TestCase):
    def test_qrc_message_populates_qrc_envelope(self):
        message = qrc_crypto.QrcMessage(
            client_ec_public_key=b'client',
            mlkem_encapsulated_key=b'encapsulation',
            encrypted_transmission_key=b'encrypted-key',
        )
        request = endpoint.prepare_api_request(
            7,
            b'transmission-key',
            b'payload',
            qrc_message=message,
            qrc_key_id=136,
            qrc_ec_key_id=10,
        )

        self.assertEqual(request.publicKeyId, 136)
        self.assertFalse(request.encryptedTransmissionKey)
        self.assertEqual(request.qrcMessageKey.clientEcPublicKey, b'client')
        self.assertEqual(request.qrcMessageKey.mlKemEncapsulatedKey, b'encapsulation')
        self.assertEqual(request.qrcMessageKey.data, b'encrypted-key')
        self.assertEqual(request.qrcMessageKey.ecKeyId, 10)

    def test_server_key_type_is_derived_from_key(self):
        self.assertTrue(endpoint.encrypt_with_keeper_key(b'data', 1))   # RSA
        self.assertTrue(endpoint.encrypt_with_keeper_key(b'data', 18))  # EC
        with self.assertRaises(errors.KeeperApiError):
            endpoint.encrypt_with_keeper_key(b'data', 136)  # ML-KEM key is not a transmission key
        self.assertTrue(endpoint.is_ec_server_key_id(7))
        self.assertFalse(endpoint.is_ec_server_key_id(1))
        self.assertFalse(endpoint.is_ec_server_key_id(None))


class TestKeeperEndpointQrcSelection(unittest.TestCase):
    def _endpoint(self, server):
        storage = MagicMock()
        storage.get.return_value = MagicMock(last_server=server, servers=MagicMock(return_value={}))
        return endpoint.KeeperEndpoint(storage, keeper_server=server)

    def test_production_cloud_uses_qrc_key(self):
        self.assertEqual(self._endpoint('keepersecurity.com').qrc_key_id, 136)

    def test_unknown_server_has_no_qrc_key(self):
        self.assertIsNone(self._endpoint('self-managed.example.com').qrc_key_id)


def _ok():
    return Mock(status_code=200, content=b'', headers={})


def _error(status_code, body):
    rs = Mock(status_code=status_code, content=b'', text='', reason='Error',
              headers={'Content-Type': 'application/json'})
    rs.json.return_value = body
    return rs


@unittest.skipUnless(qrc_crypto.is_available(), 'keeper-mlkem is not installed')
class TestQrcRequestFallback(unittest.TestCase):
    def setUp(self):
        self.endpoint = endpoint.KeeperEndpoint(configuration.InMemoryConfigurationStorage(), 'keepersecurity.com')
        patcher = patch('keepersdk.authentication.endpoint.requests.post')
        self.post = patcher.start()
        self.addCleanup(patcher.stop)

    def _sent(self):
        return [APIRequest_pb2.ApiRequest.FromString(c.kwargs['data']) for c in self.post.call_args_list]

    def _assert_qrc(self, request, ec_key_id):
        self.assertEqual(request.publicKeyId, 136)
        self.assertFalse(request.encryptedTransmissionKey)
        self.assertEqual(request.qrcMessageKey.ecKeyId, ec_key_id)

    def _assert_ecc(self, request, key_id):
        self.assertEqual(request.publicKeyId, key_id)
        self.assertTrue(request.encryptedTransmissionKey)
        self.assertFalse(request.HasField('qrcMessageKey'))

    def test_qrc_envelope_is_sent(self):
        self.post.return_value = _ok()

        self.endpoint.execute_rest('test', None)

        self._assert_qrc(self._sent()[0], 7)

    def test_unavailable_library_sends_ecc(self):
        self.post.return_value = _ok()

        with patch.object(qrc_crypto, 'is_available', return_value=False):
            self.endpoint.execute_rest('test', None)

        self._assert_ecc(self._sent()[0], 7)

    def test_encryption_failure_falls_back_to_ecc(self):
        self.post.return_value = _ok()

        with patch.object(qrc_crypto, 'encrypt_transmission_key', side_effect=RuntimeError('boom')), \
                self.assertLogs(level='WARNING'):
            self.endpoint.execute_rest('test', None)

        self._assert_ecc(self._sent()[0], 7)
        self.assertIsNone(self.endpoint.qrc_key_id)

    def test_key_error_with_new_qrc_ec_key_retries_qrc(self):
        self.post.side_effect = [_error(401, {'error': 'key', 'key_id': 136, 'qrc_ec_key_id': 10}), _ok()]

        self.endpoint.execute_rest('test', None)

        first, second = self._sent()
        self._assert_qrc(first, 7)
        self._assert_qrc(second, 10)
        self.assertEqual(self.endpoint.server_key_id, 10)

    def test_key_error_with_same_qrc_ec_key_falls_back_to_ecc(self):
        self.post.side_effect = [_error(401, {'error': 'key', 'key_id': 136, 'qrc_ec_key_id': 7}), _ok()]

        self.endpoint.execute_rest('test', None)

        self.assertEqual(self.post.call_count, 2)
        self._assert_ecc(self._sent()[1], 7)

    def test_key_error_without_qrc_ec_key_uses_suggested_key(self):
        self.post.side_effect = [_error(401, {'error': 'key', 'key_id': 9}), _ok()]

        self.endpoint.execute_rest('test', None)

        self.assertEqual(self.post.call_count, 2)
        self._assert_ecc(self._sent()[1], 9)

    def test_crypto_error_falls_back_to_ecc(self):
        self.post.side_effect = [_error(500, {'error': 'crypto_error', 'message': 'Bad envelope'}), _ok()]

        with self.assertLogs(level='WARNING'):
            self.endpoint.execute_rest('test', None)

        self._assert_ecc(self._sent()[1], 7)

    def test_qrc_wording_falls_back_to_ecc(self):
        self.post.side_effect = [_error(400, {'error': 'bad_request', 'message': 'ML-KEM decapsulation failed'}),
                                 _ok()]

        with self.assertLogs(level='WARNING'):
            self.endpoint.execute_rest('test', None)

        self._assert_ecc(self._sent()[1], 7)

    def test_ordinary_encryption_error_is_not_resent(self):
        self.post.return_value = _error(400, {'error': 'bad_request', 'message': 'Record encryption is invalid'})

        with self.assertRaises(errors.KeeperApiError):
            self.endpoint.execute_rest('test', None)

        self.assertEqual(self.post.call_count, 1)
        self.assertEqual(self.endpoint.qrc_key_id, 136)


if __name__ == '__main__':
    unittest.main()
