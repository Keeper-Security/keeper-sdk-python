from unittest import TestCase
import os
from keepersdk import configuration, crypto, utils

_KEEPER_HOST = 'keepersecurity.com'
_KEEPER_USER = 'user@keepersecurity.com'


class TestConfig(TestCase):
    def test_config(self):
        config = configuration.Configuration()
        config.last_server = _KEEPER_HOST
        config.last_username = _KEEPER_USER
        two_factor_token = utils.base64_url_encode(crypto.get_random_bytes(20))
        user_conf = configuration.UserConfiguration(username=_KEEPER_USER, two_factor_token=two_factor_token)
        config.merge_user_configuration(user_conf)
        device_id = crypto.get_random_bytes(20)
        server_conf = configuration.ServerConfiguration(server=_KEEPER_HOST, device_id=device_id, server_key_id=2)
        config.merge_server_configuration(server_conf)
        self.assertEqual(config.last_server, _KEEPER_HOST)
        self.assertEqual(config.last_username, _KEEPER_USER)
        self.assertEqual(len(config.users), 1)
        self.assertEqual(config.users[0].username, _KEEPER_USER)
        self.assertIsNone(config.users[0].password)
        self.assertEqual(config.users[0].two_factor_token, two_factor_token)
        self.assertEqual(len(config.servers), 1)
        self.assertEqual(config.servers[0].server, _KEEPER_HOST)
        self.assertEqual(config.servers[0].device_id, device_id)
        self.assertEqual(config.servers[0].server_key_id, 2)

        two_factor_token = utils.base64_url_encode(crypto.get_random_bytes(20))
        user_conf = configuration.UserConfiguration(username=_KEEPER_USER.upper(), two_factor_token=two_factor_token)
        config.merge_user_configuration(user_conf)
        self.assertEqual(len(config.users), 1)
        self.assertEqual(config.users[0].username, _KEEPER_USER)
        self.assertIsNone(config.users[0].password)
        self.assertEqual(config.users[0].two_factor_token, two_factor_token)

        device_id = crypto.get_random_bytes(20)
        server_conf = configuration.ServerConfiguration(server='https://{0}/api/v2/'.format(_KEEPER_HOST.upper()), device_id=device_id, server_key_id=3)
        config.merge_server_configuration(server_conf)
        self.assertEqual(len(config.servers), 1)
        self.assertEqual(config.servers[0].server, _KEEPER_HOST)
        self.assertEqual(config.servers[0].device_id, device_id)
        self.assertEqual(config.servers[0].server_key_id, 3)

    def test_json_config(self):
        config_file = os.path.abspath('.')
        config_file = os.path.join(config_file, 'empty.json')
        if os.path.isfile(config_file):
            os.remove(config_file)
        storage = configuration.JsonConfiguration(config_file)
        self.assertIsNotNone(storage)
        config = storage.get_configuration()
        self.assertIsNotNone(config)

        config.last_server = _KEEPER_HOST
        config.last_username = _KEEPER_USER
        two_factor_token = utils.base64_url_encode(crypto.get_random_bytes(20))
        user_conf = configuration.UserConfiguration(username=_KEEPER_USER, two_factor_token=two_factor_token)
        config.merge_user_configuration(user_conf)
        device_id = crypto.get_random_bytes(20)
        server_conf = configuration.ServerConfiguration(server=_KEEPER_HOST, device_id=device_id, server_key_id=2)
        config.merge_server_configuration(server_conf)
        storage.put_configuration(config)

        storage = configuration.JsonConfiguration(config_file)
        config = storage.get_configuration()
        self.assertEqual(config.last_server, _KEEPER_HOST)
        self.assertEqual(config.last_username, _KEEPER_USER)
        self.assertEqual(len(config.users), 1)
        self.assertEqual(config.users[0].username, _KEEPER_USER)
        self.assertIsNone(config.users[0].password)
        self.assertEqual(config.users[0].two_factor_token, two_factor_token)
        self.assertEqual(len(config.servers), 1)
        self.assertEqual(config.servers[0].server, _KEEPER_HOST)
        self.assertEqual(config.servers[0].device_id, device_id)
        self.assertEqual(config.servers[0].server_key_id, 2)
