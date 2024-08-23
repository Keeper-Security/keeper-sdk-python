import json
from typing import Optional
from unittest import TestCase

from keepersdk import crypto, utils
from keepersdk.authentication import configuration

user_name = 'user@company.com'
user_password = 'password'
server_name = 'company.com'
device_token = utils.generate_uid()
private_key, public_key = crypto.generate_rsa_key()
private_key_str = utils.base64_url_encode(crypto.unload_rsa_private_key(private_key))
public_key_str = utils.base64_url_encode(crypto.unload_rsa_public_key(public_key))
clone_code = utils.generate_uid()


class JsonInMemoryLoader(configuration.IJsonLoader):
    def __init__(self):
        self.data: Optional[bytes] = None

    def load_json(self):
        return self.data

    def store_json(self, data):
        self.data = data


class TestConfiguration(TestCase):

    def test_json(self) -> None:
        config = self.create_default_configuration()
        in_memory = JsonInMemoryLoader()
        holder = configuration.JsonConfigurationStorage(in_memory)
        holder.put(config)
        self.assertGreater(len(in_memory.data), 0)
        json_config = holder.get()
        self._compare_configurations(config, json_config)

    def _compare_configurations(self, config1: configuration.IKeeperConfiguration,
                                config2: configuration.IKeeperConfiguration) -> None:
        self.assertEqual(config1.last_login, config2.last_login)
        self.assertEqual(config1.last_server, config2.last_server)
        for uc1 in config1.users().list():
            self.assertEqual(uc1.username, uc1.get_id())
            uc2 = config2.users().get(uc1.get_id())
            assert uc2 is not None
            self.assertEqual(uc1.username, uc2.username)
            self.assertEqual(uc1.password, uc2.password)
            self.assertEqual(uc1.server, uc2.server)
            uld1 = uc1.last_device
            assert isinstance(uld1, configuration.IUserDeviceConfiguration)
            uld2 = uc2.last_device
            assert isinstance(uld2, configuration.IUserDeviceConfiguration)
            if uld1:
                self.assertEqual(uld1.device_token, uld1.get_id())
                self.assertEqual(uld1.device_token, uld2.device_token)
        for sc1 in config1.servers().list():
            self.assertEqual(sc1.server, sc1.get_id())
            sc2 = config2.servers().get(sc1.get_id())
            assert sc2 is not None
            self.assertEqual(sc1.server, sc2.server)
            self.assertEqual(sc1.server_key_id, sc2.server_key_id)
        for dc1 in config1.devices().list():
            self.assertEqual(dc1.device_token, dc1.get_id())
            dc2 = config2.devices().get(dc1.get_id())
            assert dc2 is not None
            self.assertEqual(dc1.device_token, dc2.device_token)
            self.assertEqual(dc1.private_key, dc2.private_key)
            for dsc1 in dc1.get_server_info().list():
                self.assertEqual(dsc1.server, dsc1.server)
                dsc2 = dc2.get_server_info().get(dsc1.get_id())
                assert dsc2 is not None
                self.assertEqual(dsc1.server, dsc2.server)
                self.assertEqual(dsc1.clone_code, dsc2.clone_code)

    @staticmethod
    def create_default_configuration():
        config = configuration.KeeperConfiguration()
        config.last_login = user_name
        config.last_server = server_name
        uc = configuration.UserConfiguration('user@company.com')
        uc.password = user_password
        uc.server = server_name
        uc.last_device = configuration.UserDeviceConfiguration(device_token)
        config.users().put(uc)
        sc = configuration.ServerConfiguration(server_name)
        sc.server_key_id = 2
        config.servers().put(sc)
        dc = configuration.DeviceConfiguration(device_token)
        dc.private_key = private_key_str
        dc.public_key = public_key_str
        dsc = configuration.DeviceServerConfiguration(server_name)
        dsc.clone_code = clone_code
        dc.get_server_info().put(dsc)
        config.devices().put(dc)

        return config

    def test_configuration_copy(self):
        config = self.create_default_configuration()
        config_copy = configuration.KeeperConfiguration(config)
        self._compare_configurations(config_copy, config)

    def test_json_extras(self):
        obj = {
            'users': [{
                'user': 'user@company.com',
                'password': 'user@company.com',
                'server': 'keepersecurity.com',
                'extra': 'anything'
            }],
            'last_login': 'user@company.com',
            'int_value': 1,
            'str_value': 'qwerty'
        }
        config = configuration.JsonKeeperConfiguration(obj)

        obj1 = configuration.KeeperConfiguration()
        obj1.last_server = 'keepersecurity.eu'
        u1 = configuration.UserConfiguration('user@company.com')
        u1.server = 'keepersecurity.eu'
        u1.password = 'user1@company.com'
        ud = configuration.UserDeviceConfiguration('Device1')
        u1.last_device = ud
        obj1.users().put(u1)
        config.assign(obj1)

        in_memory = JsonInMemoryLoader()
        holder = configuration.JsonConfigurationStorage(in_memory)
        holder.put(config)
        obj2 = json.loads(in_memory.data.decode())
        self.assertIn('int_value', obj2)
        self.assertEqual(obj2['int_value'], obj['int_value'])
        self.assertIn('users', obj2)
        self.assertEqual(len(obj2['users']), 1)
        self.assertIn('extra', obj2['users'][0])



