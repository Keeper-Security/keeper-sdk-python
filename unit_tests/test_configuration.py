from unittest import TestCase

from keepersdk import utils, crypto
from keepersdk.login import configuration

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
        self.data = None

    def load_json(self):
        return self.data

    def store_json(self, data):
        self.data = data


class TestConfiguration(TestCase):

    def test_json(self):
        config = self.create_default_configuration()
        in_memory = JsonInMemoryLoader()
        holder = configuration.JsonConfigurationStorage(in_memory)
        holder.put(config)
        self.assertGreater(len(in_memory.data), 0)
        json_config = holder.get()
        self._compare_configurations(config, json_config)

    def _compare_configurations(self, config1, config2):
        # type: (configuration.IKeeperConfiguration, configuration.IKeeperConfiguration) -> None
        self.assertEqual(config1.last_login, config2.last_login)
        self.assertEqual(config1.last_server, config2.last_server)
        for uc1 in config1.users().list():
            self.assertEqual(uc1.username, uc1.get_id())
            uc2 = config2.users().get(uc1.get_id())
            self.assertIsNotNone(uc2)
            self.assertEqual(uc1.username, uc2.username)
            self.assertEqual(uc1.password, uc2.password)
            self.assertEqual(uc1.server, uc2.server)
            uld1 = uc1.last_device
            uld2 = uc2.last_device
            self.assertIsInstance(uld1, configuration.IUserDeviceConfiguration)
            self.assertIsInstance(uld2, configuration.IUserDeviceConfiguration)
            if uld1:
                self.assertEqual(uld1.device_token, uld1.get_id())
                self.assertEqual(uld1.device_token, uld2.device_token)
        for sc1 in config1.servers().list():
            self.assertEqual(sc1.server, sc1.get_id())
            sc2 = config2.servers().get(sc1.get_id())
            self.assertIsNotNone(sc2)
            self.assertEqual(sc1.server, sc2.server)
            self.assertEqual(sc1.server_key_id, sc2.server_key_id)
        for dc1 in config1.devices().list():
            self.assertEqual(dc1.device_token, dc1.get_id())
            dc2 = config2.devices().get(dc1.get_id())
            self.assertIsNotNone(dc2)
            self.assertEqual(dc1.device_token, dc2.device_token)
            self.assertEqual(dc1.private_key, dc2.private_key)
            self.assertEqual(dc1.public_key, dc2.public_key)
            for dsc1 in dc1.get_server_info().list():
                self.assertEqual(dsc1.server, dsc1.server)
                dsc2 = dc2.get_server_info().get(dsc1.get_id())
                self.assertIsNotNone(dsc2)
                self.assertEqual(dsc1.server, dsc2.server)
                self.assertEqual(dsc1.clone_code, dsc2.clone_code)

    @staticmethod
    def create_default_configuration():
        config = configuration.KeeperConfiguration()
        config.last_login = user_name
        config.last_server = server_name
        uc = configuration.UserConfiguration('user@company.com')
        uc.password = user_password
        uc.server = 'server_name'
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
