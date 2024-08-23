import os
import sqlite3
import unittest

from keepersdk.enterprise import enterprise_loader, sqlite_enterprise_storage
from keepersdk.authentication import configuration, login_auth, endpoint


class MyTestCase(unittest.TestCase):
    def get_keeper_auth(self):
        config_filename = os.path.join(os.path.dirname(__file__), 'login.json')
        config_storage = configuration.JsonConfigurationStorage.from_file(config_filename)
        config = config_storage.get()
        username = next((x.username for x in config.users().list() if 'enterprise' in x.username), None)
        self.assertIsNotNone(username, 'Enterprise username was not found in the configuration file')
        keeper_endpoint = endpoint.KeeperEndpoint(config_storage)
        auth = login_auth.LoginAuth(keeper_endpoint)
        auth.login(username)
        step = auth.login_step
        self.assertIsInstance(step, login_auth.LoginStepConnected)
        return step.take_keeper_auth()

    def test_load_enterprise(self):
        keeper_auth = self.get_keeper_auth()
        connection = sqlite3.Connection(':memory:')
        storage = sqlite_enterprise_storage.SqliteEnterpriseStorage(lambda: connection, keeper_auth.auth_context.enterprise_id)
        e_loader = enterprise_loader.EnterpriseLoader(keeper_auth, storage)
        affected = e_loader.load()

        self.assertTrue(len(affected) > 0)
