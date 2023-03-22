import sqlite3
import os
import unittest
from typing import Optional

from login import auth, endpoint, configuration
from enterprise import legacy_enterprise, sqlite_storage, loader


class MyTestCase(unittest.TestCase):
    def get_keeper_auth(self):
        config_filename = os.path.join(os.path.dirname(__file__), 'login.json')
        config = configuration.JsonConfigurationStorage(file_name=config_filename)
        keeper_endpoint = endpoint.KeeperEndpoint(config)
        login_auth = auth.LoginAuth(keeper_endpoint)
        login_auth.login('integration.enterprise@keepersecurity.com')
        login_auth.login_step.is_final()
        self.assertIsInstance(login_auth.login_step, auth.LoginStepConnected)
        return login_auth.login_step.keeper_auth()

    def test_load_enterprise(self):
        keeper_auth = self.get_keeper_auth()
        l_enterprise = legacy_enterprise.LegacyEnterpriseData()

        file_name = ':memory:'
        connection = None  # type: Optional[sqlite3.Connection]

        def get_connection():
            nonlocal connection
            if connection is None:
                connection = sqlite3.Connection(file_name)
            return connection

        l_storage = sqlite_storage.SqliteEnterpriseStorage(get_connection, 191)
        e_loader = loader.EnterpriseLoader(l_enterprise, l_storage)
        e_loader.load(keeper_auth)
        self.assertTrue(len(l_enterprise.enterprise_data) > 0)