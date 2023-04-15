import os
import unittest

from keepersdk.enterprise import legacy_enterprise, loader
from keepersdk.login import auth, endpoint, configuration
from keepersdk.proto import enterprise_pb2


class MyTestCase(unittest.TestCase):
    def get_keeper_auth(self):
        config_filename = os.path.join(os.path.dirname(__file__), 'login.json')
        config_storage = configuration.JsonConfigurationStorage(file_name=config_filename)
        config = config_storage.get()
        username = next((x.username for x in config.users().list() if 'enterprise' in x.username), None)
        self.assertIsNotNone(username, 'Enterprise username was not found in the configuration file')
        keeper_endpoint = endpoint.KeeperEndpoint(config_storage)
        login_auth = auth.LoginAuth(keeper_endpoint)
        login_auth.login(username)
        login_auth.login_step.is_final()
        step = login_auth.login_step
        self.assertIsInstance(step, auth.LoginStepConnected)
        return step.keeper_auth()

    def test_load_enterprise(self):
        keeper_auth = self.get_keeper_auth()
        l_enterprise = legacy_enterprise.LegacyEnterpriseData()

        e_loader = loader.EnterpriseLoader(l_enterprise)
        affected = e_loader.load(keeper_auth)
        if enterprise_pb2.MANAGED_NODES in affected:
            role_uids = l_enterprise.get_missing_role_keys()
            if len(role_uids) > 0:
                e_loader.load_role_keys(keeper_auth, role_uids)
        enterprise_data = {}
        l_enterprise.synchronize(enterprise_data, affected)
        self.assertTrue(len(enterprise_data) > 0)
