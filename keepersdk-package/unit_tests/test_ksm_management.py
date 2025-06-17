import unittest
from unittest.mock import MagicMock, patch

from keepersdk.vault import ksm_management

class ListSecretsManagerAppsTestCase(unittest.TestCase):
    def setUp(self):
        self.vault = MagicMock()
        self.vault.keeper_auth.execute_auth_rest.return_value.applicationSummary = [
            MagicMock(
                appRecordUid=b'uid1',
                folderRecords=2,
                folderShares=1,
                clientCount=3,
                lastAccess=1710000000000
            )
        ]
        self.vault.vault_data.load_record.return_value = MagicMock(title='App1')
        self.patcher = patch('keepersdk.vault.ksm_management.utils.base64_url_encode', return_value='encoded_uid1')
        self.mock_encode = self.patcher.start()

    def tearDown(self):
        self.patcher.stop()

    def test_returns_list_of_apps(self):
        apps = ksm_management.list_secrets_manager_apps(self.vault)
        self.assertEqual(len(apps), 1)
        self.assertEqual(apps[0].name, 'App1')
        self.assertEqual(apps[0].uid, 'encoded_uid1')
        self.assertEqual(apps[0].records, 2)
        self.assertEqual(apps[0].folders, 1)
        self.assertEqual(apps[0].count, 3)
        self.assertIsNotNone(apps[0].last_access)


class GetSecretsManagerAppTestCase(unittest.TestCase):
    def setUp(self):
        self.vault = MagicMock()
        self.ksm_app = MagicMock(record_uid='uid1', title='App1')
        self.vault.vault_data.records.return_value = [self.ksm_app]
        self.patcher_encode = patch('keepersdk.vault.ksm_management.utils.base64_url_encode', return_value='encoded_uid1')
        self.mock_encode = self.patcher_encode.start()
        self.patcher_decode = patch('keepersdk.vault.ksm_management.utils.base64_url_decode', return_value=b'uid1')
        self.mock_decode = self.patcher_decode.start()
        self.patcher_client = patch('keepersdk.vault.ksm_management.ksm.ClientDevice', side_effect=lambda **kwargs: kwargs)
        self.mock_client = self.patcher_client.start()
        self.patcher_shared = patch('keepersdk.vault.ksm_management.ksm.SharedSecretsInfo', side_effect=lambda **kwargs: kwargs)
        self.mock_shared = self.patcher_shared.start()
        self.patcher_app = patch('keepersdk.vault.ksm_management.ksm.SecretsManagerApp', side_effect=lambda **kwargs: kwargs)
        self.mock_app = self.patcher_app.start()
        self.patcher_type = patch('keepersdk.vault.ksm_management.APIRequest_pb2.ApplicationShareType.Name', return_value='SHARE_TYPE_RECORD')
        self.mock_type = self.patcher_type.start()
        self.patcher_enterprise = patch('keepersdk.vault.ksm_management.enterprise_pb2.GENERAL', 1)
        self.mock_enterprise = self.patcher_enterprise.start()
        self.patcher_short = patch('keepersdk.vault.ksm_management.shorten_client_id', return_value='shortid')
        self.mock_short = self.patcher_short.start()

    def tearDown(self):
        self.patcher_encode.stop()
        self.patcher_decode.stop()
        self.patcher_client.stop()
        self.patcher_shared.stop()
        self.patcher_app.stop()
        self.patcher_type.stop()
        self.patcher_enterprise.stop()
        self.patcher_short.stop()

    def test_app_found_and_returns_app(self):
        app_info = MagicMock()
        client = MagicMock(appClientType=1, id='client1', createdOn=1710000000000, accessExpireOn=0, firstAccess=0, lastAccess=0, lockIp=False, ipAddress='1.2.3.4')
        app_info.clients = [client]
        share = MagicMock(secretUid=b'secret1', shareType=1, editable=True)
        app_info.shares = [share]
        with patch('keepersdk.vault.ksm_management.get_app_info', return_value=[app_info]):
            result = ksm_management.get_secrets_manager_app(self.vault, 'uid1')
            self.assertIn('name', result)
            self.assertEqual(result['name'], 'App1')
            self.assertIn('client_devices', result)
            self.assertEqual(len(result['client_devices']), 1)
            self.assertIsNone(result['last_access'])

    def test_app_not_found_raises(self):
        self.vault.vault_data.records.return_value = []
        with self.assertRaises(ValueError):
            ksm_management.get_secrets_manager_app(self.vault, 'notfound')

    def test_no_app_info_raises(self):
        with patch('keepersdk.vault.ksm_management.get_app_info', return_value=[]):
            with self.assertRaises(ValueError):
                ksm_management.get_secrets_manager_app(self.vault, 'uid1')

class GetAppInfoTestCase(unittest.TestCase):
    def setUp(self):
        self.vault = MagicMock()
        self.patcher_decode = patch('keepersdk.vault.ksm_management.utils.base64_url_decode', return_value=b'uid1')
        self.mock_decode = self.patcher_decode.start()

    def tearDown(self):
        self.patcher_decode.stop()

    def test_calls_execute_auth_rest(self):
        response = MagicMock()
        response.appInfo = ['info']
        self.vault.keeper_auth.execute_auth_rest.return_value = response
        result = ksm_management.get_app_info(self.vault, 'uid1')
        self.assertEqual(result, ['info'])


if __name__ == "__main__":
    unittest.main()