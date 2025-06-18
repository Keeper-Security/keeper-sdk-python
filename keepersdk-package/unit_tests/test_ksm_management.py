import datetime
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
        self.patcher_app = patch('keepersdk.vault.ksm_management.ksm.SecretsManagerApp', side_effect=lambda **kwargs: type('App', (), kwargs))
        self.mock_app = self.patcher_app.start()

    def tearDown(self):
        self.patcher.stop()
        self.patcher_app.stop()

    def test_returns_list_of_apps(self):
        apps = ksm_management.list_secrets_manager_apps(self.vault)
        self.assertEqual(len(apps), 1)
        self.assertEqual(apps[0].name, 'App1')
        self.assertEqual(apps[0].uid, 'encoded_uid1')
        self.assertEqual(apps[0].records, 2)
        self.assertEqual(apps[0].folders, 1)
        self.assertEqual(apps[0].count, 3)
        self.assertIsNotNone(apps[0].last_access)

    def test_empty_summary_returns_empty_list(self):
        self.vault.keeper_auth.execute_auth_rest.return_value.applicationSummary = []
        apps = ksm_management.list_secrets_manager_apps(self.vault)
        self.assertEqual(apps, [])

    def test_missing_app_record_sets_empty_name(self):
        self.vault.vault_data.load_record.return_value = None
        apps = ksm_management.list_secrets_manager_apps(self.vault)
        self.assertEqual(apps[0].name, '')


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
        self.patcher_type = patch('keepersdk.vault.ksm_management.APIRequest_pb2.ApplicationShareType.Name', side_effect=lambda x: 'SHARE_TYPE_RECORD' if x == 1 else 'SHARE_TYPE_FOLDER' if x == 2 else 'UNKNOWN')
        self.mock_type = self.patcher_type.start()
        self.patcher_enterprise = patch('keepersdk.vault.ksm_management.GENERAL', 1)
        self.mock_enterprise = self.patcher_enterprise.start()
        self.patcher_short = patch('keepersdk.vault.ksm_management.shorten_client_id', return_value='shortid')
        self.mock_short = self.patcher_short.start()
        self.patcher_folders = patch('keepersdk.vault.ksm_management.vault_online.VaultOnline.vault_data', create=True)
        self.mock_folders = self.patcher_folders.start()

    def tearDown(self):
        self.patcher_encode.stop()
        self.patcher_decode.stop()
        self.patcher_client.stop()
        self.patcher_shared.stop()
        self.patcher_app.stop()
        self.patcher_type.stop()
        self.patcher_enterprise.stop()
        self.patcher_short.stop()
        self.patcher_folders.stop()

    def test_app_found_and_returns_app(self):
        app_info = MagicMock()
        client = MagicMock(appClientType=1, id='client1', createdOn=1710000000000, accessExpireOn=0, firstAccess=0, lastAccess=0, lockIp=False, ipAddress='1.2.3.4', clientId=b'clientid')
        app_info.clients = [client]
        share = MagicMock(secretUid=b'secret1', shareType=1, editable=True)
        app_info.shares = [share]
        with patch('keepersdk.vault.ksm_management.get_app_info', return_value=[app_info]):
            result = ksm_management.get_secrets_manager_app(self.vault, 'uid1')
            self.assertEqual(result['name'], 'App1')
            self.assertIn('client_devices', result)
            self.assertEqual(len(result['client_devices']), 1)
            self.assertIsNone(result['last_access'])
            self.assertEqual(result['records'], 1)
            self.assertEqual(result['folders'], 0)

    def test_app_found_with_folder_share(self):
        app_info = MagicMock()
        client = MagicMock(appClientType=1, id='client1', createdOn=1710000000000, accessExpireOn=0, firstAccess=0, lastAccess=0, lockIp=False, ipAddress='1.2.3.4', clientId=b'clientid')
        app_info.clients = [client]
        share = MagicMock(secretUid=b'secret2', shareType=2, editable=False)
        app_info.shares = [share]
        with patch('keepersdk.vault.ksm_management.get_app_info', return_value=[app_info]):
            result = ksm_management.get_secrets_manager_app(self.vault, 'uid1')
            self.assertEqual(result['folders'], 1)
            self.assertEqual(result['records'], 0)

    def test_app_not_found_raises(self):
        self.vault.vault_data.records.return_value = []
        with self.assertRaises(ValueError):
            ksm_management.get_secrets_manager_app(self.vault, 'notfound')

    def test_no_app_info_raises(self):
        with patch('keepersdk.vault.ksm_management.get_app_info', return_value=[]):
            with self.assertRaises(ValueError):
                ksm_management.get_secrets_manager_app(self.vault, 'uid1')

    def test_handle_share_type_unknown(self):
        app_info = MagicMock()
        client = MagicMock(appClientType=1, id='client1', createdOn=1710000000000, accessExpireOn=0, firstAccess=0, lastAccess=0, lockIp=False, ipAddress='1.2.3.4', clientId=b'clientid')
        app_info.clients = [client]
        share = MagicMock(secretUid=b'secret3', shareType=99, editable=False)
        app_info.shares = [share]
        with patch('keepersdk.vault.ksm_management.get_app_info', return_value=[app_info]):
            result = ksm_management.get_secrets_manager_app(self.vault, 'uid1')
            self.assertEqual(result['records'], 0)
            self.assertEqual(result['folders'], 0)
            self.assertEqual(result['shared_secrets'][0]['type'], 'UNKOWN SHARE TYPE')


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

    def test_empty_app_info(self):
        response = MagicMock()
        response.appInfo = []
        self.vault.keeper_auth.execute_auth_rest.return_value = response
        result = ksm_management.get_app_info(self.vault, 'uid1')
        self.assertEqual(result, [])

    def test_multiple_app_info(self):
        response = MagicMock()
        response.appInfo = ['info1', 'info2']
        self.vault.keeper_auth.execute_auth_rest.return_value = response
        result = ksm_management.get_app_info(self.vault, 'uid1')
        self.assertEqual(result, ['info1', 'info2'])


class ShortenClientIdTestCase(unittest.TestCase):
    def setUp(self):
        self.patcher_encode = patch('keepersdk.vault.ksm_management.utils.base64_url_encode', side_effect=lambda x: x.decode() if isinstance(x, bytes) else x)
        self.mock_encode = self.patcher_encode.start()

    def tearDown(self):
        self.patcher_encode.stop()

    def test_shorten_client_id_unique(self):
        all_clients = [MagicMock(clientId=b'abc12345'), MagicMock(clientId=b'def67890')]
        result = ksm_management.shorten_client_id(all_clients, 'abc12345', 3)
        self.assertEqual(result, 'abc')

    def test_shorten_client_id_increase_length(self):
        all_clients = [MagicMock(clientId=b'abc12345'), MagicMock(clientId=b'abc12346')]
        # Should increase length until unique
        result = ksm_management.shorten_client_id(all_clients, 'abc12345', 3)
        self.assertTrue(result.startswith('abc12345'))


class IntToDatetimeTestCase(unittest.TestCase):
    def test_valid_timestamp(self):
        dt = ksm_management.int_to_datetime(1710000000000)
        self.assertIsInstance(dt, datetime.datetime)

    def test_zero_timestamp(self):
        dt = ksm_management.int_to_datetime(0)
        self.assertIsNone(dt)

    def test_none_timestamp(self):
        dt = ksm_management.int_to_datetime(None)
        self.assertIsNone(dt)


if __name__ == "__main__":
    unittest.main()