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
        self.patcher_type = patch('keepersdk.proto.APIRequest_pb2.ApplicationShareType.Name', side_effect=lambda x: 'SHARE_TYPE_RECORD' if x == 1 else 'SHARE_TYPE_FOLDER' if x == 2 else 'UNKNOWN')
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


class CreateSecretsManagerAppTestCase(unittest.TestCase):
    def setUp(self):
        self.vault = MagicMock()
        self.vault.vault_data.records.return_value = []
        self.vault.keeper_auth.auth_context.data_key = b'datakey'
        self.patcher_uid = patch('keepersdk.vault.ksm_management.utils.generate_uid', return_value='uidstr')
        self.mock_uid = self.patcher_uid.start()
        self.patcher_decode = patch('keepersdk.vault.ksm_management.utils.base64_url_decode', return_value=b'uidbytes')
        self.mock_decode = self.patcher_decode.start()
        self.patcher_encode = patch('keepersdk.vault.ksm_management.utils.base64_url_encode', return_value='encoded_uid')
        self.mock_encode = self.patcher_encode.start()
        self.patcher_aes = patch('keepersdk.vault.ksm_management.utils.generate_aes_key', return_value=b'aeskey')
        self.mock_aes = self.patcher_aes.start()
        self.patcher_encrypt = patch('keepersdk.vault.ksm_management.crypto.encrypt_aes_v2', side_effect=lambda data, key: b'encrypted_' + data if isinstance(data, bytes) else b'encrypted_' + data.encode())
        self.mock_encrypt = self.patcher_encrypt.start()
        self.patcher_time = patch('keepersdk.vault.ksm_management.utils.current_milli_time', return_value=1710000000000)
        self.mock_time = self.patcher_time.start()
        self.patcher_req = patch('keepersdk.vault.ksm_management.ApplicationAddRequest', autospec=True)
        self.mock_req = self.patcher_req.start()

    def tearDown(self):
        self.patcher_uid.stop()
        self.patcher_decode.stop()
        self.patcher_encode.stop()
        self.patcher_aes.stop()
        self.patcher_encrypt.stop()
        self.patcher_time.stop()
        self.patcher_req.stop()

    def test_create_app_success(self):
        app_uid = ksm_management.create_secrets_manager_app(self.vault, 'TestApp')
        self.assertEqual(app_uid, 'encoded_uid')
        self.vault.keeper_auth.execute_auth_rest.assert_called_once()
        self.mock_req.assert_called_once()
        args, kwargs = self.vault.keeper_auth.execute_auth_rest.call_args
        self.assertEqual(kwargs.get('rest_endpoint'), ksm_management.URL_CREATE_APP_API)

    def test_create_app_duplicate_raises(self):
        mock_record = MagicMock(title='TestApp')
        self.vault.vault_data.records.return_value = [mock_record]
        with self.assertRaises(ValueError) as cm:
            ksm_management.create_secrets_manager_app(self.vault, 'TestApp')
        self.assertEqual(str(cm.exception), 'Application with the same name TestApp already exists. Set force to true to add Application with same name')

    def test_create_app_duplicate_force_add(self):
        mock_record = MagicMock(title='TestApp')
        self.vault.vault_data.records.return_value = [mock_record]
        app_uid = ksm_management.create_secrets_manager_app(self.vault, 'TestApp', force_add=True)
        self.assertEqual(app_uid, 'encoded_uid')


class RemoveSecretsManagerAppTestCase(unittest.TestCase):
    def setUp(self):
        self.vault = MagicMock()
        self.patcher_get = patch('keepersdk.vault.ksm_management.get_secrets_manager_app')
        self.mock_get = self.patcher_get.start()
        self.patcher_delete = patch('keepersdk.vault.ksm_management.record_management.delete_vault_objects')
        self.mock_delete = self.patcher_delete.start()
        self.patcher_path = patch('keepersdk.vault.ksm_management.vault_types.RecordPath', side_effect=lambda folder_uid, record_uid: MagicMock(folder_uid=folder_uid, record_uid=record_uid))
        self.mock_path = self.patcher_path.start()

    def tearDown(self):
        self.patcher_get.stop()
        self.patcher_delete.stop()
        self.patcher_path.stop()

    def test_remove_app_success(self):
        app = MagicMock(uid='appuid', records=0, folders=0, count=0)
        self.mock_get.return_value = app
        uid = ksm_management.remove_secrets_manager_app(self.vault, 'appuid')
        self.mock_delete.assert_called_once()
        self.assertEqual(uid, 'appuid')

    def test_remove_app_with_clients_raises(self):
        app = MagicMock(uid='appuid', records=1, folders=0, count=0)
        self.mock_get.return_value = app
        with self.assertRaises(ValueError) as cm:
            ksm_management.remove_secrets_manager_app(self.vault, 'appuid')
        self.assertEqual(str(cm.exception), 'Cannot remove application with clients, shared record, shared folder. Force remove to proceed')

    def test_remove_app_with_clients_force(self):
        app = MagicMock(uid='appuid', records=1, folders=1, count=1)
        self.mock_get.return_value = app
        uid = ksm_management.remove_secrets_manager_app(self.vault, 'appuid', force=True)
        self.mock_delete.assert_called_once()
        self.assertEqual(uid, 'appuid')


if __name__ == "__main__":
    unittest.main()