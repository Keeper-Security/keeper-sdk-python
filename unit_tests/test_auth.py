from unittest import TestCase, mock

from keepersdk.APIRequest_pb2 import PreLoginResponse, DeviceStatus
from keepersdk.errors import KeeperApiError
from keepersdk import utils, crypto
from keepersdk.configuration import InMemoryConfigurationStorage, UserConfiguration, Configuration, JsonConfigurationStorage
from data_vault import VaultEnvironment, get_connected_auth_context, get_auth_context

vault_env = VaultEnvironment()


class TestLogin(TestCase):
    has2fa = False
    dataKeyAsEncParam = False

    def setUp(self):
        self.pre_login_mock = mock.patch('keepersdk.auth.Auth.pre_login').start()
        self.pre_login_mock.side_effect = TestLogin.process_pre_login

        self.v2_execute_mock = mock.patch('keepersdk.endpoint.KeeperEndpoint.v2_execute').start()
        self.v2_execute_mock.side_effect = TestLogin.process_login_command

        TestLogin.has2fa = False
        TestLogin.dataKeyAsEncParam = False

    def tearDown(self):
        mock.patch.stopall()

    def test_login_success(self):
        auth = get_auth_context()
        config = auth.storage.get_configuration()
        user_config = config.get_user_configuration(config.last_username)
        auth.login(user_config.username, user_config.password)
        self.assertEqual(auth.auth_context.session_token, vault_env.session_token)
        self.assertEqual(auth.auth_context.data_key, vault_env.data_key)

    def test_refresh_session_token(self):
        auth = get_connected_auth_context()
        auth.auth_context.session_token = 'BadSessionToken'
        auth.refresh_session_token()
        self.assertEqual(auth.auth_context.session_token, vault_env.session_token)
        self.assertEqual(auth.auth_context.data_key, vault_env.data_key)

    def test_login_success_params(self):
        TestLogin.dataKeyAsEncParam = True
        auth = get_auth_context()
        config = auth.storage.get_configuration()
        user_config = config.get_user_configuration(config.last_username)
        auth.login(user_config.username, user_config.password)
        self.assertEqual(auth.auth_context.data_key, vault_env.data_key)
        self.assertEqual(auth.auth_context.session_token, vault_env.session_token)

    def test_login_success_2fa_device_token(self):
        TestLogin.has2fa = True
        auth = get_auth_context()

        config = auth.storage.get_configuration()
        user_config = config.get_user_configuration(config.last_username)
        user_config.two_factor_token = vault_env.device_token
        config.merge_user_configuration(user_config)
        auth.storage.put_configuration(config)

        auth.login(user_config.username, user_config.password)
        self.assertEqual(auth.auth_context.session_token, vault_env.session_token)
        self.assertEqual(auth.auth_context.data_key, vault_env.data_key)

    def test_login_success_2fa_one_time(self):
        TestLogin.has2fa = True
        auth = get_auth_context()
        auth.auth_ui.get_two_factor_code = mock.MagicMock(side_effect=[(vault_env.one_time_token, 'forever'), KeyboardInterrupt()])
        m = mock.MagicMock()
        auth.store_configuration = m
        config = auth.storage.get_configuration()
        user_config = config.get_user_configuration(config.last_username)
        auth.login(user_config.username, user_config.password)
        m.assert_called()
        self.assertEqual(auth.auth_context.session_token, vault_env.session_token)
        self.assertEqual(auth.auth_context.data_key, vault_env.data_key)

    def test_login_2fa_cancel(self):
        TestLogin.has2fa = True
        auth = get_auth_context()
        auth.auth_ui.get_two_factor_code = mock.MagicMock(side_effect=[KeyboardInterrupt()])
        config = auth.storage.get_configuration()
        user_config = config.get_user_configuration(config.last_username)
        with self.assertRaises(KeyboardInterrupt):
            auth.login(user_config.username, user_config.password)

    def test_login_failed(self):
        auth = get_auth_context()
        auth.auth_ui.get_two_factor_code = mock.MagicMock(side_effect=[KeyboardInterrupt()])
        config = auth.storage.get_configuration()
        user_config = config.get_user_configuration(config.last_username)
        with self.assertRaises(KeeperApiError):
            auth.login(user_config.username, '123456')

    def test_login_invalid_user(self):
        auth = get_auth_context()
        with self.assertRaises(KeeperApiError):
            auth.login('wrong.user@keepersecurity.com', '123456')

    def test_password_not_stored(self):
        config = Configuration()
        user_config = UserConfiguration(vault_env.user, password="old_password")
        config.merge_user_configuration(user_config)
        storage = InMemoryConfigurationStorage(config)
        config = storage.get_configuration()
        user_config = UserConfiguration(vault_env.user, password="new_password")
        config.merge_user_configuration(user_config)
        storage.put_configuration(config)
        config = storage.get_configuration()
        user_config = config.get_user_configuration(vault_env.user)
        self.assertIsNotNone(user_config)
        self.assertEqual(user_config.password, "old_password")

    def test_password_not_stored_json(self):
        storage = JsonConfigurationStorage("test.json")
        config = storage.get_configuration()
        user_config = UserConfiguration(vault_env.user, password="password")
        config.merge_user_configuration(user_config)
        storage.put_configuration(config)
        storage = JsonConfigurationStorage("test.json")
        config = storage.get_configuration()
        user_config = config.get_user_configuration(vault_env.user)
        self.assertIsNotNone(user_config)
        self.assertIsNone(user_config.password)

    def test_login_auth_expired(self):
        auth = get_auth_context()
        config = auth.storage.get_configuration()
        user_config = config.get_user_configuration(config.last_username)

        call_no = 0

        def return_auth_expired(rq):
            nonlocal call_no
            call_no += 1
            rs = TestLogin.process_login_command(rq)
            if call_no == 1:
                rs['result'] = 'fail'
                rs['result_code'] = 'auth_expired'
                rs['message'] = 'Auth expired'
            elif call_no == 2:
                pass
            else:
                raise Exception()
            return rs

        self.v2_execute_mock.side_effect = return_auth_expired

        m_passwd = mock.MagicMock(return_value=vault_env.password)
        auth.change_master_password = m_passwd
        with self.assertLogs():
            auth.login(user_config.username, user_config.password)
            m_passwd.assert_called()

        self.assertEqual(auth.auth_context.session_token, vault_env.session_token)
        self.assertEqual(auth.auth_context.data_key, vault_env.data_key)

    def test_account_transfer_expired(self):
        auth = get_auth_context()
        config = auth.storage.get_configuration()
        user_config = config.get_user_configuration(config.last_username)

        call_no = 0

        def return_auth_expired(rq):
            nonlocal call_no
            call_no += 1
            rs = TestLogin.process_login_command(rq)
            if call_no == 1:
                rs['result'] = 'fail'
                rs['result_code'] = 'auth_expired_transfer'
                rs['message'] = 'Auth Transfer expired'
                rs['settings'] = {
                    'share_account_to': [{
                        'role_id': 123456789,
                        'public_key': vault_env.encoded_public_key
                    }]
                }
            elif call_no == 2:
                pass
            else:
                raise Exception()
            return rs

        self.v2_execute_mock.side_effect = return_auth_expired

        m_transfer = mock.MagicMock()
        auth.accept_account_transfer_consent = m_transfer

        m_transfer.return_value = True
        with self.assertLogs():
            auth.login(user_config.username, user_config.password)
        m_transfer.assert_called()

        self.assertEqual(auth.auth_context.session_token, vault_env.session_token)
        self.assertEqual(auth.auth_context.data_key, vault_env.data_key)

    @staticmethod
    def process_pre_login(username):
        # type: (str) -> PreLoginResponse
        if username == vault_env.user:
            rs = PreLoginResponse()
            rs.status = DeviceStatus.Value('OK')
            salt = rs.salt.add()
            salt.iterations = vault_env.iterations
            salt.salt = vault_env.salt
            salt.algorithm = 2
            salt.name = 'Master password'
            return rs

        raise KeeperApiError('user_does_not_exist', 'user_does_not_exist')

    @staticmethod
    def process_login_command(request):
        # type: (dict) -> dict
        if request['username'] == vault_env.user:
            auth1 = utils.base64_url_encode(crypto.derive_keyhash_v1(vault_env.password, vault_env.salt, vault_env.iterations))
            if auth1 == request['auth_response']:
                device_token = None
                if TestLogin.has2fa:
                    method = request.get('2fa_type') or ''
                    token = request.get('2fa_token') or ''
                    if method == 'one_time':
                        if token != vault_env.one_time_token:
                            return {
                                'result': 'fail',
                                'result_code': 'invalid_totp',
                                'channel': 'two_factor_channel_google'
                            }
                        device_token = vault_env.device_token
                    elif method == 'device_token':
                        if token != vault_env.device_token:
                            return {
                                'result': 'fail',
                                'result_code': 'invalid_device_token',
                                'channel': 'two_factor_channel_google'
                            }
                    else:
                        return {
                            'result': 'fail',
                            'result_code': 'need_totp',
                            'channel': 'two_factor_channel_google'
                        }

                rs = {
                    'result': 'success',
                    'result_code': 'auth_success',
                    'session_token': vault_env.session_token
                }
                if TestLogin.has2fa and device_token:
                    rs['device_token'] = device_token
                    rs['dt_scope'] = 'expiration'

                if 'include' in request:
                    include = request['include']
                    if 'keys' in include:
                        keys = {
                            'encrypted_private_key': vault_env.encrypted_private_key
                        }
                        if TestLogin.dataKeyAsEncParam:
                            keys['encryption_params'] = vault_env.encryption_params
                        else:
                            keys['encrypted_data_key'] = vault_env.encrypted_data_key
                        rs['keys'] = keys

                    if 'is_enterprise_admin' in include:
                        rs['is_enterprise_admin'] = False
                    if 'client_key' in include:
                        rs['client_key'] = utils.base64_url_encode(crypto.encrypt_aes_v1(vault_env.client_key, vault_env.data_key))

                return rs

            return {
                'result': 'fail',
                'result_code': 'auth_failed',
                'salt': utils.base64_url_encode(vault_env.salt),
                'iterations': vault_env.iterations
            }

        return {
            'result': 'fail',
            'result_code': 'Failed_to_find_user'
        }
