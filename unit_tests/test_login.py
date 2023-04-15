import concurrent.futures
import threading
from unittest import TestCase
from unittest.mock import MagicMock

import data_vault
from keepersdk import crypto, utils, errors
from keepersdk.login import endpoint, auth, configuration, notifications
from keepersdk.proto import APIRequest_pb2


class TestLogin(TestCase):
    StopAtDeviceApproval = False
    StopAtTwoFactor = False
    StopAtPassword = False

    @staticmethod
    def mock_execute_rest(keeper_endpoint, rest_endpoint, request=None, response_type=None, session_token=None):
        concurrent.futures.ThreadPoolExecutor(max_workers=10)

        if keeper_endpoint.server != data_vault.DefaultEnvironment:
            raise errors.RegionRedirectError(data_vault.DefaultEnvironment, '')

        if rest_endpoint == 'authentication/register_device':
            device = response_type()
            device.encryptedDeviceToken = crypto.get_random_bytes(64)
            return device
        if rest_endpoint == 'authentication/register_device_in_region':
            return
        if rest_endpoint == 'authentication/start_login':
            lrq = request   # type: APIRequest_pb2.StartLoginRequest
            lrs = response_type()
            lrs.encryptedLoginToken = data_vault.EncryptedLoginToken
            if TestLogin.StopAtDeviceApproval:
                lrs.loginState = APIRequest_pb2.DEVICE_APPROVAL_REQUIRED
            elif TestLogin.StopAtTwoFactor:
                lrs.loginState = APIRequest_pb2.REQUIRES_2FA
                channel = APIRequest_pb2.TwoFactorChannelInfo()
                channel.channelType = APIRequest_pb2.TWO_FA_CT_TOTP
                channel.channel_uid = crypto.get_random_bytes(8)
                channel.channelName = 'Mock'
                lrs.channels.append(channel)
            elif TestLogin.StopAtPassword:
                lrs.loginState = APIRequest_pb2.REQUIRES_AUTH_HASH
                salt = APIRequest_pb2.Salt()
                salt.iterations = data_vault.UserIterations
                salt.salt = data_vault.UserSalt
                salt.uid = crypto.get_random_bytes(8)
                salt.name = 'Master'
                lrs.salt.append(salt)
                salt = APIRequest_pb2.Salt()
                salt.iterations = data_vault.UserIterations
                salt.salt = data_vault.UserAlternateSalt
                salt.uid = crypto.get_random_bytes(8)
                salt.name = 'alternate'
                lrs.salt.append(salt)
                if lrq.loginType == APIRequest_pb2.ALTERNATE:
                    lrs.encryptedLoginToken = data_vault.EncryptedLoginTokenAlternate
            else:
                lrs.loginState = APIRequest_pb2.LOGGED_IN
                lrs.accountUid = data_vault.AccountUid
                lrs.primaryUsername = data_vault.UserName
                lrs.cloneCode = crypto.get_random_bytes(8)
                lrs.encryptedSessionToken = data_vault.SessionToken
                storage = keeper_endpoint.get_configuration_storage().get()
                dc = storage.devices().get(utils.base64_url_encode(lrq.encryptedDeviceToken))
                if not dc:
                    raise errors.KeeperError('Device Public Key')
                public_key = crypto.load_ec_public_key(utils.base64_url_decode(dc.public_key))
                lrs.encryptedDataKey = crypto.encrypt_ec(data_vault.UserDataKey, public_key)
                lrs.encryptedDataKeyType = APIRequest_pb2.BY_DEVICE_PUBLIC_KEY
            return lrs
        if rest_endpoint == 'authentication/request_device_verification':
            return
        if rest_endpoint == 'authentication/validate_device_verification_code':
            dvrq = request  # type:  APIRequest_pb2.ValidateDeviceVerificationCodeRequest
            if dvrq.verificationCode == data_vault.DeviceVerificationEmailCode:
                TestLogin.StopAtDeviceApproval = False
            return
        if rest_endpoint == 'authentication/2fa_send_push':
            return
        if rest_endpoint == 'authentication/2fa_validate':
            tfarq = request  # type:  APIRequest_pb2.TwoFactorValidateRequest
            if tfarq.value == data_vault.TwoFactorOneTimeToken:
                tfars = response_type()
                tfars.encryptedLoginToken = data_vault.EncryptedLoginToken
                if TestLogin.StopAtDeviceApproval:
                    TestLogin.StopAtDeviceApproval = False
                elif TestLogin.StopAtTwoFactor:
                    TestLogin.StopAtTwoFactor = False
                return tfars
            else:
                raise errors.AuthFailedError('unit test')
        if rest_endpoint == 'authentication/validate_auth_hash':
            prq = request  # type:  APIRequest_pb2.ValidateAuthHashRequest
            if prq.passwordMethod == APIRequest_pb2.BIOMETRICS:
                expected_auth_hash = crypto.create_bio_auth_hash(data_vault.UserBiometricKey)
            else:
                if prq.encryptedLoginToken == data_vault.EncryptedLoginTokenAlternate:
                    expected_auth_hash = crypto.derive_keyhash_v1(
                        data_vault.UserAlternatePassword, data_vault.UserAlternateSalt, data_vault.UserIterations)
                else:
                    expected_auth_hash = crypto.derive_keyhash_v1(
                        data_vault.UserPassword, data_vault.UserSalt, data_vault.UserIterations)
            if expected_auth_hash == prq.authResponse:
                lrs = response_type()
                lrs.encryptedLoginToken = data_vault.EncryptedLoginToken
                lrs.loginState = APIRequest_pb2.LOGGED_IN
                lrs.accountUid = data_vault.AccountUid
                lrs.primaryUsername = data_vault.UserName
                lrs.cloneCode = crypto.get_random_bytes(8)
                lrs.encryptedSessionToken = data_vault.SessionToken
                if prq.passwordMethod == APIRequest_pb2.BIOMETRICS:
                    lrs.encryptedDataKey = crypto.encrypt_aes_v2(data_vault.UserDataKey, data_vault.UserBiometricKey)
                    lrs.encryptedDataKeyType = APIRequest_pb2.BY_BIO
                else:
                    if prq.encryptedLoginToken == data_vault.EncryptedLoginTokenAlternate:
                        key = crypto.derive_keyhash_v2(
                            'data_key', data_vault.UserAlternatePassword, data_vault.UserAlternateSalt,
                            data_vault.UserIterations)
                        lrs.encryptedDataKey = crypto.encrypt_aes_v2(data_vault.UserDataKey, key)
                        lrs.encryptedDataKeyType = APIRequest_pb2.BY_ALTERNATE
                    else:
                        lrs.encryptedDataKey = utils.create_encryption_params(
                            data_vault.UserPassword, data_vault.UserSalt, data_vault.UserIterations,
                            data_vault.UserDataKey)
                        lrs.encryptedDataKeyType = APIRequest_pb2.BY_PASSWORD
                return lrs
            else:
                raise errors.AuthFailedError('invalid password')
        if rest_endpoint == 'login/account_summary':
            return data_vault.generate_account_summary(keeper_endpoint)

        raise errors.KeeperError('Canceled')

    @staticmethod
    def get_auth_sync():
        storage = data_vault.get_configuration_storage()
        keeper_endpoint = endpoint.KeeperEndpoint(storage)
        keeper_endpoint.client_version = data_vault.TestClientVersion
        keeper_endpoint.device_name = 'Python Unit Tests'

        def execute_rest(rest_endpoint, request=None, response_type=None, session_token=None):
            return TestLogin.mock_execute_rest(keeper_endpoint, rest_endpoint,
                                               request=request,
                                               response_type=response_type,
                                               session_token=session_token)

        def connect_to_push_server(payload=None):
            return notifications.FanOut()

        mock = MagicMock()
        mock.side_effect = execute_rest
        keeper_endpoint.execute_rest = mock

        mock = MagicMock()
        mock.side_effect = connect_to_push_server
        keeper_endpoint.connect_to_push_server = mock

        mock = MagicMock()
        mock.side_effect = Exception
        keeper_endpoint.v2_execute = mock

        mock = MagicMock()
        mock.side_effect = Exception
        keeper_endpoint._communicate_keeper = mock

        return auth.LoginAuth(keeper_endpoint)

    @staticmethod
    def reset_stops():
        TestLogin.StopAtDeviceApproval = False
        TestLogin.StopAtTwoFactor = False
        TestLogin.StopAtPassword = False

    def test_success_flow(self):
        TestLogin.reset_stops()

        login_auth = self.get_auth_sync()
        login_auth.login(data_vault.UserName)
        self.assertTrue(isinstance(login_auth.login_step, auth.LoginStepConnected))

    def test_register_device(self):
        TestLogin.reset_stops()

        login_auth = self.get_auth_sync()
        config = login_auth.keeper_endpoint.get_configuration_storage().get()
        device_token = utils.base64_url_encode(data_vault.DeviceId)
        config.devices().delete(device_token)
        login_auth.keeper_endpoint.get_configuration_storage().put(config)

        login_auth.login(data_vault.UserName)
        self.assertTrue(isinstance(login_auth.login_step, auth.LoginStepConnected))
        config = login_auth.keeper_endpoint.get_configuration_storage().get()
        uc = config.users().get(data_vault.UserName)
        self.assertIsNotNone(uc)
        ld = uc.last_device
        self.assertIsNotNone(ld)
        self.assertNotEqual(device_token, ld.device_token)

    def test_region_redirect(self):
        TestLogin.reset_stops()

        login_auth = self.get_auth_sync()
        config = login_auth.keeper_endpoint.get_configuration_storage().get()
        device_token = utils.base64_url_encode(data_vault.DeviceId)
        idc = config.devices().get(device_token)
        self.assertIsNotNone(idc)
        config.devices().delete(device_token)
        dc = configuration.DeviceConfiguration(idc.device_token)
        dc.private_key = idc.private_key
        dc.public_key = idc.public_key
        config.devices().put(dc)
        config.last_server = 'other.company.com'
        login_auth.keeper_endpoint.get_configuration_storage().put(config)

        login_auth.login(data_vault.UserName)
        self.assertTrue(isinstance(login_auth.login_step, auth.LoginStepConnected))
        self.assertEqual(login_auth.keeper_endpoint.server, data_vault.DefaultEnvironment)

    def test_device_approve_email_code(self):
        TestLogin.reset_stops()
        TestLogin.StopAtDeviceApproval = True

        login_auth = self.get_auth_sync()
        login_auth.login(data_vault.UserName)
        step = login_auth.login_step
        self.assertIsInstance(step, auth.LoginStepDeviceApproval)
        step.send_push(auth.DeviceApprovalChannel.Email)
        step.send_code(auth.DeviceApprovalChannel.Email, data_vault.DeviceVerificationEmailCode)
        self.assertIsInstance(login_auth.login_step, auth.LoginStepConnected)

    def test_device_approve_email_push(self):
        TestLogin.reset_stops()
        TestLogin.StopAtDeviceApproval = True

        event = threading.Event()
        login_auth = self.get_auth_sync()

        def set_if_connected():
            if isinstance(login_auth.login_step, auth.LoginStepConnected):
                event.set()

        login_auth.on_next_step = set_if_connected
        login_auth.login(data_vault.UserName)
        step = login_auth.login_step
        self.assertIsInstance(step, auth.LoginStepDeviceApproval)
        step.send_push(auth.DeviceApprovalChannel.Email)

        def send_push():
            if TestLogin.StopAtDeviceApproval:
                TestLogin.StopAtDeviceApproval = False
            login_auth.push_notifications.push({
                'command': 'device_verified',
            })
        threading.Thread(daemon=True, target=send_push).start()
        event.wait(1)

        self.assertTrue(isinstance(login_auth.login_step, auth.LoginStepConnected))

    def test_device_approve_keeper_push(self):
        TestLogin.reset_stops()
        TestLogin.StopAtDeviceApproval = True

        event = threading.Event()
        login_auth = self.get_auth_sync()

        def set_if_connected():
            if isinstance(login_auth.login_step, auth.LoginStepConnected):
                event.set()

        login_auth.on_next_step = set_if_connected
        login_auth.login(data_vault.UserName)
        step = login_auth.login_step
        self.assertIsInstance(step, auth.LoginStepDeviceApproval)
        step.send_push(auth.DeviceApprovalChannel.KeeperPush)

        def send_push():
            if TestLogin.StopAtDeviceApproval:
                TestLogin.StopAtDeviceApproval = False
            login_auth.push_notifications.push({
                'message': 'device_approved',
                'approved': True
            })
        threading.Thread(daemon=True, target=send_push).start()
        event.wait(1)

        self.assertIsInstance(login_auth.login_step, auth.LoginStepConnected)

    def test_two_factor_code(self):
        TestLogin.reset_stops()
        TestLogin.StopAtTwoFactor = True

        login_auth = self.get_auth_sync()
        login_auth.login(data_vault.UserName)
        step = login_auth.login_step
        self.assertIsInstance(step, auth.LoginStepTwoFactor)
        channels = list(step.get_channels())
        step.send_code(channels[0].channel_uid, data_vault.TwoFactorOneTimeToken)
        self.assertIsInstance(login_auth.login_step, auth.LoginStepConnected)

    def test_provided_password(self):
        TestLogin.reset_stops()
        TestLogin.StopAtPassword = True

        login_auth = self.get_auth_sync()
        config = login_auth.keeper_endpoint.get_configuration_storage().get()
        iuc = config.users().get(data_vault.UserName)
        self.assertIsInstance(iuc, configuration.IUserConfiguration)
        uc = configuration.UserConfiguration(iuc)
        uc.password = data_vault.UserPassword
        config.users().put(uc)
        login_auth.keeper_endpoint.get_configuration_storage().put(config)
        login_auth.login(data_vault.UserName)
        self.assertIsInstance(login_auth.login_step, auth.LoginStepConnected)

    def test_password(self):
        TestLogin.reset_stops()
        TestLogin.StopAtPassword = True

        login_auth = self.get_auth_sync()
        login_auth.login(data_vault.UserName)
        step = login_auth.login_step
        self.assertIsInstance(step, auth.LoginStepPassword)
        step.verify_password(data_vault.UserPassword)
        self.assertIsInstance(login_auth.login_step, auth.LoginStepConnected)

    def test_alternate_password(self):
        TestLogin.reset_stops()
        TestLogin.StopAtPassword = True

        login_auth = self.get_auth_sync()
        login_auth.alternate_password = True
        login_auth.login(data_vault.UserName)
        step = login_auth.login_step
        self.assertIsInstance(step, auth.LoginStepPassword)
        step.verify_password(data_vault.UserAlternatePassword)
        self.assertIsInstance(login_auth.login_step, auth.LoginStepConnected)

    def test_biometrics(self):
        TestLogin.reset_stops()
        TestLogin.StopAtPassword = True

        login_auth = self.get_auth_sync()
        login_auth.login(data_vault.UserName)
        step = login_auth.login_step
        self.assertIsInstance(step, auth.LoginStepPassword)
        step.verify_biometric_key(data_vault.UserBiometricKey)
        self.assertIsInstance(login_auth.login_step, auth.LoginStepConnected)

    def test_invalid_password(self):
        TestLogin.reset_stops()
        TestLogin.StopAtPassword = True

        login_auth = self.get_auth_sync()
        login_auth.login(data_vault.UserName)
        step = login_auth.login_step
        self.assertIsInstance(step, auth.LoginStepPassword)
        with self.assertRaises(errors.AuthFailedError):
            step.verify_password('wrong password')
