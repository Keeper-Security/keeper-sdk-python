#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2019 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import logging

from .APIRequest_pb2 import LoginType, PreLoginRequest, PreLoginResponse

from . import crypto, ui, utils
from .endpoint import KeeperEndpoint
from .errors import KeeperApiError, KeeperError
from .configuration import InMemoryConfigurationStorage, UserConfiguration, ServerConfiguration


class AuthContext:
    def __init__(self):
        self.username = ''
        self.data_key = None
        self.client_key = None
        self.private_key = None
        self.is_enterprise_admin = False
        self.session_token = ''
        self.two_factor_token = ''
        self.enforcements = None
        self.settings = None


class Auth:
    def __init__(self, auth_ui, storage=None):
        self.ui = auth_ui
        self.storage = storage or InMemoryConfigurationStorage()
        self.endpoint = KeeperEndpoint()
        self.auth_context = None

        conf = self.storage.get_configuration()
        if conf.last_server:
            self.endpoint.server = conf.last_server
            server_conf = conf.get_server_configuration(conf.last_server)
            if server_conf:
                self.endpoint.encrypted_device_token = server_conf.device_id
                self.endpoint.server_key_id = server_conf.server_key_id

        self.auth_response = None

    @property
    def is_authenticated(self):
        return True if self.auth_context and self.auth_context.session_token else False

    def logout(self):
        self.auth_response = None

    def login(self, username, password):
        if not username or not password:
            logging.error('invalid username or password')

        config = self.storage.get_configuration()
        user_conf = config.get_user_configuration(username)

        auth_verifier = ''
        pre_login = None   # type: PreLoginResponse
        mfa_token = user_conf.two_factor_token if user_conf is not None else None
        mfa_type = 'device_token'
        mfa_duration = 30

        self.auth_context = AuthContext()
        success = False
        while not success:
            if not auth_verifier:
                if not pre_login:
                    pre_login = self.pre_login(username)
                auth_params = pre_login.salt[0]
                key_hash = crypto.derive_keyhash_v1(password, auth_params.salt, auth_params.iterations)
                auth_verifier = utils.base64_url_encode(key_hash)

            rq = {
                'command': 'login',
                'include': ['keys', 'license', 'settings', 'enforcements', 'is_enterprise_admin', 'client_key'],
                'version': 2,
                'auth_response': auth_verifier,
                'username': username.lower()
            }

            if mfa_token:
                rq['2fa_token'] = mfa_token
                rq['2fa_type'] = mfa_type or 'device_token'
                if mfa_type == 'one_time':
                    rq['device_token_expire_days'] = mfa_duration

            rs = self.endpoint.v2_execute(rq)
            if rs['result'] == 'fail' and rs['result_code'] == 'auth_failed':
                raise KeeperApiError(rs['result_code'], rs.get('message'))

            if 'device_token' in rs:
                mfa_token = rs['device_token']
                mfa_type = 'device_token'

            if 'keys' in rs:
                keys = rs['keys']
                if 'encrypted_data_key' in keys:
                    auth_params = pre_login.salt[0]
                    key = crypto.derive_keyhash_v2('data_key', password, auth_params.salt, auth_params.iterations)
                    self.auth_context.data_key = crypto.decrypt_aes_v2(utils.base64_url_decode(keys['encrypted_data_key']), key)
                elif 'encryption_params' in keys:
                    self.auth_context.data_key = utils.decrypt_encryption_params(keys['encryption_params'], password)

                enc_private_key = utils.base64_url_decode(keys['encrypted_private_key'])
                decrypted_private_key = crypto.decrypt_aes_v1(enc_private_key, self.auth_context.data_key)
                self.auth_context.private_key = crypto.load_private_key(decrypted_private_key)

            if 'session_token' in rs:
                self.auth_context.session_token = rs['session_token']
                self.auth_context.username = username

            if 'settings' in rs:
                self.auth_context.settings = rs['settings']
            if 'enforcements' in rs:
                self.auth_context.enforcements = rs['enforcements']
            if 'is_enterprise_admin' in rs:
                self.auth_context.is_enterprise_admin = rs['is_enterprise_admin']

            if rs['result'] == 'success':
                self.auth_context.two_factor_token = mfa_token
                self.auth_response = auth_verifier
                self.auth_context.is_enterprise_admin = rs.get('is_enterprise_admin') or False
                self.store_configuration(config)
                try:
                    if 'client_key' in rs:
                        client_key = utils.base64_url_decode(rs['client_key'])
                    else:
                        client_key = crypto.get_random_bytes(32)
                        client_key = crypto.encrypt_aes_v1(client_key, self.auth_context.data_key)
                        rq = {
                            "command": "set_client_key",
                            "client_key": utils.base64_url_encode(client_key)
                        }
                        rs = self.execute_auth_command(rq, throw_on_error=False)
                        if rs['result'] != 'success':
                            if rs['result_code'] == 'exists':
                                client_key = utils.base64_url_decode(rs['client_key'])
                            else:
                                raise KeeperApiError(rs['result_code'], rs['message'])
                    self.auth_context.client_key = crypto.decrypt_aes_v1(client_key, self.auth_context.data_key)
                except Exception as e:
                    logging.warning('Client Key decrypt error: %s', e)
                success = True
            else:
                result_code = rs['result_code']
                if result_code in {'need_totp', 'invalid_device_token', 'invalid_totp'}:
                    channel = ui.TwoFactorChannel.Other
                    channel_code = rs['channel']
                    if channel_code == 'two_factor_channel_sms':
                        channel = ui.TwoFactorChannel.TextMessage
                    elif channel_code == 'two_factor_channel_google':
                        channel = ui.TwoFactorChannel.Authenticator
                    elif channel_code == 'two_factor_channel_duo':
                        channel = ui.TwoFactorChannel.DuoSecurity
                    tfa_code, expiration = self.ui.get_two_factor_code(channel)
                    if tfa_code:
                        mfa_token = tfa_code
                        mfa_type = 'one_time'
                        mfa_duration = 9999 if expiration == ui.TwoFactorCodeDuration.Forever \
                            else 30 if expiration == ui.TwoFactorCodeDuration.Every30Days else 0
                        continue
                elif result_code == 'auth_expired':
                    logging.warning(rs['message'])
                    auth_params = pre_login.salt[0]
                    new_password = self.change_master_password(auth_params.iterations)
                    if new_password:
                        pre_login = None
                        auth_verifier = None
                        password = new_password
                        continue
                elif result_code == 'auth_expired_transfer':
                    logging.warning(rs['message'])
                    prompt = 'Do you accept Account Transfer policy?'
                    if self.ui.confirmation(rs['message'] + '\n\n' + prompt):
                        share_account_to = self.auth_context.settings['share_account_to']
                        self.accept_account_transfer_consent(share_account_to)
                        self.auth_context.session_token = None
                        continue

                raise KeeperApiError(result_code, rs['message'])

    def accept_account_transfer_consent(self, share_account_to):
        for role in share_account_to:
            public_key = crypto.load_public_key(utils.base64_url_decode(role['public_key']))
            transfer_key = crypto.encrypt_rsa(self.auth_context.data_key, public_key)
            request = {
                'command': 'share_account',
                'to_role_id': role['role_id'],
                'transfer_key': transfer_key
            }
            self.execute_auth_command(request)

    def change_master_password(self, iterations):
        rules_intro = ""
        rules = []
        if self.is_authenticated and self.auth_context.settings:
            rules_intro = self.auth_context.settings['password_rules_intro']
            for r in self.auth_context.settings['password_rules']:
                rule = ui.PasswordRule()
                rule.match = r.get('match') or True
                rule.pattern = r.get('pattern')
                rule.description = r.get('description')
                rules.append(rule)
        else:
            user_params = self.endpoint.get_new_user_params(self.auth_context.username)
            for r, d in zip(user_params.PasswordMatchRegex, user_params.PasswordMatchDescription):
                rule = ui.PasswordRule()
                rule.match = True
                rule.pattern = r
                rule.description = d
                rules.append(rule)
        matcher = ui.PasswordRuleMatcher(rules_intro, rules)
        password = self.ui.get_new_password(matcher)
        if password:
            failed_rules = matcher.match_failed_rules(password)
            if not failed_rules:
                salt1 = crypto.get_random_bytes(16)
                auth_verifier = utils.create_auth_verifier(password, salt1, iterations)
                salt2 = crypto.get_random_bytes(16)
                encryption_params = utils.create_encryption_params(password, salt2, iterations, self.auth_context.data_key)
                request = {
                    'command': 'change_master_password',
                    'auth_verifier': auth_verifier,
                    'encryption_params': encryption_params
                }
                self.execute_auth_command(request)
            else:
                raise KeeperApiError("password_rule_failed", failed_rules[0].description)

        return password

    def execute_auth_command(self, command, throw_on_error=True):
        command['username'] = self.auth_context.username.lower()
        command['session_token'] = self.auth_context.session_token
        response = self.endpoint.v2_execute(command)
        if response['result'] != 'success' and response['result_code'] == 'auth_failed':
            try:
                logging.debug('Refresh Session Token')
                self.auth_context.session_token = ''
                self.refresh_session_token()
            except KeeperApiError as e:
                logging.info('Refresh Session Token Error: %s', e)

            if self.is_authenticated:
                command['session_token'] = self.auth_context.session_token
                response = self.endpoint.v2_execute(command)
            else:
                self.logout()

        if response['result'] != 'success' and throw_on_error:
            raise KeeperApiError(response['result_code'], response['message'])
        return response

    def pre_login(self, username, two_factor_token=None):
        attempt = 0
        while attempt < 3:
            attempt += 1
            rq = PreLoginRequest()
            rq.authRequest.clientVersion = self.endpoint.client_version
            rq.authRequest.username = username.lower()
            rq.authRequest.encryptedDeviceToken = self.endpoint.get_device_token()
            rq.loginType = LoginType.Value('NORMAL')
            if two_factor_token:
                rq.twoFactorToken = two_factor_token

            rs = self.endpoint.execute_rest('authentication/pre_login', rq.SerializeToString())
            if type(rs) == bytes:
                pre_login_rs = PreLoginResponse()
                pre_login_rs.ParseFromString(rs)
                return pre_login_rs

            if type(rs) == dict:
                if 'error' in rs and 'message' in rs:
                    if rs['error'] == 'region_redirect':
                        self.endpoint.encrypted_device_token = None
                        self.endpoint.server = rs['region_host']
                        config = self.storage.get_configuration()
                        server_config = config.get_server_configuration(self.endpoint.server)
                        if server_config:
                            self.endpoint.encrypted_device_token = server_config.device_id
                        logging.warning('Switching to keeper host: %s.', self.endpoint.server)
                        continue
                    if rs['error'] == 'bad_request':
                        self.endpoint.encrypted_device_token = None
                        logging.warning('Pre-Login error: %s', rs.get('additional_info'))
                        continue

                    raise KeeperApiError(rs['error'], rs['message'])

        raise KeeperError('Cannot get user information')

    def store_configuration(self, config):
        should_save_config = not config.last_username or not config.last_server
        if not should_save_config:
            should_save_config = config.last_username != UserConfiguration.adjust_name(self.auth_context.username) or \
                                 config.last_server != ServerConfiguration.adjust_name(self.endpoint.server)

        user_conf = config.get_user_configuration(self.auth_context.username)
        should_save_user = not user_conf
        if user_conf:
            should_save_user = user_conf.two_factor_token != self.auth_context.two_factor_token

        server_conf = config.get_server_configuration(self.endpoint.server)
        should_save_server = not server_conf
        if server_conf:
            should_save_server = server_conf.device_id != self.endpoint.encrypted_device_token or \
                                 server_conf.server_key_id != self.endpoint.server_key_id

        if should_save_config or should_save_user or should_save_server:
            if should_save_config:
                config.last_username = UserConfiguration.adjust_name(self.auth_context.username)
                config.last_server = ServerConfiguration.adjust_name(self.endpoint.server)

            if should_save_user:
                if not user_conf:
                    user_conf = UserConfiguration(username=self.auth_context.username)
                user_conf.two_factor_token = self.auth_context.two_factor_token
                config.merge_user_configuration(user_conf)

            if should_save_server:
                if not server_conf:
                    server_conf = ServerConfiguration(server=self.endpoint.server)
                server_conf.device_id = self.endpoint.encrypted_device_token
                server_conf.server_key_id = self.endpoint.server_key_id
                config.merge_server_configuration(server_conf)

            self.storage.put_configuration(config)

    def refresh_session_token(self):
        request = {
            'command': 'login',
            'version': 2,
            'auth_response': self.auth_response,
            'username': self.auth_context.username
        }
        if self.auth_context.two_factor_token:
            request['2fa_token'] = self.auth_context.two_factor_token
            request['2fa_type'] = 'device_token'

        response = self.endpoint.v2_execute(request)
        if response['result'] == 'success':
            self.auth_context.session_token = response['session_token']
        else:
            raise KeeperApiError(result_code=response['result_code'], message=response['message'])
