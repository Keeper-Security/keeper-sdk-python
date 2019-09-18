from typing import Optional
from unittest import TestCase

import os

from keepersdk import configuration, auth, ui
from keepersdk.vault import Vault


class TestUi(ui.AuthUI):
    def confirmation(self, information):  # type: (str) -> bool
        print(information)
        answer = input('(Y)es/(No): ')
        return answer.lower() in {'y', 'yes'}

    def get_twofactor_code(self, provider):  # type: (ui.TwoFactorChannel) -> str
        return input('Enter Two Factor Code: ')

    def get_new_password(self, matcher):  # type: (ui.PasswordRuleMatcher) -> Optional[str]
        raise NotImplemented()


class TestLogin(TestCase):
    def test_login(self):
        config_file = os.path.abspath('.')
        config_file = os.path.join(config_file, 'login.json')
        storage = configuration.JsonConfiguration(config_file)
        keeper_ui = TestUi()
        keeper_auth = auth.Auth(keeper_ui, storage)
        config = storage.get_configuration()
        user_conf = config.get_user_configuration(config.last_username)
        if user_conf:
            keeper_auth.login(user_conf.username, user_conf.password)
        self.assertIsNotNone(keeper_auth.session_token)
        rq = {
            "command": "account_summary",
            "include": ["client_key"]
        }
        keeper_auth.session_token += '1'
        rs = keeper_auth.execute_auth_command(rq)
        self.assertEqual(rs["result"], "success")

    def test_sync_down(self):
        config_file = os.path.abspath('.')
        config_file = os.path.join(config_file, 'login.json')
        storage = configuration.JsonConfiguration(config_file)
        keeper_ui = TestUi()
        keeper_auth = auth.Auth(keeper_ui, storage)
        config = storage.get_configuration()
        user_conf = config.get_user_configuration(config.last_username)
        if user_conf:
            keeper_auth.login(user_conf.username, user_conf.password)
        self.assertIsNotNone(keeper_auth.session_token)

        vault = Vault(keeper_auth)
        vault.sync_down()
        self.assertIsNotNone(vault)

        record = next(vault.get_all_records())
        vault.update_record(record)
        self.assertIsNotNone(record.record_uid)

