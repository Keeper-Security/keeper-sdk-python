import unittest
from unittest.mock import Mock, patch

from keepersdk.proto import APIRequest_pb2

from keepercli import login, prompt_utils
from keepercli.commands import account_commands

STRONG_PASSWORD = 'correct horse battery staple'


class ResetPasswordNonInteractiveTest(unittest.TestCase):
    def setUp(self):
        self.command = account_commands.ResetPasswordCommand()
        patches = {
            'validate_current': patch.object(self.command, '_validate_current_password_with_salt', return_value=True),
            'validate_rules': patch.object(self.command, '_validate_password_rules', return_value=True),
            'breachwatch': patch.object(self.command, '_perform_breachwatch_scan'),
            'change': patch.object(self.command, '_change_regular_password'),
            'output': patch.object(prompt_utils, 'output_text'),
        }
        self.mocks = {name: p.start() for name, p in patches.items()}
        for p in patches.values():
            self.addCleanup(p.stop)

    def test_reports_strength_and_changes_password(self):
        self.command._change_password_non_interactive(Mock(), 'Old-Passw0rd!', STRONG_PASSWORD, False, object())

        self.mocks['output'].assert_called_once_with('Password strength: STRONG')
        self.mocks['change'].assert_called_once()

    def test_same_password_is_rejected_before_server_validation(self):
        with self.assertLogs(level='WARNING') as logs:
            self.command._change_password_non_interactive(Mock(), STRONG_PASSWORD, STRONG_PASSWORD, False, object())

        self.assertIn(account_commands.RESET_PASSWORD_SAME_AS_CURRENT, logs.output[0])
        self.mocks['validate_current'].assert_not_called()
        self.mocks['change'].assert_not_called()

    def test_strength_is_not_reported_when_rules_fail(self):
        self.mocks['validate_rules'].return_value = False

        self.command._change_password_non_interactive(Mock(), 'Old-Passw0rd!', 'weak', False, object())

        self.mocks['output'].assert_not_called()
        self.mocks['change'].assert_not_called()


class ChangeMasterPasswordInteractiveTest(unittest.TestCase):
    def setUp(self):
        self.ui = Mock(spec=login.ConsoleMasterPasswordStrengthUI)
        change_command = patch.object(login.LoginAPI, 'change_master_password_command')
        output = patch.object(prompt_utils, 'output_text')
        self.change_command = change_command.start()
        output.start()
        self.addCleanup(change_command.stop)
        self.addCleanup(output.stop)

    def _run(self, *passwords, rules=()):
        inputs = iter(passwords)
        with patch.object(prompt_utils, 'input_password', side_effect=lambda *_a, **_k: next(inputs, '')):
            return login.LoginAPI.change_master_password(
                Mock(), password_rules=list(rules), min_iterations=1000, user_interaction=self.ui)

    def test_reports_strength_once_before_change(self):
        result = self._run(STRONG_PASSWORD, STRONG_PASSWORD)

        self.assertEqual(result, STRONG_PASSWORD)
        self.ui.report_master_password_strength.assert_called_once_with(100, 'STRONG')
        self.change_command.assert_called_once()

    def test_no_report_when_rule_fails(self):
        rule = APIRequest_pb2.PasswordRules(pattern='.{40,}', description='At least 40 characters')

        result = self._run(STRONG_PASSWORD, STRONG_PASSWORD, rules=[rule])

        self.assertIsNone(result)
        self.ui.report_master_password_strength.assert_not_called()
        self.change_command.assert_not_called()

    def test_no_report_when_passwords_do_not_match(self):
        result = self._run(STRONG_PASSWORD, 'something else')

        self.assertIsNone(result)
        self.ui.report_master_password_strength.assert_not_called()


if __name__ == '__main__':
    unittest.main()
