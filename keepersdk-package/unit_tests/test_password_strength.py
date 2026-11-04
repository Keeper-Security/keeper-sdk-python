import unittest
from unittest.mock import Mock, patch

from keepersdk.password_strength import MasterPasswordStrength, IMasterPasswordStrengthUI, ZXCVBN_MAX_LENGTH


class MasterPasswordStrengthTest(unittest.TestCase):
    @patch('keepersdk.password_strength.zxcvbn', return_value={'score': 0})
    def test_zxcvbn_score_zero_maps_to_weak(self, estimator):
        self.assertEqual(25, MasterPasswordStrength.get_score('example'))
        estimator.assert_called_once_with('example')

    @patch('keepersdk.password_strength.zxcvbn', return_value={'score': 1})
    def test_zxcvbn_score_one_maps_to_weak(self, _estimator):
        self.assertEqual(25, MasterPasswordStrength.get_score('example'))

    @patch('keepersdk.password_strength.zxcvbn', return_value={'score': 2})
    def test_zxcvbn_score_two_maps_to_fair(self, _estimator):
        self.assertEqual(50, MasterPasswordStrength.get_score('example'))

    @patch('keepersdk.password_strength.zxcvbn', return_value={'score': 3})
    def test_zxcvbn_score_three_maps_to_medium(self, _estimator):
        self.assertEqual(75, MasterPasswordStrength.get_score('example'))

    @patch('keepersdk.password_strength.zxcvbn', return_value={'score': 4})
    def test_zxcvbn_score_four_maps_to_strong(self, _estimator):
        self.assertEqual(100, MasterPasswordStrength.get_score('example'))

    def test_empty_password_returns_zero(self):
        self.assertEqual(0, MasterPasswordStrength.get_score(''))

    def test_categories_match_dotnet_mapping(self):
        self.assertEqual('WEAK', MasterPasswordStrength.get_category(25))
        self.assertEqual('FAIR', MasterPasswordStrength.get_category(50))
        self.assertEqual('MEDIUM', MasterPasswordStrength.get_category(75))
        self.assertEqual('STRONG', MasterPasswordStrength.get_category(100))
        self.assertEqual('UNKNOWN', MasterPasswordStrength.get_category(0))

    @patch('keepersdk.password_strength.zxcvbn', side_effect=RuntimeError('estimator error'))
    def test_estimator_error_returns_zero(self, _estimator):
        self.assertEqual(0, MasterPasswordStrength.get_score('example'))

    @patch('keepersdk.password_strength.zxcvbn', return_value={'score': 99})
    def test_unexpected_score_returns_zero(self, _estimator):
        self.assertEqual(0, MasterPasswordStrength.get_score('example'))

    @patch('keepersdk.password_strength.zxcvbn', return_value={'score': None})
    def test_missing_score_returns_zero(self, _estimator):
        self.assertEqual(0, MasterPasswordStrength.get_score('example'))

    @patch('keepersdk.password_strength.zxcvbn', None)
    def test_missing_library_returns_zero_and_warns(self):
        with self.assertLogs(level='WARNING') as logs:
            self.assertEqual(0, MasterPasswordStrength.get_score('example'))
        self.assertIn('zxcvbn is not installed', logs.output[0])

    @patch('keepersdk.password_strength.zxcvbn', side_effect=RuntimeError('estimator error'))
    def test_estimator_error_does_not_log_password(self, _estimator):
        password = 'secret-Passw0rd'
        with self.assertLogs(level='WARNING') as logs:
            MasterPasswordStrength.get_score(password)
        self.assertNotIn(password, ''.join(logs.output))

    @patch('keepersdk.password_strength.zxcvbn', return_value={'score': 4})
    def test_long_password_is_truncated_for_estimator(self, estimator):
        password = 'a' * (ZXCVBN_MAX_LENGTH + 10)
        self.assertEqual(100, MasterPasswordStrength.get_score(password))
        estimator.assert_called_once_with(password[:ZXCVBN_MAX_LENGTH])

    def test_real_library_scores_weak_and_strong(self):
        self.assertEqual('WEAK', MasterPasswordStrength.get_category(MasterPasswordStrength.get_score('password')))
        self.assertEqual('STRONG', MasterPasswordStrength.get_category(
            MasterPasswordStrength.get_score('correct horse battery staple')))

    def test_real_library_scores_passphrase_longer_than_limit(self):
        passphrase = 'Correct-Horse-Battery-Staple-' * 3
        self.assertGreater(len(passphrase), ZXCVBN_MAX_LENGTH)
        self.assertEqual(100, MasterPasswordStrength.get_score(passphrase))

    @patch('keepersdk.password_strength.zxcvbn', return_value={'score': 3})
    def test_report_passes_score_and_category_to_ui(self, _estimator):
        ui = Mock(spec=IMasterPasswordStrengthUI)
        MasterPasswordStrength.report(ui, 'example')
        ui.report_master_password_strength.assert_called_once_with(75, 'MEDIUM')

    @patch('keepersdk.password_strength.zxcvbn')
    def test_report_without_ui_does_not_score(self, estimator):
        MasterPasswordStrength.report(None, 'example')
        estimator.assert_not_called()


if __name__ == '__main__':
    unittest.main()
