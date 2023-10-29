import unittest

from keepersdk import utils


class UtilsTestCase(unittest.TestCase):
    def test_is_email(self):
        self.assertTrue(utils.is_email('username@company.cc'))
        self.assertTrue(utils.is_email('username@sub-domain.company.cc'))
        self.assertTrue(utils.is_email('username@group.sub-domain.company.cc'))
        self.assertFalse(utils.is_email('username-company.cc'))
        self.assertFalse(utils.is_email('username@company'))
        self.assertFalse(utils.is_email('@company.cc'))
        self.assertFalse(utils.is_email('company'))
        self.assertFalse(utils.is_email('username@cc'))

    def test_password_score(self):
        self.assertLessEqual(utils.password_score(' '), 10)
        self.assertEqual(utils.password_score(utils.generate_uid()), 100)
