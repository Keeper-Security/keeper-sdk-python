import unittest
from unittest import mock

from keepersdk.vault import share_management_utils


class TestRotateOnExpirationValidation(unittest.TestCase):

    def test_validate_rotate_on_expiration_requires_positive_expiration(self):
        with self.assertRaises(share_management_utils.ShareValidationError):
            share_management_utils.validate_rotate_on_expiration(0, True)
        with self.assertRaises(share_management_utils.ShareValidationError):
            share_management_utils.validate_rotate_on_expiration(-1, True)

    def test_validate_rotate_on_expiration_allows_positive_expiration(self):
        share_management_utils.validate_rotate_on_expiration(1_700_000_000, True)

    def test_set_expiration_fields_sets_rotate_flag(self):
        from keepersdk.proto import record_pb2
        from keepersdk.vault.shares_management import set_expiration_fields

        ro = record_pb2.SharedRecord()
        set_expiration_fields(ro, 1_700_000_000, rotate_on_expiration=True)
        self.assertTrue(ro.rotateOnExpiration)
        self.assertGreater(ro.expiration, 0)

    def test_validate_record_shares_requires_pam_user(self):
        vault = mock.Mock()
        info = mock.Mock(record_type='login', title='Not PAM')
        vault.vault_data.get_record.return_value = info

        with self.assertRaises(share_management_utils.ShareValidationError):
            share_management_utils.validate_record_shares_rotate_on_expiration(
                vault, ['abc123'], True
            )


if __name__ == '__main__':
    unittest.main()
