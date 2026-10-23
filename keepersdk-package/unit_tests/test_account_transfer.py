"""Unit tests for KeeperDrive/NSF account-transfer handling.

Run from the keeper-sdk-python repository root with:
    python -m pytest keepersdk-package/unit_tests/test_account_transfer.py -v

These tests mock cryptographic operations and the authenticated API call. They do
not perform a live account transfer.
"""
import unittest
from unittest.mock import MagicMock, patch

from keepersdk import utils
from keepersdk.enterprise.account_transfer import (
    AccountTransferError,
    AccountTransferManager,
    EncryptionType,
    PreTransferResponse,
    TransferDataKeys,
    TransferKeyType,
)
from keepersdk.authentication.keeper_auth import UserKeys


class KeeperDriveTransferTests(unittest.TestCase):
    def setUp(self):
        self.auth = MagicMock()
        self.auth.auth_context.forbid_rsa = False
        self.manager = AccountTransferManager(MagicMock(), self.auth)
        self.target_keys = UserKeys(aes=b"a" * 32, rsa=b"rsa-public-key", ec=None)
        self.user_data_key = b"d" * 32

    # Parsing and payload shape
    def test_pre_transfer_parser_keeps_all_kd_collections(self):
        response = {
            "kd_folder_keys": [{"folder_uid": "folder-1"}],
            "kd_record_keys": [{"record_uid": "record-1"}],
            "kd_nested_record_owner_keys": [{"record_uid": "nested-1"}],
        }
        parsed = self.manager._parse_pre_transfer_response(response)
        self.assertEqual(parsed.kd_folder_keys, response["kd_folder_keys"])
        self.assertEqual(parsed.kd_record_keys, response["kd_record_keys"])
        self.assertEqual(
            parsed.kd_nested_record_owner_keys,
            response["kd_nested_record_owner_keys"],
        )

    def test_pre_transfer_parser_defaults_missing_kd_collections_to_empty(self):
        parsed = self.manager._parse_pre_transfer_response({})
        self.assertEqual(parsed.kd_folder_keys, [])
        self.assertEqual(parsed.kd_record_keys, [])
        self.assertEqual(parsed.kd_nested_record_owner_keys, [])

    def test_transfer_data_keys_contains_kd_and_corrupted_kd_fields(self):
        fields = {item.value for item in TransferDataKeys}
        self.assertTrue({
            "kd_folder_keys",
            "kd_record_keys",
            "kd_nested_record_owner_keys",
            "kd_folder_transfer",
            "corrupted_kd_folder_keys",
            "corrupted_kd_record_keys",
            "corrupted_kd_nested_record_owner_keys",
        }.issubset(fields))

    def test_empty_kd_collections_do_not_add_kd_payload(self):
        pre = PreTransferResponse()
        with patch.object(
            self.manager, "_reencrypt_user_folder_keys", return_value=([], [], {})
        ):
            payload = self.manager._prepare_transfer_data(
                pre, self.user_data_key, None, None, self.target_keys, "from@example.com"
            )
        for key in (
            "kd_folder_keys", "kd_record_keys", "kd_nested_record_owner_keys",
            "kd_folder_transfer", "corrupted_kd_folder_keys",
            "corrupted_kd_record_keys", "corrupted_kd_nested_record_owner_keys",
        ):
            self.assertNotIn(key, payload)

    def test_prepare_transfer_data_adds_kd_sections_and_transfer_folder(self):
        pre = PreTransferResponse(
            kd_folder_keys=[{"folder_uid": "f1"}],
            kd_record_keys=[{"record_uid": "r1"}],
            kd_nested_record_owner_keys=[{"record_uid": "n1"}],
        )
        with (
            patch.object(self.manager, "_reencrypt_user_folder_keys", return_value=([], [], {})),
            patch.object(self.manager, "_reencrypt_kd_folder_keys", return_value=([{"folder_uid": "f1", "folder_key_type": 1}], [])),
            patch.object(self.manager, "_reencrypt_kd_record_keys", return_value=([{"record_uid": "r1", "record_key_type": 2}], [])),
            patch.object(self.manager, "_reencrypt_kd_nested_owner_keys", return_value=([{"record_uid": "n1", "owner_key_type": 2}], [])),
            patch.object(self.manager, "_create_kd_transfer_folder", return_value={"folder_uid": "transfer-folder"}) as create_folder,
        ):
            payload = self.manager._prepare_transfer_data(
                pre, self.user_data_key, None, None, self.target_keys, "from@example.com"
            )
        self.assertEqual(payload["kd_folder_keys"][0]["folder_uid"], "f1")
        self.assertEqual(payload["kd_record_keys"][0]["record_uid"], "r1")
        self.assertEqual(payload["kd_nested_record_owner_keys"][0]["record_uid"], "n1")
        self.assertEqual(payload["kd_folder_transfer"]["folder_uid"], "transfer-folder")
        self.assertEqual(payload["corrupted_kd_folder_keys"], [])
        self.assertEqual(payload["corrupted_kd_record_keys"], [])
        self.assertEqual(payload["corrupted_kd_nested_record_owner_keys"], [])
        create_folder.assert_called_once_with(self.target_keys, "from@example.com")

    def test_prepare_transfer_data_includes_corrupted_kd_items(self):
        pre = PreTransferResponse(
            kd_folder_keys=[{"folder_uid": "bad-folder"}],
            kd_record_keys=[{"record_uid": "bad-record"}],
            kd_nested_record_owner_keys=[{"record_uid": "bad-nested"}],
        )
        with (
            patch.object(self.manager, "_reencrypt_user_folder_keys", return_value=([], [], {})),
            patch.object(self.manager, "_reencrypt_kd_folder_keys", return_value=([], pre.kd_folder_keys)),
            patch.object(self.manager, "_reencrypt_kd_record_keys", return_value=([], pre.kd_record_keys)),
            patch.object(self.manager, "_reencrypt_kd_nested_owner_keys", return_value=([], pre.kd_nested_record_owner_keys)),
            patch.object(self.manager, "_create_kd_transfer_folder", return_value={"folder_uid": "transfer-folder"}),
        ):
            payload = self.manager._prepare_transfer_data(
                pre, self.user_data_key, None, None, self.target_keys, "from@example.com"
            )
        self.assertEqual(payload["corrupted_kd_folder_keys"], pre.kd_folder_keys)
        self.assertEqual(payload["corrupted_kd_record_keys"], pre.kd_record_keys)
        self.assertEqual(payload["corrupted_kd_nested_record_owner_keys"], pre.kd_nested_record_owner_keys)
        # A transfer folder is only created when at least one KD key is re-encrypted.
        self.assertNotIn("kd_folder_transfer", payload)

    # Encryption type selection
    @patch("keepersdk.enterprise.account_transfer.crypto.encrypt_aes_v1", return_value=b"encrypted-aes-v1")
    def test_encrypt_kd_key_uses_aes_v1_type_1_when_rsa_allowed(self, encrypt):
        encrypted, key_type = self.manager._encrypt_kd_key(b"key", self.target_keys)
        self.assertEqual((encrypted, key_type), (b"encrypted-aes-v1", 1))
        encrypt.assert_called_once_with(b"key", self.target_keys.aes)

    @patch("keepersdk.enterprise.account_transfer.crypto.encrypt_rsa", return_value=b"encrypted-rsa")
    @patch("keepersdk.enterprise.account_transfer.crypto.load_rsa_public_key", return_value="loaded-rsa")
    def test_encrypt_kd_key_uses_rsa_type_2_when_aes_unavailable(self, load_key, encrypt):
        target = UserKeys(aes=None, rsa=b"rsa-public-key", ec=None)
        encrypted, key_type = self.manager._encrypt_kd_key(b"key", target)
        self.assertEqual((encrypted, key_type), (b"encrypted-rsa", 2))
        load_key.assert_called_once_with(target.rsa)
        encrypt.assert_called_once_with(b"key", "loaded-rsa")

    @patch("keepersdk.enterprise.account_transfer.crypto.encrypt_aes_v2", return_value=b"encrypted-aes-v2")
    def test_encrypt_kd_key_uses_aes_v2_type_3_when_rsa_forbidden(self, encrypt):
        self.auth.auth_context.forbid_rsa = True
        encrypted, key_type = self.manager._encrypt_kd_key(b"key", self.target_keys)
        self.assertEqual((encrypted, key_type), (b"encrypted-aes-v2", 3))
        encrypt.assert_called_once_with(b"key", self.target_keys.aes)

    @patch("keepersdk.enterprise.account_transfer.crypto.encrypt_ec", return_value=b"encrypted-ec")
    @patch("keepersdk.enterprise.account_transfer.crypto.load_ec_public_key", return_value="loaded-ec")
    def test_encrypt_kd_key_uses_ecc_type_4_when_rsa_forbidden_and_no_aes(self, load_key, encrypt):
        self.auth.auth_context.forbid_rsa = True
        target = UserKeys(aes=None, rsa=None, ec=b"ec-public-key")
        encrypted, key_type = self.manager._encrypt_kd_key(b"key", target)
        self.assertEqual((encrypted, key_type), (b"encrypted-ec", 4))
        load_key.assert_called_once_with(target.ec)
        encrypt.assert_called_once_with(b"key", "loaded-ec")

    def test_encrypt_kd_key_fails_when_no_permitted_target_key_exists(self):
        with self.assertRaises(AccountTransferError):
            self.manager._encrypt_kd_key(b"key", UserKeys(aes=None, rsa=None, ec=None))
        self.auth.auth_context.forbid_rsa = True
        with self.assertRaises(AccountTransferError):
            self.manager._encrypt_kd_key(b"key", UserKeys(aes=None, rsa=b"rsa", ec=None))

    @patch("keepersdk.enterprise.account_transfer.crypto.encrypt_rsa", return_value=b"owner-rsa")
    @patch("keepersdk.enterprise.account_transfer.crypto.load_rsa_public_key", return_value="loaded-rsa")
    def test_owner_key_uses_rsa_type_2_when_allowed(self, load_key, encrypt):
        encrypted, key_type = self.manager._encrypt_kd_owner_key(b"owner", self.target_keys)
        self.assertEqual((encrypted, key_type), (b"owner-rsa", 2))
        load_key.assert_called_once_with(self.target_keys.rsa)
        encrypt.assert_called_once_with(b"owner", "loaded-rsa")

    @patch("keepersdk.enterprise.account_transfer.crypto.encrypt_ec", return_value=b"owner-ec")
    @patch("keepersdk.enterprise.account_transfer.crypto.load_ec_public_key", return_value="loaded-ec")
    def test_owner_key_prefers_ecc_type_4(self, load_key, encrypt):
        target = UserKeys(aes=b"a" * 32, rsa=b"rsa", ec=b"ec")
        encrypted, key_type = self.manager._encrypt_kd_owner_key(b"owner", target)
        self.assertEqual((encrypted, key_type), (b"owner-ec", 4))
        load_key.assert_called_once_with(target.ec)
        encrypt.assert_called_once_with(b"owner", "loaded-ec")

    def test_owner_key_rejects_rsa_when_rsa_forbidden_and_no_ecc(self):
        self.auth.auth_context.forbid_rsa = True
        with self.assertRaises(AccountTransferError):
            self.manager._encrypt_kd_owner_key(b"owner", UserKeys(aes=b"a" * 32, rsa=b"rsa", ec=None))

    # Folder, record, and nested-owner key re-encryption
    @patch("keepersdk.enterprise.account_transfer.utils.base64_url_decode", side_effect=lambda value: value.encode())
    @patch("keepersdk.enterprise.account_transfer.utils.base64_url_encode", side_effect=lambda value: value.decode())
    def test_reencrypt_kd_folder_keys_preserves_numeric_key_type(self, encode, decode):
        with (
            patch.object(self.manager, "_decrypt_key_by_type", return_value=b"plain-folder-key") as decrypt,
            patch.object(self.manager, "_encrypt_kd_key", return_value=(b"new-folder-key", 2)) as encrypt,
        ):
            result, corrupted = self.manager._reencrypt_kd_folder_keys(
                [{"folder_uid": "f1", "folder_key": "old", "folder_key_type": 3}],
                self.user_data_key, None, None, self.target_keys,
            )
        self.assertEqual(corrupted, [])
        self.assertEqual(result, [{"folder_uid": "f1", "folder_key": "new-folder-key", "folder_key_type": 2}])
        decrypt.assert_called_once_with(b"old", 3, self.user_data_key, None, None)
        encrypt.assert_called_once_with(b"plain-folder-key", self.target_keys)
        encode.assert_called_once()
        decode.assert_called_once_with("old")

    @patch("keepersdk.enterprise.account_transfer.utils.base64_url_decode", side_effect=lambda value: value.encode())
    @patch("keepersdk.enterprise.account_transfer.utils.base64_url_encode", side_effect=lambda value: value.decode())
    def test_reencrypt_kd_record_keys_preserves_numeric_key_type_and_owner_key(self, encode, decode):
        item = {
            "record_uid": "r1", "record_key": "record-old", "record_key_type": 3,
            "record_owner_key": "owner-old", "record_owner_key_type": 4,
        }
        with (
            patch.object(self.manager, "_decrypt_key_by_type", side_effect=[b"record-plain", b"owner-plain"]) as decrypt,
            patch.object(self.manager, "_encrypt_kd_key", return_value=(b"record-new", 1)) as encrypt_record,
            patch.object(self.manager, "_encrypt_kd_owner_key", return_value=(b"owner-new", 2)) as encrypt_owner,
        ):
            result, corrupted = self.manager._reencrypt_kd_record_keys(
                [item], self.user_data_key, None, None, self.target_keys
            )
        self.assertEqual(corrupted, [])
        self.assertEqual(result, [{
            "record_uid": "r1", "record_key": "record-new", "record_key_type": 1,
            "record_owner_key": "owner-new", "record_owner_key_type": 2,
        }])
        self.assertEqual(decrypt.call_count, 2)
        encrypt_record.assert_called_once_with(b"record-plain", self.target_keys)
        encrypt_owner.assert_called_once_with(b"owner-plain", self.target_keys)
        self.assertEqual(decode.call_count, 2)
        self.assertEqual(encode.call_count, 2)

    @patch("keepersdk.enterprise.account_transfer.utils.base64_url_decode", side_effect=lambda value: value.encode())
    @patch("keepersdk.enterprise.account_transfer.utils.base64_url_encode", side_effect=lambda value: value.decode())
    def test_reencrypt_kd_nested_owner_keys_uses_numeric_owner_type(self, encode, decode):
        with (
            patch.object(self.manager, "_decrypt_key_by_type", return_value=b"owner-plain") as decrypt,
            patch.object(self.manager, "_encrypt_kd_owner_key", return_value=(b"owner-new", 4)) as encrypt,
        ):
            result, corrupted = self.manager._reencrypt_kd_nested_owner_keys(
                [{"record_uid": "n1", "owner_key": "owner-old", "owner_key_type": 2}],
                self.user_data_key, None, None, self.target_keys,
            )
        self.assertEqual(corrupted, [])
        self.assertEqual(result, [{"record_uid": "n1", "owner_key": "owner-new", "owner_key_type": 4}])
        decrypt.assert_called_once_with(b"owner-old", 2, self.user_data_key, None, None)
        encrypt.assert_called_once_with(b"owner-plain", self.target_keys)
        decode.assert_called_once_with("owner-old")
        encode.assert_called_once()

    def test_reencrypt_handlers_collect_bad_items_as_corrupted(self):
        bad_folder = {"folder_uid": "bad", "folder_key": "not-valid"}
        bad_record = {"record_uid": "bad-record", "record_key": "not-valid"}
        bad_nested = {"record_uid": "bad-nested", "owner_key": "not-valid"}
        with patch.object(self.manager, "_decrypt_key_by_type", side_effect=ValueError("bad key")):
            folders, corrupted_folders = self.manager._reencrypt_kd_folder_keys(
                [bad_folder], self.user_data_key, None, None, self.target_keys
            )
            records, corrupted_records = self.manager._reencrypt_kd_record_keys(
                [bad_record], self.user_data_key, None, None, self.target_keys
            )
            nested, corrupted_nested = self.manager._reencrypt_kd_nested_owner_keys(
                [bad_nested], self.user_data_key, None, None, self.target_keys
            )
        self.assertEqual(folders, [])
        self.assertEqual(records, [])
        self.assertEqual(nested, [])
        self.assertEqual(corrupted_folders, [bad_folder])
        self.assertEqual(corrupted_records, [bad_record])
        self.assertEqual(corrupted_nested, [bad_nested])

    # Outgoing request and result accounting
    def test_execute_transfer_includes_kd_fields_and_corrupted_fields(self):
        transfer_data = {
            "kd_folder_keys": [{"folder_uid": "f1"}],
            "corrupted_kd_folder_keys": [{"folder_uid": "bad-f"}],
            "kd_record_keys": [{"record_uid": "r1"}],
            "corrupted_kd_record_keys": [{"record_uid": "bad-r"}],
            "kd_nested_record_owner_keys": [{"record_uid": "n1"}],
            "corrupted_kd_nested_record_owner_keys": [{"record_uid": "bad-n"}],
            "kd_folder_transfer": {"folder_uid": "transfer-folder"},
            "unexpected_field": "must-not-be-sent",
        }
        result = self.manager._execute_transfer("from@example.com", "to@example.com", transfer_data)
        request = self.auth.execute_auth_command.call_args.args[0]
        self.assertEqual(request["command"], "transfer_and_delete_user")
        self.assertEqual(request["from_user"], "from@example.com")
        self.assertEqual(request["to_user"], "to@example.com")
        for key in (
            "kd_folder_keys", "corrupted_kd_folder_keys", "kd_record_keys",
            "corrupted_kd_record_keys", "kd_nested_record_owner_keys",
            "corrupted_kd_nested_record_owner_keys", "kd_folder_transfer",
        ):
            self.assertEqual(request[key], transfer_data[key])
        self.assertNotIn("unexpected_field", request)
        self.assertEqual(result.kd_folders_transferred, 1)
        self.assertEqual(result.kd_records_transferred, 1)
        self.assertEqual(result.kd_nested_record_owners_transferred, 1)

    def test_execute_transfer_reports_corrupted_kd_counts(self):
        transfer_data = {
            "corrupted_kd_folder_keys": [{"folder_uid": "bad-f"}],
            "corrupted_kd_record_keys": [{"record_uid": "bad-r1"}, {"record_uid": "bad-r2"}],
            "corrupted_kd_nested_record_owner_keys": [{"record_uid": "bad-n"}],
        }
        result = self.manager._execute_transfer("from@example.com", "to@example.com", transfer_data)
        self.assertEqual(result.corrupted_kd_folders, 1)
        self.assertEqual(result.corrupted_kd_records, 2)
        self.assertEqual(result.corrupted_kd_nested_record_owners, 1)

    def test_decrypt_key_by_type_supports_raw_and_rejects_unknown_type(self):
        self.assertEqual(
            self.manager._decrypt_key_by_type(b"ignored", TransferKeyType.RAW_DATA_KEY.value,
                                               self.user_data_key, None, None),
            self.user_data_key,
        )
        with self.assertRaises(Exception):
            self.manager._decrypt_key_by_type(b"ignored", 999, self.user_data_key, None, None)


class RecipientKeyFallbackTests(unittest.TestCase):
    """Regression tests: KeeperDrive transfer encryption must follow the same recipient-key
    fallback as the rest of the transfer code (AES, then ECC, then RSA when RSA is allowed).
    These use real EC and RSA keys and decrypt the output to prove it is readable."""

    @classmethod
    def setUpClass(cls):
        from keepersdk import crypto
        cls.crypto = crypto
        cls.ec_private, ec_public = crypto.generate_ec_key()
        cls.ec_public_bytes = crypto.unload_ec_public_key(ec_public)
        cls.rsa_private, rsa_public = crypto.generate_rsa_key()
        cls.rsa_public_bytes = crypto.unload_rsa_public_key(rsa_public)

    def setUp(self):
        self.auth = MagicMock()
        self.auth.auth_context.forbid_rsa = False
        self.manager = AccountTransferManager(MagicMock(), self.auth)
        self.user_data_key = b"d" * 32

    def ec_only(self):
        return UserKeys(aes=None, rsa=None, ec=self.ec_public_bytes)

    def rsa_only(self):
        return UserKeys(aes=None, rsa=self.rsa_public_bytes, ec=None)

    def test_ec_only_recipient_gets_ecc_key_when_rsa_allowed(self):
        encrypted, key_type = self.manager._encrypt_kd_key(b"record-key-32-bytes-long-value!", self.ec_only())
        self.assertEqual(key_type, 4)
        self.assertEqual(self.crypto.decrypt_ec(encrypted, self.ec_private), b"record-key-32-bytes-long-value!")

    def test_rsa_only_recipient_gets_rsa_key_when_rsa_allowed(self):
        encrypted, key_type = self.manager._encrypt_kd_key(b"record-key-32-bytes-long-value!", self.rsa_only())
        self.assertEqual(key_type, 2)
        self.assertEqual(self.crypto.decrypt_rsa(encrypted, self.rsa_private), b"record-key-32-bytes-long-value!")

    def test_rsa_forbidden_with_ec_only_recipient_uses_ecc(self):
        self.auth.auth_context.forbid_rsa = True
        encrypted, key_type = self.manager._encrypt_kd_key(b"record-key-32-bytes-long-value!", self.ec_only())
        self.assertEqual(key_type, 4)
        self.assertEqual(self.crypto.decrypt_ec(encrypted, self.ec_private), b"record-key-32-bytes-long-value!")

    def test_rsa_forbidden_with_rsa_only_recipient_fails(self):
        self.auth.auth_context.forbid_rsa = True
        with self.assertRaises(AccountTransferError):
            self.manager._encrypt_kd_key(b"record-key", self.rsa_only())

    def test_aes_is_preferred_over_ecc_and_rsa(self):
        target = UserKeys(aes=b"a" * 32, rsa=self.rsa_public_bytes, ec=self.ec_public_bytes)
        _, key_type = self.manager._encrypt_kd_key(b"record-key", target)
        self.assertEqual(key_type, 1)

    def test_transfer_folder_for_rsa_only_recipient(self):
        folder = self.manager._create_kd_transfer_folder(self.rsa_only(), "from@example.com")
        self.assertEqual(folder["folder_key_type"], "encrypted_by_public_key")
        folder_key = self.crypto.decrypt_rsa(
            utils.base64_url_decode(folder["folder_key"]), self.rsa_private)
        self.assertIn(b"from@example.com", self.crypto.decrypt_aes_v2(
            utils.base64_url_decode(folder["folder_data"]), folder_key))

    def test_transfer_folder_for_ec_only_recipient(self):
        folder = self.manager._create_kd_transfer_folder(self.ec_only(), "from@example.com")
        self.assertEqual(folder["folder_key_type"], "encrypted_by_public_key_ecc")
        folder_key = self.crypto.decrypt_ec(utils.base64_url_decode(folder["folder_key"]), self.ec_private)
        self.assertIn(b"from@example.com", self.crypto.decrypt_aes_v2(
            utils.base64_url_decode(folder["folder_data"]), folder_key))

    def test_transfer_folder_for_ec_only_recipient_when_rsa_forbidden(self):
        self.auth.auth_context.forbid_rsa = True
        folder = self.manager._create_kd_transfer_folder(self.ec_only(), "from@example.com")
        self.assertEqual(folder["folder_key_type"], "encrypted_by_public_key_ecc")

    def test_transfer_folder_for_rsa_only_recipient_when_rsa_forbidden_fails(self):
        self.auth.auth_context.forbid_rsa = True
        with self.assertRaises(AccountTransferError):
            self.manager._create_kd_transfer_folder(self.rsa_only(), "from@example.com")

    def test_record_keys_for_ec_only_recipient_are_not_corrupted(self):
        record_key = b"record-key-32-bytes-long-value!"
        encrypted_for_user = self.crypto.encrypt_aes_v1(record_key, self.user_data_key)
        items = [{
            "record_uid": "r1",
            "record_key": utils.base64_url_encode(encrypted_for_user),
            "record_key_type": 1,
        }]
        with patch.object(self.manager, "_decrypt_key_by_type", return_value=record_key):
            reencrypted, corrupted = self.manager._reencrypt_kd_record_keys(
                items, self.user_data_key, None, None, self.ec_only())
        self.assertEqual(corrupted, [])
        self.assertEqual(reencrypted[0]["record_key_type"], 4)
        self.assertEqual(
            self.crypto.decrypt_ec(utils.base64_url_decode(reencrypted[0]["record_key"]), self.ec_private),
            record_key)


if __name__ == "__main__":
    unittest.main()
