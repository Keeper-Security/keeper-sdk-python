import unittest
from unittest.mock import MagicMock, patch

from keepersdk.proto import record_pb2
from keepersdk.vault import record_type_management


class CreateCustomRecordTypeTestCase(unittest.TestCase):
    def setUp(self):
        self.vault = MagicMock()
        self.vault.keeper_auth.execute_auth_rest = MagicMock()
        self.vault.keeper_auth.auth_context.is_enterprise_admin = True

    def test_successful_creation(self):
        title = "TestType"
        fields = [{"$ref": "login"}]
        description = "A test type"
        categories = ["test", "example"]
        record_type_management.record_types.FieldTypes = {"login": {}}
        self.vault.keeper_auth.execute_auth_rest.return_value = record_pb2.RecordTypeModifyResponse()
        result = record_type_management.create_custom_record_type(self.vault, title, fields, description, categories)
        self.assertIsInstance(result, record_pb2.RecordTypeModifyResponse)
        self.vault.keeper_auth.execute_auth_rest.assert_called_once_with(
            'vault/record_type_add',
            unittest.mock.ANY,
            response_type=record_pb2.RecordTypeModifyResponse
        )

    def test_not_enterprise_admin(self):
        self.vault.keeper_auth.auth_context.is_enterprise_admin = False
        with self.assertRaises(ValueError) as cm:
            record_type_management.create_custom_record_type(self.vault, "Title", [{"$ref": "login"}], "desc", ["test"])
        self.assertIn("restricted to Keeper Enterprise administrators", str(cm.exception))

    def test_missing_fields(self):
        with self.assertRaises(ValueError) as cm:
            record_type_management.create_custom_record_type(self.vault, "Title", [], "desc", ["test"])
        self.assertIn("At least one field", str(cm.exception))

    def test_missing_ref(self):
        record_type_management.record_types.FieldTypes = {"login": {}}
        with self.assertRaises(ValueError) as cm:
            record_type_management.create_custom_record_type(self.vault, "Title", [{}], "desc", ["test"])
        self.assertIn("Each field must contain a '$ref'", str(cm.exception))

    def test_invalid_field_name(self):
        record_type_management.record_types.FieldTypes = {"login": {}}
        with self.assertRaises(ValueError) as cm:
            record_type_management.create_custom_record_type(self.vault, "Title", [{"$ref": "not_a_field"}], "desc", ["test"])
        self.assertIn("is not a valid RecordField", str(cm.exception))


class EditCustomRecordTypesTestCase(unittest.TestCase):
    def setUp(self):
        self.vault = MagicMock()
        self.vault.keeper_auth.execute_auth_rest = MagicMock()
        self.vault.keeper_auth.auth_context.is_enterprise_admin = True
        record_type_management.record_types.FieldTypes = {"login": {}}

    def test_successful_edit(self):
        title = "EditedType"
        fields = [{"$ref": "login"}]
        description = "Edited description"
        categories = ["test", "example"]
        record_type_id = 2000001
        self.vault.keeper_auth.execute_auth_rest.return_value = record_pb2.RecordTypeModifyResponse()
        result = record_type_management.edit_custom_record_types(self.vault, record_type_id, title, fields, description, categories)
        self.assertIsInstance(result, record_pb2.RecordTypeModifyResponse)
        self.vault.keeper_auth.execute_auth_rest.assert_called_once_with(
            'vault/record_type_update',
            unittest.mock.ANY,
            response_type=record_pb2.RecordTypeModifyResponse
        )

    def test_not_enterprise_admin(self):
        self.vault.keeper_auth.auth_context.is_enterprise_admin = False
        record_type_id = 2000001
        with self.assertRaises(ValueError) as cm:
            record_type_management.edit_custom_record_types(self.vault, record_type_id, "Title", [{"$ref": "login"}], "desc", ["test"])
        self.assertIn("restricted to Keeper Enterprise administrators", str(cm.exception))

    def test_not_enterprise_record_type_id(self):
        record_type_id = 1
        with self.assertRaises(ValueError) as cm:
            record_type_management.edit_custom_record_types(self.vault, record_type_id, "Title", [{"$ref": "login"}], "desc", ["test"])
        self.assertIn("can be modified", str(cm.exception))

    def test_missing_fields(self):
        record_type_id = 2000001
        with self.assertRaises(ValueError) as cm:
            record_type_management.edit_custom_record_types(self.vault, record_type_id, "Title", [], "desc", ["test"])
        self.assertIn("At least one field", str(cm.exception))

    def test_missing_ref(self):
        record_type_id = 2000001
        with self.assertRaises(ValueError) as cm:
            record_type_management.edit_custom_record_types(self.vault, record_type_id, "Title", [{}], "desc", ["test"])
        self.assertIn("Each field must contain a '$ref'", str(cm.exception))

    def test_invalid_field_name(self):
        record_type_id = 2000001
        record_type_management.record_types.FieldTypes = {"login": {}}
        with self.assertRaises(ValueError) as cm:
            record_type_management.edit_custom_record_types(self.vault, record_type_id, "Title", [{"$ref": "not_a_field"}], "desc", ["test"])
        self.assertIn("is not a valid RecordField", str(cm.exception))


class DeleteCustomRecordTypesTestCase(unittest.TestCase):
    def setUp(self):
        self.vault = MagicMock()
        self.vault.keeper_auth.execute_auth_rest = MagicMock()
        self.vault.keeper_auth.auth_context.is_enterprise_admin = True

    def test_successful_delete(self):
        record_type_id = 2000001
        self.vault.keeper_auth.execute_auth_rest.return_value = record_pb2.RecordTypeModifyResponse()
        result = record_type_management.delete_custom_record_types(self.vault, record_type_id)
        self.assertIsInstance(result, record_pb2.RecordTypeModifyResponse)
        self.vault.keeper_auth.execute_auth_rest.assert_called_once_with(
            'vault/record_type_delete',
            unittest.mock.ANY,
            response_type=record_pb2.RecordTypeModifyResponse
        )

    def test_not_enterprise_admin(self):
        self.vault.keeper_auth.auth_context.is_enterprise_admin = False
        record_type_id = 2000001
        with self.assertRaises(ValueError) as cm:
            record_type_management.delete_custom_record_types(self.vault, record_type_id)
        self.assertIn("restricted to Keeper Enterprise administrators", str(cm.exception))

    def test_not_enterprise_record_type_id(self):
        record_type_id = 1
        with self.assertRaises(ValueError) as cm:
            record_type_management.delete_custom_record_types(self.vault, record_type_id)
        self.assertIn("can be removed", str(cm.exception))


class RecordTypeInfoTestCase(unittest.TestCase):
    def setUp(self):
        self.vault = MagicMock()
        self.vault.vault_data.get_record_type_by_name = MagicMock()
        self.vault.vault_data.get_record_types = MagicMock()

    @patch('keepersdk.vault.record_type_management.tabulate')
    @patch('keepersdk.vault.record_type_management.record_types')
    def test_field_name_all(self, mock_record_types, mock_tabulate):
        # Setup mock FieldTypes and RecordFields
        mock_ft = MagicMock()
        mock_ft.name = 'login'
        mock_ft.description = 'desc'
        mock_record_types.FieldTypes.values.return_value = [mock_ft]
        mock_rf = MagicMock()
        mock_rf.name = 'login'
        mock_rf.multiple.name = 'Optional'
        mock_record_types.RecordFields.values.return_value = [mock_rf]
        mock_tabulate.tabulate.return_value = 'table'
        result = record_type_management.record_type_info(self.vault, field_name='*')
        self.assertEqual(result, 'table')

    @patch('keepersdk.vault.record_type_management.tabulate')
    @patch('keepersdk.vault.record_type_management.record_types')
    def test_field_name_specific(self, mock_record_types, mock_tabulate):
        mock_ft = MagicMock()
        mock_ft.name = 'login'
        mock_ft.description = 'desc'
        mock_record_types.FieldTypes.get.return_value = mock_ft
        mock_rf = MagicMock()
        mock_rf.name = 'login'
        mock_rf.multiple.name = 'Optional'
        mock_record_types.RecordFields.values.return_value = [mock_rf]
        mock_tabulate.tabulate.return_value = 'table'
        result = record_type_management.record_type_info(self.vault, field_name='login')
        self.assertEqual(result, 'table')

    @patch('keepersdk.vault.record_type_management.record_type_utils')
    def test_record_type_example(self, mock_utils):
        mock_utils.get_record_type_example.return_value = '{"type": "login"}'
        result = record_type_management.record_type_info(self.vault, record_type_name='login', example=True)
        self.assertEqual(result, '{"type": "login"}')

    @patch('keepersdk.vault.record_type_management.tabulate')
    @patch('keepersdk.vault.record_type_management.record_type_utils')
    def test_record_type_name_all(self, mock_utils, mock_tabulate):
        mock_utils.get_record_types.return_value = [(1, 'login', 'Standard')]
        mock_tabulate.tabulate.return_value = 'table'
        result = record_type_management.record_type_info(self.vault, record_type_name='*')
        self.assertEqual(result, 'table')

    def test_record_type_name_not_found(self):
        self.vault.vault_data.get_record_type_by_name.return_value = None
        result = record_type_management.record_type_info(self.vault, record_type_name='notfound')
        self.assertIn("not found", result)

    @patch('keepersdk.vault.record_type_management.tabulate')
    def test_record_type_name_details(self, mock_tabulate):
        mock_record_type = MagicMock()
        mock_record_type.id = 1
        mock_record_type.name = 'login'
        mock_record_type.scope = 0
        field = MagicMock()
        field.label = 'username'
        mock_record_type.fields = [field]
        self.vault.vault_data.get_record_type_by_name.return_value = mock_record_type
        mock_tabulate.tabulate.return_value = 'table'
        result = record_type_management.record_type_info(self.vault, record_type_name='login')
        self.assertEqual(result, 'table')


if __name__ == "__main__":
    unittest.main()
