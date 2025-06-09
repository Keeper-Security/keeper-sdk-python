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
        with self.assertRaises(ValueError) as cm:
            record_type_management.record_type_info(self.vault, record_type_name='notfound')
        self.assertIn('not found', str(cm.exception))

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


class LoadRecordTypesTestCase(unittest.TestCase):
    def setUp(self):
        self.vault = MagicMock()
        self.filepath = 'dummy.json'
        self.patcher_validate = patch('keepersdk.vault.record_type_management.record_type_utils.validate_record_type_file')
        self.mock_validate = self.patcher_validate.start()
        self.addCleanup(self.patcher_validate.stop)
        self.patcher_create = patch('keepersdk.vault.record_type_management.create_custom_record_type')
        self.mock_create = self.patcher_create.start()
        self.addCleanup(self.patcher_create.stop)
        self.patcher_get_types = patch('keepersdk.vault.record_type_management.record_type_utils.get_record_types')
        self.mock_get_types = self.patcher_get_types.start()
        self.addCleanup(self.patcher_get_types.stop)
        self.patcher_record_fields = patch('keepersdk.vault.record_type_management.record_types.RecordFields', {})
        self.mock_record_fields = self.patcher_record_fields.start()
        self.addCleanup(self.patcher_record_fields.stop)

    def test_file_not_found(self):
        self.mock_validate.side_effect = ValueError('Record type file not found: dummy.json')
        with self.assertRaises(ValueError) as cm:
            record_type_management.load_record_types(self.vault, self.filepath)
        self.assertIn('Record type file not found', str(cm.exception))

    def test_invalid_json(self):
        self.mock_validate.side_effect = ValueError('Invalid JSON in record type file: ...')
        with self.assertRaises(ValueError) as cm:
            record_type_management.load_record_types(self.vault, self.filepath)
        self.assertIn('Invalid JSON in record type file', str(cm.exception))

    def test_json_not_dict(self):
        self.mock_validate.side_effect = ValueError('Invalid custom record types file')
        with self.assertRaises(ValueError) as cm:
            record_type_management.load_record_types(self.vault, self.filepath)
        self.assertIn('Invalid custom record types file', str(cm.exception))

    def test_missing_record_types_list(self):
        self.mock_validate.side_effect = ValueError('Invalid custom record types list')
        with self.assertRaises(ValueError) as cm:
            record_type_management.load_record_types(self.vault, self.filepath)
        self.assertIn('Invalid custom record types list', str(cm.exception))

    def test_record_types_list_not_list(self):
        self.mock_validate.side_effect = ValueError('Invalid custom record types list')
        with self.assertRaises(ValueError) as cm:
            record_type_management.load_record_types(self.vault, self.filepath)
        self.assertIn('Invalid custom record types list', str(cm.exception))

    def test_skip_record_type_without_name(self):
        self.mock_validate.return_value = [{}]
        self.mock_get_types.return_value = []
        result = record_type_management.load_record_types(self.vault, self.filepath)
        self.assertEqual(result, 0)
        self.mock_create.assert_not_called()

    def test_skip_existing_record_type(self):
        self.mock_validate.return_value = [{"record_type_name": "foo", "fields": [{"$type": "login", "$ref": "login"}]}]
        mock_existing = MagicMock()
        mock_existing.name = 'foo'
        self.mock_get_types.return_value = [(1, 'foo', 'Enterprise')]
        result = record_type_management.load_record_types(self.vault, self.filepath)
        self.assertEqual(result, 0)
        self.mock_create.assert_not_called()

    def test_skip_invalid_fields(self):
        self.mock_validate.return_value = [{"record_type_name": "foo", "fields": [{"$type": "invalid", "$ref": "login"}]}]
        self.mock_get_types.return_value = []
        with patch.dict('keepersdk.vault.record_type_management.record_types.RecordFields', {'login': MagicMock()}):
            result = record_type_management.load_record_types(self.vault, self.filepath)
            self.assertEqual(result, 0)
            self.mock_create.assert_not_called()

    def test_successful_add(self):
        self.mock_validate.return_value = [{"record_type_name": "foo", "fields": [{"$type": "login", "$ref": "login"}]}]
        self.mock_get_types.return_value = []
        with patch.dict('keepersdk.vault.record_type_management.record_types.RecordFields', {'login': MagicMock()}):
            self.mock_create.return_value = True
            result = record_type_management.load_record_types(self.vault, self.filepath)
            self.assertEqual(result, 1)
            self.mock_create.assert_called_once()


if __name__ == "__main__":
    unittest.main()
