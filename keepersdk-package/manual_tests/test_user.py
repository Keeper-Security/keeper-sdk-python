import os
import sqlite3
import unittest
from typing import Callable

from keepersdk import generator
from keepersdk.authentication import configuration, login_auth, endpoint
from keepersdk.vault import (sqlite_storage, record_facades, folder_management, vault_online,
                             vault_record, vault_types, attachment, record_management)


class MyTestCase(unittest.TestCase):
    def test_attachments(self):
        vault = self.get_connected_vault()
        record_uids = [r.record_uid for r in
                       (vault.get_record(x) for x in vault.root_folder.records)
                       if r is not None and r.has_attachments]
        if len(record_uids) > 0:
            record_management.delete_vault_objects(vault, [vault_types.RecordPath(x, '') for x in record_uids])

        r1 = vault_record.PasswordRecord()
        r1.title = '1Record'
        r1.login = 'aaaaaaaa'
        r1.password = 'bbbbbbb'
        a = attachment.BytesUploadTask(b'Attachment text')
        a.name = 'V2 Attachment'
        attachment.upload_attachments(vault, r1, [a])
        record_management.add_record_to_folder(vault, r1)

        r2 = vault_record.TypedRecord()
        r2.title = '2Record'
        login_facade = record_facades.LoginRecordFacade()
        login_facade.record = r2
        login_facade.login = 'dddddddd'
        login_facade.password = 'eeeeeee'
        a = attachment.BytesUploadTask(b'Attachment text')
        a.name = 'V3 Attachment'
        attachment.upload_attachments(vault, r2, [a])
        record_management.add_record_to_folder(vault, r2)
        vault.sync_down()

        for record_uid in (r1.record_uid, r2.record_uid):
            ri = vault.get_record(record_uid)
            self.assertIsNotNone(ri)
            self.assertTrue(ri.has_attachments)

        vault.close()

    def test_folder_create(self):
        vault = self.get_connected_vault()
        MyTestCase.wipe_vault(vault)

        vault.sync_down(force=True)
        self.assertEqual(vault.record_count, 0)
        self.assertEqual(vault.shared_folder_count, 0)

        shared_folder_uid = folder_management.add_folder(
            vault, 'Shared Folder', is_shared_folder=True, manage_users=True)
        user_folder_uid = folder_management.add_folder(vault, 'User Folder')
        vault.sync_down()
        sub_folder_uid = folder_management.add_folder(vault, 'Sub Folder', parent_uid=shared_folder_uid)
        vault.sync_down()

        sf1 = vault.get_shared_folder(shared_folder_uid)
        self.assertIsNotNone(sf1)

        f1 = vault.get_folder(shared_folder_uid)
        self.assertIsNotNone(f1)
        self.assertEqual(f1.folder_type, 'shared_folder')

        f2 = vault.get_folder(sub_folder_uid)
        self.assertIsNotNone(f2)
        self.assertEqual(f2.folder_type, 'shared_folder_folder')

        f3 = vault.get_folder(user_folder_uid)
        self.assertIsNotNone(f3)
        self.assertEqual(f3.folder_type, 'user_folder')

    def test_record_update(self):
        vault = self.get_connected_vault()
        facade = record_facades.LoginRecordFacade()

        typed_record_uid = next((x.record_uid for x in vault.records() if x.version == 3 and x.record_type == 'authentication'), None)
        if typed_record_uid is None:
            tr = vault_record.TypedRecord()
            facade.record = tr
            facade.title = 'Typed Record for Update'
            facade.login = 'username'
            facade.password = 'password'
            facade.notes = 'notes'
            record_management.add_record_to_folder(vault, tr)
            typed_record_uid = tr.record_uid

        legacy_record_uid = next((x.record_uid for x in vault.records() if x.version == 2), None)
        if legacy_record_uid is None:
            pr = vault_record.PasswordRecord()
            pr.title = 'Legacy Record for Update'
            pr.login = 'username'
            pr.password = 'password'
            pr.notes = 'notes'
            record_management.add_record_to_folder(vault, pr)
            legacy_record_uid = pr.record_uid

        vault.sync_down()

        pg = generator.KeeperPasswordGenerator(length=20, symbols=0, digits=2, caps=4, lower=4)
        new_password = pg.generate()

        self.assertIsNotNone(typed_record_uid)
        self.assertIsInstance(typed_record_uid, str)
        typed_record = vault.load_record(typed_record_uid)
        self.assertIsInstance(typed_record, vault_record.TypedRecord)
        self.assertEqual(typed_record.record_type, 'authentication')
        facade.record = typed_record
        facade.password = new_password
        record_management.update_record(vault, typed_record)

        self.assertIsNotNone(legacy_record_uid)
        self.assertIsInstance(legacy_record_uid, str)
        legacy_record = vault.load_record(legacy_record_uid)
        self.assertIsInstance(legacy_record, vault_record.PasswordRecord)
        legacy_record.password = new_password
        record_management.update_record(vault, legacy_record)

        vault.sync_down(force=True)

        typed_record = vault.load_record(typed_record_uid)
        self.assertIsInstance(typed_record, vault_record.TypedRecord)
        self.assertEqual(typed_record.record_type, 'authentication')
        facade.record = typed_record
        self.assertEqual(facade.password, new_password)

        legacy_record = vault.load_record(legacy_record_uid)
        self.assertIsInstance(legacy_record, vault_record.PasswordRecord)
        self.assertEqual(legacy_record.password, new_password)

    def test_wipe_out(self):
        # logging.basicConfig(level=logging.DEBUG)
        vault = self.get_connected_vault()
        MyTestCase.wipe_vault(vault)
        vault.close()

    @staticmethod
    def in_memory_database() -> Callable[[], sqlite3.Connection]:
        connection = sqlite3.Connection('file:///?mode=memory&cache=shared', uri=True)
        def get_connection() -> sqlite3.Connection:
            return connection

        return get_connection

    def get_connected_vault(self):
        config_filename = os.path.join(os.path.dirname(__file__), 'login.json')
        config = configuration.JsonConfigurationStorage.from_file(config_filename)
        keeper_endpoint = endpoint.KeeperEndpoint(config)
        auth = login_auth.LoginAuth(keeper_endpoint)
        auth.login('integration.tests@keepersecurity.com')
        auth.login_step.is_final()
        step = auth.login_step
        self.assertIsInstance(step, login_auth.LoginStepConnected)
        keeper_auth = step.take_keeper_auth()
        vault_storage = sqlite_storage.SqliteVaultStorage(
            MyTestCase.in_memory_database(), vault_owner=keeper_auth.auth_context.account_uid)
        vault = vault_online.VaultOnline(keeper_auth, vault_storage)
        vault.sync_down()
        return vault

    @staticmethod
    def wipe_vault(vault: vault_online.VaultOnline) -> None:
        # delete root level records
        root_level_records = list(vault.root_folder.records)
        if len(root_level_records) > 0:
            record_management.delete_vault_objects(
                vault, [record_management.RecordPath(x, '') for x in root_level_records])

        # delete root level folders
        root_level_folders = [x.folder_uid for x in vault.folders() if x.folder_uid and not x.parent_uid]
        if len(root_level_folders) > 0:
            record_management.delete_vault_objects(vault, root_level_folders)
