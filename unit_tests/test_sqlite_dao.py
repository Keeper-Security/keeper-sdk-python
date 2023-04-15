import sqlite3
from typing import List
from unittest import TestCase
from dataclasses import dataclass, field

from keepersdk import utils, crypto, sqlite_dao
from keepersdk.storage import types, sqlite
from keepersdk.vault import storage_types
from keepersdk.proto import enterprise_pb2


@dataclass
class Settings:
    str_value: str = field(default_factory=str)
    bool_value: bool = field(default_factory=bool)
    int_value: int = field(default_factory=int)
    list_value: List[int] = field(default_factory=list)


class TestSqliteDao(TestCase):
    def test_proto(self):

        settings_table = sqlite_dao.TableSchema.load_schema(
            enterprise_pb2.Node, ['nodeId'], owner_column='enterprise_id', owner_type=int)
        connection = sqlite3.Connection(':memory:')
        queries = list(sqlite_dao.verify_database(connection, (settings_table,), apply_changes=True))

        settings_storage: types.IEntityStorage[enterprise_pb2.Node, int] = \
            sqlite.SqliteEntityStorage(lambda: connection, settings_table, 191)
        s = enterprise_pb2.Node()
        s.nodeId = 3432423432
        s.parentId = 0
        s.restrictVisibility = True
        s.ssoServiceProviderIds.extend((13432432, 2343242342))
        settings_storage.put_entities([s])
        s1 = settings_storage.get_entity(3432423432)


    def test_create_query(self):
        connection = sqlite3.Connection(':memory:')

        settings_table = sqlite_dao.TableSchema.load_schema(
            Settings, [], owner_column='account_uid', owner_type=str)
        queries = list(sqlite_dao.verify_database(connection, (settings_table,), apply_changes=False))
        self.assertEqual(len(queries), 1)

        record_table = sqlite_dao.TableSchema.load_schema(
            storage_types.StorageRecord, 'record_uid', owner_column='account_uid', owner_type=str)
        record_key_table = sqlite_dao.TableSchema.load_schema(
            storage_types.StorageRecordKey, ['record_uid', 'shared_folder_uid'],
            indexes={'object': 'shared_folder_uid'}, owner_column='account_uid', owner_type=str)

        queries = list(sqlite_dao.verify_database(connection, (record_table, record_key_table), apply_changes=False))
        self.assertEqual(len(queries), 3)
        for query in queries:
            connection.execute(query)
        connection.commit()

        queries = list(sqlite_dao.verify_database(connection, (record_table, record_key_table), apply_changes=False))
        self.assertEqual(len(queries), 0)

        record_table.indexes = {'version': ['version']}
        record_table.columns.append('eeee')
        queries = list(sqlite_dao.verify_database(connection, (record_table, record_key_table), apply_changes=False))
        self.assertEqual(len(queries), 2)

    def test_entity_storage(self):
        connection = sqlite3.Connection(':memory:')
        record_table = sqlite_dao.TableSchema.load_schema(
            storage_types.StorageRecord, 'record_uid', owner_column='account_uid', owner_type=str)
        record_key_table = sqlite_dao.TableSchema.load_schema(
            storage_types.StorageRecordKey, ['record_uid', 'shared_folder_uid'],
            indexes={'object': 'shared_folder_uid'}, owner_column='account_uid', owner_type=str)
        settings_table = sqlite_dao.TableSchema.load_schema(
            Settings, [], owner_column='account_uid', owner_type=str)

        sqlite_dao.verify_database(connection, (record_table, record_key_table, settings_table), apply_changes=True)

        record_storage: types.IEntityStorage[storage_types.StorageRecord] = \
            sqlite.SqliteEntityStorage(lambda: connection, record_table, 'user@company.com')
        record_key_storage: types.ILinkStorage[storage_types.StorageRecordKey] = \
            sqlite.SqliteLinkStorage(lambda: connection, record_key_table, 'user@company.com')
        settings_storage: types.IRecordStorage[Settings] = \
            sqlite.SqliteRecordStorage(lambda: connection, settings_table, 'user@company.com')

        setting = settings_storage.load()
        if setting is None:
            setting = Settings()
            setting.str_value = '123456'
            setting.bool_value = True
            setting.int_value = 123456
            setting.list_value = [1,2,3,4,5]
            settings_storage.store(setting)
        setting1 = settings_storage.load()
        self.assertIsNotNone(setting1)
        self.assertEqual(setting, setting1)

        record = storage_types.StorageRecord()
        record.record_uid = utils.generate_uid()
        record.revision = 3232323
        record.data = b'DATA'
        record.owner = True
        record.version = 2

        record_storage.put_entities((record,))

        client_key = utils.generate_aes_key()
        record_key = utils.generate_aes_key()

        link = storage_types.StorageRecordKey()
        link.record_uid = record.record_uid
        link.shared_folder_uid = 'Personal UID'
        link.key_type = storage_types.KeyType.DataKey
        link.record_key = crypto.encrypt_aes_v2(record_key, client_key)
        link.can_edit = True

        record_key_storage.put_links((link,))

        recs = list(record_storage.get_all())
        self.assertEqual(len(recs), 1)
        self.assertEqual(record.record_uid, recs[0].record_uid)
        self.assertEqual(record.owner, recs[0].owner)
        self.assertEqual(record.revision, recs[0].revision)

        links = list(record_key_storage.get_links_for_subject(record.record_uid))
        self.assertEqual(len(links), 1)
        self.assertEqual(link.record_uid, links[0].record_uid)
