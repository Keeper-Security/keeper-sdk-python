from unittest import TestCase

from vault import sqlite_storage, vault_storage, memory_storage


class TestVaultStorage(TestCase):
    def test_memory_storage_create(self):
        vault_data: vault_storage.IVaultStorage = memory_storage.InMemoryVaultStorage()
        self.assertIsNotNone(vault_data)
        recs = list(vault_data.records.get_all())
        for record in recs:
            if record.record_uid:
                pass

    def test_sqlite_storage_create(self):
        vault_data: vault_storage.IVaultStorage = \
            sqlite_storage.SqliteVaultStorage(':memory:', 'user@company.com')
        self.assertIsNotNone(vault_data)
        recs = list(vault_data.records.get_all())
        for record in recs:
            if record.record_uid:
                pass
