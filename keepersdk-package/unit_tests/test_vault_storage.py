import sqlite3
from unittest import TestCase

from keepersdk import utils
from keepersdk.vault import sqlite_storage, memory_storage, vault_storage


class TestVaultStorage(TestCase):
    def test_memory_storage_create(self) -> None:
        vault_data: vault_storage.IVaultStorage = memory_storage.InMemoryVaultStorage()
        self.assertIsNotNone(vault_data)
        recs = list(vault_data.records.get_all())
        for record in recs:
            if record.record_uid:
                pass

    def test_sqlite_storage_create(self) -> None:
        conn = sqlite3.Connection('file:///?mode=memory&cache=shared', uri=True)
        vault_data: vault_storage.IVaultStorage = \
            sqlite_storage.SqliteVaultStorage(lambda: conn, utils.generate_aes_key())
        self.assertIsNotNone(vault_data)
        recs = list(vault_data.records.get_all())
        for record in recs:
            if record.record_uid:
                pass
