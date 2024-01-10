import sqlite3
from typing import Callable

from . import enterprise_types
from .. import sqlite_dao
from ..storage import sqlite, storage_types


class SqliteEnterpriseStorage(enterprise_types.IEnterpriseStorage):
    def __init__(self, get_connection: Callable[[], sqlite3.Connection], enterprise_id: int) -> None:
        super().__init__()
        self.get_connection = get_connection
        self.enterprise_id = enterprise_id
        self.owner_column = 'enterprise_id'

        settings_schema = sqlite_dao.TableSchema.load_schema(
            enterprise_types.EnterpriseSettings, [], owner_column=self.owner_column, owner_type=int)
        data_schema = sqlite_dao.TableSchema.load_schema(
            enterprise_types.EnterpriseEntityData, ['type', 'key'], indexes={'Object': 'key'}, owner_column=self.owner_column, owner_type=int)

        sqlite_dao.verify_database(self.get_connection(), (settings_schema, data_schema))
        self._settings_storage = sqlite.SqliteRecordStorage(self.get_connection, settings_schema, owner=self.enterprise_id)
        self._data_storage = sqlite.SqliteLinkStorage(self.get_connection, data_schema, owner=self.enterprise_id)

    @property
    def settings(self) -> storage_types.IRecordStorage[enterprise_types.EnterpriseSettings]:
        return self._settings_storage

    @property
    def entity_data(self) -> storage_types.ILinkStorage[enterprise_types.EnterpriseEntityData, int, str]:
        return self._data_storage

    def clear(self):
        self._settings_storage.delete_all()
        self._data_storage.delete_all()
