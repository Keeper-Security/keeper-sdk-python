import dataclasses
import sqlite3
from typing import Callable, Iterator

from keepersdk import sqlite_dao
from keepersdk.storage import sqlite, storage_types


@dataclasses.dataclass
class StorageSoxSettings:
    continuation_token: bytes = b''


@dataclasses.dataclass
class StorageSoxRecord:
    record_uid: str = ''
    record_data: bytes = b''
    owner_user_id: int = 0
    shared: bool = False

class SqliteSoxStorage:
    def __init__(self, get_connection: Callable[[], sqlite3.Connection], enterprise_id: int) -> None:
        self.get_connection: Callable[[], sqlite3.Connection] = get_connection
        self.enterprise_column = 'enterprise_id'

        sox_settings_schema = sqlite_dao.TableSchema.load_schema(
            StorageSoxSettings, [], owner_column=self.enterprise_column, owner_type=int)
        sox_record_schema = sqlite_dao.TableSchema.load_schema(
            StorageSoxRecord, ['record_uid'], indexes={'OWNER_ID': 'owner_user_id'}, owner_column=self.enterprise_column, owner_type=int)

        sqlite_dao.verify_database(self.get_connection(),(sox_settings_schema, sox_record_schema))

        self._sox_settings_storage = sqlite.SqliteRecordStorage(self.get_connection, sox_settings_schema, owner=enterprise_id)
        self._sox_record_storage = sqlite.SqliteEntityStorage(self.get_connection, sox_record_schema, owner=enterprise_id)

    @property
    def sox_record_storage(self) -> storage_types.IEntityReaderStorage[StorageSoxRecord, str]:
        return self._sox_record_storage

    def get_owned_records(self, user_id: int) -> Iterator[StorageSoxRecord]:
        schema = self._sox_record_storage.schema
        assert isinstance(schema.indexes, dict)
        owner_index = schema.indexes['OWNER_ID']
        assert owner_index is not None and isinstance(owner_index, list) and len(owner_index) == 1
        yield from self._sox_record_storage.select_by_filter(owner_index[0], user_id)

