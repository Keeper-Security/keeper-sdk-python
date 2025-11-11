import sqlite3
from typing import Callable, Union, Iterable, Tuple, Optional

from . import storage_types
from .. import sqlite_dao


class SqliteEntityStorage(sqlite_dao.SqliteStorage, storage_types.IEntityReaderStorage):
    def __init__(self, get_connection: Callable[[], sqlite3.Connection], schema: sqlite_dao.TableSchema,
                 owner: Optional[sqlite_dao.KeyTypes]=None) -> None:
        super(SqliteEntityStorage, self).__init__(get_connection, schema, owner)
        if len(self.schema.primary_key) != 1:
            raise ValueError('SqliteEntityStorage: Primary key to have one column.')

    def get_entity(self, uid):
        for entity in self.select_by_filter(self.schema.primary_key, [uid]):
            return entity

    def get_all_entities(self):
        for entity in self.select_all():
            yield entity

    def put_entities(self, entities):
        self.put(entities)

    def delete_uids(self, uids):
        self.delete_by_filter(self.schema.primary_key, uids, multiple_criteria=True)


class SqliteLinkStorage(sqlite_dao.SqliteStorage, storage_types.ILinkReaderStorage):
    def __init__(self, get_connection: Callable[[], sqlite3.Connection], schema: sqlite_dao.TableSchema,
                 owner: Optional[sqlite_dao.KeyTypes]=None) -> None:
        super(SqliteLinkStorage, self).__init__(get_connection, schema, owner)
        if len(self.schema.primary_key) != 2:
            raise ValueError('SqliteLinkStorage: Primary key to have two columns.')

        object_column = self.schema.primary_key[1]
        object_index_name = None
        if self.schema.indexes:
            for index_name, index_columns in self.schema.indexes.items():
                if index_columns[0].lower() == object_column.lower():
                    object_index_name = index_name
                    break
        if not object_index_name:
            raise ValueError(
                f'SqliteLinkStorage: Object UID column "{object_column}"is not indexed in table "{schema.table_name}".')

    def put_links(self, links):
        self.put(links)

    @staticmethod
    def expand_link_to_tuple(links: Iterable[Union[storage_types.IUidLink, Tuple[str, str]]]) -> Iterable[Tuple[str, str]]:
        for link in links:
            if isinstance(link, storage_types.IUidLink):
                yield link.subject_uid(), link.object_uid()
            elif isinstance(link, (list, tuple)) and len(link) == 2:
                yield link[0], link[1]
            else:
                raise ValueError('Unsupported link type')

    def delete_links(self, links):
        self.delete_by_filter(self.schema.primary_key, SqliteLinkStorage.expand_link_to_tuple(links),
                              multiple_criteria=True)

    def delete_links_by_subjects(self, subject_uids):
        self.delete_by_filter(self.schema.primary_key[0], subject_uids, multiple_criteria=True)

    def delete_links_by_objects(self, object_uids):
        self.delete_by_filter(self.schema.primary_key[1], object_uids, multiple_criteria=True)

    def get_links_by_subject(self, subject_uid):
        for link in self.select_by_filter(self.schema.primary_key[0], subject_uid):
            yield link

    def get_links_by_object(self, object_uid):
        for link in self.select_by_filter(self.schema.primary_key[1], object_uid):
            yield link

    def get_all_links(self):
        for link in self.select_all():
            yield link

    def get_link(self, subject_uid, object_uid):
        for link in self.select_by_filter(self.schema.primary_key, (subject_uid, object_uid)):
            return link


class SqliteRecordStorage(sqlite_dao.SqliteStorage, storage_types.IRecordStorage):
    def __init__(self, get_connection: Callable[[], sqlite3.Connection], schema: sqlite_dao.TableSchema,
                 owner: Optional[sqlite_dao.KeyTypes]) -> None:
        super(SqliteRecordStorage, self).__init__(get_connection, schema, owner)
        if not schema.owner_column:
            raise ValueError(f'SqliteRecordStorage: Schema \"{schema.table_name}\" should have an owner')
        if schema.primary_key:
            raise ValueError(f'SqliteRecordStorage: Schema \"{schema.table_name}\" should not have primary key')

    def load(self):
        return next(self.select_all(), None)

    def store(self, record):
        self.put([record])

    def delete(self):
        self.delete_all()
