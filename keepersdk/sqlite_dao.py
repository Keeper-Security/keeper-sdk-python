import json
import sqlite3
from dataclasses import dataclass

from typing import Dict, Union, Sequence, Any, List, Optional, Type, Callable, Iterator

from . import utils
from google.protobuf.descriptor import FieldDescriptor

KeyTypes = Union[str, int, bytes]


@dataclass
class FieldSchema:
    name: str
    type: type
    element_type: Optional[Type] = None


class TableSchema:
    def __init__(self):                 # type: () -> None
        self.table_name = ''            # type: str
        self.class_type = type(object)  # type: Type
        self.columns = []               # type: List[str]
        self.primary_key = []           # type: List[str]
        self.indexes = None             # type: Optional[Dict[str, List[str]]]
        self.owner_column = None        # type: Optional[str]
        self.owner_column_type = None   # type: Union[Type[int], Type[str], None]
        self.class_fields = {}          # type: Dict[str, FieldSchema]

    @staticmethod
    def _load_proto_fields(class_type):     # type: (Type[Any]) -> Iterator[FieldSchema]
        class_name = class_type.__name__
        if hasattr(class_type, 'DESCRIPTOR'):
            for column in class_type.DESCRIPTOR.fields_by_name:
                class_field = class_type.DESCRIPTOR.fields_by_name[column]  # type: FieldDescriptor
                if class_field.has_options:
                    options = class_field.GetOptions()
                    if options and hasattr(options, 'deprecated'):
                        deprecated = getattr(options, 'deprecated')
                        if deprecated is True:
                            continue
                field_type = None  # type: Optional[Type]
                element_type = None  # type: Optional[Type]
                if isinstance(class_field.default_value, str):
                    field_type = str
                elif isinstance(class_field.default_value, bool):
                    field_type = bool
                elif isinstance(class_field.default_value, int):
                    field_type = int
                elif isinstance(class_field.default_value, float):
                    field_type = float
                elif isinstance(class_field.default_value, bytes):
                    field_type = bytes
                elif isinstance(class_field.default_value, list):
                    field_type = list
                    if class_field.type == FieldDescriptor.TYPE_STRING:
                        element_type = str
                    elif class_field.type == FieldDescriptor.TYPE_BOOL:
                        element_type = bool
                    elif class_field.type in (FieldDescriptor.TYPE_INT32, FieldDescriptor.TYPE_INT64, FieldDescriptor.TYPE_SINT32, FieldDescriptor.TYPE_SINT64, FieldDescriptor.TYPE_UINT32, FieldDescriptor.TYPE_UINT64):
                        element_type = int
                    elif class_field.type in (FieldDescriptor.TYPE_DOUBLE, FieldDescriptor.TYPE_FLOAT, FieldDescriptor.TYPE_FIXED32, FieldDescriptor.TYPE_FIXED64):
                        element_type = float
                    elif class_field.type == FieldDescriptor.TYPE_BYTES:
                        element_type = bytes
                else:
                    utils.get_logger().debug(
                        'load_schema: Unsupported type for attribute \"%s\" in class \"%s\". Skipping',
                        column, class_name)
                if field_type:
                    yield FieldSchema(column, field_type, element_type)
        else:
            raise ValueError(f'Class {class_name} does not seem to be a protobuf message')

    @staticmethod
    def _load_class_fields(class_type):     # type: (Type[Any]) -> Iterator[FieldSchema]
        class_name = class_type.__name__
        obj = class_type()
        obj_values = {x: getattr(obj, x) for x in dir(obj) if not x.startswith('_')}
        for field_name, value in obj_values.items():
            if callable(value):
                continue
            field_type = None     # type: Optional[Type]
            if isinstance(value, str):
                field_type = str
            elif isinstance(value, bool):
                field_type = bool
            elif isinstance(value, int):
                field_type = int
            elif isinstance(value, float):
                field_type = float
            elif isinstance(value, (bytes, bytearray)):
                field_type = bytes
            elif isinstance(value, list):
                field_type = list
            elif value is None:
                utils.get_logger().debug(
                    'load_schema: Attribute \"%s\" in class \"%s\" is skipped since it is None',
                    field_name, class_name)
            else:
                utils.get_logger().debug(
                    'load_schema: Unsupported type for attribute \"%s\" in class \"%s\". Skipping',
                    field_name, class_name)
            if field_type:
                yield FieldSchema(field_name, field_type)

    @classmethod
    def load_schema(cls,
                    class_type,         # type: Type
                    primary_key,        # type: Sequence[str]
                    indexes=None,       # type: Optional[Dict[str, Union[str, Sequence[str]]]]
                    owner_column=None,  # type: Optional[str]
                    owner_type=None     # type: Optional[Type[Union[str, int]]]
                    ):                  # type: (...) -> TableSchema
        schema = cls()
        schema.class_type = class_type
        schema.table_name = class_type.__name__

        if hasattr(class_type, 'DESCRIPTOR'):
            class_fields = TableSchema._load_proto_fields(class_type)
        else:
            class_fields = TableSchema._load_class_fields(class_type)

        for class_field in class_fields:
            column_name = class_field.name.lower()
            schema.class_fields[column_name] = class_field
            schema.columns.append(class_field.name)

        if len(schema.columns) == 0:
            raise ValueError(f'Table {schema.table_name} does not have any column defined')

        if isinstance(primary_key, str):
            schema.primary_key.append(primary_key)
        elif isinstance(primary_key, (list, tuple)):
            schema.primary_key.extend(primary_key)
        else:
            if not owner_column:
                raise ValueError(f'Schema \"{schema.table_name}\" does not have either primary key or owner column')

        for column in schema.primary_key:
            if column.lower() in schema.class_fields:
                cf = schema.class_fields[column.lower()]
                if cf.type not in (str, int, bytes):
                    raise ValueError(f'Table {schema.table_name} column {column}: Unsupported primary key type')
            else:
                raise ValueError(f'Primary Key: Table {schema.table_name} does not have column {column}')

        if isinstance(indexes, dict):
            schema.indexes = {}
            for index_name, index_columns in indexes.items():
                if isinstance(index_columns, str):
                    index_columns = [index_columns]
                if not isinstance(index_columns, (list, tuple)):
                    raise ValueError(f'Index \"{index_name}\": invalid columns')
                for column in index_columns:
                    if column.lower() in schema.class_fields:
                        cf = schema.class_fields[column.lower()]
                        if cf.type not in (str, int, bytes):
                            raise ValueError(f'Table {schema.table_name} column {column}: Unsupported primary key type')
                    else:
                        raise ValueError(
                            f'Index \"{index_name}\": Table {schema.table_name} does not have column {column}')
                schema.indexes[index_name] = [x for x in index_columns]

        if owner_column:
            if owner_column.lower() in schema.class_fields:
                raise ValueError(f'Owner: Table {schema.table_name} contains owner column {owner_column}')
            schema.owner_column = owner_column
            schema.owner_column_type = str
            if owner_type and owner_type == int:
                schema.owner_column_type = int

        return schema


def _to_sqlite_type(column_type):
    # type: (Type) -> str
    if column_type in {bool, int}:
        return 'INTEGER'
    if column_type == float:
        return 'REAL'
    if column_type == bytes:
        return 'BLOB'
    if column_type == list:
        return 'JSON'
    return 'TEXT'


def verify_database(connection, tables, apply_changes=True):
    # type: (sqlite3.Connection, Sequence[TableSchema], bool) -> List[str]
    result = []
    existing_tables = set((x[0].lower() for x in
                           connection.execute('SELECT name FROM sqlite_master where type=?', ('table',))))
    for table in tables:
        queries = []
        if table.table_name.lower() in existing_tables:
            column_info = connection.execute(f'PRAGMA table_info(\'{table.table_name}\')').fetchall()
            column_info.sort(key=lambda x: x[0])
            columns = set((x[1].lower() for x in column_info))

            pk_cols = []
            if table.owner_column:
                pk_cols.append(table.owner_column)
            pk_cols.extend(table.primary_key)
            for col in pk_cols:
                if col.lower() not in columns:
                    raise ValueError(f'Table \"{table.table_name}\" misses primary key \"{col}\".')
            missing_columns = [x for x in table.columns if x.lower() not in columns]
            for col in missing_columns:
                field_schema = table.class_fields.get(col.lower())
                column_type = _to_sqlite_type(field_schema.type if field_schema else str)
                queries.append(f'ALTER TABLE {table.table_name} ADD COLUMN {col} {column_type}')

            if table.indexes:
                index_names = [x[1] for x in connection.execute(f'PRAGMA index_list(\'{table.table_name}\')')]
                indexes = {}
                for index_name in index_names:
                    index_info = connection.execute(f'PRAGMA index_info(\'{index_name}\')').fetchall()
                    index_info.sort(key=lambda x: x[0])
                    indexes[index_name.lower()] = [x[2] for x in index_info]
                for index_name, index_columns in table.indexes.items():
                    cols = []
                    if table.owner_column:
                        cols.append(table.owner_column)
                    cols.extend(index_columns)
                    index_found = None
                    for existing_index_name, existing_index_columns in indexes.items():
                        if len(existing_index_columns) != len(cols):
                            continue
                        if any(True for x in zip(existing_index_columns, cols) if x[0].lower() != x[1].lower()):
                            continue
                        index_found = existing_index_name
                        break
                    if index_found:
                        continue
                    index_name = f'{table.table_name}_{index_name}_IDX'
                    if index_name.lower() in indexes:
                        queries.append(f'DROP INDEX "{index_name}"')
                    queries.append(f'CREATE INDEX "{index_name}" ON {table.table_name} (' + ', '.join(cols) + ')')
        else:
            added_columns = set()
            table_columns = []
            pks = []
            if table.owner_column:
                pks.append(table.owner_column)
                column_type = _to_sqlite_type(table.owner_column_type or str)
                table_columns.append(f'\t{table.owner_column} {column_type} NOT NULL')
                added_columns.add(table.owner_column.lower())
            for pk_column in table.primary_key:
                pks.append(pk_column)
                column_type = _to_sqlite_type(table.class_fields[pk_column.lower()].type)
                table_columns.append(f'\t{pk_column} {column_type} NOT NULL')
                added_columns.add(pk_column.lower())
            for column in table.columns:
                if column.lower() in added_columns:
                    continue

                field_schema = table.class_fields.get(column.lower())
                column_type = _to_sqlite_type(field_schema.type if field_schema else str)
                table_columns.append(f'\t{column} {column_type}')
                added_columns.add(column.lower())
            queries.append(f'CREATE TABLE {table.table_name} (\n' + ',\n'.join(table_columns) + ',\n' +
                           '\tPRIMARY KEY (' + ', '.join(pks) + ')\n)')
            if table.indexes:
                for index_name, index_columns in table.indexes.items():
                    cols = []
                    if table.owner_column:
                        cols.append(table.owner_column)
                    cols.extend(index_columns)
                    queries.append(f'CREATE INDEX "{table.table_name}_{index_name}_IDX" '
                                   f'ON {table.table_name} (' + ', '.join(cols) + ')')

        if len(queries) > 0:
            for query in queries:
                if apply_changes:
                    connection.execute(query)
                else:
                    result.append(query)
            if apply_changes:
                connection.commit()
    return result


class SqliteStorage:
    def __init__(self, get_connection, schema, owner=None):
        # type: (Callable[[], sqlite3.Connection], TableSchema, Optional[KeyTypes]) -> None
        if not callable(get_connection):
            raise ValueError(f'"get_connection" should be callable.')
        self.get_connection = get_connection
        if not isinstance(schema, TableSchema):
            raise ValueError(f'"schema": Invalid type. TableSchema expected')
        self.schema = schema
        self.owner = None
        if owner:
            if not schema.owner_column:
                raise ValueError(f'"owner": schema does not define owner column.')
            if not isinstance(owner, schema.owner_column_type or str):
                raise ValueError(f'"owner": Invalid type. {(schema.owner_column_type or str).__name__} expected')
            self.owner = owner
        self._queries = {}    # type: Dict[str, str]

    def _populate_data_object(self, values):  # type: (Sequence[Any]) -> Any
        obj = self.schema.class_type()
        for i, column in enumerate(self.schema.columns):
            field_schema = self.schema.class_fields.get(column.lower())
            if field_schema:
                value = values[i]
                if field_schema.type == list and isinstance(value, str):
                    try:
                        j_value = json.loads(value)
                        if isinstance(j_value, list):
                            if field_schema.element_type is not None:
                                j_value = [x for x in j_value if isinstance(x, field_schema.element_type)]
                            list_field = getattr(obj, field_schema.name)
                            if list_field is not None:
                                list_field.extend(j_value)
                            else:
                                setattr(obj, field_schema.name, value)
                    except ValueError as e:
                        utils.get_logger().debug('Error parsing json array: %s', e)
                else:
                    if field_schema.type == bool and isinstance(value, int):
                        value = value != 0
                    setattr(obj, field_schema.name, value)
        return obj

    def _adjust_filter_columns(self, columns):  # type: (Union[str, Sequence[str]]) -> Sequence[str]
        if not columns:
            raise ValueError('adjust_filter_columns: columns cannot be empty')
        if isinstance(columns, str):
            columns = [columns]
        if not isinstance(columns, (list, tuple)):
            raise ValueError('adjust_filter_columns: columns should be a sequence of str')
        for column in columns:
            if column.lower() not in self.schema.class_fields:
                raise ValueError(
                    f'adjust_filter_columns: table \"{self.schema.table_name}\" does not have column \"{column}\"')
        return columns

    @staticmethod
    def _adjust_values_for_columns(columns, values):
        # type: (Sequence[str], Union[Any, Sequence[Any]]) -> Sequence[Any]
        if not isinstance(values, (list, tuple)):
            values = [values]
        if len(columns) != len(values):
            raise ValueError(
                f'adjust_values_for_columns: number of values {len(values)} does not match columns {len(columns)}')
        return values

    def prepare_params(self, columns, values):
        # type: (Sequence[str], Union[str, Sequence[Any]]) -> Dict[str, Any]
        params = {}
        if self.schema.owner_column:
            params[self.schema.owner_column] = self.owner
        adjusted_values = self._adjust_values_for_columns(columns, values)
        for i, column in enumerate(columns):
            params[column] = adjusted_values[i]
        return params

    def select_all(self, order_by=None):
        # type: (Union[str, Sequence[str], None]) -> Iterator[Any]
        key = 'select-all'
        if order_by:
            if isinstance(order_by, str):
                order_by = [order_by]
            elif isinstance(order_by, (list, tuple)):
                order_by = order_by
            else:
                raise ValueError(f'select_all: \"order_by\" invalid type.')
            for column_name in order_by:
                if not isinstance(column_name, str):
                    raise ValueError(f'select_all: \"order_by\" invalid type.')
                if column_name.lower() not in self.schema.class_fields:
                    raise ValueError(
                        f'select_all: table \"{self.schema.table_name}\" does not have column \"{column_name}\"')
            key += f': ' + ', '.join(order_by)

        query = self._queries.get(key)
        if not query:
            query = 'SELECT ' + ', '.join(self.schema.columns)
            query += f' FROM {self.schema.table_name}'
            if self.schema.owner_column:
                query += f' WHERE {self.schema.owner_column}=:{self.schema.owner_column}'
            if order_by:
                query += ' ORDER BY ' + ', '.join(order_by)
            self._queries[key] = query

        conn = self.get_connection()
        if self.schema.owner_column:
            params = {self.schema.owner_column: self.owner}
            curr = conn.execute(query, params)
        else:
            curr = conn.execute(query)
        for row in curr:
            yield self._populate_data_object(row)

    def select_by_filter(self, columns, values):
        # type: (Union[str, Sequence[str]], Union[Any, Sequence[Any]]) -> Iterator[Any]
        adjusted_columns = self._adjust_filter_columns(columns)

        key = f'select-by-filter: ' + ', '.join(adjusted_columns)
        query = self._queries.get(key)
        if not query:
            wheres = []
            if self.schema.owner_column:
                wheres.append(f'{self.schema.owner_column}=:{self.schema.owner_column}')
            wheres.extend((f'{x}=:{x}' for x in adjusted_columns))
            query = 'SELECT ' + ', '.join(self.schema.columns) + f' FROM {self.schema.table_name} ' +\
                    'WHERE ' + ' AND '.join(wheres)
            self._queries[key] = query

        conn = self.get_connection()
        curr = conn.execute(query, self.prepare_params(adjusted_columns, values))
        for row in curr:
            yield self._populate_data_object(row)

    def delete_all(self):   # type: () -> int
        query = self._queries.get('delete-all')
        if not query:
            wheres = []
            if self.schema.owner_column:
                wheres.append(f'{self.schema.owner_column}=:{self.schema.owner_column}')
            else:
                wheres.append('1=1')
            query = f'DELETE FROM {self.schema.table_name} WHERE ' + ' AND '.join(wheres)
            self._queries['delete-all'] = query

        conn = self.get_connection()
        try:
            if self.schema.owner_column:
                params = {self.schema.owner_column: self.owner}
                rs = conn.execute(query, params)
            else:
                rs = conn.execute(query)
            conn.commit()
            return rs.rowcount
        except Exception as e:
            conn.rollback()
            raise e

    def delete_by_filter(self, columns, values, multiple_criteria=False):
        # type: (Union[str, Sequence[str]], Union[Any, Sequence[Any]], bool) -> int
        adjusted_columns = self._adjust_filter_columns(columns)

        key = f'delete_by_filter: ' + ', '.join(adjusted_columns)
        query = self._queries.get(key)
        if not query:
            wheres = []
            if self.schema.owner_column:
                wheres.append(f'{self.schema.owner_column}=:{self.schema.owner_column}')
            wheres.extend((f'{x}=:{x}' for x in adjusted_columns))
            query = f'DELETE FROM {self.schema.table_name} WHERE ' + ' AND '.join(wheres)
            self._queries[key] = query

        conn = self.get_connection()
        row_count = 0
        try:
            if multiple_criteria:
                if not isinstance(values, (tuple, list)):
                    values = [values]
                rs = conn.executemany(query, (self.prepare_params(adjusted_columns, x) for x in values))
            else:
                rs = conn.execute(query, self.prepare_params(adjusted_columns, values))
            row_count += rs.rowcount
            conn.commit()
            return row_count
        except Exception as e:
            conn.rollback()
            raise e

    def get_entity_values(self, entity):   # type: (Any) -> Dict[str, Any]
        if not isinstance(entity, self.schema.class_type):
            raise ValueError('SqliteStorage:get_entity_values: invalid entity type. '
                             f'Expected {self.schema.class_type.__name__}')

        d = {}
        if self.schema.owner_column:
            d[self.schema.owner_column] = self.owner
        for column in self.schema.columns:
            column_value = None
            if hasattr(entity, column):
                value = getattr(entity, column)
                c_type = self.schema.class_fields.get(column.lower())
                if c_type and c_type.type == list:
                    if isinstance(value, (tuple, list, Sequence)):
                        column_value = json.dumps([x for x in value])
                else:
                    column_value = value
            d[column] = column_value
        return d

    def put(self, entities):       # type: (Union[Any, Sequence[Any]]) -> None
        key = 'put-entities'
        query = self._queries.get(key)
        if not query:
            cols = []
            if self.schema.owner_column:
                cols.append(self.schema.owner_column)
            cols.extend(self.schema.columns)
            query = f'INSERT OR REPLACE INTO {self.schema.table_name} (' + ', '.join(cols) + ') VALUES (' + \
                    ', '.join((f':{x}' for x in cols)) + ')'
            self._queries[key] = query

        conn = self.get_connection()
        try:
            conn.executemany(query, (self.get_entity_values(x) for x in entities))
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
