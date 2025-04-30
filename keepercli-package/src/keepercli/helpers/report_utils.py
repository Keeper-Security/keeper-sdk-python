import csv
import datetime
import io
import json
import os

from typing import List, Any, Sequence, Optional, Iterable, Callable
from tabulate import tabulate

from .. import api

WORDS_TO_CAPITALIZE = {'Id', 'Uid', 'Ip', 'Url', 'Scim'}


def json_serialized(obj):
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    return str(obj)


def is_json_value_field(obj: Any) -> bool:
    if obj is None:
        return False
    if isinstance(obj, str):
        return len(obj) > 0
    return True


def field_to_title(field: str) -> str:
    if field[0] == '"' and field[-1] == '"':
        return field.strip('"')
    words = field.split('_')
    words = [x.capitalize() for x in words if x]
    words = [x.upper() if x in WORDS_TO_CAPITALIZE else x for x in words]
    return ' '.join(words)


def get_date_key(value: Any) -> int:
    if isinstance(value, datetime.datetime):
        return int(value.timestamp())
    if isinstance(value, datetime.date):
        dt = datetime.datetime.combine(value, datetime.datetime.min.time())
        return int(dt.timestamp())
    return 0


def get_str_key(value: Any) -> str:
    if isinstance(value, str):
        return value.casefold()
    return ''


def get_num_key(value: Any) -> float:
    if isinstance(value, int):
        return float(value)
    if isinstance(value, float):
        return value
    if isinstance(value, str):
        if value.isnumeric():
            try:
                return float(value)
            except Exception:
                pass
    return 0.0


def get_bool_key(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return False


def detect_column_type(values: Iterable[Any]) -> Optional[Callable[[Any], Any]]:
    str_no = 0
    date_no = 0
    bool_no = 0
    num_no = 0
    for value in values:
        if value is not None:
            if isinstance(value, str):
                str_no += 1
            elif isinstance(value, (datetime.datetime, datetime.date)):
                date_no += 1
            elif isinstance(value, (int, float)):
                num_no += 1
            elif isinstance(value, bool):
                bool_no += 1
    nums = [('str', str_no), ('date', date_no), ('bool', bool_no), ('num', num_no)]
    nums.sort(key=lambda x: x[1], reverse=True)
    column_type, column_no = nums[0]
    if column_no > 0:
        if column_type == 'date':
            return get_date_key
        if column_type == 'str':
            return get_str_key
        if column_type == 'num':
            return get_num_key
        if column_type == 'bool':
            return get_bool_key
    return None



def dump_report_data(data: List[List[Any]],
                     headers: Sequence[str],
                     *,
                     fmt: Optional[str]=None,
                     filename: Optional[str]=None,
                     no_header: Optional[bool]=None,     # Do not print header
                     row_number: Optional[bool]=None,    # Add row number. table only
                     **kwargs) -> Optional[str]:
    # kwargs:
    #           title: str                 - Table title
    #           append: bool               - append to existing file
    #           column_width: int          - Truncate long columns. table only
    #           group_by: int              - Sort and Group by columnNo
    #           sort_by: int               - Sort by columnNo
    #           sort_desc: bool            - Descending Sort
    #           right_align: Sequence[int] - Force right align

    append = kwargs.get('append') is True
    title = kwargs.get('title')
    sort_by = kwargs.get('sort_by')
    group_by = kwargs.get('group_by')
    if group_by is not None:
        group_by = int(group_by)
        sort_by = group_by

    if isinstance(sort_by, int):
        reverse = kwargs.get('sort_desc') is True
        key_fn = detect_column_type((x[sort_by] for x in data if 0 <= sort_by < len(x)))
        if callable(key_fn):
            def key_func(r: List[Any]) -> Any:
                assert sort_by is not None
                assert key_fn is not None
                if isinstance(r, list):
                    if 0 <= sort_by < len(r):
                        return key_fn(r[sort_by])
                return None
            data.sort(key=key_func, reverse=reverse)

    if fmt == 'csv':
        if filename:
            _, ext = os.path.splitext(filename)
            if not ext:
                filename += '.csv'

        with open(filename, 'a' if append else 'w', newline='', encoding='utf-8') if filename else io.StringIO() as fd:
            csv_writer = csv.writer(fd)
            if title:
                csv_writer.writerow([])
                csv_writer.writerow([title])
                csv_writer.writerow([])
            elif append:
                csv_writer.writerow([])

            starting_column = 0
            if headers:
                if headers[0] == '#':
                    starting_column = 1
                csv_writer.writerow(headers[starting_column:])
            for row in data:
                for i in range(len(row)):
                    if isinstance(row[i], list):
                        row[i] = '\n'.join(row[i])
                csv_writer.writerow(row[starting_column:])
            if isinstance(fd, io.StringIO):
                report = fd.getvalue()
                if append:
                    api.get_logger().info(report)
                else:
                    return report
    elif fmt == 'json':
        data_list = []
        for row in data:
            obj = {}
            for index, column in filter(lambda x: is_json_value_field(x[1]), enumerate(row)):
                name = headers[index] if headers and index < len(headers) else "#{:0>2}".format(index)
                if name != '#':
                    obj[name] = column
            data_list.append(obj)
        if filename:
            _, ext = os.path.splitext(filename)
            if not ext:
                filename += '.json'
            with open(filename, 'a' if append else 'w') as fd:
                json.dump(data_list, fd, indent=2, default=json_serialized)
        else:
            report = json.dumps(data_list, indent=2, default=json_serialized)
            if append:
                api.get_logger().info(report)
            else:
                return report
    else:
        if title:
            print('\n{0}\n'.format(title))
        elif append:
            print('\n')
        if not isinstance(row_number, bool):
            row_number = False
        column_width = kwargs.get('column_width')
        if not isinstance(column_width, int):
            column_width = 0
        if 0 < column_width < 32:
            column_width = 32

        if row_number and headers:
            headers = list(headers)
            headers.insert(0, '#')

        expanded_data = []
        last_group_by_value = None
        for row_no in range(len(data)):
            row = data[row_no]
            if isinstance(group_by, int):
                if 0 <= group_by < len(row):
                    group_by_value = row[group_by]
                    if group_by_value == last_group_by_value:
                        row[group_by] = None
                    else:
                        last_group_by_value = group_by_value
            if row_number:
                if not isinstance(row, list):
                    row = list(row)
                row.insert(0, row_no + 1)
            expanded_rows = 1
            for column in row:
                if isinstance(column, list):
                    if len(column) > expanded_rows:
                        expanded_rows = len(column)
            for i in range(expanded_rows):
                rowi = []
                for column in row:
                    value = ''
                    if isinstance(column, list):
                        if i < len(column):
                            value = column[i]
                    elif i == 0:
                        value = column
                    if column_width > 0:
                        if isinstance(value, str) and len(value) > column_width:
                            lines = value.split('\n')
                            lines = [x if len(x) < column_width else x[:column_width-2] + '...' for x in lines]
                            value = '\n'.join(lines)
                    rowi.append(value)
                expanded_data.append(rowi)
        tablefmt = 'simple'
        right_align = kwargs.get('right_align')
        if isinstance(right_align, int):
            right_align = [right_align]
        if isinstance(right_align, (list, tuple)) and isinstance(headers, (list, tuple)):
            colalign = ['left'] * len(headers)
            if row_number:
                colalign[0] = 'decimal'
            for i in range(len(right_align)):
                pos = right_align[i]
                if row_number:
                    pos += 1
                if isinstance(pos, int) and pos < len(colalign):
                    colalign[pos] = 'decimal'
        else:
            colalign = None

        if no_header:
            headers = ()
            tablefmt = 'plain'

        print(tabulate(expanded_data, headers=headers, tablefmt=tablefmt, colalign=colalign if expanded_data else None))


