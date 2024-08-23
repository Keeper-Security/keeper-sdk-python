import copy
import dataclasses
import datetime
import enum
import time
from typing import Optional, Union, List, Iterable, Dict, Any

from ..authentication import keeper_auth


@dataclasses.dataclass
class CreatedFilterCriteria:
    from_date: Optional[Union[str, int]] = None
    exclude_from: Optional[bool] = None
    to_date: Optional[Union[str, int]] = None
    exclude_to: Optional[bool] = None


@dataclasses.dataclass
class AuditReportFilter:
    created: Optional[Union[str, CreatedFilterCriteria]] = None
    event_type: Optional[Union[str, int, List[Union[str, int]]]] = None
    keeper_version: Optional[Union[int, List[int]]] = None
    username: Optional[Union[str, List[str]]] = None
    to_username: Optional[Union[str, List[str]]] = None
    ip_address: Optional[Union[str, List[str]]] = None
    record_uid: Optional[Union[str, List[str]]] = None
    shared_folder_uid: Optional[Union[str, List[str]]] = None
    parent_id: Optional[Union[int, List[int]]] = None


class ReportOrder(enum.IntEnum):
    Asc = enum.auto()
    Desc = enum.auto()


def expand_created_preset(preset: str) -> CreatedFilterCriteria:
    today = datetime.date.today()
    from_date: datetime.date
    to_date: datetime.date
    if preset == 'today':
        from_date = today
        to_date = today + datetime.timedelta(days=1)
    elif preset == 'yesterday':
        from_date = today - datetime.timedelta(days=1)
        to_date = today
    elif preset == 'last_7_days':
        from_date = today - datetime.timedelta(days=7)
        to_date = today
    elif preset == 'last_30_days':
        from_date = today - datetime.timedelta(days=30)
        to_date = today
    elif preset == 'month_to_date':
        from_date = datetime.date(year=today.year, month=today.month, day=1)
        to_date = today
    elif preset == 'last_month':
        year = today.year
        month = today.month
        to_date = datetime.date(year=year, month=month, day=1)
        if month == 1:
            month = 12
            year -= 1
        else:
            month -= 1
        from_date = datetime.date(year=year, month=month, day=1)
    elif preset == 'last_year':
        from_date = datetime.date(year=today.year - 1, month=1, day=1)
        to_date = datetime.date(year=today.year, month=1, day=1)
    elif preset == 'year_to_date':
        from_date = datetime.date(year=today.year, month=1, day=1)
        to_date = today
    else:
        raise ValueError(f'Unknown preset {preset}')

    range_filter = CreatedFilterCriteria()
    range_filter.from_date = int(datetime.datetime.combine(from_date, datetime.datetime.min.time()).timestamp())
    range_filter.exclude_from = False
    range_filter.to_date = int(datetime.datetime.combine(to_date, datetime.datetime.min.time()).timestamp())
    range_filter.exclude_to = True
    return range_filter


class AuditReportCommon:
    def __init__(self) -> None:
        self.filter: Optional[AuditReportFilter] = None
        self.order: Optional[ReportOrder] = None
        self.limit: Optional[int] = None
        self.timezone: Optional[str] = None

    def get_timezone(self) -> str:
        if self.timezone is None:
            tt = time.tzname
            if tt:
                if time.daylight < len(tt):
                    return tt[time.daylight]
                else:
                    return tt[0]
            else:
                now = time.time()
                utc_offset = datetime.datetime.fromtimestamp(now) - datetime.datetime.fromtimestamp(now, tz=datetime.timezone.utc)
                hours = (utc_offset.days * 24) + (utc_offset.seconds // 60 // 60)
                return f'Etc/GMT{hours:+}'
        else:
            return self.timezone


    def get_filter(self) -> Optional[Dict[str, Any]]:
        if not self.filter:
            return None
        report_filter: Dict[str, Any] = {}
        if self.filter.created is not None:
            if isinstance(self.filter.created, CreatedFilterCriteria):
                created: Dict[str, Any] = {}
                if self.filter.created.from_date is not None:
                    created['min'] = self.filter.created.from_date
                    if self.filter.created.exclude_from is True:
                        created['exclude_min'] = True
                if self.filter.created.to_date is not None:
                    created['max'] = self.filter.created.to_date
                    if self.filter.created.exclude_to is True:
                        created['exclude_max'] = True
                if len(created) > 0:
                    report_filter['created'] = created
            elif isinstance(self.filter.created, str):
                if self.filter.created in ('today', 'yesterday', 'last_7_days', 'last_30_days', 'month_to_date', 'last_month', 'year_to_date', 'last_year'):
                    report_filter['created'] = self.filter.created
                else:
                    raise ValueError(f'Invalid created filter: {self.filter.created}')
        if self.filter.event_type is not None:
            if isinstance(self.filter.event_type, str):
                if self.filter.event_type.isnumeric():
                    report_filter['event_type'] = int(self.filter.event_type)
                else:
                    report_filter['event_type'] = self.filter.event_type
            elif isinstance(self.filter.event_type, int):
                report_filter['event_type'] = self.filter.event_type
            elif isinstance(self.filter.event_type, list):
                report_filter['event_type'] = []
                for x in self.filter.event_type:
                    if isinstance(x, str):
                        if x.isnumeric():
                            report_filter['event_type'].append(int(x))
                        else:
                            report_filter['event_type'].append(x)
                    elif isinstance(x, int):
                        report_filter['event_type'].append(x)
                    else:
                        raise ValueError(f'Invalid event_type filter: {x}')
            else:
                raise ValueError(f'Invalid event type filter: {self.filter.event_type}')
        if self.filter.keeper_version:
            if isinstance(self.filter.keeper_version, (str, int)):
                report_filter['keeper_version'] = self.filter.keeper_version
            else:
                raise ValueError(f'Invalid keeper_version filter: {self.filter.keeper_version}')
        if self.filter.username:
            if isinstance(self.filter.username, (str, list)):
                report_filter['username'] = self.filter.username
            else:
                raise ValueError(f'Invalid username filter: {self.filter.username}')
        if self.filter.to_username:
            if isinstance(self.filter.to_username, (str, list)):
                report_filter['to_username'] = self.filter.to_username
            else:
                raise ValueError(f'Invalid to_username filter: {self.filter.to_username}')
        if self.filter.ip_address:
            if isinstance(self.filter.ip_address, str):
                report_filter['ip_address'] = [self.filter.ip_address]
            elif isinstance(self.filter.ip_address, list):
                report_filter['ip_address'] = self.filter.ip_address
            else:
                raise ValueError(f'Invalid record_uid filter: {self.filter.record_uid}')
        if self.filter.record_uid:
            if isinstance(self.filter.record_uid, (str, list)):
                report_filter['record_uid'] = self.filter.record_uid
            else:
                raise ValueError(f'Invalid record_uid filter: {self.filter.record_uid}')
        if self.filter.shared_folder_uid:
            if isinstance(self.filter.shared_folder_uid, (str, list)):
                report_filter['shared_folder_uid'] = self.filter.shared_folder_uid
            else:
                raise ValueError(f'Invalid shared_folder_uid filter: {self.filter.shared_folder_uid}')
        if self.filter.parent_id:
            if isinstance(self.filter.parent_id, (int, list)):
                report_filter['parent_id'] = self.filter.parent_id
            else:
                raise ValueError(f'Invalid parent_id filter: {self.filter.parent_id}')

        return report_filter if len(report_filter) > 0 else None


class RawAuditReport(AuditReportCommon):
    def __init__(self, auth: keeper_auth.KeeperAuth):
        super().__init__()
        self._auth = auth

    def execute_audit_report(self) -> Iterable[dict]:
        limit: int = self.limit or 50
        if limit == 0:
            yield from iter([])
        is_paginated = limit < 0 or limit > 1000
        report_filter = copy.copy(self.filter) if self.filter else None
        order = self.order
        if order is None:
            order = ReportOrder.Desc
        if is_paginated:
            if report_filter and isinstance(report_filter.created, str):
                report_filter.created = expand_created_preset(report_filter.created)

        timezone = self.get_timezone()

        events_returned = 0
        done = False
        while not done:
            done = True
            if is_paginated:
                if limit <= 0:
                    query_limit = 1000
                else:
                    left = limit - events_returned
                    query_limit = min(1000, left)
            else:
                query_limit = limit
            report_rq = {
                'command': 'get_audit_event_reports',
                'report_type': 'raw',
                'scope': 'enterprise',
                'timezone': timezone,
                'limit': query_limit,
                'order': 'ascending' if self.order == ReportOrder.Asc else 'descending'
            }

            json_filter = self.get_filter()
            if json_filter is not None:
                report_rq['filter'] = json_filter

            report_rs = self._auth.execute_auth_command(report_rq)
            events: Optional[List[Dict[str, Any]]] = report_rs.get('audit_event_overview_report_rows')
            if is_paginated and isinstance(events, list) and len(events) == 1000:
                done = False
                last_event = events[-1]
                ts = int(last_event['created'])
                pos = len(events) - 1
                while pos > 900:
                    e_ts = int(events[pos]['created'])
                    if e_ts == ts:
                        pos -= 1
                    else:
                        break
                if pos > 900:
                    events = events[:pos]
                else:
                    ts += 1
                fd = self.filter
                if fd is None:
                    fd = AuditReportFilter()
                if fd.created is None:
                    fd.created = CreatedFilterCriteria()
                assert(isinstance(fd.created, CreatedFilterCriteria))
                if order == ReportOrder.Asc:
                    fd.created.from_date = ts
                    fd.created.exclude_from = False
                else:
                    fd.created.to_date = ts
                    fd.created.exclude_to = False

            if isinstance(events, list):
                events_returned += len(events)
                yield from events
            else:
                break


SUMMARY_REPORTS = ('hour', 'day', 'week', 'month', 'span')
AGGREGATES = ('occurrences', 'first_created', 'last_created')


class SummaryAuditReport(AuditReportCommon):
    def __init__(self, auth: keeper_auth.KeeperAuth):
        super().__init__()
        self._auth = auth
        self._summary_type: str = ''
        self.aggregates: List[str] = []
        self.columns: List[str] = []

    @property
    def summary_type(self) -> str:
        return self._summary_type
    @summary_type.setter
    def summary_type(self, value: str):
        if value in SUMMARY_REPORTS:
            self._summary_type = value
        else:
            raise ValueError(f'"{value}" is not a valid summary report type')

    def execute_summary_report(self) -> Iterable[dict]:
        if isinstance(self.limit, int):
            if self.limit <= 0:
                limit = 100
            elif self.limit > 2000:
                limit = 2000
            else:
                limit = self.limit
        else:
            limit = 100

        timezone = self.get_timezone()

        report_rq = {
            'command': 'get_audit_event_reports',
            'report_type': self._summary_type,
            'scope': 'enterprise',
            'timezone': timezone,
            'limit': limit,
        }
        if self.aggregates:
            report_rq['aggregate'] = self.aggregates
        if self.columns:
            report_rq['columns'] = self.columns

        if self.order is not None:
            report_rq['order'] = 'ascending' if self.order == ReportOrder.Asc else 'descending'

        report_filter = self.get_filter()
        if report_filter is not None:
            report_rq['filter'] = report_filter

        report_rs = self._auth.execute_auth_command(report_rq)
        events: Optional[List[Dict[str, Any]]] = report_rs.get('audit_event_overview_report_rows')
        if isinstance(events, list):
            yield from events


class DimAuditReport(AuditReportCommon):
    def __init__(self, auth: keeper_auth.KeeperAuth):
        super().__init__()
        self._auth = auth

    def execute_dimension_report(self, dimension) -> List[dict]:
        dim_rq = {
            'command': 'get_audit_event_dimensions',
            'report_type': 'dim',
            'columns': [dimension],
            'limit': 2000,
            'scope': 'enterprise'
        }
        dim_rs = self._auth.execute_auth_command(dim_rq)

        dimensions = dim_rs['dimensions'][dimension]
        if dimension == 'ip_address':
            for row in dimensions:
                city = row.get('city', '')
                region = row.get('region', '')
                country = row.get('country_code', '')
                if city or region or country:
                    row['geo_location'] = ', '.join((city, region, country))

        return dimensions
