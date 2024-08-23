import argparse
import copy
import datetime
import re
from typing import Any, Union, Optional, Set, Dict, List

from keepersdk.authentication import keeper_auth
from keepersdk.enterprise import audit_report
from . import base
from .. import prompt_utils
from ..helpers import report_utils
from ..params import KeeperParams


syslog_templates: Optional[Dict[str, str]] = None

def load_syslog_templates(auth: keeper_auth.KeeperAuth) -> None:
    global syslog_templates
    if syslog_templates is None:
        syslog_templates = {}
        dim_report = audit_report.DimAuditReport(auth)
        event_types = dim_report.execute_dimension_report('audit_event_type')
        for et in event_types:
            name = et.get('name')
            syslog = et.get('syslog')
            if name and syslog:
                syslog_templates[name] = syslog

def get_event_message(event: Dict[str, Any]) -> str:
    global syslog_templates
    if not syslog_templates:
        return ''

    message = ''
    audit_event_type: str = event.get('audit_event_type') or ''
    if audit_event_type in syslog_templates:
        info = syslog_templates[audit_event_type]
        while True:
            pattern = re.search(r'\${(\w+)}', info)
            if pattern is not None:
                field = pattern[1]
                val = event.get(field)
                if val is None:
                    val = '<missing>'

                sp = pattern.span()
                info = info[:sp[0]] + str(val) + info[sp[1]:]
            else:
                break
        message = info
    return message

class EnterpriseAuditReport(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='audit-report', parents=[base.report_output_parser], description='Run an audit trail report.')
        parser.add_argument('--syntax-help', dest='syntax_help', action='store_true', help='display help')
        parser.add_argument('--report-type', dest='report_type', action='store',
                            choices=['raw', 'dim', 'hour', 'day', 'week', 'month', 'span'],
                            help='report type')
        parser.add_argument('--report-format', dest='report_format', action='store', default='message',
                            choices=['message', 'fields'], help='output format (raw reports only)')
        parser.add_argument('--column', dest='columns', action='append',
                            help='Can be repeated. (ignored for raw reports)')
        parser.add_argument('--aggregate', dest='aggregates', action='append',
                            choices=['occurrences', 'first_created', 'last_created'],
                            help='aggregated value. Can be repeated. (ignored for raw reports)')
        parser.add_argument('--timezone', dest='timezone', action='store',
                            help='return results for specific timezone')
        parser.add_argument('--limit', dest='limit', type=int, action='store',
                            help='maximum number of returned rows (set to -1 to get all rows for raw report-type)')
        parser.add_argument('--order', dest='order', action='store', choices=['desc', 'asc'],
                            help='sort order')
        parser.add_argument('--created', dest='created', action='store',
                            help='Filter: Created date. Predefined filters: '
                                 'today, yesterday, last_7_days, last_30_days, month_to_date, last_month, year_to_date, last_year')
        parser.add_argument('--event-type', dest='event_type', action='append',
                            help='Filter: Audit Event Type')
        parser.add_argument('--username', dest='username', action='append',
                            help='Filter: Username of event originator')
        parser.add_argument('--to-username', dest='to_username', action='append',
                            help='Filter: Username of event target')
        parser.add_argument('--ip-address', dest='ip_address', action='append',
                            help='Filter: IP Address(es)')
        parser.add_argument('--record-uid', dest='record_uid', action='append',
                            help='Filter: Record UID')
        parser.add_argument('--shared-folder-uid', dest='shared_folder_uid', action='append',
                            help='Filter: Shared Folder UID')
        parser.add_argument('--geo-location', dest='geo_location', action='store',
                            help='Filter: Geo location')
        parser.add_argument('--device-type', dest='device_type', action='store',
                            help='Filter: Device type')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        assert context.auth
        assert context.enterprise_data

        report_type = kwargs.get('report_type')
        if kwargs.get('syntax_help') is True or not report_type:
            prompt_utils.output_text(audit_report_description)
            if not report_type:
                dim_report = audit_report.DimAuditReport(context.auth)
                events = dim_report.execute_dimension_report('audit_event_type')
                table = []
                for event in events:
                    table.append([event['id'], event['name']])
                table.sort(key=lambda x: x[0])
                prompt_utils.output_text('\nThe following are possible event type id and event type name values\n')
                report_utils.dump_report_data(table, headers=['Event ID', 'Event Name'])
            return

        has_aram = False
        keeper_license = next(iter(context.enterprise_data.licenses.get_all_entities()), None)
        if keeper_license and keeper_license.add_ons:
            has_aram = any((True for x in keeper_license.add_ons if x.name.lower() == 'enterprise_audit_and_reporting'))

        fmt = kwargs.get('format')

        report_type = kwargs.get('report_type')
        if report_type == 'dim':
            columns = kwargs['columns']
            if not isinstance(columns, list):
                raise base.CommandError("'columns' parameter is missing")
            if len(columns) != 1:
                raise base.CommandError('"dim" reports expect one "columns" parameter')

            column = columns[0]
            dimension = EnterpriseAuditReport.load_audit_dimension(context.auth, column)
            if dimension:
                table = []
                if column == 'audit_event_type':
                    fields = ['id', 'name', 'category', 'syslog']
                elif column == 'keeper_version':
                    fields = ['version_id', 'type_name', 'version', 'type_category']
                elif column == 'ip_address':
                    fields = ['ip_address', 'city', 'region', 'country_code']
                elif column == 'geo_location':
                    fields = ['geo_location', 'city', 'region', 'country_code', 'ip_count']
                elif column == 'device_type':
                    fields = ['type_name', 'type_category']
                else:
                    fields = [column]
                for dim in dimension:
                    if isinstance(dim, dict):
                        table.append([dim.get(x) for x in fields])
                    else:
                        table.append([dim])
                if fmt != 'json':
                    fields = [report_utils.field_to_title(x) for x in fields]
                return report_utils.dump_report_data(table, fields, fmt=fmt, filename=kwargs.get('output'))

        elif report_type == 'raw':
            raw_report = audit_report.RawAuditReport(context.auth)
            if has_aram:
                raw_report.filter = self.get_report_filter(context.auth, **kwargs)
                limit = kwargs.get('limit')
                if isinstance(limit, int):
                    raw_report.limit = limit
                order = kwargs.get('order')
                if isinstance(order, str):
                    if order == 'asc':
                        raw_report.order = audit_report.ReportOrder.Asc
                    elif order == 'desc':
                        raw_report.order = audit_report.ReportOrder.Desc
            else:
                raw_report.limit = 1000
                raw_report.filter = audit_report.AuditReportFilter(created='last_30_days')
            raw_report.timezone = kwargs.get('timezone')

            report_format = kwargs.get('report_format')
            fields = []
            table = []
            fields.extend(RAW_FIELDS)
            misc_fields: Set[str] = set()
            if report_format == 'message':
                fields.append('message')
                load_syslog_templates(context.auth)
            else:
                misc_fields.update(MISC_FIELDS)

            for event in raw_report.execute_audit_report():
                if len(misc_fields) > 0:
                    new_fields = misc_fields.intersection(event.keys())
                    if len(new_fields) > 0:
                        fields.extend(new_fields)
                        misc_fields.difference_update(new_fields)
                row = []
                for field in fields:
                    if field == 'message':
                        row.append(get_event_message(event))
                    else:
                        row.append(EnterpriseAuditReport.get_field_value(field, event.get(field), report_type='raw'))
                table.append(row)

            if fmt != 'json':
                fields = [report_utils.field_to_title(x) for x in fields]
            return report_utils.dump_report_data(table, fields, fmt=fmt, filename=kwargs.get('output'))
        else:
            if not has_aram:
                raise base.CommandError('Audit Reporting addon is not enabled')
            summary_report = audit_report.SummaryAuditReport(context.auth)
            summary_report.summary_type = report_type
            summary_report.filter = self.get_report_filter(context.auth, **kwargs)
            limit = kwargs.get('limit')
            if isinstance(limit, int):
                if not (0 <= limit <= 2000):
                    raise base.CommandError(f'Invalid "limit" value: {limit}')
                summary_report.limit = limit
            order = kwargs.get('order')
            if isinstance(order, str):
                if order == 'asc':
                    summary_report.order = audit_report.ReportOrder.Asc
                elif order == 'desc':
                    summary_report.order = audit_report.ReportOrder.Desc
            summary_report.timezone = kwargs.get('timezone')
            columns = kwargs.get('columns')
            if not columns:
                raise base.CommandError(f'"columns" parameter cannot be empty')
            if isinstance(columns, str):
                columns = [columns]
            elif not isinstance(columns, list):
                raise base.CommandError(f'Invalid "columns" value: {columns}')
            summary_report.columns = columns

            aggregates = kwargs.get('aggregates')
            if not aggregates:
                aggregates = ['occurrences']
            else:
                if isinstance(aggregates, str):
                    aggregates = [aggregates]
                elif not isinstance(aggregates, list):
                    raise base.CommandError(f'Invalid "aggregates" value: {aggregates}')
            summary_report.aggregates = aggregates
            fields = aggregates
            if report_type != 'span':
                fields.append('created')
            fields.extend(columns)

            table = []
            for event in summary_report.execute_summary_report():
                row = []
                for field in fields:
                    row.append(EnterpriseAuditReport.get_field_value(field, event.get(field), report_type=report_type))
                table.append(row)

            if fmt != 'json':
                fields = [report_utils.field_to_title(x) for x in fields]
            return report_utils.dump_report_data(table, fields, fmt=fmt, filename=kwargs.get('output'))

    @staticmethod
    def get_field_value(field: str, value: Any, *, report_type: str = 'raw') -> Any:
        if field in ('created', 'first_created', 'last_created'):
            if isinstance(value, str):
                return value
            if isinstance(value, (int, float)):
                value = int(value)
                dt = datetime.datetime.fromtimestamp(value, tz=datetime.timezone.utc)
                dt = dt.replace(tzinfo=datetime.timezone.utc).astimezone(tz=None)
                if report_type in ('day', 'week'):
                    return dt.date()
                if report_type == 'month':
                    return dt.strftime('%B, %Y')
                if report_type == 'hour':
                    return dt.strftime('%Y-%m-%d @%H:00')
                return dt
        return value


    @staticmethod
    def convert_date_filter(value):
        if isinstance(value, datetime.datetime):
            value = value.timestamp()
        elif isinstance(value, datetime.date):
            dt = datetime.datetime.combine(value, datetime.datetime.min.time())
            value = dt.timestamp()
        elif isinstance(value, (int, float)):
            value = float(value)
        elif isinstance(value, str):
            if len(value) <= 10:
                value = datetime.datetime.strptime(value, '%Y-%m-%d')
            else:
                value = datetime.datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ')
            value = value.timestamp()
        return int(value)

    @staticmethod
    def convert_str_or_int(property_name, value: Any) -> Optional[Union[str, int]]:
        if isinstance(value, str):
            if value.isdigit():
                return int(value)
            else:
                return value
        elif isinstance(value, int):
            return value
        raise ValueError(f'Invalid "{property_name}" filter value: {value}')

    @staticmethod
    def get_created_filter_criteria(filter_value: str) -> audit_report.CreatedFilterCriteria:
        filter_value = filter_value.strip()
        bet = between_pattern.match(filter_value)
        if bet is not None:
            dt1, dt2, *_ = bet.groups()
            dt1 = EnterpriseAuditReport.convert_date_filter(dt1)
            dt2 = EnterpriseAuditReport.convert_date_filter(dt2)
            return audit_report.CreatedFilterCriteria(from_date=dt1, to_date=dt2)

        for prefix in ('>=', '<=', '>', '<', '='):
            if filter_value.startswith(prefix):
                value = EnterpriseAuditReport.convert_date_filter(filter_value[len(prefix):].strip())
                if prefix == '>=':
                    return audit_report.CreatedFilterCriteria(from_date=value)
                if prefix == '<=':
                    return audit_report.CreatedFilterCriteria(to_date=value)
                if prefix == '>':
                    return audit_report.CreatedFilterCriteria(from_date=value, exclude_from=True)
                if prefix == '<':
                    return audit_report.CreatedFilterCriteria(to_date=value, exclude_to=True)

        raise ValueError(f'Invalid created filter value "{filter_value}"')

    @staticmethod
    def get_report_filter(auth: keeper_auth.KeeperAuth, **kwargs) -> audit_report.AuditReportFilter:
        report_filter = audit_report.AuditReportFilter()
        created = kwargs.get('created')
        if isinstance(created, str):
            if created in ['today', 'yesterday', 'last_7_days', 'last_30_days', 'month_to_date', 'last_month', 'year_to_date', 'last_year']:
                report_filter.created = created
            else:
                report_filter.created = EnterpriseAuditReport.get_created_filter_criteria(created)

        event_type = kwargs.get('event_type')
        if event_type is not None:
            if isinstance(event_type, int):
                report_filter.event_type = event_type
            elif isinstance(event_type, str):
                report_filter.event_type = EnterpriseAuditReport.convert_str_or_int('--event-type', event_type)
            elif isinstance(event_type, (list, set, tuple)):
                report_filter.event_type = [y for y in (EnterpriseAuditReport.convert_str_or_int('--event-type', x) for x in event_type) if y]
            else:
                raise ValueError(f'Invalid "--event-type" filter value: {event_type}')

        for filter_property in ('username', 'to_username', 'record_uid', 'shared_folder_uid'):
            property_value = kwargs.get(filter_property)
            if property_value is not None:
                if isinstance(property_value, str):
                    setattr(report_filter, filter_property, property_value)
                elif isinstance(property_value, (list, set, tuple)):
                    setattr(report_filter, filter_property, [str(x) for x in property_value])
                else:
                    raise ValueError(f'Invalid "--{filter_property.replace("_", "-")}" filter value: {property_value}')

        geo_location = kwargs.get('geo_location')
        ip_addresses = kwargs.get('ip_address')
        if geo_location or ip_addresses:
            ip_filter: Set[str] = set()
            if isinstance(geo_location, str):
                geo_location_comps = geo_location.split(',')
                country = (geo_location_comps.pop() if geo_location_comps else '').strip().lower()
                if not country:
                    raise ValueError('"--geo-location" filter misses country')
                region = (geo_location_comps.pop() if geo_location_comps else '').strip().lower()
                city = (geo_location_comps.pop() if geo_location_comps else '').strip().lower()
                geo_dimension = EnterpriseAuditReport.load_audit_dimension(auth, 'geo_location')
                if geo_dimension:
                    for geo in geo_dimension:
                        if geo.get('country_code', '').lower() != country:
                            continue
                        if region:
                            if geo.get('region', '').lower() != region:
                                continue
                        if city:
                            if geo.get('city', '').lower() != city:
                                continue
                        geo_ips = geo.get('ip_addresses')
                        if isinstance(geo_ips, list):
                            ip_filter.update(geo_ips)
                if len(ip_filter) == 0:
                    raise ValueError(f'"geo_location" filter: invalid GEO location {geo_location}')

            if ip_addresses:
                if isinstance(ip_addresses, str):
                    ip_filter.add(ip_addresses)
                elif isinstance(ip_addresses, list):
                    ip_filter.update(ip_addresses)
                else:
                    raise ValueError(f'"ip_address" filter: invalid value {ip_addresses}')
            if len(ip_filter) > 0:
                report_filter.ip_address = list(ip_filter)

        device_type_filter = kwargs.get('device_type')
        if isinstance(device_type_filter, str):
            version_filter: Set[int] = set()
            device_comps = device_type_filter.split(',')
            device_type = (device_comps[0] if len(device_comps) > 0 else '').strip().lower()
            version = (device_comps[1] if len(device_comps) > 1 else '').strip().lower()
            if version and version.find('.') == -1:
                version += '.'
            if not device_type and not version:
                raise ValueError("'device_type' filter: empty")

            device_types = EnterpriseAuditReport.load_audit_dimension(auth, 'device_type')
            if device_types:
                for ver in device_types:
                    if device_type:
                        type_name = ver.get('type_name', '').lower()
                        type_category = ver.get('type_category', '').lower()
                        if not (device_type == type_name or device_type == type_category):
                            continue
                    if version:
                        if not ver.get('version', '').startswith(version):
                            continue
                    version_ids = ver.get('version_ids')
                    if isinstance(version_ids, list):
                        version_filter.update((x for x in version_ids if isinstance(x, int)))
            if len(version_filter) == 0:
                raise ValueError(f'"device_type" filter: no events')
            report_filter.keeper_version = list(version_filter)

        alert_uid = kwargs.get('alert_uid')
        if alert_uid:
            parent_id: Optional[Union[int, List[int]]] = None
            if isinstance(alert_uid, int):
                parent_id = alert_uid
            elif isinstance(alert_uid, str):
                if alert_uid.isnumeric():
                    parent_id = int(alert_uid)
                else:
                    raise ValueError(f'"alert_uid" filter invalid value: {alert_uid}')
            elif isinstance(alert_uid, list):
                parent_id = []
                for a in alert_uid:
                    if isinstance(a, int):
                        parent_id.append(a)
                    elif isinstance(a, str) and a.isnumeric():
                        parent_id.append(int(a))
                    else:
                        raise ValueError(f'"alert_uid" filter invalid value: {a}')
            if parent_id:
                report_filter.parent_id = parent_id

        return report_filter

    DimensionCache: Dict[str, List[Dict[str, Any]]] = {}
    CachedUsername = ''
    VirtualDimensions = {
        'geo_location': 'ip_address',
        'device_type': 'keeper_version',
    }

    @staticmethod
    def ensure_same_user(username: str) -> None:
        if username != EnterpriseAuditReport.CachedUsername:
            EnterpriseAuditReport.DimensionCache.clear()
            EnterpriseAuditReport.CachedUsername = username

    @staticmethod
    def load_audit_dimension(auth: keeper_auth.KeeperAuth, dimension) -> Optional[List[Dict[str, Any]]]:
        EnterpriseAuditReport.ensure_same_user(auth.auth_context.username)
        if dimension in EnterpriseAuditReport.DimensionCache:
            return EnterpriseAuditReport.DimensionCache[dimension]

        dimensions: Optional[List[Dict[str, Any]]] = None
        if dimension in EnterpriseAuditReport.VirtualDimensions:
            report_dimension = EnterpriseAuditReport.VirtualDimensions[dimension]
            report_dimensions = EnterpriseAuditReport.load_audit_dimension(auth, report_dimension)
            if report_dimensions:
                if dimension == 'geo_location':
                    geo_dim: Dict[str, Any] = {}
                    for geo in report_dimensions:
                        location = geo.get('geo_location')
                        ip = geo.get('ip_address')
                        if location and ip:
                            if location in geo_dim:
                                geo_dim[location]['ip_addresses'].append(ip)
                            else:
                                location_entry = copy.copy(geo)
                                del location_entry['ip_address']
                                location_entry['ip_addresses'] = [ip]
                                geo_dim[location] = location_entry
                    dimensions = list(geo_dim.values())
                    for geo in dimensions:
                        geo['ip_count'] = len(geo.get('ip_addresses', []))

                elif dimension == 'device_type':
                    device_dim: Dict[str, Any] = {}
                    for version in report_dimensions:
                        type_id = version.get('type_id')
                        version_id = version.get('version_id')
                        if type_id and version_id:
                            if type_id in device_dim:
                                device_dim[type_id]['version_ids'].append(version_id)
                            else:
                                type_entry = copy.copy(version)
                                del type_entry['version_id']
                                type_entry['version_ids'] = [version_id]
                                device_dim[type_id] = type_entry
                    dimensions = list(device_dim.values())
        else:
            dim_report = audit_report.DimAuditReport(auth)
            dimensions = list(dim_report.execute_dimension_report(dimension))

        if dimensions:
            EnterpriseAuditReport.DimensionCache[dimension] = dimensions
        return dimensions


audit_report_description = '''
Audit Report Command Syntax Description:

Event properties
  id                    event ID
  created               event time
  username              user that created audit event
  to_username           user that is audit event target
  from_username         user that is audit event source
  ip_address            IP address
  audit_event_type      Audit event type
  keeper_version        Keeper application version
  channel               2FA channel
  status                Keeper API result_code
  record_uid            Record UID
  record_title          Record title
  record_url            Record URL
  shared_folder_uid     Shared Folder UID
  shared_folder_title   Shared Folder title
  node                  Node ID (enterprise events only)
  node_title            Node title (enterprise events only)
  team_uid              Team UID (enterprise events only)
  team_title            Team title (enterprise events only)
  role_id               Role ID (enterprise events only)
  role_title            Role title (enterprise events only)

--report-type:
            raw         Returns individual events. All event properties are returned.
                        Valid parameters: filters. Ignored parameters: columns, aggregates

  span hour day	        Aggregates audit event by created date. Span drops date aggregation
     week month         Valid parameters: filters, columns, aggregates

            dim         Returns event property description or distinct values.
                        Valid columns: 
                        audit_event_type, keeper_version, device_type, ip_address, geo_location, 
                        username
                        Ignored parameters: filters, aggregates

--columns:              Defines break down report properties.
                        can be any event property except: id, created

--aggregate:            Defines the aggregate value:
     occurrences        number of events. COUNT(*)
   first_created        starting date. MIN(created)
    last_created        ending date. MAX(created)

--limit:                Limits the number of returned records

--order:                "desc" or "asc"
                        raw report type: created
                        aggregate reports: first aggregate

Filters                 Supported: '=', '>', '<', '>=', '<=', 'IN(<>,<>,<>)'. Default '='
--created               Predefined ranges: today, yesterday, last_7_days, last_30_days, month_to_date, last_month, year_to_date, last_year
                        Range 'BETWEEN <> AND <>'
                        where value is UTC date or epoch time in seconds
--username              User email
--to-username           Target user email
--record-uid            Record UID
--shared-folder-uid     Shared Folder UID
--event-type            Audit Event Type.  Value is event type id or event type name
                        audit-report --report-type=dim --columns=audit_event_type
--geo-location          Geo location 
                        Example: "El Dorado Hills, California, US", "CH", "Munich,Bayern,DE"
                        audit-report --report-type=dim --columns=geo_location
--ip-address            IP Address
--device-type           Keeper device/application and optional version
                        Example: "Commander", "Web App, 16.3.4"    
                        audit-report --report-type=dim --columns=device_type                     
'''
in_pattern = re.compile(r"\s*in\s*\(\s*(.*)\s*\)", re.IGNORECASE)
between_pattern = re.compile(r"\s*between\s+(\S*)\s+and\s+(.*)", re.IGNORECASE)

RAW_FIELDS = ('created', 'audit_event_type', 'username', 'ip_address', 'keeper_version', 'geo_location')
MISC_FIELDS = (
    'to_username', 'from_username', 'record_uid', 'shared_folder_uid',
    'node', 'role_id', 'team_uid', 'channel', 'status', 'recipient', 'value'
)
