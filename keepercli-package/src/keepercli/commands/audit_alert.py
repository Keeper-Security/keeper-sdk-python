import argparse
import datetime
import os
import secrets
from typing import Optional, List, Tuple, Dict, Any, Union

from keepersdk.authentication import keeper_auth
from keepersdk.enterprise import audit_report
from keepersdk import utils
from . import base
from .. import api
from ..helpers import report_utils
from ..params import KeeperParams


class AuditAlerts(base.GroupCommand):
    def __init__(self):
        super(AuditAlerts, self).__init__('Display alert list')
        self.register_command(AuditAlertList(), 'list', 'l')
        self.register_command(AuditAlertView(), 'view', 'v')
        self.register_command(AuditAlertHistory(), 'history', 'h')
        self.register_command(AuditAlertDelete(), 'delete', 'd')
        self.register_command(AuditAlertAdd(), 'add', 'a')
        self.register_command(AuditAlertEdit(), 'edit', 'e')
        self.register_command(AuditAlertResetCount(), 'reset-counts')
        self.register_command(AuditAlertRecipients(), 'recipient', 'r')
        self.default_verb = 'list'


class AuditSettingMixin:
    LAST_USERNAME = ""
    LAST_ENTERPRISE_ID = 0
    SETTINGS = None  # type: Optional[dict]
    EVENT_TYPES = None  # type: Optional[List[Tuple[int, str]]]

    @staticmethod
    def load_settings(auth: keeper_auth.KeeperAuth, reload: bool=False) -> Optional[Dict[str, Any]]:
        if not auth.auth_context.enterprise_id:
            AuditSettingMixin.SETTINGS = None
            AuditSettingMixin.LAST_ENTERPRISE_ID = 0
            return None

        if AuditSettingMixin.EVENT_TYPES is None:
            dim_report = audit_report.DimAuditReport(auth)
            events = dim_report.execute_dimension_report('audit_event_type')
            AuditSettingMixin.EVENT_TYPES = []
            for et in events:
                event_id = et.get('id')
                event_name = et.get('name')
                if event_name and isinstance(event_id, int):
                    AuditSettingMixin.EVENT_TYPES.append((event_id, event_name))

        enterprise_id = auth.auth_context.enterprise_id
        username = auth.auth_context.username

        if AuditSettingMixin.SETTINGS is None:
            reload = True
        elif AuditSettingMixin.LAST_USERNAME != username:
            reload = True
        elif AuditSettingMixin.LAST_ENTERPRISE_ID != enterprise_id:
            reload = True

        if reload:
            rq = {
                'command': 'get_enterprise_setting',
                'include': ['AuditAlertContext', 'AuditAlertFilter', 'AuditReportFilter']
            }
            AuditSettingMixin.SETTINGS = auth.execute_auth_command(rq)
            AuditSettingMixin.LAST_USERNAME = username
            AuditSettingMixin.LAST_ENTERPRISE_ID = enterprise_id
        return AuditSettingMixin.SETTINGS

    @staticmethod
    def invalidate_alerts():
        AuditSettingMixin.SETTINGS = None

    @staticmethod
    def frequency_to_text(freq: Any) -> Optional[str]:
        if not isinstance(freq, dict):
            return None
        period = freq.get('period')
        count = freq.get('count')
        if period == 'event':
            if isinstance(count, int):
                return f'{count} of Occurrences Triggered'
            else:
                return 'Every Occurrence'
        elif period in ('day', 'hour', 'minutes') and isinstance(count, int):
            if period == 'minutes':
                period = 'minute'
            period = period.capitalize()
            return f'{count} {period}(s) from First Occurrence'
        else:
            return 'Not supported'

    @staticmethod
    def text_to_frequency(text: str) -> Dict[str, Any]:
        if not isinstance(text, str):
            return {'period': 'event'}
        num: int = 0
        s_num, sep, occ = text.partition(':')
        if sep:
            if isinstance(s_num, str) and s_num.isnumeric():
                num = int(s_num)
            occ = occ.lower()
        else:
            num = 0
            occ = text.lower()
        if occ in ('event', 'e'):
            occ = 'event'
        elif occ in ('minute', 'minutes', 'm'):
            occ = 'minutes'
        elif occ in ('hour', 'h'):
            occ = 'hour'
        elif occ in ('day', 'd'):
            occ = 'day'
        else:
            raise ValueError(f'Invalid alert frequency \"{occ}\". "event", "day", "hour", "minute"')
        if num <= 0:
            if occ == 'event':
                num = 0
            else:
                num = 1
        freq: Dict[str, Any] = {
            'period': occ
        }
        if num > 0:
            freq['count'] = num
        return freq

    @staticmethod
    def get_alert_context(alert_id: int) -> Optional[Dict[str, Any]]:
        settings = AuditSettingMixin.SETTINGS
        if not settings:
            return None
        alert_context = settings.get('AuditAlertContext')
        if not isinstance(alert_context, list):
            return None

        return next((x for x in alert_context if x.get('id') == alert_id), None)

    @staticmethod
    def get_alert_configuration(auth: keeper_auth.KeeperAuth, alert_name: Any) -> Dict[str, Any]:
        if not alert_name:
            raise Exception(f'Alert name cannot be empty')
        if not isinstance(alert_name, str):
            raise Exception(f'Alert name must be a text')

        settings = AuditSettingMixin.load_settings(auth)
        if not settings:
            raise ValueError(f'Alert with name \"{alert_name}\" not found')
        alert_filter = settings.get('AuditAlertFilter')
        if not isinstance(alert_filter, list):
            raise ValueError(f'Alert with name \"{alert_name}\" not found')

        a_number = int(alert_name) if alert_name.isnumeric() else 0
        if a_number > 0:
            for alert_filter in alert_filter:
                a_id = alert_filter.get('id')
                if isinstance(a_id, int):
                    if a_id == a_number:
                        return alert_filter

        alerts = []
        l_name = alert_name.casefold()
        for alert_filter in alert_filter:
            a_name = alert_filter.get('name') or ''
            if a_name.casefold() == l_name:
                alerts.append(alert_filter)

        if len(alerts) == 0:
            raise ValueError(f'Alert with name \"{alert_name}\" not found')
        if len(alerts) > 1:
            raise ValueError(f'There are {len(alerts)} alerts with name \"{alert_name})\". Use alert ID.')
        return alerts[0]

    @staticmethod
    def apply_alert_options(context: KeeperParams, alert: Dict[str, Any], **kwargs) -> None:
        assert context.enterprise_data
        assert context.vault

        alert_name = kwargs.get('name')
        if alert_name:
            alert['name'] = alert_name

        frequency = kwargs.get('frequency')
        if frequency:
            alert['frequency'] = AuditSettingMixin.text_to_frequency(frequency)

        alert_filter: Optional[Dict[str, Any]] = alert.get('filter')
        if not isinstance(alert_filter, dict):
            alert_filter = {}
            alert['filter'] = alert_filter

        events_option = kwargs.get('audit_event')
        if isinstance(events_option, list):
            event_ids = set()
            event_lookup = {n: i for i, n in AuditSettingMixin.EVENT_TYPES or []}
            for events in events_option:
                for event_name in (x.strip().lower() for x in events.split(',')):
                    if event_name in event_lookup:
                        event_ids.add(event_lookup[event_name])
                    else:
                        raise ValueError(f'Event name \"{event_name}\" is invalid')
            if len(event_ids) > 0:
                event_list = list(event_ids)
                event_list.sort()
                alert_filter['events'] = event_list
            else:
                if 'events' in alert_filter:
                    del alert_filter['event']

        users_option: Optional[List[str]] = kwargs.get('user')
        if isinstance(users_option, list):
            user_ids = set()
            user_lookup = {x.username: x for x in context.enterprise_data.users.get_all_entities()}
            # TODO aliases
            for users in users_option:
                for username in (x.strip().lower() for x in users.split(',')):
                    if username in user_lookup:
                        user_ids.add(user_lookup[username].enterprise_user_id)
                    else:
                        raise ValueError(f'Username \"{username}\" is unknown')
            if len(user_ids) > 0:
                alert_filter['userIds'] = list(user_ids)
            else:
                if 'userIds' in alert_filter:
                    del alert_filter['userIds']

        record_uid_option : Optional[List[str]]= kwargs.get('record_uid')
        if isinstance(record_uid_option, list):
            record_uids = set()
            for r_uids in record_uid_option:
                for record_uid in (x.strip() for x in r_uids.split(',')):
                    if not record_uid:
                        continue
                    record = context.vault.vault_data.get_record(record_uid)
                    if not record:
                        api.get_logger().info('Record UID \"%s\" cannot be verified as existing.', record_uid)
                    record_uids.add(record_uid)
            if len(record_uids) > 0:
                alert_filter['recordUids'] = [{'id': x, 'selected': True} for x in record_uids]
            else:
                if 'recordUids' in alert_filter:
                    del alert_filter['recordUids']

        shared_folder_uid_option: Optional[List[str]] = kwargs.get('shared_folder_uid')
        if isinstance(shared_folder_uid_option, list):
            shared_folder_uids = set()
            sf_uids: str
            for sf_uids in shared_folder_uid_option:
                for shared_folder_uid in (x.strip() for x in sf_uids.split(',')):
                    if not shared_folder_uid:
                        continue
                    shared_folder = context.vault.vault_data.get_shared_folder(shared_folder_uid)
                    if not shared_folder:
                        api.get_logger().info('Shared Folder UID \"%s\" cannot be verified as existing.', shared_folder_uid)
                    shared_folder_uids.add(shared_folder_uid)
            if len(shared_folder_uids) > 0:
                alert_filter['sharedFolderUids'] = [{'id': x, 'selected': True} for x in shared_folder_uids]
            else:
                if 'sharedFolderUids' in alert_filter:
                    del alert_filter['sharedFolderUids']


class AuditAlertList(base.ArgparseCommand, AuditSettingMixin):
    def __init__(self) -> None:
        parser = argparse.ArgumentParser(prog='audit-alert list', parents=[base.report_output_parser],
                                         description='Display alert list.')
        parser.add_argument('--reload', dest='reload', action='store_true', help='reload alert information')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        assert context.auth
        alerts = self.load_settings(context.auth, kwargs.get('reload') or False)
        if not isinstance(alerts, dict):
            raise base.CommandError('No alerts found')
        alert_filter = alerts.get('AuditAlertFilter')
        if not isinstance(alert_filter, list):
            raise base.CommandError('No alerts found')

        fmt = kwargs.get('format') or ''
        table = []
        headers = ['id', 'name', 'events', 'frequency', 'occurrences', 'alerts_sent', 'last_sent', 'active']
        event_lookup = {i: n for i, n in self.EVENT_TYPES or []}
        for alert in alert_filter:
            alert_id = alert.get('id')
            ctx = AuditSettingMixin.get_alert_context(alert_id) or alert
            alert_name = alert.get('name')
            events: Union[str, List[str]] = ''
            alert_filter = alert.get('filter')
            if isinstance(alert_filter, dict):
                es = list((event_lookup[x] for x in alert_filter.get('events') or [] if x in event_lookup))
                if len(es) == 1:
                    events = es[0]
                elif len(es) <= 5:
                    events = '\n'.join(es)
                elif len(es) > 5:
                    events = '\n'.join(es[:4]) + f'\n+{len(es) - 4} more'
            freq = self.frequency_to_text(alert.get('frequency'))
            occurrences = ctx.get('counter')
            alerts_sent = ctx.get('sentCounter')
            last_sent = ctx.get('lastSent')
            if last_sent:
                try:
                    last_sent = datetime.datetime.strptime(last_sent, '%Y-%m-%dT%H:%M:%S.%fZ')
                    last_sent = last_sent.replace(microsecond=0, tzinfo=datetime.timezone.utc).astimezone()
                except ValueError:
                    pass
            disabled = ctx.get('disabled') is True
            table.append([alert_id, alert_name, events, freq, occurrences, alerts_sent, last_sent, not disabled])

        if fmt != 'json':
            headers = [report_utils.field_to_title(x) for x in headers]
        return report_utils.dump_report_data(table, headers, fmt=fmt, filename=kwargs.get('output'), sort_by=0)


alert_target_parser = argparse.ArgumentParser(add_help=False)
alert_target_parser.add_argument('target', metavar='ALERT', help='Alert ID or Name.')

class AuditAlertView(base.ArgparseCommand, AuditSettingMixin):
    def __init__(self) -> None:
        parser = argparse.ArgumentParser(prog='audit-alert view', parents=[alert_target_parser],
                                         description='View alert configuration.')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        assert context.auth
        assert context.enterprise_data

        show_recipient = True
        show_filter = True
        show_stat = True
        if kwargs.get('recipient_only'):
            show_recipient = True
            show_filter = False
            show_stat = False

        alert = AuditSettingMixin.get_alert_configuration(context.auth, kwargs.get('target'))
        alert_id: int = alert.get('id') or 0
        ctx = AuditSettingMixin.get_alert_context(alert_id) or alert
        table = []
        header = ['name', 'value']
        table.append(['Alert ID', alert_id])
        table.append(['Alert name', alert.get('name')])
        table.append(['Status', 'Disabled' if ctx.get('disabled') is True else 'Enabled'])
        if show_stat:
            table.append(['Frequency', self.frequency_to_text(alert.get('frequency'))])
            table.append(['Occurrences', ctx.get('counter')])
            table.append(['Sent Counter', ctx.get('sentCounter')])
            last_sent = ctx.get('lastSent')
            if last_sent:
                try:
                    last_sent = datetime.datetime.strptime(last_sent, '%Y-%m-%dT%H:%M:%S.%fZ')
                    last_sent = last_sent.replace(microsecond=0, tzinfo=datetime.timezone.utc).astimezone()
                except ValueError:
                    pass
            table.append(['Last Sent', last_sent.isoformat() if last_sent else ''])

        if show_filter:
            alert_filter = alert.get('filter') or {}
            table.append(['', ''])
            table.append(['Alert Filter:', ''])
            if 'events' in alert_filter:
                event_lookup = {i: n for i, n in self.EVENT_TYPES or []}
                events = [event_lookup[x] for x in alert_filter.get('events') or [] if x in event_lookup]
                table.append(['Event Types', events])
            if 'userIds' in alert_filter:
                user_lookup = {x.enterprise_user_id: x.username for x in context.enterprise_data.users.get_all_entities()}
                users = [user_lookup[x] for x in alert_filter.get('userIds') or [] if x in user_lookup]
                table.append(['User', users])
            if 'sharedFolderUids' in alert_filter:
                table.append(['Shared Folder', [x['id'] for x in alert_filter['sharedFolderUids'] if x['selected']]])
            if 'recordUids' in alert_filter:
                table.append(['Record', [x['id'] for x in alert_filter['recordUids'] if x['selected']]])

        if show_recipient:
            recipients: List[List[Any]] = []
            for r in alert.get('recipients') or []:
                recipients.append(['', ''])
                recipients.append(['Recipient ID', r.get('id')])
                recipients.append(['Name', r.get('name')])
                recipients.append(['Status', 'Disabled' if r.get('disabled') is True else 'Enabled'])
                if 'webhook' in r:
                    wh = r['webhook']
                    recipients.append(['Webhook URL', wh.get('url')])
                    http_body = wh.get('template')
                    if http_body:
                        recipients.append(['HTTP Body', http_body])
                    recipients.append(['Webhook Token', wh.get('token')])
                    recipients.append(['Certificate Errors', 'Ignore' if wh.get('allowUnverifiedCertificate') else 'Enforce'])
                email = r.get('email')
                if email:
                    recipients.append(['Email To', email])
                phone = r.get('phone')
                if phone:
                    phone_country = r.get('phoneCountry')
                    if phone_country:
                        recipients.append(['Text To', f'(+{r.get("phoneCountry")}) {phone}'])
                    else:
                        recipients.append(['Text To', phone])
            table.append(['', ''])
            table.append(['Recipients:', ''])
            table.append(['Send To Originator (*)', alert.get('sendToOriginator') or False])
            table.extend(recipients)

        report_utils.dump_report_data(table, header, no_header=True, right_align=(0,))


class AuditAlertHistory(base.ArgparseCommand, AuditSettingMixin):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='audit-alert history', parents=[base.report_output_parser, alert_target_parser],
                                         description='View alert history.')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        assert context.auth

        alert = AuditSettingMixin.get_alert_configuration(context.auth, kwargs.get('target'))

        raw_report = audit_report.RawAuditReport(context.auth)
        report_filter = audit_report.AuditReportFilter()
        report_filter.parent_id = alert.get('alertUid')
        report_filter.event_type ='audit_alert_sent'
        raw_report.filter = report_filter
        raw_report.order = audit_report.ReportOrder.Desc
        raw_report.limit = 100

        events = raw_report.execute_audit_report()
        fmt = kwargs.get('format') or ''
        table: List[List[Any]] = []
        for event in events:
            if 'recipient' in event:
                recipient = event.get('recipient')
                if recipient == 'throttled':
                    if len(table) > 0:
                        table[-1][1] += 1
                else:
                    table.append([event.get('created'), 1])
        headers = ['alert_sent_at', 'occurrences']
        if fmt != 'json':
            headers = [report_utils.field_to_title(x) for x in headers]
        return report_utils.dump_report_data(table, headers, fmt=fmt, filename=kwargs.get('output'))


class AuditAlertDelete(base.ArgparseCommand, AuditSettingMixin):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='audit-alert remove', parents=[alert_target_parser],
                                         description='Delete audit alert.')
        super().__init__(parser)
    def execute(self, context: KeeperParams, **kwargs) -> Any:
        assert context.auth

        alert = AuditSettingMixin.get_alert_configuration(context.auth, kwargs.get('target'))

        rq = {
            'command': 'delete_enterprise_setting',
            'type': 'AuditAlertFilter',
            'id': alert['id'],
        }
        context.auth.execute_auth_command(rq)
        self.invalidate_alerts()
        command = AuditAlertList()
        command.execute(context, reload=True)


alert_edit_options = argparse.ArgumentParser(add_help=False)
alert_edit_options.add_argument('--name', action='store', metavar='NAME', help='Alert Name.')
alert_edit_options.add_argument('--frequency', dest='frequency', action='store', metavar='FREQUENCY',
                                help='Alert Frequency. "[N:]event|minute|hour|day"')
alert_edit_options.add_argument('--audit-event', dest='audit_event', action='append', metavar='EVENT',
                                help='Audit Event. Can be repeated.')
alert_edit_options.add_argument('--user', dest='user', action='append', metavar='USER',
                                help='Username. Can be repeated.')
alert_edit_options.add_argument('--record-uid', dest='record_uid', action='append', metavar='RECORD_UID',
                                help='Record UID. Can be repeated.')
alert_edit_options.add_argument('--shared-folder-uid', dest='shared_folder_uid', action='append',
                                metavar='SHARED_FOLDER_UID', help='Shared Folder UID. Can be repeated.')
alert_edit_options.add_argument('--active', dest='active', action='store', metavar='ACTIVE',
                                choices=['on', 'off'], help='Enable or disable alert')

class AuditAlertAdd(base.ArgparseCommand, AuditSettingMixin):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='audit-alert add', parents=[alert_edit_options],
                                         description='Add audit alert')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        assert context.auth
        name = kwargs.get('name')
        if not name:
            raise base.CommandError('Alert name is required parameter')

        last_id: int = 0
        settings = self.load_settings(context.auth)
        if isinstance(settings, dict):
            alert_filter: Optional[List[Dict[str, Any]]] = settings.get('AuditAlertFilter')
            if isinstance(alert_filter, list):
                exists = next((True for x in alert_filter if x['name'].lower() == name.lower()), False)
                if exists:
                    raise base.CommandError(f'Alert name \"{name}\" is not unique')
                last_id = max((x['id'] for x in alert_filter), default=0)

        alert_id = last_id + 1
        alert = {
            'id': alert_id,
            'alertUid': secrets.randbelow(2**31),
            'name': name,
            'frequency': {
                'period': 'event'
            },
            'filter': {}
        }
        self.apply_alert_options(context, alert, **kwargs)

        rq = {
            'command': 'put_enterprise_setting',
            'type': 'AuditAlertFilter',
            'settings': alert,
        }
        context.auth.execute_auth_command(rq)

        active = kwargs.get('active')
        if isinstance(active, str):
            if active == 'off':
                rq = {
                    'command': 'put_enterprise_setting',
                    'type': 'AuditAlertContext',
                    'settings': {
                        'id': alert_id,
                        'disabled': True
                    }
                }
                context.auth.execute_auth_command(rq)

        self.invalidate_alerts()
        command = AuditAlertView()
        command.execute(context, target=str(alert_id))


class AuditAlertEdit(base.ArgparseCommand, AuditSettingMixin):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='audit-alert edit', parents=[alert_target_parser, alert_edit_options],
                                         description='Edit audit alert')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        assert context.auth

        alert = AuditSettingMixin.get_alert_configuration(context.auth, kwargs.get('target'))
        self.apply_alert_options(context, alert, **kwargs)

        rq = {
            'command': 'put_enterprise_setting',
            'type': 'AuditAlertFilter',
            'settings': alert,
        }
        context.auth.execute_auth_command(rq)

        active = kwargs.get('active')
        if isinstance(active, str):
            alert_id = alert.get('id')
            assert isinstance(alert_id, int)
            ctx = AuditSettingMixin.get_alert_context(alert_id) or {'id': alert_id}
            current_active = 'off' if ctx.get('disabled') is True else 'on'
            if active != current_active:
                rq = {
                    'command': 'put_enterprise_setting',
                    'type': 'AuditAlertContext',
                    'settings': {
                        'id': alert_id,
                        'disabled': active == 'off'
                    }
                }
                context.auth.execute_auth_command(rq)

        self.invalidate_alerts()
        command = AuditAlertView()
        command.execute(context, target=kwargs.get('target'))


class AuditAlertResetCount(base.ArgparseCommand, AuditSettingMixin):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='audit-alert reset-counts', parents=[alert_target_parser],
                                         description='Reset alert counts')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        assert context.auth
        alert = AuditSettingMixin.get_alert_configuration(context.auth, kwargs.get('target'))
        rq = {
            'command': 'put_enterprise_setting',
            'type': 'AuditAlertContext',
            'settings': {
                'id': alert.get('id'),
                'counter': 0,
                'sentCounter': 0,
                'lastReset': utils.current_milli_time()
            }
        }
        context.auth.execute_auth_command(rq)
        AuditSettingMixin.invalidate_alerts()
        api.get_logger().info('Alert counts reset to zero')


class AuditAlertRecipients(base.ArgparseCommand, AuditSettingMixin):
    def __init__(self):
        edit_options = argparse.ArgumentParser(add_help=False)
        edit_options.add_argument('--name', dest='name', metavar='NAME', action='store',
                                  help='recipient name')
        edit_options.add_argument('--email', dest='email', metavar='EMAIL', action='store',
                                  help='email address')
        edit_options.add_argument('--phone', dest='phone', metavar='PHONE', action='store',
                                  help='phone number. +1 (555) 555-1234')
        edit_options.add_argument('--webhook', dest='webhook', metavar='URL', action='store',
                                  help='Webhook URL. See https://docs.keeper.io/enterprise-guide/webhooks')
        edit_options.add_argument('--http-body', dest='http_body', metavar='HTTP_BODY', action='store',
                                  help='Webhook HTTP Body')
        edit_options.add_argument('--cert-errors', dest='cert_errors', action='store', choices=['ignore', 'enforce'],
                                  help='Webhook SSL Certificate errors')
        edit_options.add_argument('--generate-token', dest='generate_token', action='store_true',
                                  help='Generate new access token')

        parser = argparse.ArgumentParser(prog='audit-alert recipient', parents=[alert_target_parser],
                                         description='Modify alert recipients')
        subparsers = parser.add_subparsers(title='recipient actions', dest='action')
        enable_parser = subparsers.add_parser('enable', help='enables recipient')
        enable_parser.add_argument('recipient', metavar='RECIPIENT',
                                   help='Recipient ID or Name. Use "*" for "User who generated event"')

        disable_parser = subparsers.add_parser('disable', help='disables recipient')
        disable_parser.add_argument('recipient', metavar='RECIPIENT',
                                    help='Recipient ID or Name. Use "*" for "User who generated event"')

        delete_parser = subparsers.add_parser('delete', help='deletes recipient')
        delete_parser.add_argument('recipient', metavar='RECIPIENT', help='Recipient ID or Name.')

        add_parser = subparsers.add_parser('add', help='adds recipient', parents=[edit_options])

        edit_parser = subparsers.add_parser('edit', help='edit recipient', parents=[edit_options])
        edit_parser.add_argument('recipient', metavar='RECIPIENT', help='Recipient ID or Name.')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        assert context.auth
        alert = AuditSettingMixin.get_alert_configuration(context.auth, kwargs.get('target'))
        action = kwargs.get('action')
        skip_update = False
        if action in ('enable', 'disable'):
            name = kwargs.get('recipient')
            if name == '*':
                alert['sendToOriginator'] = action == 'enable'
            elif isinstance(name, str):
                r = self.find_recipient(alert, name)
                r['disabled'] = action == 'disable'
        elif action == 'delete':
            name = kwargs.get('recipient')
            if isinstance(name, str):
                r = self.find_recipient(alert, name)
                alert['recipients'].remove(r)
        elif action == 'edit':
            name = kwargs.get('recipient')
            if isinstance(name, str):
                r = self.find_recipient(alert, name)
                self.apply_recipient(r, **kwargs)
        elif action == 'add':
            if 'recipients' not in alert:
                alert['recipients'] = []
            ids = {x['id'] for x in alert['recipients'] if 'id' in x}
            r = {}
            for i in range(1000):
                if i+1 not in ids:
                    r['id'] = i + 1
                    break
            alert['recipients'].append(r)
            self.apply_recipient(r, **kwargs)
        else:
            skip_update = True

        if not skip_update:
            rq = {
                'command': 'put_enterprise_setting',
                'type': 'AuditAlertFilter',
                'settings': alert,
            }
            context.auth.execute_auth_command(rq)
            self.invalidate_alerts()
        command = AuditAlertView()
        command.execute(context, target=kwargs.get('target'), recipient_only=True)

    @staticmethod
    def apply_recipient(recipient: Dict[str, Any], **kwargs) -> None:
        name = kwargs.get('name')
        if name:
            recipient['name'] = name
        email = kwargs.get('email')
        if email is not None:
            recipient['email'] = email
        phone = kwargs.get('phone')
        if phone is not None:
            if phone:
                if phone.startswith('+'):
                    pc = ''
                    phone = phone[1:].strip()
                    while len(phone) > 0:
                        if phone[0:1].isnumeric():
                            pc += phone[0:1]
                            phone = phone[1:]
                        else:
                            break
                    phone_country = int(pc) if pc else 1
                    phone = phone.strip()
                else:
                    phone_country = 1
                recipient['phoneCountry'] = phone_country
                recipient['phone'] = phone
            else:
                recipient['phone'] = ''
                if 'phoneCountry' in recipient:
                    del recipient['phoneCountry']
        webhook = kwargs.get('webhook')
        if webhook is not None:
            if webhook == '':
                if 'webhook' in recipient:
                    del recipient['webhook']
            else:
                if 'webhook' not in recipient:
                    recipient['webhook'] = {
                        'url': webhook,
                        'allowUnverifiedCertificate': False,
                        'token': utils.generate_uid()
                    }
                else:
                    recipient['webhook']['url'] = webhook
        http_body = kwargs.get('http_body')
        if http_body is not None:
            if 'webhook' in recipient:
                webhook = recipient['webhook']
                if http_body:
                    if http_body[0] == '@':
                        file_name = http_body[1:]
                        file_name = os.path.expanduser(file_name)
                        if os.path.isfile(file_name):
                            with open(file_name, 'rt') as tf:
                                webhook_body = tf.read()
                        else:
                            raise base.CommandError(f'File \"{file_name}\" not found')
                    webhook['template'] = webhook_body
                elif 'template' in webhook:
                    webhook['template'] = None

        cert_errors = kwargs.get('cert_errors')
        if cert_errors is not None:
            if 'webhook' in recipient:
                recipient['webhook']['allowUnverifiedCertificate'] = cert_errors == 'ignore'
        if kwargs.get('generate_token') is True:
            recipient['webhook']['token'] = utils.generate_uid()

    @staticmethod
    def find_recipient(alert: Dict[str, Any], name: str) -> Dict[str, Any]:
        recs = []
        if isinstance(alert, dict):
            recipients = alert.get('recipients')
            if isinstance(recipients, list):
                r_id = int(name) if name.isnumeric() else -1
                if r_id > 0:
                    for r in recipients:
                        if r.get('id') == r_id:
                            return r
                l_name = name.lower()
                for r in recipients:
                    if (r.get('name') or '').lower() == l_name:
                        recs.append(r)
        if len(recs) == 0:
            raise ValueError(f'Recipient \"{name}\" not found')
        if len(recs) > 1:
            raise ValueError(f'There are {len(recs)} recipients with name \"{name}\". User recipient ID.')
        return recs[0]
