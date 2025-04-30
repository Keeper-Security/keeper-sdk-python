import argparse
import datetime
import json
from typing import Dict, Any

from keepersdk.proto import NotificationCenter_pb2
from keepersdk import crypto

from . import base
from ..params import KeeperParams
from ..helpers import report_utils

class NotificationCommand(base.GroupCommand):
    def __init__(self):
        super().__init__('Notification Center')
        self.register_command(NotificationListCommand(), 'list', 'l')
        self.register_command(NotificationMarkReadCommand(), 'mark-read')

    @staticmethod
    def to_read_status_text(status: NotificationCenter_pb2.NotificationReadStatus) -> str:
        if status == NotificationCenter_pb2.NotificationReadStatus.NRS_READ:
            return 'Read'
        if status == NotificationCenter_pb2.NotificationReadStatus.NRS_UNREAD:
            return 'Unread'
        if status == NotificationCenter_pb2.NotificationReadStatus.NRS_LAST:
            return 'Last'
        return ''

    @staticmethod
    def to_approval_status_text(status: NotificationCenter_pb2.NotificationApprovalStatus) -> str:
        if status == NotificationCenter_pb2.NotificationApprovalStatus.NAS_APPROVED:
            return 'Approved'
        if status == NotificationCenter_pb2.NotificationApprovalStatus.NAS_DENIED:
            return 'Denied'
        if status == NotificationCenter_pb2.NotificationApprovalStatus.NAS_LOST_APPROVAL_RIGHTS:
            return 'Lost Approval Rights'
        if status == NotificationCenter_pb2.NotificationApprovalStatus.NAS_LOST_ACCESS:
            return 'Lost Access'
        return ''


class NotificationListCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='list', description='List notifications', parents=[base.report_output_parser])
        parser.add_argument('--unread-only', dest='unread_only', action='store_true',
                            help='Show unread notifications only')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs):
        assert context.auth is not None
        assert context.vault is not None
        assert context.auth.auth_context.ec_private_key is not None

        is_read_only = kwargs.get('unread_only') is True
        storage = context.vault.vault_data.storage
        table = []
        headers = ['notification_uid', 'sender', 'justification', 'read_status', 'approval_status', 'created']
        notifications = list(storage.notifications.get_all_entities())
        notifications.sort(key=lambda n: n.created, reverse=True)
        for notification in notifications:
            if is_read_only and not notification.read_status != NotificationCenter_pb2.NotificationReadStatus.NRS_READ:
                continue
            if notification.encrypted_data:
                data = crypto.decrypt_ec(notification.encrypted_data, context.auth.auth_context.ec_private_key)
                if data[0] == '{' and data[-1] == '}':
                    data_json: Dict[str, Any] = json.loads(data)
                    justification = [f'{k}={v}' for k, v in data_json.items()]
                else:
                    justification = [x.strip() for x in data.decode('utf-8').split('\n')]
            else:
                justification = None

            read_status = NotificationCommand.to_read_status_text(notification.read_status)
            approval_status = NotificationCommand.to_approval_status_text(notification.approval_status)
            created = datetime.datetime.fromtimestamp(notification.created // 1000.0)
            row = [notification.notification_uid, notification.sender, justification, read_status, approval_status, created]
            table.append(row)

        fmt = kwargs.get('format')
        if fmt != 'json':
            headers = [report_utils.field_to_title(x) for x in headers]
        return report_utils.dump_report_data(table, headers, column_width=40, fmt=fmt, filename=kwargs.get('output'))

class NotificationMarkReadCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='mark-read', description='Mark notifications as read')
        parser.add_argument('notifications', help='Deployment name or UID')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs):
        assert context.auth is not None
        assert context.vault is not None