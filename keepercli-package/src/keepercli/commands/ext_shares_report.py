"""External shares report command: records and shared folders shared with external users."""

import argparse
import os
from typing import Any, List

from keepersdk.enterprise import compliance
from keepersdk.plugins.sox import compliance_storage as cs

from . import base
from . import shares
from ..helpers import report_utils
from ..params import KeeperParams
from ..prompt_utils import user_choice
from .. import api

logger = api.get_logger()

DEFAULT_FORMAT = 'table'
REPORT_TITLE = 'External Shares Report'
PDF_OUTPUT_FILENAME = 'external_shares_report.txt'
ROW_UID, ROW_NAME, ROW_TYPE, ROW_SHARED_TO, ROW_PERMISSIONS = 0, 1, 2, 3, 4
SHARE_TYPE_DIRECT = 'Direct'
SHARE_TYPE_SHARED_FOLDER = 'Shared Folder'
SHARE_TYPE_DIRECT_FILTER = 'direct'
SHARE_TYPE_SF_FILTER = 'shared-folder'
SHARE_TYPE_ALL_FILTER = 'all'


def get_compliance_storage(context: KeeperParams):
    if not context.auth or not context.auth.auth_context:
        return None
    enterprise_id = context.auth.auth_context.enterprise_id
    if not enterprise_id:
        return None
    config_path = context.keeper_config.config_filename or os.path.expanduser('~/.keeper/config.json')
    db_name = cs.get_compliance_database_name(config_path, enterprise_id)

    def get_connection():
        return cs.get_cached_connection(db_name)

    storage = cs.SqliteComplianceStorage(get_connection, enterprise_id)
    storage.database_name = db_name
    storage.close_connection = lambda: cs.close_cached_connection(db_name)
    return storage


class ProgressSpinner:
    def start(self, message: str = '') -> None:
        if message:
            logger.info(message)

    def update(self, message: str) -> None:
        if message:
            logger.info(message)

    def stop(self, final_message: str = '') -> None:
        if final_message:
            logger.info(final_message)


def _format_headers(headers: list, fmt: str) -> list:
    return [report_utils.field_to_title(h) for h in headers] if fmt == DEFAULT_FORMAT else headers


def create_progress_callback(spinner: ProgressSpinner):
    def callback(msg):
        if msg:
            spinner.update(msg)
        else:
            spinner.stop()
    return callback


class ExtSharesReportCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='external-shares-report',
            description='Run an external record sharing report',
        )
        ExtSharesReportCommand.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            '--format',
            dest='format',
            action='store',
            choices=['table', 'csv', 'json', 'pdf'],
            default=DEFAULT_FORMAT,
            help='format of output',
        )
        parser.add_argument(
            '--output',
            dest='output',
            action='store',
            help='path to resulting output file (ignored for "table" format)',
        )
        parser.add_argument(
            '-a', '--action',
            dest='action',
            action='store',
            choices=['remove', 'none'],
            default='none',
            help="action to perform on external shares, 'none' if omitted",
        )
        parser.add_argument(
            '-t', '--share-type',
            dest='share_type',
            action='store',
            choices=[SHARE_TYPE_DIRECT_FILTER, SHARE_TYPE_SF_FILTER, SHARE_TYPE_ALL_FILTER],
            default=SHARE_TYPE_ALL_FILTER,
            help="filter report by share type, 'all' if omitted",
        )
        parser.add_argument(
            '-f', '--force',
            dest='force',
            action='store_true',
            help='apply action w/o confirmation',
        )
        parser.add_argument(
            '-r', '--refresh-data',
            dest='refresh_data',
            action='store_true',
            help='retrieve fresh data',
        )

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        base.require_login(context)
        base.require_enterprise_admin(context)

        action = kwargs.get('action', 'none')
        share_type = kwargs.get('share_type', SHARE_TYPE_ALL_FILTER)
        force = kwargs.get('force', False)
        refresh_data = kwargs.get('refresh_data', False)
        fmt = kwargs.get('format', DEFAULT_FORMAT)
        output_file = kwargs.get('output')

        if fmt == 'pdf':
            fmt = 'table'
            if not output_file:
                output_file = PDF_OUTPUT_FILENAME

        config = compliance.ComplianceReportConfig(
            shared=True,
            rebuild=refresh_data,
            no_rebuild=not refresh_data,
            external_share_type=share_type,
        )

        spinner = ProgressSpinner()
        spinner.start('Loading...')

        generator = compliance.ComplianceReportGenerator(
            context.enterprise_data,
            context.auth,
            config,
            compliance_storage=get_compliance_storage(context),
            progress_callback=create_progress_callback(spinner),
        )

        rows = list(generator.generate_report_rows(compliance.REPORT_TYPE_EXTERNAL_SHARES))
        spinner.stop()

        if action == 'remove' and rows:
            if not force:
                answer = user_choice('\nDo you wish to proceed?', 'yn', 'n')
                if answer and answer.lower() not in ('y', 'yes'):
                    logger.info('Action aborted.')
                    return self._dump_report(rows, fmt, output_file)
            self._remove_external_shares(context, rows, share_type)
            spinner.start('Reloading...')
            config_reload = compliance.ComplianceReportConfig(
                shared=True,
                rebuild=True,
                external_share_type=share_type,
            )
            generator_reload = compliance.ComplianceReportGenerator(
                context.enterprise_data,
                context.auth,
                config_reload,
                compliance_storage=get_compliance_storage(context),
                progress_callback=create_progress_callback(spinner),
            )
            rows = list(generator_reload.generate_report_rows(compliance.REPORT_TYPE_EXTERNAL_SHARES))
            spinner.stop()

        return self._dump_report(rows, fmt, output_file)

    def _dump_report(self, rows: List[List[Any]], fmt: str, output_file: str) -> Any:
        headers = compliance.ComplianceReportGenerator.get_headers(compliance.REPORT_TYPE_EXTERNAL_SHARES)
        return report_utils.dump_report_data(
            rows,
            _format_headers(headers, fmt),
            fmt=fmt,
            filename=output_file,
            title=REPORT_TITLE,
        )

    def _remove_external_shares(self, context: KeeperParams, rows: List[List[Any]], share_type: str) -> None:
        share_record_cmd = shares.ShareRecordCommand()
        share_folder_cmd = shares.ShareFolderCommand()
        direct_emails_by_record = {}
        sf_emails_by_folder = {}

        for row in rows:
            if len(row) < 5:
                continue
            uid = row[ROW_UID]
            row_type = row[ROW_TYPE]
            shared_to = row[ROW_SHARED_TO]
            if not shared_to:
                continue
            if row_type == SHARE_TYPE_DIRECT:
                direct_emails_by_record.setdefault(uid, []).append(shared_to)
            elif row_type == SHARE_TYPE_SHARED_FOLDER:
                sf_emails_by_folder.setdefault(uid, []).append(shared_to)

        if share_type in (SHARE_TYPE_DIRECT_FILTER, SHARE_TYPE_ALL_FILTER):
            for record_uid, emails in direct_emails_by_record.items():
                try:
                    share_record_cmd.execute(context, record=record_uid, email=emails, action='revoke')
                except Exception as e:
                    logger.debug('Revoke failed for record %s: %s', record_uid, e)

        if share_type in (SHARE_TYPE_SF_FILTER, SHARE_TYPE_ALL_FILTER):
            for folder_uid, emails in sf_emails_by_folder.items():
                try:
                    share_folder_cmd.execute(context, folder=[folder_uid], user=emails, action='remove')
                except Exception as e:
                    logger.debug('Remove user failed for folder %s: %s', folder_uid, e)
