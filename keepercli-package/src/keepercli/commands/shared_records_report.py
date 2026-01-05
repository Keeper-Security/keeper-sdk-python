"""Shared Records Report command for Keeper CLI."""

import argparse
import os
from typing import Any, List, Optional

from keepersdk.vault import shared_records_report

from . import base
from ..helpers import report_utils
from ..params import KeeperParams
from .. import api


class SharedRecordsReportCommand(base.ArgparseCommand):
    """Command to generate shared records reports for a logged-in user."""

    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='shared-records-report',
            description='Report shared records for a logged-in user',
            parents=[base.report_output_parser]
        )
        parser.add_argument(
            '-tu', '--show-team-users',
            dest='show_team_users',
            action='store_true',
            help='show members of team for records shared via share team folders.'
        )
        parser.add_argument(
            '--all-records',
            dest='all_records',
            action='store_true',
            help='report on all records in the vault. only owned records are included if this argument is omitted.'
        )
        parser.add_argument(
            'folder',
            type=str,
            nargs='*',
            help='Optional (w/ multiple values allowed). Path or UID of folder containing the records to be shown'
        )
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        """Execute the shared-records-report command."""
        base.require_login(context)

        if context.vault is None:
            raise base.CommandError('Vault data not available. Please run sync-down first.')

        logger = api.get_logger()
        output_format = kwargs.get('format', 'table')
        output_file = kwargs.get('output')
        show_team_users = kwargs.get('show_team_users', False)
        all_records = kwargs.get('all_records', False)
        folder_filter = kwargs.get('folder') or None

        # Log folder filter if provided
        if folder_filter:
            logger.info(f'Filtering by folder(s): {", ".join(folder_filter)}')

        config = shared_records_report.SharedRecordsReportConfig(
            folder_filter=folder_filter,
            show_team_users=show_team_users,
            all_records=all_records
        )

        enterprise = getattr(context, 'enterprise_data', None)
        generator = shared_records_report.SharedRecordsReportGenerator(
            vault=context.vault,
            enterprise=enterprise,
            auth=context.auth,
            config=config
        )

        rows: List[List[Any]] = list(generator.generate_report_rows())
        headers = shared_records_report.SharedRecordsReportGenerator.get_headers(all_records=all_records)

        if not rows:
            logger.info('No shared records found matching the criteria.')
            if output_format == 'json':
                return report_utils.dump_report_data([], headers, fmt=output_format, filename=output_file)
            return None

        if output_format != 'json':
            headers = [report_utils.field_to_title(h) for h in headers]

        # Sort rows by title (index 2 if all_records, else index 1)
        sort_index = 2 if all_records else 1
        rows.sort(key=lambda x: (x[sort_index] or '').lower() if len(x) > sort_index else '')

        result = report_utils.dump_report_data(
            rows,
            headers,
            fmt=output_format,
            filename=output_file,
            row_number=True,
            sort_by=(1, 3) if all_records else (0, 2)
        )

        if output_file:
            _, ext = os.path.splitext(output_file)
            if not ext:
                output_file += '.json' if output_format == 'json' else '.csv'
            logger.info(f'Report saved to: {os.path.abspath(output_file)}')

        return result

