"""Password aging report command for Keeper CLI."""

import argparse
import datetime
import os
from typing import Any, List

from keepersdk.enterprise import aging_report, enterprise_types
from keepersdk.authentication import keeper_auth
from . import base
from ..helpers import report_utils
from ..params import KeeperParams
from .. import api


class AgingReportCommand(base.ArgparseCommand):
    """Command to generate a password aging report."""
    
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='aging-report',
            description='Run a password aging report',
            parents=[base.report_output_parser]
        )
        AgingReportCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('-r', '--rebuild', dest='rebuild', action='store_true',
                            help='Rebuild record database')
        parser.add_argument('--delete', dest='delete', action='store_true',
                            help='Delete local database cache')
        parser.add_argument('--no-cache', '-nc', dest='no_cache', action='store_true',
                            help='Remove local storage upon command completion')
        parser.add_argument('-s', '--sort', dest='sort_by', action='store', default='last_changed',
                            choices=['owner', 'title', 'last_changed', 'shared'],
                            help='Sort output by column')
        temporal_group = parser.add_mutually_exclusive_group()
        temporal_group.add_argument('--period', dest='period', action='store',
                                    help='Period password has not been modified (e.g., 10d, 3m, 1y)')
        temporal_group.add_argument('--cutoff-date', dest='cutoff_date', action='store',
                                    help='Date since password has not been modified (e.g., 2024-01-01)')
        parser.add_argument('--username', dest='username', action='store',
                            help='Report expired passwords for user')
        parser.add_argument('--exclude-deleted', dest='exclude_deleted', action='store_true',
                            help='Exclude deleted records from report')
        parser.add_argument('--in-shared-folder', dest='in_shared_folder', action='store_true',
                            help='Limit report to records in shared folders')
    
    def execute(self, context: KeeperParams, **kwargs) -> Any:
        base.require_login(context)
        base.require_enterprise_admin(context)
        
        logger = api.get_logger()
        enterprise_data = context.enterprise_data
        auth = context.auth
        enterprise_id = self._get_enterprise_id(auth)
        
        if kwargs.get('delete'):
            return self._handle_delete(enterprise_data, auth, enterprise_id, logger)
        
        period_days, cutoff_date = self._parse_temporal_args(kwargs, logger)
        
        username = kwargs.get('username')
        if username and not self._validate_username(enterprise_data, username, logger):
            return
        
        config = aging_report.AgingReportConfig(
            period_days=period_days,
            cutoff_date=cutoff_date,
            username=username,
            exclude_deleted=kwargs.get('exclude_deleted', False),
            in_shared_folder=kwargs.get('in_shared_folder', False),
            rebuild=kwargs.get('rebuild', False),
            no_cache=kwargs.get('no_cache', False),
            server=context.keeper_config.server or 'keepersecurity.com'
        )
        
        if config.rebuild:
            logger.info('Rebuilding record database...')
        logger.info('Loading record password change information...')
        
        generator = aging_report.AgingReportGenerator(
            context.enterprise_data, context.auth, config, vault=context.vault
        )
        
        try:
            return self._generate_and_output_report(
                generator, config, cutoff_date, period_days, kwargs, logger
            )
        finally:
            if config.no_cache:
                generator.cleanup(enterprise_id)
                logger.info('Local cache has been removed.')
    
    def _get_enterprise_id(self, auth: keeper_auth.KeeperAuth) -> int:
        """Extract enterprise ID from context."""
        return auth.auth_context.enterprise_id
    
    def _handle_delete(self, enterprise_data: enterprise_types.IEnterpriseData, auth: keeper_auth.KeeperAuth, enterprise_id: int, logger) -> None:
        """Handle --delete option."""
        config = aging_report.AgingReportConfig()
        generator = aging_report.AgingReportGenerator(enterprise_data, auth, config)
        if generator.delete_local_cache(enterprise_id):
            logger.info('Local encrypted storage has been deleted.')
        else:
            logger.info('Local encrypted storage does not exist.')
    
    def _parse_temporal_args(self, kwargs, logger) -> tuple:
        """Parse period/cutoff date arguments."""
        period_days = aging_report.DEFAULT_PERIOD_DAYS
        cutoff_date = None
        
        cutoff_str = kwargs.get('cutoff_date')
        period_str = kwargs.get('period')
        
        if cutoff_str:
            cutoff_date = aging_report.parse_date(cutoff_str)
            if cutoff_date is None:
                raise base.CommandError(f'Invalid date format: {cutoff_str}')
            logger.info(f'Reporting passwords not changed since {cutoff_date.strftime("%Y-%m-%d")}')
        elif period_str:
            parsed_days = aging_report.parse_period(period_str)
            if parsed_days is None:
                raise base.CommandError(f'Invalid period format: {period_str}. Use format like 10d, 3m, or 1y')
            period_days = parsed_days
            logger.info(f'Reporting passwords not changed in the last {period_days} days')
        else:
            logger.info('\n\nThe default password aging period is 3 months\n'
                       'To change this value pass --period=[PERIOD] parameter\n'
                       '[PERIOD] example: 10d for 10 days; 3m for 3 months; 1y for 1 year\n\n')
        
        return period_days, cutoff_date
    
    def _validate_username(self, enterprise_data: enterprise_types.IEnterpriseData, username: str, logger) -> bool:
        """Validate username exists in enterprise."""
        for user in enterprise_data.users.get_all_entities():
            if user.username.lower() == username.lower():
                return True
        logger.info(f'User {username} is not a valid enterprise user')
        return False
    
    def _generate_and_output_report(self, generator, config, cutoff_date, period_days, kwargs, logger):
        """Generate report and output in requested format."""
        in_shared_folder = kwargs.get('in_shared_folder', False)
        output_format = kwargs.get('format', 'table')
        output_file = kwargs.get('output')
        sort_by = kwargs.get('sort_by', 'last_changed')
        
        rows: List[List[Any]] = list(generator.generate_report_rows(include_shared_folder=in_shared_folder))
        headers = aging_report.AgingReportGenerator.get_headers(include_shared_folder=in_shared_folder)
        
        if output_format != 'json':
            headers = [report_utils.field_to_title(h) for h in headers]
        
        sort_columns = {'owner': 0, 'title': 1, 'last_changed': 2, 'shared': 3}
        cutoff_dt = cutoff_date or (datetime.datetime.now() - datetime.timedelta(days=period_days))
        
        result = report_utils.dump_report_data(
            rows, headers, fmt=output_format, filename=output_file,
            title=f'Aging Report: Records With Passwords Last Modified Before {cutoff_dt.strftime("%Y/%m/%d %H:%M:%S")}',
            sort_by=sort_columns.get(sort_by, 2),
            sort_desc=sort_by in ('last_changed', 'shared')
        )
        
        logger.info(f'Found {len(rows)} record(s) with aging passwords')
        
        if output_file:
            _, ext = os.path.splitext(output_file)
            if not ext:
                output_file += '.json' if output_format == 'json' else '.csv'
            logger.info(f'Report saved to: {os.path.abspath(output_file)}')
        
        return result
