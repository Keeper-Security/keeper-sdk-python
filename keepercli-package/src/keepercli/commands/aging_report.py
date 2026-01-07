"""Password aging report command for Keeper CLI."""

import argparse
import datetime
import os
from typing import Any, List

from keepersdk.enterprise import aging_report

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
        
        # Database/cache management options
        parser.add_argument(
            '-r', '--rebuild',
            dest='rebuild',
            action='store_true',
            help='Rebuild record database'
        )
        parser.add_argument(
            '--delete',
            dest='delete',
            action='store_true',
            help='Delete local database cache containing encrypted compliance record data'
        )
        parser.add_argument(
            '--no-cache', '-nc',
            dest='no_cache',
            action='store_true',
            help='Remove any local non-memory storage of data upon command completion'
        )
        
        # Sort option
        parser.add_argument(
            '-s', '--sort',
            dest='sort_by',
            action='store',
            default='last_changed',
            choices=['owner', 'title', 'last_changed', 'shared'],
            help='Sort output by column'
        )
        
        # Temporal filters (mutually exclusive)
        temporal_group = parser.add_mutually_exclusive_group()
        temporal_group.add_argument(
            '--period',
            dest='period',
            action='store',
            help='Period the password has not been modified (e.g., 10d, 3m, 1y). Not valid with --cutoff-date flag'
        )
        temporal_group.add_argument(
            '--cutoff-date',
            dest='cutoff_date',
            action='store',
            help='Date since which the password has not been modified (e.g., 2024-01-01). Not valid with --period flag'
        )
        
        # User filter
        parser.add_argument(
            '--username',
            dest='username',
            action='store',
            help='Report expired passwords for user'
        )
        
        # Record filters
        parser.add_argument(
            '--exclude-deleted',
            dest='exclude_deleted',
            action='store_true',
            help='Exclude deleted records from report'
        )
        parser.add_argument(
            '--in-shared-folder',
            dest='in_shared_folder',
            action='store_true',
            help='Limit report to records in shared folders'
        )
        
        super().__init__(parser)
    
    def execute(self, context: KeeperParams, **kwargs) -> Any:
        base.require_login(context)
        base.require_enterprise_admin(context)
        
        logger = api.get_logger()
        
        # Get enterprise ID for cache operations
        enterprise_id = 0
        if hasattr(context, 'enterprise_data') and context.enterprise_data:
            if hasattr(context.enterprise_data, 'enterprise_info'):
                enterprise_id = getattr(context.enterprise_data.enterprise_info, 'enterprise_id', 0)
        
        # Handle --delete option: delete local database cache
        if kwargs.get('delete'):
            config = aging_report.AgingReportConfig()
            generator = aging_report.AgingReportGenerator(context.enterprise_data, context.auth, config)
            if generator.delete_local_cache(enterprise_id):
                logger.info('Local encrypted storage has been deleted.')
            else:
                logger.info('Local encrypted storage does not exist.')
            return
        
        # Parse period/cutoff date
        period_days = aging_report.DEFAULT_PERIOD_DAYS
        cutoff_date = None
        
        period_str = kwargs.get('period')
        cutoff_str = kwargs.get('cutoff_date')
        
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
        
        username = kwargs.get('username')
        exclude_deleted = kwargs.get('exclude_deleted', False)
        in_shared_folder = kwargs.get('in_shared_folder', False)
        rebuild = kwargs.get('rebuild', False)
        no_cache = kwargs.get('no_cache', False)
        output_format = kwargs.get('format', 'table')
        output_file = kwargs.get('output')
        sort_by = kwargs.get('sort_by', 'last_changed')
        
        # Validate username if provided
        if username:
            # Check if user exists in enterprise
            user_found = False
            for user in context.enterprise_data.users.get_all_entities():
                if user.username.lower() == username.lower():
                    user_found = True
                    break
            if not user_found:
                logger.info(f'User {username} is not a valid enterprise user')
                return
        
        # Get server from config (old code line 137: params.server)
        server = context.keeper_config.server or 'keepersecurity.com'
        
        config = aging_report.AgingReportConfig(
            period_days=period_days,
            cutoff_date=cutoff_date,
            username=username,
            exclude_deleted=exclude_deleted,
            in_shared_folder=in_shared_folder,
            rebuild=rebuild,
            no_cache=no_cache,
            server=server
        )
        
        if rebuild:
            logger.info('Rebuilding record database...')
        
        logger.info('Loading record password change information...')
        
        # Pass vault to generator so it can get record titles
        generator = aging_report.AgingReportGenerator(
            context.enterprise_data, 
            context.auth, 
            config,
            vault=context.vault
        )
        
        try:
            rows: List[List[Any]] = list(generator.generate_report_rows(include_shared_folder=in_shared_folder))
            headers = aging_report.AgingReportGenerator.get_headers(include_shared_folder=in_shared_folder)
            
            if output_format != 'json':
                headers = [report_utils.field_to_title(h) for h in headers]
            
            # Determine sort column (last_changed maps to password_changed column at index 2)
            sort_columns = {'owner': 0, 'title': 1, 'last_changed': 2, 'shared': 3}
            sort_column = sort_columns.get(sort_by, 2)
            # Sort descending for last_changed and shared (like old code line 149)
            sort_desc = sort_by in ('last_changed', 'shared')
            
            # Build title
            if cutoff_date:
                cutoff_dt = cutoff_date
            else:
                cutoff_dt = datetime.datetime.now() - datetime.timedelta(days=period_days)
            
            title = f'Aging Report: Records With Passwords Last Modified Before {cutoff_dt.strftime("%Y/%m/%d %H:%M:%S")}'
            
            result = report_utils.dump_report_data(
                rows, 
                headers, 
                fmt=output_format, 
                filename=output_file,
                title=title,
                sort_by=sort_column,
                sort_desc=sort_desc
            )
            
            logger.info(f'Found {len(rows)} record(s) with aging passwords')
            
            if output_file:
                _, ext = os.path.splitext(output_file)
                if not ext:
                    output_file += '.json' if output_format == 'json' else '.csv'
                logger.info(f'Report saved to: {os.path.abspath(output_file)}')
            
            return result
            
        finally:
            # Clean up cache if no_cache option is set
            if no_cache:
                generator.cleanup(enterprise_id)
                logger.info('Local cache has been removed.')
