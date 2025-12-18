"""User report command for Keeper CLI."""

import argparse
import os
from typing import Any, List

from keepersdk.enterprise import user_report

from . import base
from ..helpers import report_utils
from ..params import KeeperParams
from .. import api


class UserReportCommand(base.ArgparseCommand):
    """Command to generate a user report with login activity."""
    
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='user-report',
            description='Run a user report with login activity.',
            parents=[base.report_output_parser]
        )
        parser.add_argument(
            '--days',
            dest='days',
            type=int,
            default=365,
            help='Days to look back for last login (0 = no limit). Default: 365'
        )
        parser.add_argument(
            '-l', '--last-login',
            dest='last_login',
            action='store_true',
            help='Simplify report to show only last-login info'
        )
        super().__init__(parser)
    
    def execute(self, context: KeeperParams, **kwargs) -> Any:
        base.require_login(context)
        base.require_enterprise_admin(context)
        
        logger = api.get_logger()
        lookback_days = kwargs.get('days', 365)
        simplified = kwargs.get('last_login', False)
        output_format = kwargs.get('format', 'table')
        output_file = kwargs.get('output')
        
        if lookback_days > 0:
            logger.info(f'Querying latest login for the last {lookback_days} days')
        else:
            logger.info('Querying latest login without date limit')
        
        config = user_report.UserReportConfig(
            lookback_days=lookback_days,
            include_last_login=True,
            include_roles=not simplified,
            include_teams=not simplified,
            simplified_report=simplified
        )
        
        generator = user_report.UserReportGenerator(context.enterprise_data, context.auth, config)
        rows: List[List[Any]] = list(generator.generate_report_rows())
        headers = user_report.UserReportGenerator.get_headers(simplified=simplified)
        
        if output_format != 'json':
            headers = [report_utils.field_to_title(h) for h in headers]
        
        result = report_utils.dump_report_data(rows, headers, fmt=output_format, filename=output_file)
        
        if output_file:
            _, ext = os.path.splitext(output_file)
            if not ext:
                output_file += '.json' if output_format == 'json' else '.csv'
            logger.info(f'Report saved to: {os.path.abspath(output_file)}')
        
        return result
