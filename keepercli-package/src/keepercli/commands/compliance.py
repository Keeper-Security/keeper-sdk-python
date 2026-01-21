"""Compliance command for Keeper CLI."""

import argparse
import os
import re
from typing import Any, List

from keepersdk.enterprise import compliance

from . import base
from ..helpers import report_utils
from ..params import KeeperParams
from .. import api


def filter_rows(rows: List[List[Any]], patterns: List[str], use_regex: bool = False) -> List[List[Any]]:
    """Filter rows based on patterns.
    
    Args:
        rows: List of rows to filter
        patterns: List of search patterns
        use_regex: Whether to use regular expression matching
        
    Returns:
        Filtered list of rows
    """
    if not patterns:
        return rows
    
    filtered = []
    for row in rows:
        row_text = ' '.join(str(cell) for cell in row if cell is not None)
        for pattern in patterns:
            if use_regex:
                if re.search(pattern, row_text, re.IGNORECASE):
                    filtered.append(row)
                    break
            else:
                if pattern.lower() in row_text.lower():
                    filtered.append(row)
                    break
    
    return filtered


class ComplianceCommand(base.GroupCommand):
    """Group command for all compliance reporting functions."""
    
    def __init__(self):
        super().__init__('Compliance Reporting for auditing')
        self.register_command(ComplianceReportCommand(), 'report', 'r')
        self.register_command(ComplianceTeamReportCommand(), 'team-report', 'tr')
        self.register_command(ComplianceRecordAccessReportCommand(), 'record-access-report', 'rar')
        self.register_command(ComplianceSummaryReportCommand(), 'summary-report', 'sr')
        self.register_command(ComplianceSharedFolderReportCommand(), 'shared-folder-report', 'sfr')
        self.default_verb = 'report'


class ComplianceReportCommand(base.ArgparseCommand):
    """Command to generate default compliance report."""
    
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='compliance report',
            description='Run a compliance report.',
            parents=[base.report_output_parser]
        )
        ComplianceReportCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        rebuild_group = parser.add_mutually_exclusive_group()
        rebuild_group.add_argument('--rebuild', '-r', action='store_true',
                                  help='rebuild local data from source')
        rebuild_group.add_argument('--no-rebuild', '-nr', action='store_true',
                                  help='prevent remote data fetching if local cache present')
        parser.add_argument('--no-cache', '-nc', action='store_true',
                           help='remove any local non-memory storage of data after report is generated')
        parser.add_argument('--node', action='store',
                           help='ID or name of node (defaults to root node)')
        parser.add_argument('--regex', action='store_true',
                           help='Allow use of regular expressions in search criteria')
        parser.add_argument('pattern', type=str, nargs='*',
                           help='Search string / pattern to filter results by. Multiple values allowed.')
        parser.add_argument('--username', '-u', action='append',
                           help='user(s) whose records are to be included in report')
        parser.add_argument('--job-title', '-jt', action='append',
                           help='job title(s) of users whose records are to be included in report')
        parser.add_argument('--team', action='append',
                           help='name or UID of team(s) whose members\' records are to be included in report')
        parser.add_argument('--record', action='append',
                           help='UID or title of record(s) to include in report')
        parser.add_argument('--url', action='append',
                           help='URL of record(s) to include in report')
        parser.add_argument('--shared', action='store_true',
                           help='show shared records only')
        deleted_status_group = parser.add_mutually_exclusive_group()
        deleted_status_group.add_argument('--deleted-items', action='store_true',
                                         help='show deleted records only')
        deleted_status_group.add_argument('--active-items', action='store_true',
                                         help='show active records only')
    
    def execute(self, context: KeeperParams, **kwargs) -> Any:
        base.require_login(context)
        base.require_enterprise_admin(context)
        
        logger = api.get_logger()
        output_format = kwargs.get('format', 'table')
        output_file = kwargs.get('output')
        
        # Parse node filter
        node_id = None
        node_name = kwargs.get('node')
        if node_name:
            # Try to find node by name or ID
            for node in context.enterprise_data.nodes.get_all_entities():
                if str(node.node_id) == node_name or node.name == node_name:
                    node_id = node.node_id
                    break
        
        config = compliance.ComplianceReportConfig(
            username=kwargs.get('username'),
            job_title=kwargs.get('job_title'),
            team=kwargs.get('team'),
            record=kwargs.get('record'),
            url=kwargs.get('url'),
            shared=kwargs.get('shared', False),
            deleted_items=kwargs.get('deleted_items', False),
            active_items=kwargs.get('active_items', False),
            node_id=node_id
        )
        
        logger.info('Loading compliance data...')
        
        # Get vault storage for shared folder extraction
        vault_storage = None
        if context.vault:
            vault_storage = context.vault.vault_data.storage
        
        generator = compliance.ComplianceReportGenerator(
            context.enterprise_data,
            context.auth,
            config,
            vault_storage=vault_storage
        )
        
        # For table format, blank duplicate record UIDs for better readability
        blank_dupes = (output_format == 'table')
        rows = list(generator.generate_report_rows('default', blank_duplicate_uids=blank_dupes))
        headers = compliance.ComplianceReportGenerator.get_headers('default')
        
        if output_format != 'json':
            headers = [report_utils.field_to_title(h) for h in headers]
        
        # Apply pattern filter if specified
        patterns = kwargs.get('pattern', [])
        if patterns:
            rows = filter_rows(rows, patterns, use_regex=kwargs.get('regex'))
        
        result = report_utils.dump_report_data(
            rows, headers, fmt=output_format, filename=output_file,
            title='Compliance Report'
        )
        
        if output_file:
            _, ext = os.path.splitext(output_file)
            if not ext:
                output_file += '.json' if output_format == 'json' else '.csv'
            logger.info(f'Report saved to: {os.path.abspath(output_file)}')
        
        return result


class ComplianceTeamReportCommand(base.ArgparseCommand):
    """Command to generate team access report."""
    
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='compliance team-report',
            description='Run a report showing which shared folders enterprise teams have access to',
            parents=[base.report_output_parser]
        )
        parser.add_argument('-tu', '--show-team-users', action='store_true',
                           help='show all members of each team')
        parser.add_argument('--node', action='store',
                           help='ID or name of node (defaults to root node)')
        parser.add_argument('--regex', action='store_true',
                           help='Allow use of regular expressions in search criteria')
        parser.add_argument('pattern', type=str, nargs='*',
                           help='Search string / pattern to filter results by')
        super().__init__(parser)
    
    def execute(self, context: KeeperParams, **kwargs) -> Any:
        base.require_login(context)
        base.require_enterprise_admin(context)
        
        logger = api.get_logger()
        output_format = kwargs.get('format', 'table')
        output_file = kwargs.get('output')
        show_team_users = kwargs.get('show_team_users', False)
        
        config = compliance.ComplianceReportConfig(
            shared=True,
            show_team_users=show_team_users
        )
        
        logger.info('Loading team access data...')
        generator = compliance.ComplianceReportGenerator(
            context.enterprise_data,
            context.auth,
            config
        )
        
        rows = list(generator.generate_report_rows('team'))
        headers = compliance.ComplianceReportGenerator.get_headers('team', show_team_users)
        
        if output_format != 'json':
            headers = [report_utils.field_to_title(h) for h in headers]
        
        # Apply pattern filter if specified
        patterns = kwargs.get('pattern', [])
        if patterns:
            rows = filter_rows(rows, patterns, use_regex=kwargs.get('regex'))
        
        result = report_utils.dump_report_data(
            rows, headers, fmt=output_format, filename=output_file,
            title='Team Access Report'
        )
        
        if output_file:
            _, ext = os.path.splitext(output_file)
            if not ext:
                output_file += '.json' if output_format == 'json' else '.csv'
            logger.info(f'Report saved to: {os.path.abspath(output_file)}')
        
        return result


class ComplianceRecordAccessReportCommand(base.ArgparseCommand):
    """Command to generate record access history report."""
    
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='compliance record-access-report',
            description='Run a report showing all records a user has accessed or can access',
            parents=[base.report_output_parser]
        )
        parser.add_argument('--email', '-e', action='append', type=str,
                           help='username(s) or ID(s). Set to "@all" to run report for all users')
        parser.add_argument('--report-type', action='store', choices=['history', 'vault'],
                           default='history',
                           help='select type of record-access data (defaults to "history")')
        parser.add_argument('--aging', action='store_true',
                           help='include record-aging data')
        parser.add_argument('--node', action='store',
                           help='ID or name of node (defaults to root node)')
        parser.add_argument('--regex', action='store_true',
                           help='Allow use of regular expressions in search criteria')
        parser.add_argument('pattern', type=str, nargs='*',
                           help='Search string / pattern to filter results by')
        super().__init__(parser)
    
    def execute(self, context: KeeperParams, **kwargs) -> Any:
        base.require_login(context)
        base.require_enterprise_admin(context)
        
        logger = api.get_logger()
        output_format = kwargs.get('format', 'table')
        output_file = kwargs.get('output')
        
        logger.warning('Record access report functionality requires additional audit log integration.')
        logger.info('Please use the aging-report command for password aging analysis.')
        
        return None


class ComplianceSummaryReportCommand(base.ArgparseCommand):
    """Command to generate summary compliance report."""
    
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='compliance summary-report',
            description='Run a summary compliance report',
            parents=[base.report_output_parser]
        )
        parser.add_argument('--node', action='store',
                           help='ID or name of node (defaults to root node)')
        parser.add_argument('--regex', action='store_true',
                           help='Allow use of regular expressions in search criteria')
        parser.add_argument('pattern', type=str, nargs='*',
                           help='Search string / pattern to filter results by')
        super().__init__(parser)
    
    def execute(self, context: KeeperParams, **kwargs) -> Any:
        base.require_login(context)
        base.require_enterprise_admin(context)
        
        logger = api.get_logger()
        output_format = kwargs.get('format', 'table')
        output_file = kwargs.get('output')
        
        # Parse node filter
        node_id = None
        node_name = kwargs.get('node')
        if node_name:
            for node in context.enterprise_data.nodes.get_all_entities():
                if str(node.node_id) == node_name or node.name == node_name:
                    node_id = node.node_id
                    break
        
        config = compliance.ComplianceReportConfig(node_id=node_id)
        
        logger.info('Loading summary data...')
        generator = compliance.ComplianceReportGenerator(
            context.enterprise_data,
            context.auth,
            config
        )
        
        rows = list(generator.generate_report_rows('summary'))
        headers = compliance.ComplianceReportGenerator.get_headers('summary')
        
        if output_format != 'json':
            headers = [report_utils.field_to_title(h) for h in headers]
        
        # Apply pattern filter if specified
        patterns = kwargs.get('pattern', [])
        if patterns:
            rows = filter_rows(rows, patterns, use_regex=kwargs.get('regex'))
        
        result = report_utils.dump_report_data(
            rows, headers, fmt=output_format, filename=output_file,
            title='Compliance Summary Report'
        )
        
        if output_file:
            _, ext = os.path.splitext(output_file)
            if not ext:
                output_file += '.json' if output_format == 'json' else '.csv'
            logger.info(f'Report saved to: {os.path.abspath(output_file)}')
        
        return result


class ComplianceSharedFolderReportCommand(base.ArgparseCommand):
    """Command to generate shared folder access report."""
    
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='compliance shared-folder-report',
            description='Run an enterprise-wide shared-folder report',
            parents=[base.report_output_parser]
        )
        parser.add_argument('-tu', '--show-team-users', action='store_true',
                           help='show all members of each team')
        parser.add_argument('--node', action='store',
                           help='ID or name of node (defaults to root node)')
        parser.add_argument('--regex', action='store_true',
                           help='Allow use of regular expressions in search criteria')
        parser.add_argument('pattern', type=str, nargs='*',
                           help='Search string / pattern to filter results by')
        super().__init__(parser)
    
    def execute(self, context: KeeperParams, **kwargs) -> Any:
        base.require_login(context)
        base.require_enterprise_admin(context)
        
        logger = api.get_logger()
        output_format = kwargs.get('format', 'table')
        output_file = kwargs.get('output')
        show_team_users = kwargs.get('show_team_users', False)
        
        config = compliance.ComplianceReportConfig(
            shared=True,
            show_team_users=show_team_users
        )
        
        logger.info('Loading shared folder data...')
        generator = compliance.ComplianceReportGenerator(
            context.enterprise_data,
            context.auth,
            config
        )
        
        rows = list(generator.generate_report_rows('shared-folder'))
        headers = compliance.ComplianceReportGenerator.get_headers('shared-folder')
        
        if output_format != 'json':
            headers = [report_utils.field_to_title(h) for h in headers]
        
        # Apply pattern filter if specified
        patterns = kwargs.get('pattern', [])
        if patterns:
            rows = filter_rows(rows, patterns, use_regex=kwargs.get('regex'))
        
        title = '(TU) denotes a user whose membership in a team grants them access to the shared folder' \
                if show_team_users else 'Shared Folder Report'
        
        result = report_utils.dump_report_data(
            rows, headers, fmt=output_format, filename=output_file,
            title=title
        )
        
        if output_file:
            _, ext = os.path.splitext(output_file)
            if not ext:
                output_file += '.json' if output_format == 'json' else '.csv'
            logger.info(f'Report saved to: {os.path.abspath(output_file)}')
        
        return result
