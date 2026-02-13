"""Compliance command for Keeper CLI."""

import argparse
import os
import re
import sqlite3
import sys
import threading
import time
from typing import Any, List, Optional

from keepersdk.enterprise import compliance
from keepersdk.plugins.sox import compliance_storage as cs

from . import base
from ..helpers import report_utils
from ..params import KeeperParams
from .. import api

logger = api.get_logger()


class ProgressSpinner:
    """Animated spinner for progress display."""
    
    def __init__(self):
        self._spinner_chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        self._current = 0
        self._running = False
        self._thread = None
        self._message = ''
        self._lock = threading.Lock()
    
    def start(self, message: str = '') -> None:
        self._message = message
        self._running = True
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
    
    def update(self, message: str) -> None:
        with self._lock:
            self._message = message
    
    def stop(self, final_message: str = '') -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=0.5)
        sys.stdout.write('\r' + ' ' * 80 + '\r')
        if final_message:
            sys.stdout.write(final_message + '\n')
        sys.stdout.flush()
    
    def _spin(self) -> None:
        while self._running:
            with self._lock:
                char = self._spinner_chars[self._current % len(self._spinner_chars)]
                sys.stdout.write(f'\r{char} {self._message}')
                sys.stdout.flush()
            self._current += 1
            time.sleep(0.1)


def get_compliance_storage(context: KeeperParams) -> Optional[cs.SqliteComplianceStorage]:
    """Create or get the SQLite compliance storage."""
    if not context.auth or not context.auth.auth_context:
        return None
    
    enterprise_id = context.auth.auth_context.enterprise_id
    if not enterprise_id:
        return None
    
    config_path = context.keeper_config.config_filename or os.path.expanduser('~/.keeper/config.json')
    db_name = cs.get_compliance_database_name(config_path, enterprise_id)
    
    def get_connection() -> sqlite3.Connection:
        return cs.get_cached_connection(db_name)
    
    storage = cs.SqliteComplianceStorage(get_connection, enterprise_id)
    storage.database_name = db_name
    storage.close_connection = lambda: cs.close_cached_connection(db_name)
    return storage


def get_node_id(enterprise_data, name: str) -> int:
    """Resolve node ID from name or numeric ID."""
    if isinstance(name, str) and name.isdecimal():
        name = int(name)
    
    nodes = list(enterprise_data.nodes.get_all_entities())
    if not nodes:
        return 0
    
    node_ids = {n.node_id for n in nodes}
    node_id_lookup = {n.name: n.node_id for n in nodes if n.name}
    
    if isinstance(name, str) and name in node_id_lookup:
        return node_id_lookup[name]
    elif isinstance(name, int) and name in node_ids:
        return name
    return nodes[0].node_id


def filter_rows(rows: List[List[Any]], patterns: List[str], use_regex: bool = False) -> List[List[Any]]:
    """Filter rows based on search patterns."""
    if not patterns:
        return rows
    
    filtered = []
    for row in rows:
        row_text = ' '.join(str(cell) for cell in row if cell is not None)
        for pattern in patterns:
            match = re.search(pattern, row_text, re.IGNORECASE) if use_regex else pattern.lower() in row_text.lower()
            if match:
                filtered.append(row)
                break
    return filtered


def add_common_arguments(parser: argparse.ArgumentParser):
    """Add common arguments shared by all compliance subcommands."""
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


def create_progress_callback(spinner: ProgressSpinner):
    """Create a progress callback function for the spinner."""
    def callback(msg):
        if msg:
            spinner.update(msg)
        else:
            spinner.stop()
    return callback


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
        add_common_arguments(parser)
        ComplianceReportCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        """Add compliance report specific arguments."""
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
        
        output_format = kwargs.get('format', 'table')
        no_cache = kwargs.get('no_cache', False)
        enterprise_data = context.enterprise_data
        node_id = get_node_id(enterprise_data, kwargs['node']) if kwargs.get('node') else None
        
        config = compliance.ComplianceReportConfig(
            username=kwargs.get('username'),
            job_title=kwargs.get('job_title'),
            team=kwargs.get('team'),
            record=kwargs.get('record'),
            url=kwargs.get('url'),
            shared=kwargs.get('shared', False),
            deleted_items=kwargs.get('deleted_items', False),
            active_items=kwargs.get('active_items', False),
            node_id=node_id,
            rebuild=kwargs.get('rebuild', False),
            no_rebuild=kwargs.get('no_rebuild', False),
            no_cache=no_cache
        )
        
        spinner = ProgressSpinner()
        spinner.start('Loading...')
        
        generator = compliance.ComplianceReportGenerator(
            enterprise_data, context.auth, config,
            vault_storage=context.vault.vault_data.storage,
            compliance_storage=None if no_cache else get_compliance_storage(context),
            progress_callback=create_progress_callback(spinner)
        )
        
        rows = list(generator.generate_report_rows('default', blank_duplicate_uids=(output_format == 'table')))
        spinner.stop()
        
        headers = compliance.ComplianceReportGenerator.get_headers('default')
        if output_format != 'json':
            headers = [report_utils.field_to_title(h) for h in headers]
        
        if kwargs.get('pattern'):
            rows = filter_rows(rows, kwargs['pattern'], use_regex=kwargs.get('regex'))
        
        if node_id:
            logger.info(f'Output is limited to "{kwargs["node"]}" node')
        
        return report_utils.dump_report_data(
            rows, headers, fmt=output_format, filename=kwargs.get('output'),
            title='Compliance Report'
        )


class ComplianceTeamReportCommand(base.ArgparseCommand):
    """Command to generate team access report."""
    
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='compliance team-report',
            description='Run a report showing which shared folders enterprise teams have access to',
            parents=[base.report_output_parser]
        )
        add_common_arguments(parser)
        ComplianceTeamReportCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        """Add team report specific arguments."""
        parser.add_argument('-tu', '--show-team-users', action='store_true',
                           help='show all members of each team')
    
    def execute(self, context: KeeperParams, **kwargs) -> Any:
        base.require_login(context)
        base.require_enterprise_admin(context)
        
        output_format = kwargs.get('format', 'table')
        output_file = kwargs.get('output')
        no_cache = kwargs.get('no_cache', False)
        show_team_users = kwargs.get('show_team_users', False)
        enterprise_data = context.enterprise_data
        node_id = get_node_id(enterprise_data, kwargs.get('node')) if kwargs.get('node') else None
        
        config = compliance.ComplianceReportConfig(
            shared=True,
            show_team_users=show_team_users,
            node_id=node_id,
            rebuild=kwargs.get('rebuild', False),
            no_rebuild=kwargs.get('no_rebuild', False),
            no_cache=no_cache
        )
        
        spinner = ProgressSpinner()
        spinner.start('Loading...')
        
        generator = compliance.ComplianceReportGenerator(
            enterprise_data, context.auth, config,
            compliance_storage=None if no_cache else get_compliance_storage(context),
            progress_callback=create_progress_callback(spinner)
        )
        
        rows = list(generator.generate_report_rows('team'))
        spinner.stop()
        
        headers = compliance.ComplianceReportGenerator.get_headers('team', show_team_users)
        if output_format != 'json':
            headers = [report_utils.field_to_title(h) for h in headers]
        
        if kwargs.get('pattern'):
            rows = filter_rows(rows, kwargs['pattern'], use_regex=kwargs.get('regex'))
        
        result = report_utils.dump_report_data(
            rows, headers, fmt=output_format, filename=output_file, title='Team Access Report'
        )
        
        if output_file:
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
        add_common_arguments(parser)
        ComplianceRecordAccessReportCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        """Add record access report specific arguments."""
        parser.add_argument('--email', '-e', action='append', type=str,
                           help='username(s) or ID(s), use "@all" for all users')
        parser.add_argument('--report-type', action='store', choices=['history', 'vault'], default='history',
                           help='type of record-access data: "history" or "vault"')
        parser.add_argument('--aging', action='store_true',
                           help='include record-aging data')
    
    def execute(self, context: KeeperParams, **kwargs) -> Any:
        base.require_login(context)
        base.require_enterprise_admin(context)
        
        output_format = kwargs.get('format', 'table')
        output_file = kwargs.get('output')
        report_type = kwargs.get('report_type', 'history')
        no_cache = kwargs.get('no_cache', False)
        aging = kwargs.get('aging', False)
        emails = kwargs.get('email', [])
        enterprise_data = context.enterprise_data
        node_id = get_node_id(enterprise_data, kwargs.get('node')) if kwargs.get('node') else None
        
        config = compliance.ComplianceReportConfig(
            username=emails if emails and '@all' not in emails else None,
            node_id=node_id,
            rebuild=kwargs.get('rebuild', False),
            no_rebuild=kwargs.get('no_rebuild', False),
            no_cache=no_cache,
            aging=aging
        )
        
        spinner = ProgressSpinner()
        spinner.start('Loading...')
        
        generator = compliance.ComplianceReportGenerator(
            enterprise_data, context.auth, config,
            vault_storage=context.vault.vault_data.storage,
            compliance_storage=None if no_cache else get_compliance_storage(context),
            progress_callback=create_progress_callback(spinner)
        )
        
        rows = list(generator.generate_report_rows('record_access', report_type=report_type))
        spinner.stop()
        
        headers = compliance.ComplianceReportGenerator.get_headers('record_access', aging=aging)
        if output_format != 'json':
            headers = [report_utils.field_to_title(h) for h in headers]
        
        if kwargs.get('pattern'):
            rows = filter_rows(rows, kwargs['pattern'], use_regex=kwargs.get('regex'))
        
        rows.sort(key=lambda r: (r[0] or '', r[1] if len(r) > 1 else ''))
        
        result = report_utils.dump_report_data(
            rows, headers, fmt=output_format, filename=output_file,
            title=f'Record Access Report ({report_type})',
            group_by=0, column_width=30, sort_by=0
        )
        
        if output_file:
            logger.info(f'Report saved to: {os.path.abspath(output_file)}')
        return result


class ComplianceSummaryReportCommand(base.ArgparseCommand):
    """Command to generate summary compliance report."""
    
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='compliance summary-report',
            description='Run a summary compliance report',
            parents=[base.report_output_parser]
        )
        add_common_arguments(parser)
        super().__init__(parser)
    
    def execute(self, context: KeeperParams, **kwargs) -> Any:
        base.require_login(context)
        base.require_enterprise_admin(context)
        
        output_format = kwargs.get('format', 'table')
        output_file = kwargs.get('output')
        no_cache = kwargs.get('no_cache', False)
        enterprise_data = context.enterprise_data
        node_id = get_node_id(enterprise_data, kwargs.get('node')) if kwargs.get('node') else None
        
        config = compliance.ComplianceReportConfig(
            node_id=node_id,
            rebuild=kwargs.get('rebuild', False),
            no_rebuild=kwargs.get('no_rebuild', False),
            no_cache=no_cache
        )
        
        spinner = ProgressSpinner()
        spinner.start('Loading...')
        
        generator = compliance.ComplianceReportGenerator(
            enterprise_data, context.auth, config,
            compliance_storage=None if no_cache else get_compliance_storage(context),
            progress_callback=create_progress_callback(spinner)
        )
        
        rows = list(generator.generate_report_rows('summary'))
        spinner.stop()
        
        if node_id:
            logger.info(f'Output is limited to "{node_id}" node')
        
        total_items = sum(row[1] for row in rows if len(row) > 1)
        total_owned = sum(row[2] for row in rows if len(row) > 2)
        active_owned = sum(row[3] for row in rows if len(row) > 3)
        deleted_owned = sum(row[4] for row in rows if len(row) > 4)
        rows.append(['TOTAL', total_items, total_owned, active_owned, deleted_owned])
        
        headers = compliance.ComplianceReportGenerator.get_headers('summary')
        if output_format != 'json':
            headers = [report_utils.field_to_title(h) for h in headers]
        
        if kwargs.get('pattern'):
            rows = filter_rows(rows, kwargs['pattern'], use_regex=kwargs.get('regex'))
        
        result = report_utils.dump_report_data(
            rows, headers, fmt=output_format, filename=output_file, title='Compliance Summary Report'
        )
        
        if output_file:
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
        add_common_arguments(parser)
        ComplianceSharedFolderReportCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        """Add shared folder report specific arguments."""
        parser.add_argument('-tu', '--show-team-users', action='store_true',
                           help='show all members of each team')
    
    def execute(self, context: KeeperParams, **kwargs) -> Any:
        base.require_login(context)
        base.require_enterprise_admin(context)
        
        output_format = kwargs.get('format', 'table')
        output_file = kwargs.get('output')
        no_cache = kwargs.get('no_cache', False)
        show_team_users = kwargs.get('show_team_users', False)
        enterprise_data = context.enterprise_data
        node_id = get_node_id(enterprise_data, kwargs.get('node')) if kwargs.get('node') else None
        
        config = compliance.ComplianceReportConfig(
            shared=True,
            show_team_users=show_team_users,
            node_id=node_id,
            rebuild=kwargs.get('rebuild', False),
            no_rebuild=kwargs.get('no_rebuild', False),
            no_cache=no_cache
        )
        
        spinner = ProgressSpinner()
        spinner.start('Loading...')
        
        generator = compliance.ComplianceReportGenerator(
            enterprise_data, context.auth, config,
            compliance_storage=None if no_cache else get_compliance_storage(context),
            progress_callback=create_progress_callback(spinner)
        )
        
        rows = list(generator.generate_report_rows('shared_folder'))
        spinner.stop()
        
        headers = compliance.ComplianceReportGenerator.get_headers('shared_folder')
        if output_format != 'json':
            headers = [report_utils.field_to_title(h) for h in headers]
        
        if kwargs.get('pattern'):
            rows = filter_rows(rows, kwargs['pattern'], use_regex=kwargs.get('regex'))
        
        title = '(TU) denotes a user whose membership in a team grants them access' \
                if show_team_users else 'Shared Folder Report'
        
        result = report_utils.dump_report_data(
            rows, headers, fmt=output_format, filename=output_file, title=title
        )
        
        if output_file:
            logger.info(f'Report saved to: {os.path.abspath(output_file)}')
        return result
