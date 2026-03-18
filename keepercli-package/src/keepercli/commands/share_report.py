"""Share Report command for Keeper CLI."""

import argparse
from typing import Any, Optional

from keepersdk.vault import share_report

from . import base
from ..helpers import report_utils
from ..params import KeeperParams
from .. import api


class ShareReportCommand(base.ArgparseCommand):
    """Command to generate share reports for records and shared folders."""

    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='share-report',
            description='Generates a report of shared records',
            parents=[base.report_output_parser]
        )
        self.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser) -> None:
        """Add command arguments to the parser.
        
        Args:
            parser: The argument parser to add arguments to
        """
        parser.add_argument(
            '-r', '--record',
            dest='record',
            action='append',
            help='record name or UID (can be specified multiple times)'
        )
        parser.add_argument(
            '-e', '--email',
            dest='user',
            action='append',
            help='user email or team name to filter by (can be specified multiple times)'
        )
        parser.add_argument(
            '-o', '--owner',
            dest='owner',
            action='store_true',
            help='display record ownership information'
        )
        parser.add_argument(
            '--share-date',
            dest='share_date',
            action='store_true',
            help='include date when the record was shared. This data is available only to '
                 'users with permissions to execute reports for their company. '
                 'Example: share-report -v -o --share-date --format table'
        )
        parser.add_argument(
            '-sf', '--shared-folders',
            dest='shared_folders',
            action='store_true',
            help='display shared folder detail information'
        )
        parser.add_argument(
            '-v', '--verbose',
            dest='verbose',
            action='store_true',
            help='display verbose information with detailed permissions'
        )
        parser.add_argument(
            '-f', '--folders',
            dest='folders',
            action='store_true',
            default=False,
            help='limit report to shared folders (excludes shared records)'
        )
        parser.add_argument(
            '-tu', '--show-team-users',
            action='store_true',
            help='show shared-folder team members (to be used with -f flag, '
                 'ignored for non-admin accounts)'
        )
        parser.add_argument(
            'container',
            nargs='*',
            type=str,
            action='store',
            help='path(s) or UID(s) of container(s) by which to filter records'
        )

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        """Execute the share-report command."""
        base.require_login(context)

        if kwargs.get('share_date'):
            base.require_enterprise_admin(context)
        
        if context.vault is None:
            raise base.CommandError('Vault is not initialized. Login to initialize vault.')

        output_format = kwargs.get('format', 'table')
        output_file = kwargs.get('output')
        show_team_users = kwargs.get('show_team_users', False)
        verbose = kwargs.get('verbose', False) or show_team_users

        config = share_report.ShareReportConfig(
            record_filter=kwargs.get('record'),
            user_filter=kwargs.get('user'),
            container_filter=kwargs.get('container') or None,
            show_ownership=kwargs.get('owner', False),
            show_share_date=kwargs.get('share_date', False),
            folders_only=kwargs.get('folders', False),
            verbose=verbose,
            show_team_users=show_team_users
        )

        enterprise = context.enterprise_data
        generator = share_report.ShareReportGenerator(
            vault=context.vault,
            enterprise=enterprise,
            auth=context.auth,
            config=config
        )

        if config.folders_only:
            return self._generate_folders_report(generator, output_format, output_file)
        if config.show_ownership:
            return self._generate_ownership_report(
                generator, output_format, output_file, verbose,
                show_share_date=config.show_share_date
            )
        if config.record_filter:
            return self._generate_record_detail_report(generator, config)
        if config.user_filter:
            return self._generate_user_shares_report(generator, config, output_format, output_file)
        return self._generate_summary_report(generator, output_format, output_file)

    def _generate_folders_report(
        self,
        generator: share_report.ShareReportGenerator,
        output_format: str,
        output_file: Optional[str]
    ) -> Optional[str]:
        """Generate shared folders report."""
        entries = generator.generate_shared_folders_report()
        headers = share_report.ShareReportGenerator.get_headers(folders_only=True)
        table = [[e.folder_uid, e.folder_name, e.shared_to, e.permissions, e.folder_path] 
                 for e in entries]

        return report_utils.dump_report_data(
            table,
            self._format_headers(headers, output_format),
            fmt=output_format,
            filename=output_file,
            title='Shared folders'
        )

    def _generate_ownership_report(
        self,
        generator: share_report.ShareReportGenerator,
        output_format: str,
        output_file: Optional[str],
        verbose: bool,
        show_share_date: bool = False
    ) -> Optional[str]:
        """Generate record ownership report."""
        entries = generator.generate_records_report()
        headers = share_report.ShareReportGenerator.get_headers(
            ownership=True, show_share_date=show_share_date
        )
        table = [
            [e.record_owner, e.record_uid, e.record_title,
             e.shared_with if verbose else e.shared_with_count,
             '\n'.join(e.folder_paths)] + ([e.share_date or ''] if show_share_date else [])
            for e in entries
        ]

        return report_utils.dump_report_data(
            table,
            self._format_headers(headers, output_format, exclude_json=True),
            fmt=output_format,
            filename=output_file,
            sort_by=0,
            row_number=True
        )

    def _generate_record_detail_report(
        self,
        generator: share_report.ShareReportGenerator,
        config: share_report.ShareReportConfig
    ) -> None:
        """Generate detailed report for specific records (always verbose)."""
        logger = api.get_logger()
        
        verbose_config = share_report.ShareReportConfig(
            record_filter=config.record_filter,
            user_filter=config.user_filter,
            container_filter=config.container_filter,
            show_ownership=config.show_ownership,
            show_share_date=config.show_share_date,
            folders_only=config.folders_only,
            verbose=True,
            show_team_users=config.show_team_users
        )
        
        verbose_generator = share_report.ShareReportGenerator(
            vault=generator.vault,
            enterprise=generator._enterprise,
            auth=generator._auth,
            config=verbose_config
        )
        
        entries = verbose_generator.generate_records_report()
        if not entries:
            logger.info('No records found matching the criteria.')
            return
        
        for entry in entries:
            logger.info('')
            logger.info(f'{"Record UID:":>20}   {entry.record_uid}')
            logger.info(f'{"Title:":>20}   {entry.record_title}')
            self._log_shared_with(logger, entry.shared_with)
            logger.info('')
    
    def _log_shared_with(self, logger, shared_with: str) -> None:
        """Log shared with information."""
        if not shared_with:
            logger.info(f'{"Shared with:":>20}   Not shared')
            return
        
        for i, line in enumerate(shared_with.split('\n')):
            label = 'Shared with:' if i == 0 else ''
            logger.info(f'{label:>20}   {line}')

    def _generate_user_shares_report(
        self,
        generator: share_report.ShareReportGenerator,
        config: share_report.ShareReportConfig,
        output_format: str,
        output_file: Optional[str]
    ) -> Optional[str]:
        """Generate report of shares filtered by user."""
        entries = generator.generate_records_report()
        headers = ['username', 'record_owner', 'record_uid', 'record_title']
        table = [
            [user, e.record_owner, e.record_uid, e.record_title]
            for e in entries
            for user in (config.user_filter or [])
        ]

        return report_utils.dump_report_data(
            table,
            self._format_headers(headers, output_format),
            fmt=output_format,
            filename=output_file,
            group_by=0,
            row_number=True
        )

    def _generate_summary_report(
        self,
        generator: share_report.ShareReportGenerator,
        output_format: str,
        output_file: Optional[str]
    ) -> Optional[str]:
        """Generate summary report of shares by target."""
        entries = generator.generate_summary_report()
        headers = share_report.ShareReportGenerator.get_headers()
        table = [[e.shared_to, e.record_count, e.shared_folder_count] for e in entries]

        return report_utils.dump_report_data(
            table,
            self._format_headers(headers, output_format),
            fmt=output_format,
            filename=output_file,
            group_by=0,
            row_number=True
        )
    
    @staticmethod
    def _format_headers(headers: list, output_format: str, exclude_json: bool = False) -> list:
        """Format headers based on output format."""
        if output_format == 'table' or (exclude_json and output_format != 'json'):
            return [report_utils.field_to_title(h) for h in headers]
        return headers

