"""Share Report command for Keeper CLI.

This module provides the CLI command for generating share reports
for records and shared folders in a Keeper vault.

Usage:
    share-report                         # Summary of shares by target
    share-report -o                      # Record ownership report
    share-report -f                      # Shared folders report
    share-report -v -o                   # Verbose ownership report
    share-report -r <record>             # Report for specific record(s)
    share-report -e <email>              # Filter by share target
"""

import argparse
import os
from typing import Any, List, Optional

from keepersdk.vault import share_report

from . import base
from ..helpers import report_utils
from ..params import KeeperParams
from .. import api


class ShareReportCommand(base.ArgparseCommand):
    """Command to generate share reports for records and shared folders.
    
    This command generates comprehensive reports about record and folder
    sharing within the vault. It supports multiple report modes:
    
    - Summary mode (default): Shows share counts by target
    - Ownership mode (-o): Shows records grouped by owner with share details
    - Shared folders mode (-f): Shows shared folder permissions
    """

    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='share-report',
            description='Generates a report of shared records',
            parents=[base.report_output_parser]
        )
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
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        """Execute the share-report command.
        
        Args:
            context: The KeeperParams context with vault and auth info
            **kwargs: Command arguments from argparse
            
        Returns:
            Report data as string (for JSON/CSV) or None (for table output)
        """
        base.require_login(context)

        logger = api.get_logger()
        
        # Check vault is available
        if context.vault is None:
            raise base.CommandError('Vault data not available. Please run sync-down first.')

        output_format = kwargs.get('format', 'table')
        output_file = kwargs.get('output')

        # Handle show-team-users implying verbose
        show_team_users = kwargs.get('show_team_users', False)
        verbose = kwargs.get('verbose', False) or show_team_users

        # Build configuration from kwargs
        config = share_report.ShareReportConfig(
            record_filter=kwargs.get('record'),
            user_filter=kwargs.get('user'),
            container_filter=kwargs.get('container') if kwargs.get('container') else None,
            show_ownership=kwargs.get('owner', False),
            show_share_date=kwargs.get('share_date', False),
            folders_only=kwargs.get('folders', False),
            verbose=verbose,
            show_team_users=show_team_users
        )

        # Get enterprise data if available (for team expansion)
        enterprise = None
        if hasattr(context, 'enterprise_data') and context.enterprise_data:
            enterprise = context.enterprise_data

        # Create generator using SDK
        generator = share_report.ShareReportGenerator(
            vault=context.vault,
            enterprise=enterprise,
            auth=context.auth,
            config=config
        )

        # Generate appropriate report based on configuration
        if config.folders_only:
            return self._generate_folders_report(generator, output_format, output_file, show_team_users)
        elif config.show_ownership:
            return self._generate_ownership_report(generator, output_format, output_file, verbose)
        elif config.record_filter:
            return self._generate_record_detail_report(generator, config, output_format, show_team_users)
        elif config.user_filter:
            return self._generate_user_shares_report(generator, config, output_format, output_file)
        else:
            return self._generate_summary_report(generator, output_format, output_file)

    def _generate_folders_report(
        self,
        generator: share_report.ShareReportGenerator,
        output_format: str,
        output_file: Optional[str],
        show_team_users: bool
    ) -> Optional[str]:
        """Generate shared folders report."""
        logger = api.get_logger()
        
        # Log shared folder count for debugging
        sf_count = generator.vault.vault_data.shared_folder_count
        logger.debug(f"Vault has {sf_count} shared folders")
        
        entries = generator.generate_shared_folders_report()
        logger.debug(f"Generated {len(entries)} shared folder entries")
        
        headers = share_report.ShareReportGenerator.get_headers(folders_only=True)
        table = [[e.folder_uid, e.folder_name, e.shared_to, e.permissions, e.folder_path] 
                 for e in entries]

        if output_format == 'table':
            headers = [report_utils.field_to_title(h) for h in headers]

        return report_utils.dump_report_data(
            table, headers,
            fmt=output_format,
            filename=output_file,
            title='Shared folders'
        )

    def _generate_ownership_report(
        self,
        generator: share_report.ShareReportGenerator,
        output_format: str,
        output_file: Optional[str],
        verbose: bool
    ) -> Optional[str]:
        """Generate record ownership report."""
        entries = generator.generate_records_report()
        
        headers = share_report.ShareReportGenerator.get_headers(ownership=True)
        table = []
        
        for e in entries:
            shared_info = e.shared_with if verbose else e.shared_with_count
            table.append([e.record_owner, e.record_uid, e.record_title, 
                         shared_info, '\n'.join(e.folder_paths)])

        if output_format != 'json':
            headers = [report_utils.field_to_title(h) for h in headers]

        return report_utils.dump_report_data(
            table, headers,
            fmt=output_format,
            filename=output_file,
            sort_by=0,
            row_number=True
        )

    def _generate_record_detail_report(
        self,
        generator: share_report.ShareReportGenerator,
        config: share_report.ShareReportConfig,
        output_format: str,
        show_team_users: bool
    ) -> None:
        """Generate detailed report for specific records.
        
        Note: This report always shows verbose usernames (not just counts)
        to match the expected behavior of the original implementation.
        """
        logger = api.get_logger()
        
        # For record detail report, we need verbose output with usernames
        # Create a new config with verbose=True for detailed record view
        verbose_config = share_report.ShareReportConfig(
            record_filter=config.record_filter,
            user_filter=config.user_filter,
            container_filter=config.container_filter,
            show_ownership=config.show_ownership,
            show_share_date=config.show_share_date,
            folders_only=config.folders_only,
            verbose=True,  # Always verbose for record detail
            show_team_users=config.show_team_users
        )
        
        # Get enterprise data if available
        enterprise = generator._enterprise
        
        # Create new generator with verbose config
        verbose_generator = share_report.ShareReportGenerator(
            vault=generator.vault,
            enterprise=enterprise,
            auth=generator._auth,
            config=verbose_config
        )
        
        entries = verbose_generator.generate_records_report()
        
        if not entries:
            logger.info('No records found matching the criteria.')
            return
        
        for entry in entries:
            logger.info('')
            logger.info('{0:>20s}   {1}'.format('Record UID:', entry.record_uid))
            logger.info('{0:>20s}   {1}'.format('Title:', entry.record_title))
            
            # Show shared with usernames (verbose mode always for record detail)
            if entry.shared_with:
                lines = entry.shared_with.split('\n')
                for i, line in enumerate(lines):
                    label = 'Shared with:' if i == 0 else ''
                    logger.info('{0:>20s}   {1}'.format(label, line))
            else:
                logger.info('{0:>20s}   Not shared'.format('Shared with:'))
            
            logger.info('')

    def _generate_user_shares_report(
        self,
        generator: share_report.ShareReportGenerator,
        config: share_report.ShareReportConfig,
        output_format: str,
        output_file: Optional[str]
    ) -> Optional[str]:
        """Generate report of shares filtered by user.
        
        This matches old Commander logic (lines 1209-1220):
        - Always shows username, record_owner, record_uid, record_title
        - Groups by username
        """
        entries = generator.generate_records_report()
        
        # Old code always showed record_owner with -e flag
        headers = ['username', 'record_owner', 'record_uid', 'record_title']
        table = []
        
        for e in entries:
            # Each entry is already filtered to match user_filter
            # Add a row for each user in the filter
            for user in (config.user_filter or []):
                table.append([user, e.record_owner, e.record_uid, e.record_title])

        if output_format == 'table':
            headers = [report_utils.field_to_title(h) for h in headers]

        return report_utils.dump_report_data(
            table, headers,
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

        if output_format == 'table':
            headers = [report_utils.field_to_title(h) for h in headers]

        return report_utils.dump_report_data(
            table, headers,
            fmt=output_format,
            filename=output_file,
            group_by=0,
            row_number=True
        )

