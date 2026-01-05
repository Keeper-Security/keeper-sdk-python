"""Security Audit Report command for Keeper CLI."""

import argparse
from typing import Any, List, Optional

from keepersdk.enterprise import security_audit_report

from . import base, enterprise_utils
from ..helpers import report_utils
from ..params import KeeperParams
from .. import api, prompt_utils


SECURITY_AUDIT_REPORT_DESCRIPTION = '''
Security Audit Report Command Syntax Description:

Column Name       Description
  username          user name
  email             e-mail address
  weak              number of records whose password strength is in the weak category
  fair              number of records whose password strength is in the fair category
  medium            number of records whose password strength is in the medium category
  strong            number of records whose password strength is in the strong category
  reused            number of reused passwords
  unique            number of unique passwords
  securityScore     security score
  twoFactorChannel  2FA - ON/OFF

--format:
            csv     CSV format
            json    JSON format
            table   Table format (default)
'''


class SecurityAuditReportCommand(base.ArgparseCommand, enterprise_utils.EnterpriseMixin):
    """Command to generate a security audit report for enterprise users."""

    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='security-audit-report',
            description='Run a security audit report.',
            parents=[base.report_output_parser]
        )
        SecurityAuditReportCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument(
            '--syntax-help',
            dest='syntax_help',
            action='store_true',
            help='display help'
        )
        parser.add_argument(
            '-n', '--node',
            action='append',
            help='name(s) or UID(s) of node(s) to filter results of the report by'
        )
        parser.add_argument(
            '-b', '--breachwatch',
            dest='breachwatch',
            action='store_true',
            help='display BreachWatch report. Ignored if BreachWatch is not active.'
        )
        parser.add_argument(
            '-s', '--save',
            action='store_true',
            help='save updated security audit reports'
        )
        parser.add_argument(
            '-su', '--show-updated',
            action='store_true',
            help='show updated data'
        )
        parser.add_argument(
            '-st', '--score-type',
            action='store',
            choices=['strong_passwords', 'default'],
            default='default',
            help='define how score is calculated'
        )
        parser.add_argument(
            '--attempt-fix',
            action='store_true',
            help='do a "hard" sync for vaults with invalid security-data. Associated security scores '
                 'are reset and will be inaccurate until affected vaults can re-calculate and update '
                 'their security-data'
        )
        parser.add_argument(
            '-f', '--force',
            action='store_true',
            help='skip confirmation prompts (non-interactive mode)'
        )

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        base.require_login(context)
        base.require_enterprise_admin(context)

        logger = api.get_logger()

        if kwargs.get('syntax_help'):
            logger.info(SECURITY_AUDIT_REPORT_DESCRIPTION)
            return

        enterprise_data = context.enterprise_data
        show_breachwatch = kwargs.get('breachwatch')

        if show_breachwatch:
            if not context.auth.auth_context.license.get('breachWatchEnabled'):
                raise base.CommandError(
                    'BreachWatch is not enabled for this account. '
                    'Please contact your administrator to enable this feature.'
                )
            logger.info('Generating BreachWatch security audit report...')

        node_ids = self._resolve_node_ids(enterprise_data, kwargs.get('node'))
        attempt_fix = kwargs.get('attempt_fix', False)
        force = kwargs.get('force', False)
        save_report = kwargs.get('save') or attempt_fix

        config = security_audit_report.SecurityAuditConfig(
            node_ids=node_ids if node_ids else None,
            show_breachwatch=show_breachwatch,
            show_updated=save_report or kwargs.get('show_updated'),
            save_report=save_report,
            score_type=kwargs.get('score_type', 'default'),
            attempt_fix=attempt_fix
        )

        generator = security_audit_report.SecurityAuditReportGenerator(
            enterprise_data, context.auth, config
        )
        rows: List[List[Any]] = list(generator.generate_report_rows(breachwatch=show_breachwatch))

        fmt = kwargs.get('format', 'table')
        out = kwargs.get('output')

        if generator.has_errors:
            if attempt_fix:
                return self._handle_attempt_fix(generator, context, out, fmt)
            result = self._display_error_report(generator, out, fmt)
            fix_instructions = ('\nNote: To resolve the issues found above, re-run this command with the'
                                ' --attempt-fix switch, i.e., run\n\tsecurity-audit-report --attempt-fix')
            if result is None:
                logger.error(fix_instructions)
            else:
                result += fix_instructions
            return result

        if config.save_report and generator.updated_reports:
            if force or attempt_fix or self._confirm_save(len(generator.updated_reports)):
                generator.save_updated_reports()
                logger.info(f'Saved {len(generator.updated_reports)} updated security report(s).')
            else:
                logger.info('Save operation cancelled.')

        return self._format_report(rows, show_breachwatch, fmt, out)

    def _resolve_node_ids(self, enterprise_data, nodes: Optional[List[str]]) -> List[int]:
        """Resolve node names/IDs to node IDs."""
        if not nodes:
            return []

        node_ids = []
        for name_or_id in nodes:
            for n in enterprise_data.nodes.get_all_entities():
                if name_or_id == str(n.node_id) or name_or_id == n.name:
                    node_ids.append(n.node_id)
                    break
        return node_ids

    def _format_report(
        self,
        rows: List[List[Any]],
        show_breachwatch: bool,
        fmt: str,
        out: Optional[str]
    ) -> Optional[str]:
        """Format and output the security audit report."""
        headers = security_audit_report.SecurityAuditReportGenerator.get_headers(breachwatch=show_breachwatch)
        if fmt == 'table':
            headers = [report_utils.field_to_title(x) for x in headers]

        report_title = f'Security Audit Report{" (BreachWatch)" if show_breachwatch else ""}'
        return report_utils.dump_report_data(rows, headers, fmt=fmt, filename=out, title=report_title)

    @staticmethod
    def _confirm_save(count: int) -> bool:
        """Prompt user for confirmation before saving security reports (CLI interaction)."""
        question = f'Do you want to save {count} updated security report(s)?'
        answer = prompt_utils.user_choice(question, 'yn', default='n')
        return answer.lower() == 'y'

    @staticmethod
    def _display_error_report(
        generator: security_audit_report.SecurityAuditReportGenerator,
        out: Optional[str],
        fmt: str
    ) -> Optional[str]:
        """Format and output the error report with enterprise-level errors first."""
        title = 'Security Audit Report - Problems Found\nSecurity data could not be parsed for the following vaults:'
        headers = security_audit_report.SecurityAuditReportGenerator.get_error_headers()
        if fmt == 'table':
            headers = [report_utils.field_to_title(x) for x in headers]

        error_rows = list(generator.generate_error_rows())
        error_rows.sort(key=lambda row: row[0] != 'Enterprise')
        return report_utils.dump_report_data(error_rows, headers, fmt=fmt, filename=out, title=title)

    def _handle_attempt_fix(
        self,
        generator: security_audit_report.SecurityAuditReportGenerator,
        context: KeeperParams,
        out: Optional[str],
        fmt: str
    ) -> Optional[str]:
        """Sync problem vaults and regenerate the report."""
        problem_emails = [error.email for error in generator.errors if '@' in error.email]

        if problem_emails:
            generator.sync_problem_vaults(problem_emails)

        new_config = security_audit_report.SecurityAuditConfig(
            node_ids=generator.config.node_ids,
            show_breachwatch=generator.config.show_breachwatch,
            show_updated=True,
            save_report=True,
            score_type=generator.config.score_type,
            attempt_fix=False
        )
        new_generator = security_audit_report.SecurityAuditReportGenerator(
            context.enterprise_data, context.auth, new_config
        )
        rows = list(new_generator.generate_report_rows(breachwatch=generator.config.show_breachwatch))

        if new_generator.updated_reports:
            new_generator.save_updated_reports()

        return self._format_report(rows, generator.config.show_breachwatch, fmt, out)

