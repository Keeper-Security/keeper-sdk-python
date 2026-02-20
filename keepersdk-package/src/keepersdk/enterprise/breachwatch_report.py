"""BreachWatch report API: generate BreachWatch security audit reports for enterprise users."""

import dataclasses
from typing import Any, Iterable, List, Optional, Tuple

from . import enterprise_types
from ..authentication import keeper_auth
from . import security_audit_report


BREACHWATCH_REPORT_HEADERS = ['email', 'name', 'sync_pending', 'at_risk', 'passed', 'ignored']
REPORT_TITLE = 'Security Audit Report (BreachWatch)'
ERROR_REPORT_TITLE = (
    'Security Audit Report (BreachWatch) - Problems Found\n'
    'Security data could not be parsed for the following vaults:'
)
FIX_INSTRUCTIONS = (
    'To resolve the issues found above, run '
    'security-audit-report -b -s --attempt-fix'
)


@dataclasses.dataclass
class BreachWatchReportResult:
    """Result of running a BreachWatch report; all data needed for display."""
    rows: List[List[Any]]
    headers: List[str]
    report_title: str
    has_errors: bool
    error_rows: List[List[Any]]
    error_headers: List[str]
    error_title: str
    saved_count: int
    fix_instructions: str


class BreachWatchReportGenerator:
    """Generates BreachWatch security audit reports (passed/at_risk/ignored per user)."""

    def __init__(
        self,
        enterprise_data: enterprise_types.IEnterpriseData,
        auth: keeper_auth.KeeperAuth,
        node_ids: Optional[List[int]] = None,
        save_report: bool = True,
        show_updated: bool = True,
    ) -> None:
        config = security_audit_report.SecurityAuditConfig(
            node_ids=node_ids,
            show_breachwatch=True,
            show_updated=show_updated,
            save_report=save_report,
            score_type='default',
            attempt_fix=False,
        )
        self._generator = security_audit_report.SecurityAuditReportGenerator(
            enterprise_data, auth, config
        )

    @property
    def enterprise_data(self) -> enterprise_types.IEnterpriseData:
        return self._generator.enterprise_data

    @property
    def config(self) -> security_audit_report.SecurityAuditConfig:
        return self._generator.config

    @property
    def errors(self) -> List[security_audit_report.SecurityAuditError]:
        return self._generator.errors

    @property
    def has_errors(self) -> bool:
        return self._generator.has_errors

    @property
    def updated_reports(self) -> List[Any]:
        return self._generator.updated_reports

    def generate_report_rows(self) -> Iterable[List[Any]]:
        return self._generator.generate_report_rows(breachwatch=True)

    def generate_error_rows(self) -> Iterable[List[Any]]:
        return self._generator.generate_error_rows()

    def save_updated_reports(self) -> None:
        self._generator.save_updated_reports()

    def sync_problem_vaults(self, emails: List[str]) -> None:
        self._generator.sync_problem_vaults(emails)

    @staticmethod
    def get_headers() -> List[str]:
        return list(BREACHWATCH_REPORT_HEADERS)

    @staticmethod
    def get_error_headers() -> List[str]:
        return security_audit_report.SecurityAuditReportGenerator.get_error_headers()


def run_breachwatch_report(
    enterprise_data: enterprise_types.IEnterpriseData,
    auth: keeper_auth.KeeperAuth,
    node_ids: Optional[List[int]] = None,
    save_report: bool = True,
) -> BreachWatchReportResult:
    generator = BreachWatchReportGenerator(
        enterprise_data, auth,
        node_ids=node_ids,
        save_report=save_report,
        show_updated=save_report,
    )
    rows = list(generator.generate_report_rows())
    error_rows = list(generator.generate_error_rows())
    error_rows.sort(key=lambda row: row[0] != 'Enterprise')
    saved_count = 0
    if not generator.has_errors and generator.updated_reports:
        generator.save_updated_reports()
        saved_count = len(generator.updated_reports)
    return BreachWatchReportResult(
        rows=rows,
        headers=BreachWatchReportGenerator.get_headers(),
        report_title=REPORT_TITLE,
        has_errors=generator.has_errors,
        error_rows=error_rows,
        error_headers=BreachWatchReportGenerator.get_error_headers(),
        error_title=ERROR_REPORT_TITLE,
        saved_count=saved_count,
        fix_instructions=FIX_INSTRUCTIONS,
    )


def generate_breachwatch_report(
    enterprise_data: enterprise_types.IEnterpriseData,
    auth: keeper_auth.KeeperAuth,
    node_ids: Optional[List[int]] = None,
    save_report: bool = True,
) -> Tuple[List[List[Any]], BreachWatchReportGenerator]:
    generator = BreachWatchReportGenerator(
        enterprise_data, auth,
        node_ids=node_ids,
        save_report=save_report,
        show_updated=save_report,
    )
    rows = list(generator.generate_report_rows())
    return rows, generator
