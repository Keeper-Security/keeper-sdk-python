"""Enterprise security audit report functionality for Keeper SDK."""

import base64
import dataclasses
import json
from json import JSONDecodeError
from typing import Optional, List, Dict, Any, Iterable

from cryptography.hazmat.primitives.asymmetric import rsa, ec

from ..authentication import keeper_auth
from .. import crypto
from ..proto import APIRequest_pb2, enterprise_pb2
from . import enterprise_types


SECURITY_SCORE_KEYS = (
    'weak_record_passwords',
    'fair_record_passwords',
    'medium_record_passwords',
    'strong_record_passwords',
    'total_record_passwords',
    'unique_record_passwords',
)

BREACHWATCH_SCORE_KEYS = (
    'passed_records',
    'at_risk_records',
    'ignored_records'
)

SCORE_DATA_KEYS = SECURITY_SCORE_KEYS + BREACHWATCH_SCORE_KEYS


def is_pw_strong(strength: Optional[int]) -> bool:
    """Check if password strength is strong (>= 80)."""
    return isinstance(strength, int) and strength >= 80


def is_pw_fair(strength: Optional[int]) -> bool:
    """Check if password strength is fair (40-79)."""
    return isinstance(strength, int) and 40 <= strength < 80


def is_pw_weak(strength: Optional[int]) -> bool:
    """Check if password strength is weak (< 40)."""
    return isinstance(strength, int) and strength < 40


def is_rec_at_risk(bw_result: Optional[int]) -> bool:
    """Check if record is at risk based on BreachWatch result."""
    return isinstance(bw_result, int) and bw_result in (1, 2)


def passed_bw_check(bw_result: Optional[int]) -> bool:
    """Check if record passed BreachWatch check."""
    return isinstance(bw_result, int) and bw_result == 0


@dataclasses.dataclass
class SecurityAuditEntry:
    """Represents a single user entry in the security audit report."""
    enterprise_user_id: int
    email: str
    username: str = ''
    node_path: str = ''
    total: int = 0
    weak: int = 0
    fair: int = 0
    medium: int = 0
    strong: int = 0
    reused: int = 0
    unique: int = 0
    passed: int = 0
    at_risk: int = 0
    ignored: int = 0
    security_score: int = 25
    two_factor_enabled: bool = False
    sync_pending: Optional[bool] = None


@dataclasses.dataclass
class SecurityAuditConfig:
    """Configuration for security audit report generation."""
    node_ids: Optional[List[int]] = None
    show_breachwatch: bool = False
    show_updated: bool = False
    save_report: bool = False
    score_type: str = 'default'
    attempt_fix: bool = False


@dataclasses.dataclass
class SecurityAuditError:
    """Represents an error encountered during security audit processing."""
    email: str
    error_message: str


class SecurityAuditReportGenerator:
    """Generates security audit reports for enterprise users."""

    def __init__(
        self,
        enterprise_data: enterprise_types.IEnterpriseData,
        auth: keeper_auth.KeeperAuth,
        config: Optional[SecurityAuditConfig] = None
    ) -> None:
        self._enterprise_data = enterprise_data
        self._auth = auth
        self._config = config or SecurityAuditConfig()
        self._tree_key: Optional[bytes] = None
        self._user_lookup: Optional[Dict[int, Dict[str, Any]]] = None
        self._errors: List[SecurityAuditError] = []
        self._updated_reports: List[APIRequest_pb2.SecurityReport] = []
        self._rsa_key: Optional[rsa.RSAPrivateKey] = None
        self._ec_key: Optional[ec.EllipticCurvePrivateKey] = None

    @property
    def enterprise_data(self) -> enterprise_types.IEnterpriseData:
        return self._enterprise_data

    @property
    def config(self) -> SecurityAuditConfig:
        return self._config

    @property
    def errors(self) -> List[SecurityAuditError]:
        """Get list of errors encountered during report generation."""
        return self._errors

    @property
    def has_errors(self) -> bool:
        """Check if any errors were encountered."""
        return len(self._errors) > 0

    @property
    def updated_reports(self) -> List[APIRequest_pb2.SecurityReport]:
        """Get list of updated security reports ready to save."""
        return self._updated_reports

    def _add_error(self, email: str, message: str) -> None:
        """Add an error to the error list."""
        self._errors.append(SecurityAuditError(email=email, error_message=message))

    def _build_user_lookup(self) -> Dict[int, Dict[str, Any]]:
        """Build a lookup dictionary of user info by enterprise user ID."""
        if self._user_lookup is not None:
            return self._user_lookup

        self._user_lookup = {}
        for user in self._enterprise_data.users.get_all_entities():
            email = user.username
            username = user.full_name if user.full_name else None
            if username is None or not username.strip():
                username = email
            node_id = user.node_id or 0
            self._user_lookup[user.enterprise_user_id] = {
                'username': username,
                'email': email,
                'node_id': node_id
            }
        return self._user_lookup

    def resolve_user_info(self, enterprise_user_id: int) -> Dict[str, Any]:
        """Resolve user information by enterprise user ID."""
        user_lookup = self._build_user_lookup()
        info = {
            'username': str(enterprise_user_id),
            'email': str(enterprise_user_id),
            'node_id': 0
        }
        info = user_lookup.get(enterprise_user_id, info)
        return info

    @staticmethod
    def get_node_path(
        enterprise_data: enterprise_types.IEnterpriseData,
        node_id: int,
        omit_root: bool = False
    ) -> str:
        """Get the full path for a node as a backslash-separated string.

        This is a convenience wrapper around Node.get_path().
        """
        node = enterprise_data.nodes.get_entity(node_id)
        if node:
            return node.get_path(enterprise_data, omit_root)
        return ''

    @staticmethod
    def get_strong_by_total(total: int, strong: int) -> float:
        """Calculate the ratio of strong passwords to total passwords."""
        return 0 if (total == 0) else (strong / total)

    @staticmethod
    def get_security_score(total: int, strong: int, unique: int,
                           two_factor_on: bool, master_password: int = 1) -> float:
        """Calculate the overall security score."""
        strong_by_total = SecurityAuditReportGenerator.get_strong_by_total(total, strong)
        unique_by_total = 0 if (total == 0) else (unique / total)
        two_factor_val = 1 if two_factor_on else 0
        score = (strong_by_total + unique_by_total + master_password + two_factor_val) / 4
        return score

    @staticmethod
    def flatten_report_data(data: Dict[str, Any], num_reused_pws: int) -> Dict[str, int]:
        """Flatten security report data into a simple dictionary."""
        sec_stats = data.get('securityAuditStats', {})
        bw_stats = data.get('bwStats', {})
        total = data.get('total_record_passwords') or sec_stats.get('total_record_passwords', 0)
        result = {k: data.get(k) or sec_stats.get(k) or bw_stats.get(k, 0) for k in SCORE_DATA_KEYS}
        result['unique_record_passwords'] = total - num_reused_pws
        
        if not sec_stats:
            weak = result.get('weak_record_passwords', 0)
            strong = result.get('strong_record_passwords', 0)
            result['medium_record_passwords'] = total - weak - strong
        return result

    @staticmethod
    def format_report_data(flattened_data: Dict[str, int]) -> Dict[str, Dict[str, int]]:
        """Format flattened data back into structured report format."""
        sec_stats = {k: flattened_data.get(k) for k in SECURITY_SCORE_KEYS}
        bw_stats = {k: flattened_data.get(k) for k in BREACHWATCH_SCORE_KEYS}
        return {'securityAuditStats': sec_stats, 'bwStats': bw_stats}

    def _decrypt_incremental_security_data(
        self,
        sec_data: bytes,
        key_type: int,
        current_email: str
    ) -> Optional[Dict[str, int]]:
        """Decrypt security data from incremental report."""
        decrypted = None
        if sec_data:
            try:
                if key_type == enterprise_pb2.KT_ENCRYPTED_BY_PUBLIC_KEY_ECC:
                    decrypted_bytes = crypto.decrypt_ec(sec_data, self._ec_key)
                else:
                    decrypted_bytes = crypto.decrypt_rsa(sec_data, self._rsa_key)
            except Exception as e:
                self._add_error(current_email, f'Decrypt fail (incremental data): {e}')
                return None

            try:
                decoded = decrypted_bytes.decode()
            except UnicodeDecodeError:
                self._add_error(current_email, 'Decode fail, incremental data (base 64)')
                decoded_b64 = base64.b64encode(decrypted_bytes).decode('ascii')
                self._add_error(current_email, decoded_b64)
                return None
            except Exception as e:
                self._add_error(current_email, f'Decode fail: {e}')
                return None

            try:
                decrypted = json.loads(decoded)
            except JSONDecodeError:
                self._add_error(current_email, f'Invalid JSON: {decoded}')
            except Exception as e:
                self._add_error(current_email, f'Load fail (incremental data). {e}')

        return decrypted

    def _get_updated_security_report_row(
        self,
        sr: APIRequest_pb2.SecurityReport,
        last_saved_data: Dict[str, int],
        current_email: str
    ) -> Dict[str, int]:
        """Get updated security report row by applying incremental data."""

        def decrypt_incremental_data(inc_data: APIRequest_pb2.SecurityReportIncrementalData
                                     ) -> Dict[str, Optional[Dict[str, int]]]:
            decrypted = {
                'old': self._decrypt_incremental_security_data(
                    inc_data.oldSecurityData, inc_data.oldDataEncryptionType, current_email),
                'curr': self._decrypt_incremental_security_data(
                    inc_data.currentSecurityData, inc_data.currentDataEncryptionType, current_email)
            }
            return decrypted

        def get_security_score_deltas(rec_sec_data: Dict[str, Any], delta: int) -> Dict[str, int]:
            bw_result = rec_sec_data.get('bw_result')
            pw_strength = rec_sec_data.get('strength')
            sec_deltas = {k: 0 for k in SECURITY_SCORE_KEYS}
            bw_deltas = {k: 0 for k in BREACHWATCH_SCORE_KEYS}

            sec_key = 'strong_record_passwords' if is_pw_strong(pw_strength) \
                else 'fair_record_passwords' if is_pw_fair(pw_strength) \
                else 'weak_record_passwords' if is_pw_weak(pw_strength) \
                else 'medium_record_passwords'
            sec_deltas[sec_key] = delta
            sec_deltas['total_record_passwords'] = delta

            bw_key = 'at_risk_records' if is_rec_at_risk(bw_result) \
                else 'passed_records' if passed_bw_check(bw_result) \
                else 'ignored_records'
            bw_deltas[bw_key] = delta

            return {**sec_deltas, **bw_deltas}

        def apply_score_deltas(sec_data: Dict[str, int], deltas: Dict[str, int]) -> Dict[str, int]:
            new_scores = {k: v + sec_data.get(k, 0) for k, v in deltas.items()}
            return {**sec_data, **new_scores}

        def update_scores(user_sec_data: Dict[str, int],
                          inc_dataset: List[Dict[str, Optional[Dict[str, int]]]]) -> Dict[str, int]:
            def update(u_sec_data: Dict[str, int], old_sec_d: Optional[Dict[str, Any]],
                       diff: int) -> Dict[str, int]:
                if not old_sec_d:
                    return u_sec_data
                deltas = get_security_score_deltas(old_sec_d, diff)
                return apply_score_deltas(u_sec_data, deltas)

            for inc_data in inc_dataset:
                if any(d for d in inc_data.values() if d is not None and d.get('strength') is None):
                    self._add_error(current_email, 'Invalid data: "strength" is undefined')
                    break
                existing_data_keys = [k for k, d in inc_data.items() if d]
                for k in existing_data_keys:
                    user_sec_data = update(user_sec_data, inc_data.get(k), -1 if k == 'old' else 1)

            return user_sec_data

        report_data = {**last_saved_data}
        incremental_dataset = sr.securityReportIncrementalData
        if incremental_dataset:
            decrypted_dataset = [decrypt_incremental_data(x) for x in incremental_dataset]
            report_data = update_scores(report_data, decrypted_dataset)

        total = report_data.get('total_record_passwords', 0)
        report_data['unique_record_passwords'] = total - sr.numberOfReusedPassword
        return report_data

    def generate_report(self) -> List[SecurityAuditEntry]:
        """Generate the security audit report."""
        self._errors.clear()
        self._updated_reports.clear()

        enterprise_info = self._enterprise_data.enterprise_info
        tree_key = enterprise_info.tree_key
        self._rsa_key = enterprise_info._rsa_private_key
        self._ec_key = enterprise_info._ec_private_key

        from_page = 0
        complete = False
        entries: List[SecurityAuditEntry] = []

        while not complete:
            rq = APIRequest_pb2.SecurityReportRequest()
            rq.fromPage = from_page
            security_report_rs = self._auth.execute_auth_rest(
                'enterprise/get_security_report_data',
                rq,
                response_type=APIRequest_pb2.SecurityReportResponse
            )
            if security_report_rs is None:
                self._add_error('Enterprise', 'Failed to get security report data')
                break

            to_page = security_report_rs.toPage
            complete = security_report_rs.complete
            from_page = to_page + 1

            try:
                if not self._rsa_key and len(security_report_rs.enterprisePrivateKey) > 0:
                    key_data = crypto.decrypt_aes_v2(security_report_rs.enterprisePrivateKey, tree_key)
                    self._rsa_key = crypto.load_rsa_private_key(key_data)
                if not self._ec_key and len(security_report_rs.enterpriseEccPrivateKey) > 0:
                    key_data = crypto.decrypt_aes_v2(security_report_rs.enterpriseEccPrivateKey, tree_key)
                    self._ec_key = crypto.load_ec_private_key(key_data)
            except Exception as e:
                self._add_error('Enterprise', f'Invalid enterprise private key: {e}')
                continue

            for sr in security_report_rs.securityReport:
                user_info = self.resolve_user_info(sr.enterpriseUserId)
                node_id = user_info.get('node_id', 0)

                if self._config.node_ids and node_id not in self._config.node_ids:
                    continue

                email = user_info.get('email', str(sr.enterpriseUserId))
                username = user_info.get('username', str(sr.enterpriseUserId))
                node_path = self.get_node_path(self._enterprise_data, node_id) if node_id > 0 else ''
                twofa_on = sr.twoFactor != 'two_factor_disabled'

                if sr.encryptedReportData:
                    try:
                        sri = crypto.decrypt_aes_v2(sr.encryptedReportData, tree_key)
                    except Exception:
                        continue

                    try:
                        data = self.flatten_report_data(json.loads(sri), sr.numberOfReusedPassword)
                    except Exception:
                        continue
                else:
                    data = {dk: 0 for dk in SCORE_DATA_KEYS}

                if self._config.show_updated:
                    data = self._get_updated_security_report_row(sr, data, email)

                if self.has_errors:
                    continue

                if self._config.save_report:
                    updated_sr = APIRequest_pb2.SecurityReport()
                    updated_sr.revision = security_report_rs.asOfRevision
                    updated_sr.enterpriseUserId = sr.enterpriseUserId
                    report = json.dumps(self.format_report_data(data)).encode('utf-8')
                    updated_sr.encryptedReportData = crypto.encrypt_aes_v2(report, tree_key)
                    self._updated_reports.append(updated_sr)

                strong = data.get('strong_record_passwords', 0)
                total = data.get('total_record_passwords', 0)
                unique = data.get('unique_record_passwords', 0)
                master_pw_strength = 1

                if self._config.score_type == 'strong_passwords':
                    score = int(100 * self.get_strong_by_total(total, strong))
                else:
                    score = int(100 * round(self.get_security_score(total, strong, unique, twofa_on, master_pw_strength), 2))

                sync_pending = True if total == 0 and sr.numberOfReusedPassword != 0 else None

                entry = SecurityAuditEntry(
                    enterprise_user_id=sr.enterpriseUserId,
                    email=email,
                    username=username,
                    node_path=node_path,
                    total=total,
                    weak=data.get('weak_record_passwords', 0),
                    fair=data.get('fair_record_passwords', 0),
                    medium=data.get('medium_record_passwords', 0),
                    strong=strong,
                    reused=sr.numberOfReusedPassword,
                    unique=unique,
                    passed=data.get('passed_records', 0),
                    at_risk=data.get('at_risk_records', 0),
                    ignored=data.get('ignored_records', 0),
                    security_score=score,
                    two_factor_enabled=twofa_on,
                    sync_pending=sync_pending
                )
                entries.append(entry)

        return entries

    def generate_report_rows(self, breachwatch: bool = False) -> Iterable[List[Any]]:
        """Generate report rows suitable for tabular output."""
        for entry in self.generate_report():
            if breachwatch:
                yield [
                    entry.email, entry.username, entry.sync_pending,
                    entry.at_risk, entry.passed, entry.ignored
                ]
            else:
                yield [
                    entry.email, entry.username, entry.sync_pending,
                    entry.weak, entry.fair, entry.medium, entry.strong,
                    entry.reused, entry.unique, entry.security_score,
                    'On' if entry.two_factor_enabled else 'Off', entry.node_path
                ]

    def generate_error_rows(self) -> Iterable[List[Any]]:
        """Generate error report rows."""
        for error in self._errors:
            yield [error.email, error.error_message]

    def save_updated_reports(self) -> None:
        """Save updated security reports to the server."""
        if not self._updated_reports:
            return
        save_rq = APIRequest_pb2.SecurityReportSaveRequest()
        for r in self._updated_reports:
            save_rq.securityReport.append(r)
        self._auth.execute_auth_rest('enterprise/save_summary_security_report', save_rq)

    def sync_problem_vaults(self, emails: List[str]) -> None:
        """
        Perform a hard sync for vaults with invalid security-data.

        This initiates a FORCE_CLIENT_RESEND_SECURITY_DATA sync for the specified
        user vaults. Associated security scores will be reset and will be inaccurate
        until affected vaults can re-calculate and update their security-data.

        Args:
            emails: List of email addresses of users whose vaults need syncing.
        """
        if not emails:
            return

        userid_lookup = {
            u.username: u.enterprise_user_id
            for u in self._enterprise_data.users.get_all_entities()
        }

        userids = [uid for email in emails if (uid := userid_lookup.get(email))]

        if not userids:
            return

        CHUNK_SIZE = 999
        while userids:
            chunk = userids[:CHUNK_SIZE]
            userids = userids[CHUNK_SIZE:]

            rq = enterprise_pb2.ClearSecurityDataRequest()
            rq.type = enterprise_pb2.FORCE_CLIENT_RESEND_SECURITY_DATA
            rq.allUsers = False
            rq.enterpriseUserId.extend(chunk)
            self._auth.execute_auth_rest('enterprise/clear_security_data', rq)

    @staticmethod
    def get_headers(breachwatch: bool = False) -> List[str]:
        """Get report headers."""
        if breachwatch:
            return ['email', 'name', 'sync_pending', 'at_risk', 'passed', 'ignored']
        return ['email', 'name', 'sync_pending', 'weak', 'fair', 'medium', 'strong',
                'reused', 'unique', 'securityScore', 'twoFactorChannel', 'node']

    @staticmethod
    def get_error_headers() -> List[str]:
        """Get error report headers."""
        return ['vault_owner', 'error_message']


def generate_security_audit_report(
    enterprise_data: enterprise_types.IEnterpriseData,
    auth: keeper_auth.KeeperAuth,
    node_ids: Optional[List[int]] = None,
    score_type: str = 'default'
) -> List[SecurityAuditEntry]:
    """Convenience function to generate a security audit report."""
    config = SecurityAuditConfig(node_ids=node_ids, score_type=score_type)
    return SecurityAuditReportGenerator(enterprise_data, auth, config).generate_report()

