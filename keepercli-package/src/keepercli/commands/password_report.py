
import argparse
from collections import namedtuple
from typing import Optional, Dict, Tuple, Any

from . import base
from .. import api
from ..helpers import folder_utils, report_utils
from ..params import KeeperParams

from keepersdk import utils
from keepersdk.vault import vault_record, vault_extensions


logger = api.get_logger()

PW_SPECIAL_CHARACTERS = '!@#$%()+;<>=?[]{}^.,'
DEFAULT_TRUNCATION_LENGTH = 32
SUPPORTED_RECORD_VERSIONS = (2, 3)

PasswordStrength = namedtuple('PasswordStrength', 'length caps lower digits symbols')


class PasswordReportCommand(base.ArgparseCommand):
    """Command to generate password compliance reports for vault records."""
    
    def __init__(self) -> None:
        """Initialize the password report command."""
        self.parser = argparse.ArgumentParser(
            prog='password-report', parents=[base.report_output_parser], description='Display record password report.'
        )
        PasswordReportCommand.add_arguments_to_parser(self.parser)
        super().__init__(self.parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser) -> None:
        parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='Display verbose information')
        parser.add_argument('--policy', dest='policy', action='store',
                                            help='Password complexity policy. Length,Lower,Upper,Digits,Special. Default is 12,2,2,2,0')
        parser.add_argument('-l', '--length', dest='length', type=int, action='store', help='Minimum password length.')
        parser.add_argument('-u', '--upper', dest='upper', type=int, action='store', help='Minimum uppercase characters.')
        parser.add_argument('--lower', dest='lower', type=int, action='store', help='Minimum lowercase characters.')
        parser.add_argument('-d', '--digits', dest='digits', type=int, action='store', help='Minimum digits.')
        parser.add_argument('-s', '--special', dest='special', type=int, action='store', help='Minimum special characters.')
        parser.add_argument('folder', nargs='?', type=str, action='store', help='folder path or UID')

    def _parse_password_policy(self, kwargs: Dict[str, Any]) -> Tuple[int, int, int, int, int]:
        """Parse password policy from command line arguments.
        
        Returns:
            tuple: (length, lower, upper, digits, special) requirements
        """
        p_length = p_lower = p_upper = p_digits = p_special = 0
        
        policy = kwargs.get('policy')
        if policy:
            comps = [x.strip() for x in policy.split(',')]
            if any(False for c in comps if len(c) > 0 and not c.isdigit()):
                raise base.CommandError('Invalid policy format. Must be list of integer values separated by commas.')
            
            # Parse policy components with bounds checking
            policy_values = [int(comp) if comp else 0 for comp in comps[:5]]
            p_length, p_lower, p_upper, p_digits, p_special = policy_values + [0] * (5 - len(policy_values))
        else:
            # Parse individual arguments
            p_length = kwargs.get('length', 0) if isinstance(kwargs.get('length'), int) else 0
            p_upper = kwargs.get('upper', 0) if isinstance(kwargs.get('upper'), int) else 0
            p_lower = kwargs.get('lower', 0) if isinstance(kwargs.get('lower'), int) else 0
            p_digits = kwargs.get('digits', 0) if isinstance(kwargs.get('digits'), int) else 0
            p_special = kwargs.get('special', 0) if isinstance(kwargs.get('special'), int) else 0

        if p_length <= 0 and p_upper <= 0 and p_lower <= 0 and p_digits <= 0 and p_special <= 0:
            self.get_parser().print_help()
            raise base.CommandError('Password policy must be specified.')
            
        return p_length, p_lower, p_upper, p_digits, p_special

    def _resolve_folder_uid(self, context: KeeperParams, path_or_uid: Optional[str]) -> str:
        """Resolve folder path or UID to folder UID.
        
        Args:
            context: Keeper parameters
            path_or_uid: Folder path or UID
            
        Returns:
            str: Folder UID
            
        Raises:
            CommandError: If folder not found
        """
        if not path_or_uid:
            return ''
            
        # Get by UID
        if path_or_uid in context.vault.vault_data._folders:
            return path_or_uid
            
        # Try to resolve as path
        rs = folder_utils.try_resolve_path(context, path_or_uid)
        if rs is None:
            raise base.CommandError(f'Folder path {path_or_uid} not found')
            
        folder, pattern = rs
        if not folder or pattern:
            raise base.CommandError(f'Folder path {path_or_uid} not found')
            
        return folder.uid or ''

    def _extract_password_from_record(self, record: Any) -> str:
        """Extract password from a vault record.
        
        Args:
            record: Vault record object
            
        Returns:
            str: Password string or empty string if not found
        """
        if isinstance(record, vault_record.PasswordRecord):
            return record.password
        elif isinstance(record, vault_record.TypedRecord):
            password_field = record.get_typed_field('password')
            if password_field:
                return password_field.get_default_value(str)
        return ''

    def _check_password_policy_compliance(self, strength: 'PasswordStrength', p_length: int, p_lower: int, p_upper: int, p_digits: int, p_special: int) -> bool:
        """Check if password meets policy requirements.
        
        Args:
            strength: PasswordStrength object
            p_length: Minimum length requirement
            p_lower: Minimum lowercase requirement
            p_upper: Minimum uppercase requirement
            p_digits: Minimum digits requirement
            p_special: Minimum special characters requirement
            
        Returns:
            bool: True if password meets all requirements
        """
        return (strength.length >= p_length and 
                strength.caps >= p_upper and 
                strength.lower >= p_lower and
                strength.digits >= p_digits and 
                strength.symbols >= p_special)

    def _truncate_text(self, text: str, max_length: int = DEFAULT_TRUNCATION_LENGTH) -> str:
        """Truncate text to specified length with ellipsis.
        
        Args:
            text: Text to truncate
            max_length: Maximum length
            
        Returns:
            str: Truncated text
        """
        if len(text) > max_length:
            return text[:max_length-2] + '...'
        return text

    def _build_password_count_map(self, context: KeeperParams) -> Dict[str, int]:
        """Build a map of password usage counts from breach watch records.
        
        Args:
            context: Keeper parameters
            
        Returns:
            dict: Password to count mapping
        """
        password_count = {}
        for record_uid, bw_record in context.vault.vault_data._breach_watch_records:
            if record_uid in context.vault.vault_data._records:
                if isinstance(bw_record, dict):
                    data = bw_record.get('data_unencrypted')
                    if isinstance(data, dict):
                        passwords = data.get('passwords')
                        if isinstance(passwords, list):
                            for pwd in passwords:
                                password = pwd.get('value')
                                if password:
                                    password_count[password] = password_count.get(password, 0) + 1
        return password_count

    def _get_breach_watch_status(self, context: KeeperParams, record_uid: str, password: str) -> Tuple[str, Optional[int]]:
        """Get breach watch status and reuse count for a password.
        
        Args:
            context: Keeper parameters
            record_uid: Record UID
            password: Password to check
            
        Returns:
            tuple: (status, reuse_count)
        """
        status = ''
        reused = None
        
        bw_record = context.vault.vault_data.get_breach_watch_record(record_uid)
        if isinstance(bw_record, dict):
            data = bw_record.get('data_unencrypted')
            if isinstance(data, dict):
                passwords = data.get('passwords')
                if isinstance(passwords, list):
                    password_status = next((x for x in passwords if x.get('value') == password), None)
                    if isinstance(password_status, dict):
                        status = password_status.get('status', '')
        
        return status, reused

    def _display_policy_summary(self, p_length: int, p_lower: int, p_upper: int, p_digits: int, p_special: int):
        """Display password policy requirements summary.
        
        Args:
            p_length: Minimum length requirement
            p_lower: Minimum lowercase requirement
            p_upper: Minimum uppercase requirement
            p_digits: Minimum digits requirement
            p_special: Minimum special characters requirement
        """
        logger.info('')
        if p_length > 0:
            logger.info('     Password Length: %d', p_length)
        if p_lower > 0:
            logger.info('Lowercase characters: %d', p_lower)
        if p_upper > 0:
            logger.info('Uppercase characters: %d', p_upper)
        if p_digits > 0:
            logger.info('              Digits: %d', p_digits)
        if p_special > 0:
            logger.info('  Special characters: %d', p_special)
        logger.info('')

    def execute(self, context: KeeperParams, **kwargs: Any) -> Any:
        verbose = kwargs.get('verbose') is True
        p_length, p_lower, p_upper, p_digits, p_special = self._parse_password_policy(kwargs)

        path_or_uid = kwargs.get('folder')
        folder_uid = self._resolve_folder_uid(context, path_or_uid)
        
        folder = context.vault.vault_data.get_folder(folder_uid)
        records = folder.records
        report_table = []
        report_header = ['record_uid', 'title', 'description', 'length', 'lower', 'upper', 'digits', 'special']
        breach_watch_plugin = context.vault.breach_watch_plugin()

        if verbose:
            report_header.append('score')
            if breach_watch_plugin:
                report_header.extend(['status', 'reused'])
                password_usage_count = self._build_password_count_map(context)
            else:
                password_usage_count = {}

        output_format = kwargs.get('format')
        for record_uid in records:
            record = context.vault.vault_data.load_record(record_uid)
            if not record or record.version not in SUPPORTED_RECORD_VERSIONS:
                continue
                
            password = self._extract_password_from_record(record)
            if not password:
                continue
                
            strength = get_password_strength(password)
            if self._check_password_policy_compliance(strength, p_length, p_lower, p_upper, p_digits, p_special):
                continue

            title = self._truncate_text(record.title)
            description = vault_extensions.get_record_description(record)
            if isinstance(description, str):
                description = self._truncate_text(description)
            report_row = [record_uid, title, description, strength.length, strength.lower, strength.caps, strength.digits, strength.symbols]
            if verbose:
                report_row.append(utils.password_score(password))
                if breach_watch_plugin:
                    status, _ = self._get_breach_watch_status(context, record_uid, password)
                    reused_count = None
                    if password in password_usage_count:
                        count = password_usage_count[password]
                        if isinstance(count, int) and count > 1:
                            reused_count = count
                    report_row.extend([status, reused_count])

            report_table.append(report_row)

        if output_format != 'json':
            report_header = [report_utils.field_to_title(x) for x in report_header]

        self._display_policy_summary(p_length, p_lower, p_upper, p_digits, p_special)

        return report_utils.dump_report_data(report_table, report_header, fmt=output_format, filename=kwargs.get('output'), row_number=True)


def get_password_strength(password: str) -> 'PasswordStrength':
    """Analyze password strength and return character counts.
    
    Args:
        password: Password string to analyze
        
    Returns:
        PasswordStrength: Named tuple with character counts
    """
    length = len(password)
    caps = lower = digits = symbols = 0

    for char in password:
        if char.isalpha():
            if char.isupper():
                caps += 1
            else:
                lower += 1
        elif char.isdigit():
            digits += 1
        elif char in PW_SPECIAL_CHARACTERS:
            symbols += 1
            
    return PasswordStrength(length=length, caps=caps, lower=lower, digits=digits, symbols=symbols)