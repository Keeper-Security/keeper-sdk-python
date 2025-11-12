"""
Password generation command for Keeper CLI.

This module provides the CLI interface for generating passwords with
optional BreachWatch scanning and various output formats.
"""

import argparse
import json
from typing import Any, Optional, List, Dict

import pyperclip

MAX_PASSWORD_COUNT = 1000
MAX_PASSWORD_LENGTH = 256
MAX_DICE_ROLLS = 40
MIN_PASSWORD_COUNT = 1
MIN_PASSWORD_LENGTH = 1
MIN_DICE_ROLLS = 1
DEFAULT_JSON_INDENT = 2
COMPLEXITY_RULES_COUNT = 4

from . import base
from .. import api
from ..helpers.password_utils import (
    PasswordGenerationService, GenerationRequest, GeneratedPassword,
    BreachStatus, PasswordStrength
)
from ..params import KeeperParams

logger = api.get_logger()


class PasswordGenerateCommand(base.ArgparseCommand):
    """Command for generating passwords with optional BreachWatch scanning."""
    
    def __init__(self):
        """Initialize the password generate command."""
        self.parser = argparse.ArgumentParser(
            prog='generate', 
            description='Generate secure passwords with optional BreachWatch scanning'
        )
        PasswordGenerateCommand.add_arguments_to_parser(self.parser)
        super().__init__(self.parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser) -> None:
        """Add password generation arguments to parser."""
        parser.add_argument('--clipboard', '-cc', dest='clipboard', action='store_true',
                          help='Copy generated passwords to clipboard')
        parser.add_argument('--quiet', '-q', dest='quiet', action='store_true',
                          help='Only print password list (minimal output)')
        parser.add_argument('--password-list', '-p', dest='password_list', action='store_true',
                          help='Include password list in addition to formatted output')
        parser.add_argument('--output', '-o', dest='output_file', action='store',
                          help='Write output to specified file')
        parser.add_argument('--format', '-f', dest='output_format', action='store',
                          choices=['table', 'json'], default='table',
                          help='Output format (default: table)')
        parser.add_argument('--json-indent', '-i', dest='json_indent', action='store', type=int, default=DEFAULT_JSON_INDENT,
                          help='JSON format indent level (default: 2)')
        
        parser.add_argument('--number', '-n', dest='number', type=int, default=1,
                          help='Number of passwords to generate (default: 1)')
        parser.add_argument('--no-breachwatch', '-nb', dest='no_breachwatch', action='store_true',
                          help='Skip BreachWatch scanning')
        
        random_group = parser.add_argument_group('Random Password Options')
        random_group.add_argument('--length', dest='length', type=int, default=20,
                                help='Password length (default: 20)')
        random_group.add_argument('--count', '-c', dest='length', type=int, metavar='LENGTH',
                                help='Length of password')
        random_group.add_argument('--rules', '-r', dest='rules', action='store',
                                help='Complexity rules as comma-separated integers: uppercase,lowercase,digits,symbols')
        random_group.add_argument('--symbols', '-s', dest='symbols', type=int,
                                help='Minimum number of symbol characters')
        random_group.add_argument('--digits', '-d', dest='digits', type=int,
                                help='Minimum number of digit characters')
        random_group.add_argument('--uppercase', '-u', dest='uppercase', type=int,
                                help='Minimum number of uppercase characters')
        random_group.add_argument('--lowercase', '-l', dest='lowercase', type=int,
                                help='Minimum number of lowercase characters')
        
        special_group = parser.add_argument_group('Special Password Types')
        special_group.add_argument('--crypto', dest='crypto', action='store_true',
                                 help='Generate crypto-style strong password')
        special_group.add_argument('--recoveryphrase', dest='recoveryphrase', action='store_true',
                                 help='Generate 24-word recovery phrase')
        
        diceware_group = parser.add_argument_group('Diceware Options')
        diceware_group.add_argument('--dice-rolls', '-dr', dest='dice_rolls', type=int,
                                  help='Number of dice rolls for diceware generation')
        diceware_group.add_argument('--delimiter', '-dl', dest='delimiter', 
                                  choices=['-', '+', ':', '.', '/', '_', '=', ' '], default=' ',
                                  help='Word delimiter for diceware (default: space)')
        diceware_group.add_argument('--word-list', dest='word_list',
                                  help='Path to custom word list file for diceware')
    
    def execute(self, context: KeeperParams, **kwargs) -> Any:
        """Execute the password generation command."""
        if not context.vault:
            raise base.CommandError('Vault is not initialized. Please log in to initialize the vault.')
        
        try:
            request = self._create_generation_request(**kwargs)
            service = self._create_password_service(context.vault, request)
            passwords = self._generate_passwords(service, request)
            self._output_results(passwords, **kwargs)
            
        except Exception as e:
            logger.error(f"Password generation failed: {e}")
            raise base.CommandError(f"Password generation failed: {e}")
    
    def _create_password_service(self, vault, request: GenerationRequest) -> PasswordGenerationService:
        """Create password generation service with optional BreachWatch."""
        breach_watch = None
        
        if not request.enable_breach_scan:
            logger.debug("BreachWatch scanning disabled by user")
        elif vault.breach_watch_plugin():
            breach_watch_plugin = vault.breach_watch_plugin()
            breach_watch = breach_watch_plugin.breach_watch
            logger.debug("Using BreachWatch for password scanning")
        else:
            logger.warning("BreachWatch plugin not available, enable it to use")
            request.enable_breach_scan = False
        
        return PasswordGenerationService(breach_watch)
    
    def _generate_passwords(self, service: PasswordGenerationService, request: GenerationRequest) -> List[GeneratedPassword]:
        """Generate passwords using the service."""
        if request.enable_breach_scan and service.breach_watch:
            logger.info(f"Generating {request.count} password(s) with BreachWatch scanning...")
        else:
            logger.info(f"Generating {request.count} password(s)...")
        
        return service.generate_passwords(request)
    
    def _create_generation_request(self, **kwargs) -> GenerationRequest:
        """Create a GenerationRequest from command line arguments."""
        count = self._validate_count(kwargs.get('number', 1))
        length = self._validate_length(kwargs.get('length', 20))
        algorithm = self._determine_algorithm(kwargs)
        
        symbols, digits, uppercase, lowercase = self._validate_complexity_parameters(kwargs)
        rules = self._validate_rules(kwargs.get('rules'))
        dice_rolls = self._validate_dice_rolls(kwargs.get('dice_rolls'))
        
        return GenerationRequest(
            length=length,
            count=count,
            algorithm=algorithm,
            symbols=symbols,
            digits=digits,
            uppercase=uppercase,
            lowercase=lowercase,
            rules=rules,
            dice_rolls=dice_rolls,
            delimiter=kwargs.get('delimiter', ' '),
            word_list_file=kwargs.get('word_list'),
            enable_breach_scan=not kwargs.get('no_breachwatch', False)
            # max_breach_attempts uses GenerationRequest default value
        )
    
    def _validate_count(self, count: int) -> int:
        """Validate password count parameter."""
        if count < MIN_PASSWORD_COUNT:
            raise base.CommandError(f'Number of passwords must be at least {MIN_PASSWORD_COUNT}')
        if count > MAX_PASSWORD_COUNT:
            raise base.CommandError(f'Number of passwords cannot exceed {MAX_PASSWORD_COUNT}')
        return count
    
    def _validate_length(self, length: int) -> int:
        """Validate password length parameter."""
        if length < MIN_PASSWORD_LENGTH:
            raise base.CommandError(f'Password length must be at least {MIN_PASSWORD_LENGTH}')
        if length > MAX_PASSWORD_LENGTH:
            raise base.CommandError(f'Password length cannot exceed {MAX_PASSWORD_LENGTH}')
        return length
    
    def _determine_algorithm(self, kwargs: Dict[str, Any]) -> str:
        """Determine password generation algorithm from arguments."""
        if kwargs.get('crypto'):
            return 'crypto'
        elif kwargs.get('recoveryphrase'):
            return 'recovery'
        elif kwargs.get('dice_rolls'):
            return 'diceware'
        else:
            return 'random'  # default
    
    def _validate_complexity_parameters(self, kwargs: Dict[str, Any]) -> tuple:
        """Validate complexity parameters (symbols, digits, uppercase, lowercase)."""
        symbols = kwargs.get('symbols')
        digits = kwargs.get('digits') 
        uppercase = kwargs.get('uppercase')
        lowercase = kwargs.get('lowercase')
        
        # Ensure complexity parameters are non-negative
        for param_name, param_value in [('symbols', symbols), ('digits', digits), 
                                      ('uppercase', uppercase), ('lowercase', lowercase)]:
            if param_value is not None and param_value < 0:
                raise base.CommandError(f'{param_name.capitalize()} count cannot be negative')
        
        return symbols, digits, uppercase, lowercase
    
    def _validate_rules(self, rules: Optional[str]) -> Optional[str]:
        """Validate complexity rules format."""
        if not rules:
            return rules
            
        try:
            rule_parts = [x.strip() for x in rules.split(',')]
            if len(rule_parts) != COMPLEXITY_RULES_COUNT:
                raise ValueError(f"Rules must have exactly {COMPLEXITY_RULES_COUNT} comma-separated values")
            for part in rule_parts:
                if not part.isdigit():
                    raise ValueError("All rule values must be non-negative integers")
        except ValueError as e:
            raise base.CommandError(f'Invalid rules format: {e}. Expected format: "upper,lower,digits,symbols"')
        
        return rules
    
    def _validate_dice_rolls(self, dice_rolls: Optional[int]) -> Optional[int]:
        """Validate diceware dice rolls parameter."""
        if dice_rolls is None:
            return dice_rolls
            
        if dice_rolls < MIN_DICE_ROLLS:
            raise base.CommandError(f'Dice rolls must be at least {MIN_DICE_ROLLS}')
        if dice_rolls > MAX_DICE_ROLLS:
            raise base.CommandError(f'Dice rolls cannot exceed {MAX_DICE_ROLLS}')
        
        return dice_rolls
    
    def _output_results(self, passwords: List[GeneratedPassword], **kwargs) -> None:
        """Format and output the generated passwords."""
        output_format = kwargs.get('output_format', 'table')
        quiet = kwargs.get('quiet', False)
        password_list = kwargs.get('password_list', False)
        output_file = kwargs.get('output_file')
        clipboard = kwargs.get('clipboard', False)
        
        if quiet:
            output = self._format_password_list(passwords)
        elif output_format == 'json':
            output = self._format_json(passwords, kwargs.get('json_indent', DEFAULT_JSON_INDENT))
        else:
            output = self._format_table(passwords)
        
        if password_list and not quiet:
            output += '\n\n' + self._format_password_list(passwords)
        
        if clipboard:
            try:
                pyperclip.copy(output)
                logger.info("Generated passwords copied to clipboard")
            except Exception as e:
                logger.warning(f"Failed to copy to clipboard: {e}")
        
        if output_file:
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(output)
                logger.info(f"Output written to: {output_file}")
            except Exception as e:
                logger.error(f"Failed to write to file {output_file}: {e}")
                raise base.CommandError('generate', f"File write error: {e}")
        else:
            print(output)
    
    def _format_table(self, passwords: List[GeneratedPassword]) -> str:
        """Format passwords as a table with Keeper-style formatting."""
        if not passwords:
            return "No passwords generated."
        
        lines = []
        
        has_breach_info = any(pwd.breach_status is not None for pwd in passwords)
        
        if has_breach_info:
            scan_count = len([pwd for pwd in passwords if pwd.breach_status != BreachStatus.SKIPPED])
            if scan_count > 0:
                lines.append(f"Breachwatch: {scan_count} password{'s' if scan_count != 1 else ''} to scan")
        
        if has_breach_info:
            header = f"     {'Strength(%)':<12} {'BreachWatch':<12} {'Password'}"
        else:
            header = f"     {'Strength(%)':<12} {'Password'}"
        lines.append(header)
        for i, pwd in enumerate(passwords, 1):
            strength_display = str(pwd.strength_score)
            
            if has_breach_info:
                breach_display = self._get_breach_display(pwd)
                line = f"{i:<5}{strength_display:<12} {breach_display:<12} {pwd.password}"
            else:
                line = f"{i:<5}{strength_display:<12} {pwd.password}"
            
            lines.append(line)
        
        return '\n'.join(lines)
    
    def _format_json(self, passwords: List[GeneratedPassword], indent: int) -> str:
        """Format passwords as JSON."""
        data = []
        for pwd in passwords:
            entry = {
                'password': pwd.password,
                'strength': pwd.strength_score
            }
            
            if pwd.breach_status is not None:
                entry['breach_watch'] = self._get_breach_display(pwd)
            
            data.append(entry)
        
        return json.dumps(data, indent=indent if indent > 0 else None, ensure_ascii=False)
    
    def _format_password_list(self, passwords: List[GeneratedPassword]) -> str:
        """Format as simple password list."""
        return '\n'.join(pwd.password for pwd in passwords)
    
    def _get_breach_display(self, password: GeneratedPassword) -> str:
        """Get display string for breach status."""
        if password.breach_status == BreachStatus.PASSED:
            return "Passed"
        elif password.breach_status == BreachStatus.FAILED:
            return "Failed"
        elif password.breach_status == BreachStatus.SKIPPED:
            return "Skipped"
        elif password.breach_status == BreachStatus.ERROR:
            return "Error"
        else:
            return "Unknown"
