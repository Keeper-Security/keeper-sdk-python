"""
Password generation utilities for Keeper CLI.

This module provides password generation functionality with optional BreachWatch integration.
"""

import dataclasses
from typing import Optional, List, Dict, Any, Union, Iterator, Tuple
from enum import Enum

import os
import secrets

from keepersdk import generator, utils

# Constants
BREACHWATCH_MAX = 5
DEFAULT_PASSWORD_LENGTH = 20
DEFAULT_DICEWARE_ROLLS = 5
RECOVERY_PHRASE_WORDS = 24
STRENGTH_WEAK_THRESHOLD = 40
STRENGTH_FAIR_THRESHOLD = 60
STRENGTH_GOOD_THRESHOLD = 80
CRYPTO_MIN_CHAR_RATIO = 6  # Minimum 1/6th of password length for each character type
DEFAULT_DICEWARE_FILE = 'diceware.wordlist.asc.txt'
RECOVERY_WORDLIST_FILE = 'bip-39.english.txt'


class CustomDicewareGenerator(generator.PasswordGenerator):
    """Custom Diceware generator with delimiter support."""
    
    def __init__(self, number_of_rolls: int, word_list_file: Optional[str] = None, delimiter: str = ' '):
        self._number_of_rolls = number_of_rolls if number_of_rolls > 0 else DEFAULT_DICEWARE_ROLLS
        self._delimiter = delimiter
        self._vocabulary = self._load_word_list(word_list_file)
    
    def _load_word_list(self, word_list_file: Optional[str]) -> List[str]:
        """Load and validate diceware word list from file."""
        dice_path = self._get_word_list_path(word_list_file)
        
        if not os.path.isfile(dice_path):
            raise FileNotFoundError(f'Word list file "{dice_path}" not found.')
        
        return self._parse_word_list_file(dice_path)
    
    def _get_word_list_path(self, word_list_file: Optional[str]) -> str:
        """Get the full path to the word list file."""
        if word_list_file:
            dice_path = os.path.join(os.path.dirname(generator.__file__), 'resources', word_list_file)
            if not os.path.isfile(dice_path):
                dice_path = os.path.expanduser(word_list_file)
            return dice_path
        else:
            return os.path.join(os.path.dirname(generator.__file__), 'resources', DEFAULT_DICEWARE_FILE)
    
    def _parse_word_list_file(self, dice_path: str) -> List[str]:
        """Parse word list file and validate uniqueness."""
        vocabulary = []
        line_count = 0
        unique_words = set()
        
        with open(dice_path, 'r') as dw:
            for line in dw.readlines():
                if not line or line.startswith('--'):
                    continue
                    
                line_count += 1
                words = [x.strip() for x in line.split()]
                word = words[1] if len(words) >= 2 else words[0]
                vocabulary.append(word)
                unique_words.add(word.lower())
        
        if line_count != len(unique_words):
            raise Exception(f'Word list file "{dice_path}" contains non-unique words.')
        
        return vocabulary
    
    def generate(self) -> str:
        if not self._vocabulary:
            raise Exception('Diceware word list was not loaded')
        
        words = [secrets.choice(self._vocabulary) for _ in range(self._number_of_rolls)]
        self.shuffle(words)
        return self._delimiter.join(words)


class PasswordStrength(Enum):
    """Password strength levels."""
    WEAK = "WEAK"
    FAIR = "FAIR" 
    GOOD = "GOOD"
    STRONG = "STRONG"


class BreachStatus(Enum):
    """BreachWatch scan results."""
    PASSED = "PASSED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"


@dataclasses.dataclass
class GeneratedPassword:
    """Data model for a generated password with analysis results."""
    password: str
    strength_score: int
    strength_level: PasswordStrength
    breach_status: Optional[BreachStatus] = None
    breach_details: Optional[str] = None


@dataclasses.dataclass
class GenerationRequest:
    """Configuration for password generation request."""
    # Generation parameters
    length: int = 20
    count: int = 1
    algorithm: str = 'random'  # 'random', 'diceware', 'crypto', 'recovery'
    
    # Random password parameters
    symbols: Optional[int] = None
    digits: Optional[int] = None
    uppercase: Optional[int] = None
    lowercase: Optional[int] = None
    rules: Optional[str] = None
    
    # Diceware parameters
    dice_rolls: Optional[int] = None
    delimiter: str = ' '
    word_list_file: Optional[str] = None
    
    # BreachWatch parameters
    enable_breach_scan: bool = True
    max_breach_attempts: int = BREACHWATCH_MAX


class PasswordGenerationService:
    """
    Service for generating passwords with optional BreachWatch integration.
    
    This service provides a unified interface for password generation,
    strength analysis, and breach detection.
    """
    
    def __init__(self, breach_watch=None):
        """
        Initialize the password generation service.
        
        Args:
            breach_watch: Optional BreachWatch instance for breach scanning
        """
        self.breach_watch = breach_watch
    
    def generate_passwords(self, request: GenerationRequest) -> List[GeneratedPassword]:
        """
        Generate passwords according to the provided request.
        
        Args:
            request: Configuration for password generation
            
        Returns:
            List of generated passwords with analysis results
            
        Raises:
            ValueError: If generation parameters are invalid
        """
        password_generator = self._create_generator(request)
        
        if not request.enable_breach_scan or not self.breach_watch:
            return self._generate_passwords_without_breach_scan(password_generator, request.count)
        else:
            return self._generate_passwords_with_breach_scan(password_generator, request)
    
    def _generate_passwords_without_breach_scan(self, generator: generator.PasswordGenerator, count: int) -> List[GeneratedPassword]:
        """Generate passwords with strength analysis only (no BreachWatch)."""
        new_passwords = [generator.generate() for _ in range(count)]
        return [self._analyze_password(p, enable_breach_scan=False) for p in new_passwords]
    
    def _generate_passwords_with_breach_scan(self, password_generator: generator.PasswordGenerator, request: GenerationRequest) -> List[GeneratedPassword]:
        """Generate passwords with BreachWatch scanning and retry logic."""
        passwords = []
        breachwatch_count = 0
        
        while len(passwords) < request.count:
            new_passwords = [password_generator.generate() for _ in range(request.count - len(passwords))]
            breachwatch_count += 1
            breachwatch_maxed = breachwatch_count >= request.max_breach_attempts
            
            try:
                scanned_passwords = self._scan_passwords_for_breaches(new_passwords, breachwatch_maxed)
                passwords.extend(scanned_passwords)
            except Exception:
                # BreachWatch failed - fallback to strength-only analysis
                fallback_passwords = [self._analyze_password(p, enable_breach_scan=False) for p in new_passwords]
                passwords.extend(fallback_passwords)
                break
        
        return passwords[:request.count]
    
    def _scan_passwords_for_breaches(self, passwords_to_scan: List[str], accept_breached: bool) -> List[GeneratedPassword]:
        """Scan passwords using BreachWatch and return analyzed results."""
        scanned_passwords = []
        euids_to_cleanup = []
        
        try:
            # Perform batch scan
            for breach_result in self.breach_watch.scan_passwords(passwords_to_scan):
                password = breach_result[0]
                status = breach_result[1] if len(breach_result) > 1 else None
                
                # Collect EUIDs for cleanup
                if status and hasattr(status, 'euid') and status.euid:
                    euids_to_cleanup.append(status.euid)
                
                # Process scan result
                analyzed_password = self._process_breach_scan_result(password, status, accept_breached)
                if analyzed_password:
                    scanned_passwords.append(analyzed_password)
        finally:
            # Always attempt cleanup (security requirement)
            self._cleanup_breach_scan_euids(euids_to_cleanup)
        
        return scanned_passwords
    
    def _process_breach_scan_result(self, password: str, status: Any, accept_breached: bool) -> Optional[GeneratedPassword]:
        """Process a single breach scan result and return analyzed password if acceptable."""
        strength_score = utils.password_score(password)
        strength_level = self._get_strength_level(strength_score)
        
        if status and hasattr(status, 'breachDetected'):
            if status.breachDetected:
                # Password failed BreachWatch - only accept if maxed out attempts
                if accept_breached:
                    return GeneratedPassword(
                        password=password,
                        strength_score=strength_score,
                        strength_level=strength_level,
                        breach_status=BreachStatus.FAILED
                    )
                return None  # Reject breached password, retry
            else:
                # Password passed BreachWatch
                return GeneratedPassword(
                    password=password,
                    strength_score=strength_score,
                    strength_level=strength_level,
                    breach_status=BreachStatus.PASSED
                )
        else:
            # BreachWatch error - treat as passed if maxed, otherwise retry
            if accept_breached:
                return GeneratedPassword(
                    password=password,
                    strength_score=strength_score,
                    strength_level=strength_level,
                    breach_status=BreachStatus.ERROR
                )
            return None  # Retry on error unless maxed out
    
    def _cleanup_breach_scan_euids(self, euids: List[str]) -> None:
        """Clean up BreachWatch scan EUIDs (security requirement)."""
        if euids and self.breach_watch:
            try:
                self.breach_watch.delete_euids(euids)
            except Exception:
                pass  # Best effort cleanup
    
    def _create_generator(self, request: GenerationRequest) -> generator.PasswordGenerator:
        """Create appropriate password generator based on request."""
        algorithm = request.algorithm.lower()
        
        if algorithm == 'crypto':
            # Generate crypto-style strong password (high complexity)
            crypto_length = request.length or DEFAULT_PASSWORD_LENGTH
            # Distribute characters for high security (minimum 1 of each type)
            min_each = max(1, crypto_length // CRYPTO_MIN_CHAR_RATIO)
            return generator.KeeperPasswordGenerator(
                length=crypto_length,
                symbols=min_each,
                digits=min_each, 
                caps=min_each,
                lower=min_each
            )
        elif algorithm == 'recovery':
            return CustomDicewareGenerator(
                RECOVERY_PHRASE_WORDS, word_list_file=RECOVERY_WORDLIST_FILE, delimiter=' '
            )
        elif algorithm == 'diceware':
            dice_rolls = request.dice_rolls or DEFAULT_DICEWARE_ROLLS
            return CustomDicewareGenerator(
                dice_rolls, 
                word_list_file=request.word_list_file,
                delimiter=request.delimiter
            )
        else:  # 'random' or default
            # Handle rules-based generation (from original code)
            if request.rules and all(i is None for i in (request.symbols, request.digits, request.uppercase, request.lowercase)):
                kpg = generator.KeeperPasswordGenerator.create_from_rules(request.rules, request.length)
                if kpg is None:
                    # Log warning and fall back to default (from original code)
                    return generator.KeeperPasswordGenerator(length=request.length)
                return kpg
            else:
                # If rules provided with individual params, ignore rules (from original code)
                return generator.KeeperPasswordGenerator(
                    length=request.length,
                    symbols=request.symbols,
                    digits=request.digits, 
                    caps=request.uppercase,
                    lower=request.lowercase
                )
    
    def _analyze_password(self, password: str, enable_breach_scan: bool = True) -> GeneratedPassword:
        """Analyze a single password for strength and breaches."""
        # Calculate strength
        strength_score = utils.password_score(password)
        strength_level = self._get_strength_level(strength_score)
        
        # Initialize breach status
        breach_status = None
        breach_details = None
        
        # Perform breach scan if enabled and available
        if enable_breach_scan and self.breach_watch:
            try:
                scan_results = list(self.breach_watch.scan_passwords([password]))
                if scan_results:
                    _, status = scan_results[0]
                    
                    # Clean up EUID if present
                    if status and hasattr(status, 'euid') and status.euid:
                        try:
                            self.breach_watch.delete_euids([status.euid])
                        except Exception:
                            # Log but don't fail - cleanup is best effort
                            pass
                    
                    if status and hasattr(status, 'breachDetected'):
                        breach_status = (
                            BreachStatus.FAILED if status.breachDetected 
                            else BreachStatus.PASSED
                        )
                    else:
                        breach_status = BreachStatus.ERROR
                        breach_details = "Scan result incomplete"
                else:
                    breach_status = BreachStatus.ERROR
                    breach_details = "No scan results returned"
            except Exception as e:
                breach_status = BreachStatus.ERROR
                breach_details = f"Scan failed: {str(e)}"
        else:
            breach_status = BreachStatus.SKIPPED
        
        return GeneratedPassword(
            password=password,
            strength_score=strength_score,
            strength_level=strength_level,
            breach_status=breach_status,
            breach_details=breach_details
        )
    
    
    @staticmethod
    def _get_strength_level(score: int) -> PasswordStrength:
        """Convert numeric score to strength level."""
        if score < STRENGTH_WEAK_THRESHOLD:
            return PasswordStrength.WEAK
        elif score < STRENGTH_FAIR_THRESHOLD:
            return PasswordStrength.FAIR
        elif score < STRENGTH_GOOD_THRESHOLD:
            return PasswordStrength.GOOD
        else:
            return PasswordStrength.STRONG
