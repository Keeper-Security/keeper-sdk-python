import abc
import difflib
import hashlib
import logging
import os
import secrets
import string
from collections import namedtuple
from typing import Optional, List, Any, Iterator, Sequence, Tuple

from . import crypto

DEFAULT_PASSWORD_LENGTH = 32
PW_SPECIAL_CHARACTERS = '!@#$%()+;<>=?[]{}^.,'
PP_SEPARATOR_CHARACTERS = '-._?! '
DEFAULT_PASSPHRASE_SEPARATOR = '-'
DEFAULT_PASSPHRASE_WORD_COUNT = 5
MIN_PASSPHRASE_WORD_COUNT = 5
MAX_PASSPHRASE_WORD_COUNT = 9
DEFAULT_PASSPHRASE_CAPITALIZE = True
DEFAULT_PASSPHRASE_NUMBER = True
GEN_PASSWORD_ALGORITHMS = ('rand', 'dice', 'crypto', 'passphrase')
DEFAULT_DICEWARE_WORDLIST = 'diceware.wordlist.asc.txt'
PASSPHRASE_SEPARATOR_HELP = '- . _ ? ! space'

PassphraseGenOptions = namedtuple(
    'PassphraseGenOptions', ('word_count', 'separator', 'capitalize', 'append_number'))
PassphraseGenOptions.__doc__ = (
    'Parsed optional parameters for $GEN:passphrase. '
    'None fields use Vault/CLI defaults when building a generator.'
)


def clamp_passphrase_word_count(word_count: Optional[int]) -> int:
    """Clamp passphrase word count to the Vault range (5-9 words)."""
    if not isinstance(word_count, int):
        return DEFAULT_PASSPHRASE_WORD_COUNT
    original = word_count
    if word_count < MIN_PASSPHRASE_WORD_COUNT:
        word_count = MIN_PASSPHRASE_WORD_COUNT
    elif word_count > MAX_PASSPHRASE_WORD_COUNT:
        word_count = MAX_PASSPHRASE_WORD_COUNT
    if word_count != original:
        logging.warning(
            'Passphrase word count must be between %d and %d; using %d.',
            MIN_PASSPHRASE_WORD_COUNT, MAX_PASSPHRASE_WORD_COUNT, word_count)
    return word_count


def format_passphrase_separators_for_display(separators: Optional[str] = None) -> str:
    """Human-readable list of allowed passphrase separator characters."""
    if not separators:
        separators = PP_SEPARATOR_CHARACTERS
    parts: List[str] = []
    for ch in separators:
        parts.append('space' if ch == ' ' else ch)
    return ', '.join(parts)


def _normalize_passphrase_separator(separator: Optional[str]) -> str:
    """Normalize a separator string to a single allowed character."""
    if not separator:
        return DEFAULT_PASSPHRASE_SEPARATOR
    if separator == '\u2423':  # OPEN BOX (Vault UI glyph for space)
        return ' '
    return separator[0]


def _passphrase_separators_from_policy(policy_sep: str) -> str:
    """Return allowed separators in Vault order (see getPasswordRules.ts)."""
    normalized = policy_sep.replace('\u2423', ' ')
    allowed = ''
    for ch in PP_SEPARATOR_CHARACTERS:
        if ch in normalized:
            allowed += ch
    return allowed


def _default_passphrase_separator_from_policy(policy_sep: Optional[str]) -> str:
    """Pick the default generation separator matching Vault / PowerCommander."""
    if not policy_sep or not isinstance(policy_sep, str) or not policy_sep.strip():
        return DEFAULT_PASSPHRASE_SEPARATOR
    allowed = _passphrase_separators_from_policy(policy_sep.strip())
    return allowed[0] if allowed else DEFAULT_PASSPHRASE_SEPARATOR


def resolve_gen_password_algorithm(
        parameters: Optional[Sequence[str]]) -> Tuple[Optional[str], Optional[str]]:
    """Resolve $GEN password algorithm; return (algorithm, error_message)."""
    if not parameters:
        return 'rand', None
    first = parameters[0].strip()
    first_lower = first.lower()
    if first_lower in GEN_PASSWORD_ALGORITHMS:
        return first_lower, None
    if first.isdigit():
        return 'rand', None
    suggestions = difflib.get_close_matches(first_lower, GEN_PASSWORD_ALGORITHMS, n=1, cutoff=0.6)
    message = f'Unknown $GEN password algorithm "{first}".'
    if suggestions:
        message += f' Did you mean "{suggestions[0]}"?'
    message += f' Valid algorithms: {", ".join(GEN_PASSWORD_ALGORITHMS)}.'
    return None, message


def _is_strict_gen_bool_token(value: str) -> bool:
    """Return True if value is exactly 'true' or 'false' (case-insensitive)."""
    return value.strip().lower() in ('true', 'false')


def _parse_gen_bool_strict(value: str, param_name: str) -> Tuple[Optional[bool], Optional[str]]:
    """Parse a strict true/false token for $GEN:passphrase; return (value, error)."""
    normalized = value.strip().lower()
    if normalized == 'true':
        return True, None
    if normalized == 'false':
        return False, None
    return None, (
        f'Invalid $GEN:passphrase {param_name} parameter "{value}". '
        f'Expected true or false.')


def _is_passphrase_separator_token(token: str) -> bool:
    """Return True if token is a valid passphrase separator or 'space'/'sp' alias."""
    if token.lower() in ('space', 'sp'):
        return True
    return len(token) == 1 and token in PP_SEPARATOR_CHARACTERS


def _parse_passphrase_separator_token(token: str) -> Tuple[Optional[str], Optional[str]]:
    """Parse a separator token; return (separator_char, error_message)."""
    if token.lower() in ('space', 'sp'):
        return ' ', None
    if len(token) == 1 and token in PP_SEPARATOR_CHARACTERS:
        return token, None
    return None, (
        f'Invalid passphrase separator "{token}". '
        f'Allowed: {format_passphrase_separators_for_display(PP_SEPARATOR_CHARACTERS)}.')


def parse_passphrase_gen_parameters(
        parameters: Optional[Sequence[str]]) -> Tuple[PassphraseGenOptions, Optional[str]]:
    """Parse $GEN:passphrase optional parameters.

    Format: $GEN:passphrase[,word_count][,separator][,capitalize][,number]
    word_count must be between 5 and 9 (Vault range).
    """
    empty = PassphraseGenOptions(None, None, None, None)
    if not parameters:
        return empty, None

    tokens = [p if isinstance(p, str) else str(p) for p in parameters]
    if not tokens or tokens[0].strip().lower() != 'passphrase':
        return empty, None

    extras = tokens[1:]
    if any(t.strip() == '' for t in extras):
        return empty, (
            'Incomplete $GEN:passphrase parameters: missing value after comma. '
            'Format: $GEN:passphrase[,word_count][,separator][,capitalize][,number]')

    word_count = None
    separator = None
    capitalize = None
    append_number = None
    idx = 0

    if idx < len(extras):
        token = extras[idx].strip()
        if token.isdigit():
            word_count = int(token)
            if word_count < MIN_PASSPHRASE_WORD_COUNT or word_count > MAX_PASSPHRASE_WORD_COUNT:
                return empty, (
                    f'Passphrase word count must be between {MIN_PASSPHRASE_WORD_COUNT} '
                    f'and {MAX_PASSPHRASE_WORD_COUNT} (got {word_count}).')
            idx += 1
        elif not _is_passphrase_separator_token(token) and not _is_strict_gen_bool_token(token):
            return empty, (
                f'Invalid passphrase word count "{token}". '
                f'Expected an integer between {MIN_PASSPHRASE_WORD_COUNT} '
                f'and {MAX_PASSPHRASE_WORD_COUNT}.')

    if idx < len(extras) and not _is_strict_gen_bool_token(extras[idx].strip()):
        separator, sep_error = _parse_passphrase_separator_token(extras[idx].strip())
        if sep_error:
            return empty, sep_error
        idx += 1

    if idx < len(extras):
        capitalize, cap_error = _parse_gen_bool_strict(extras[idx].strip(), 'capitalize')
        if cap_error:
            return empty, cap_error
        idx += 1

    if idx < len(extras):
        append_number, num_error = _parse_gen_bool_strict(extras[idx].strip(), 'number')
        if num_error:
            return empty, num_error
        idx += 1

    if idx < len(extras):
        return empty, f'Unexpected $GEN:passphrase parameter "{extras[idx].strip()}".'

    return PassphraseGenOptions(word_count, separator, capitalize, append_number), None


def _resolve_wordlist_path(word_list_file: Optional[str] = None) -> str:
    """Resolve bundled or user-supplied diceware word list path."""
    if word_list_file:
        dice_path = os.path.join(os.path.dirname(__file__), 'resources', word_list_file)
        if not os.path.isfile(dice_path):
            dice_path = os.path.expanduser(word_list_file)
    else:
        dice_path = os.path.join(os.path.dirname(__file__), 'resources', DEFAULT_DICEWARE_WORDLIST)
    return dice_path


def _load_wordlist(word_list_file: Optional[str] = None) -> List[str]:
    """Load and validate the diceware word list from disk."""
    dice_path = _resolve_wordlist_path(word_list_file)
    if not os.path.isfile(dice_path):
        raise Exception(f'Word list file \"{dice_path}\" not found.')

    vocabulary: List[str] = []
    unique_words = set()
    with open(dice_path, 'r', encoding='utf-8') as dw:
        for line in dw:
            line = line.strip()
            if not line or line.startswith('--'):
                continue
            if line.lower().startswith('source url:') or line.lower().startswith('title:'):
                continue
            parts = line.split()
            word = parts[1] if len(parts) >= 2 else parts[0]
            vocabulary.append(word)
            unique_words.add(word.lower())
    if len(vocabulary) != len(unique_words):
        raise Exception(f'Word list file \"{dice_path}\" contains non-unique words.')
    return vocabulary


class PasswordGenerator(abc.ABC):
    @abc.abstractmethod
    def generate(self) -> str:
        pass

    @staticmethod
    def shuffle(x: List[Any]) -> None:
        # See http://en.wikipedia.org/wiki/Fisher-Yates_shuffle
        for i in range(len(x)-1, 0, -1):    # iterate from len(x)-1 down to 1
            j = secrets.randbelow(i+1)      # choose random j such that 0 <= j <= i
            x[i], x[j] = x[j], x[i]         # exchange x[i] and x[j]


class KeeperPasswordGenerator(PasswordGenerator):
    def __init__(self, length: int = DEFAULT_PASSWORD_LENGTH,
                 symbols: Optional[int]=None, digits: Optional[int]=None, caps: Optional[int]=None,
                 lower: Optional[int]=None, special_characters: str=PW_SPECIAL_CHARACTERS) -> None:

        sum_categories = sum((abs(i) if isinstance(i, int) else 0) for i in (symbols, digits, caps, lower))
        extra_count = length - sum_categories if length > sum_categories else 0
        extra_chars = ''
        if symbols is None or isinstance(symbols, int) and symbols > 0:
            extra_chars += special_characters
        if digits is None or isinstance(digits, int) and digits > 0:
            extra_chars += string.digits
        if caps is None or isinstance(caps, int) and caps > 0:
            extra_chars += string.ascii_uppercase
        if lower is None or isinstance(lower, int) and lower > 0:
            extra_chars += string.ascii_lowercase
        if extra_count > 0 and not extra_chars:
            if isinstance(symbols, int) and symbols < 0:
                extra_chars += special_characters
            if isinstance(digits, int) and digits < 0:
                extra_chars += string.digits
            if isinstance(caps, int) and caps < 0:
                extra_chars += string.ascii_uppercase
            if isinstance(lower, int) and lower < 0:
                extra_chars += string.ascii_lowercase

            if extra_count > 0 and not extra_chars:
                raise Exception('Password character set is empty')
        self.category_map = [
            (abs(symbols) if isinstance(symbols, int) else 0, special_characters),
            (abs(digits) if isinstance(digits, int) else 0, string.digits),
            (abs(caps) if isinstance(caps, int) else 0, string.ascii_uppercase),
            (abs(lower) if isinstance(lower, int) else 0, string.ascii_lowercase),
            (extra_count, extra_chars)
        ]

    def generate(self) -> str:
        password_list: List[str] = []
        for count, chars in self.category_map:
            password_list.extend(secrets.choice(chars) for _ in range(count))
        self.shuffle(password_list)
        return ''.join(password_list)

    @classmethod
    def create_from_rules(cls, rule_string: str, length: Optional[int] = None,
                          special_characters: str = PW_SPECIAL_CHARACTERS) -> Optional['KeeperPasswordGenerator']:
        """Create instance of class from rules string

        rule_string: comma separated integer character counts of uppercase, lowercase, numbers, symbols
        length: length of password
        special_characters: set of characters used to generate password symbols
        """
        rule_list = [s.strip() for s in rule_string.split(',')]
        if len(rule_list) != 4 or not all(n.isnumeric() for n in rule_list):
            logging.warning(
                'Invalid rules to generate password. Format is "upper, lower, digits, symbols"'
            )
            return None
        else:
            int_rule_list = [int(n) for n in rule_list]
            upper, lower, digits, symbols = int_rule_list
            length = sum(int_rule_list) if length is None else length
            return cls(length=length, caps=upper, lower=lower, digits=digits, symbols=symbols,
                       special_characters=special_characters)


class DicewarePasswordGenerator(PasswordGenerator):
    def __init__(self, number_of_rolls: int, word_list_file:  Optional[str]=None) -> None:
        self._number_of_rolls = number_of_rolls if number_of_rolls > 0 else 5
        if word_list_file:
            dice_path = os.path.join(os.path.dirname(__file__), 'resources', word_list_file)
            if not os.path.isfile(dice_path):
                dice_path = os.path.expanduser(word_list_file)
        else:
            dice_path = os.path.join(os.path.dirname(__file__), 'resources', 'diceware.wordlist.asc.txt')
        self._vocabulary: Optional[List[str]] = None
        if os.path.isfile(dice_path):
            with open(dice_path, 'r') as dw:
                self._vocabulary = []
                line_count = 0
                unique_words = set()
                for line in dw.readlines():
                    if not line:
                        continue
                    if line.startswith('--'):
                        continue
                    line_count += 1
                    words = [x.strip() for x in line.split()]
                    word = words[1] if len(words) >= 2 else words[0]
                    self._vocabulary.append(word)
                    unique_words.add(word.lower())
                if line_count != len(unique_words):
                    raise Exception(f'Word list file \"{dice_path}\" contains non-unique words.')
        else:
            raise Exception(f'Word list file \"{dice_path}\" not found.')

    def generate(self):
        if not self._vocabulary:
            raise Exception('Diceware word list was not loaded')

        words = [secrets.choice(self._vocabulary) for _ in range(self._number_of_rolls)]
        self.shuffle(words)
        return ' '.join(words)

class CryptoPassphraseGenerator(PasswordGenerator):
    def __init__(self) -> None:
        self._vocabulary: Optional[List[str]] = None
        dice_path = os.path.join(os.path.dirname(__file__), 'resources', 'bip-39.english.txt')
        if os.path.isfile(dice_path):
            with open(dice_path, 'r') as dw:
                self._vocabulary = []
                for line in dw.readlines():
                    if not line:
                        continue
                    if line.startswith('--'):
                        continue
                    words = [x.strip() for x in line.split()]
                    word = words[1] if len(words) >= 2 else words[0]
                    self._vocabulary.append(word)

                unique_words = set((x.lower() for x in self._vocabulary))
                if len(self._vocabulary) != len(unique_words):
                    raise Exception(f'Word list file \"{dice_path}\" contains non-unique words.')
                if len(unique_words) != 2 ** 11:
                    raise Exception(f'Word list file \"{dice_path}\" is incorrect crypto dictionary.')
        else:
            raise Exception(f'Word list file \"{dice_path}\" not found.')

    def get_vocabulary(self) -> Iterator[str]:
        return (x for x in self._vocabulary or [])

    def generate(self):
        key = crypto.get_random_bytes(32)
        hasher = hashlib.sha256()
        hasher.update(key)
        digest = hasher.digest()
        secret = int.from_bytes(key + digest[:1], byteorder='big')

        words = []
        for i in range(24):
            words.append(secret & 0x07ff)
            secret >>= 11

        words.reverse()
        return ' '.join((self._vocabulary[x] for x in words))


class KeeperPassphraseGenerator(PasswordGenerator):
    """Vault-style passphrase generator using the bundled EFF large word list.

    Matches Keeper Vault / Commander behavior: each word is chosen with a
    cryptographically secure random selector (``secrets``), using configurable
    word count (5-9), separator, optional capitalization of every word, and
    an optional single digit appended to the first word only.

    Use :meth:`create_with_options` or :meth:`create_from_policy` to apply
    enterprise passphrase policy defaults with optional CLI/$GEN overrides.
    """

    def __init__(self, word_count: int = DEFAULT_PASSPHRASE_WORD_COUNT,
                 separator: str = DEFAULT_PASSPHRASE_SEPARATOR,
                 capitalize: bool = DEFAULT_PASSPHRASE_CAPITALIZE,
                 append_number: bool = DEFAULT_PASSPHRASE_NUMBER,
                 word_list_file: Optional[str] = None) -> None:
        """Initialize a Vault-style passphrase generator with the given options."""
        self.word_count = clamp_passphrase_word_count(
            word_count if isinstance(word_count, int) else DEFAULT_PASSPHRASE_WORD_COUNT)
        self.separator = _normalize_passphrase_separator(separator)
        self.capitalize = capitalize
        self.append_number = append_number
        self._vocabulary = _load_wordlist(word_list_file)

    def generate(self) -> str:
        """Generate a passphrase using the configured word count, separator, and formatting."""
        if not self._vocabulary:
            raise Exception('Passphrase word list was not loaded')

        passphrase = ''
        first_word = True
        for _ in range(self.word_count):
            # secrets.choice / secrets.randbelow use os.urandom (CSPRNG).
            word = secrets.choice(self._vocabulary)
            if self.capitalize and word:
                word = word[0].upper() + word[1:]  # Vault UI: capitalize every word
            if self.append_number and first_word:
                word += str(secrets.randbelow(10))  # Vault UI: one digit on first word only
            if not first_word:
                passphrase += self.separator
            passphrase += word
            first_word = False
        return passphrase

    @classmethod
    def create_with_options(cls, policy: Optional[dict] = None, word_count: Optional[int] = None,
                            separator: Optional[str] = None, capitalize: Optional[bool] = None,
                            append_number: Optional[bool] = None) -> 'KeeperPassphraseGenerator':
        """Build a generator from CLI/$GEN overrides with optional policy defaults."""
        wc = word_count
        if wc is None:
            if policy:
                wc = policy.get('passphrase-length', DEFAULT_PASSPHRASE_WORD_COUNT)
            else:
                wc = DEFAULT_PASSPHRASE_WORD_COUNT

        sep = separator
        if sep is None:
            if policy:
                policy_sep = policy.get('passphrase-separator')
                sep = _default_passphrase_separator_from_policy(
                    policy_sep if isinstance(policy_sep, str) else None)
            else:
                sep = DEFAULT_PASSPHRASE_SEPARATOR

        cap = capitalize
        if cap is None:
            cap = DEFAULT_PASSPHRASE_CAPITALIZE

        num = append_number
        if num is None:
            num = DEFAULT_PASSPHRASE_NUMBER

        return cls(
            word_count=clamp_passphrase_word_count(wc) if isinstance(wc, int) else wc,
            separator=sep, capitalize=cap, append_number=num)

    @classmethod
    def create_from_policy(cls, policy: dict, length_override: Optional[int] = None,
                           separator_override: Optional[str] = None) -> 'KeeperPassphraseGenerator':
        """Build a generator using enterprise passphrase policy defaults."""
        return cls.create_with_options(
            policy,
            word_count=length_override,
            separator=separator_override,
        )
