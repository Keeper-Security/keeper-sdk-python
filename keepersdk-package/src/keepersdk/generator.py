from __future__ import annotations

import abc
import logging
import os
import secrets
import string
from typing import Optional, List, Any

DEFAULT_PASSWORD_LENGTH = 32
PW_SPECIAL_CHARACTERS = '!@#$%()+;<>=?[]{}^.,'


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
                          special_characters: str = PW_SPECIAL_CHARACTERS) -> Optional[KeeperPasswordGenerator]:
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
            raise Exception(f'Diceware word list was not loaded')

        words = [secrets.choice(self._vocabulary) for _ in range(self._number_of_rolls)]
        self.shuffle(words)
        return ' '.join(words)
