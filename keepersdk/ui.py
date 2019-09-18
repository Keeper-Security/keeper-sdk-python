#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2019 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import abc
import re

from enum import Enum
from typing import Optional, List, Callable


class TwoFactorChannel(Enum):
    Authenticator = 1,
    TextMessage = 2
    DuoSecurity = 3
    Other = 4


class PasswordRule:
    def __init__(self):
        self.match = True
        self.pattern = None
        self.description = None

    def matches(self, password):
        # type: (str) -> bool
        ok = True
        if self.pattern:
            regex = re.compile(self.pattern)
            ok = re.match(regex, password)
            if not self.match:
                ok = not ok
        return ok


class PasswordRuleMatcher:
    def __init__(self, intro, rules):   # type: (str, List[PasswordRule]) -> None
        self.intro = intro
        self.rules = rules

    def match_failed_rules(self, password):
        # type: (str) -> List[PasswordRule]
        return [x for x in self.rules if not x.matches(password)]


class AuthUI:
    """
    Defines UI methods for Auth class
    """
    def confirmation(self, information):        # type: (str) -> bool
        raise NotImplemented
    def get_new_password(self, matcher):        # type: (PasswordRuleMatcher) -> Optional[str]
        raise NotImplemented
    def get_twofactor_code(self, provider):     # type: (TwoFactorChannel) -> str
        raise NotImplemented


class DuoAction(Enum):
    DuoPush = "push",
    TextMessage = "sms",
    VoiceCall = "voice"


class DuoAccount:
    def __init__(self):
        self.capabilities = []      # type: List[DuoAction]
        self.phone = None
        self.enrollment_url = None


class DuoAuthUI(abc.ABC):
    @abc.abstractmethod
    def get_duo_twofactor_result(self, duo_account, on_action):
        # type: (DuoAccount, Callable) -> str
        pass
