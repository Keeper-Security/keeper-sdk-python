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


class TwoFactorChannel(Enum):
    Authenticator = 1
    TextMessage = 2
    DuoSecurity = 3
    Other = 4


class TwoFactorCodeDuration(Enum):
    EveryLogin = 'every_login'
    Every30Days = 'every_30_days'
    Forever = 'forever'


class PasswordRule:
    def __init__(self):
        self.match = True
        self.pattern = None
        self.description = None

    def matches(self, password):
        ok = True
        if self.pattern:
            regex = re.compile(self.pattern)
            ok = re.match(regex, password)
            if not self.match:
                ok = not ok
        return ok


class PasswordRuleMatcher:
    def __init__(self, intro, rules):
        self.intro = intro
        self.rules = rules

    def match_failed_rules(self, password):
        return [x for x in self.rules if not x.matches(password)]


class IAuthUI(abc.ABC):
    @abc.abstractmethod
    def confirmation(self, information):
        pass

    @abc.abstractmethod
    def get_new_password(self, matcher):
        pass

    @abc.abstractmethod
    def get_two_factor_code(self, provider):
        pass


'''
class DuoAction(Enum):
    DuoPush = "push",
    TextMessage = "sms",
    VoiceCall = "voice"


class DuoAccount:
    def __init__(self):
        self.capabilities = []
        self.phone = None
        self.enrollment_url = None


class IDuoAuthUI(abc.ABC):
    @abc.abstractmethod
    def get_duo_two_factor_result(self, duo_account, on_action):
        pass
'''
