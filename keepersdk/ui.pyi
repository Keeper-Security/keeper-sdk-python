from enum import Enum
from typing import List, Optional, Tuple#, Callable


class PasswordRule:
    match: bool
    pattern: Optional[str]
    description: Optional[str]

    def matches(self, password: str) -> bool: ...


class PasswordRuleMatcher:
    intro: str
    rules: List[PasswordRule]
    def __init__(self, intro: str, rules: List[PasswordRule]) -> None: ...
    def match_failed_rules(self, password: str) -> List[PasswordRule]: ...


class TwoFactorCodeDuration(Enum): ...

class TwoFactorChannel(Enum): ...

class IAuthUI:
    def confirmation(self, information: str) -> bool: ...
    def get_new_password(self, matcher: PasswordRuleMatcher) -> Optional[str]: ...
    def get_two_factor_code(self, provider: TwoFactorChannel) -> Tuple[str, TwoFactorCodeDuration]: ...

'''
class DuoAction(Enum): ...

class DuoAccount:
    capabilities: List[DuoAction]
    phone: Optional[str]
    enrollment_url: Optional[str]

class IDuoAuthUI:
    def get_duo_two_factor_result(self, duo_account: DuoAccount,
                                  on_action: Callable[[DuoAction, Optional[Callable[[str], None]]], None]) -> str: ...
'''
