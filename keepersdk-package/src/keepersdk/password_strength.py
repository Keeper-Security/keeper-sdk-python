"""Master password strength estimation using zxcvbn.

The numeric score and category mapping intentionally match the .NET SDK.
"""

import abc
from typing import Optional

from . import utils

try:
    from zxcvbn import zxcvbn
except ImportError:  # pragma: no cover - zxcvbn is a required dependency; guards against a broken install
    zxcvbn = None

# zxcvbn rejects longer input, so strength is estimated from the leading characters.
ZXCVBN_MAX_LENGTH = 72

_SCORE_MAP = {0: 25, 1: 25, 2: 50, 3: 75, 4: 100}
_CATEGORY_MAP = {25: 'WEAK', 50: 'FAIR', 75: 'MEDIUM', 100: 'STRONG'}


class IMasterPasswordStrengthUI(abc.ABC):
    """Host interface for reporting master password strength."""

    @abc.abstractmethod
    def report_master_password_strength(self, score: int, category: str) -> None:
        pass


class MasterPasswordStrength:
    """Evaluate a master password and map zxcvbn scores to SDK categories."""

    @staticmethod
    def get_score(password: str) -> int:
        if not isinstance(password, str) or not password:
            return 0
        if zxcvbn is None:
            utils.get_logger().warning(
                'Unable to determine master password strength: zxcvbn is not installed.')
            return 0

        try:
            result = zxcvbn(password[:ZXCVBN_MAX_LENGTH])
        except Exception as error:
            # Never include the password or zxcvbn input in logs.
            utils.get_logger().warning(
                'Unable to determine master password strength (%s).', type(error).__name__)
            return 0
        score = result.get('score') if isinstance(result, dict) else None
        if not isinstance(score, int):
            return 0
        return _SCORE_MAP.get(score, 0)

    @staticmethod
    def get_category(score: int) -> str:
        return _CATEGORY_MAP.get(score, 'UNKNOWN')

    @staticmethod
    def report(ui: Optional[IMasterPasswordStrengthUI], password: str) -> None:
        """Score ``password`` and pass the result to ``ui``; does nothing when ``ui`` is None."""
        if ui is None:
            return
        score = MasterPasswordStrength.get_score(password)
        ui.report_master_password_strength(score, MasterPasswordStrength.get_category(score))
