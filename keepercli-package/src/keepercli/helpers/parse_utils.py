from typing import Any, Optional


def as_boolean(value: Any, default: Optional[bool]=None) -> bool:
    if isinstance(value, bool):
        return value

    if isinstance(value, int):
        return value > 0

    if isinstance(value, str) and len(value) > 0:
        value = value.lower()
        if value in ('yes', 'y', 'on', '1', 'true', 't'):
            return True
        if value in ('no', 'n', 'off', '0', 'false', 'f'):
            return False

    if default is not None and isinstance(default, bool):
        return default

    raise ValueError("Unknown value. Available values 'yes'/'no', 'y'/'n', 'on'/'off', '1'/'0', 'true'/'false'")