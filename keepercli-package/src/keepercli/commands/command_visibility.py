from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..params import KeeperParams

DEVICE_ADMIN_COMMANDS = frozenset({'device-admin-list', 'device-admin-action'})


def is_enterprise_admin(context: Optional['KeeperParams']) -> bool:
    return bool(
        context
        and context.auth
        and context.auth.auth_context.is_enterprise_admin
    )


def is_command_visible(command: str, context: Optional['KeeperParams']) -> bool:
    if command in DEVICE_ADMIN_COMMANDS:
        return is_enterprise_admin(context)
    return True
