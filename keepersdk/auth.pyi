from typing import Optional, Any, Protocol

from .ui import IAuthUI
from .endpoint import KeeperEndpoint
from .configuration import IConfigurationStorage

class IAuth(Protocol):
    ui: IAuthUI
    storage: IConfigurationStorage
    endpoint: KeeperEndpoint
    data_key: Optional[bytes]
    client_key: Optional[bytes]
    private_key: Optional[Any]
    is_enterprise_admin: bool
    session_token: Optional[str]
    username: Optional[str]
    is_authenticated: bool

    def login(self, username: str, password: str) -> None: ...
    def logout(self) -> None: ...
    def execute_auth_command(self, command: dict, throw_on_error: bool = ...) -> dict: ...

class Auth(IAuth):
    def __init__(self, auth_ui: IAuthUI, storage: Optional[IConfigurationStorage] = ...) -> None: ...
