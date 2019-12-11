from typing import Optional, Protocol

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from .configuration import IConfigurationStorage
from .endpoint import KeeperEndpoint
from .auth_ui import IAuthUI


class AuthContext:
    username: str
    data_key: Optional[bytes]
    client_key: Optional[bytes]
    private_key: Optional[RSAPrivateKey]
    is_enterprise_admin: bool
    session_token: str
    two_factor_token: str
    enforcements: Optional[dict]
    settings: Optional[dict]

class IAuth(Protocol):
    auth_ui: IAuthUI
    storage: IConfigurationStorage
    endpoint: KeeperEndpoint
    is_authenticated: bool
    auth_context: Optional[AuthContext]

    def login(self, username: str, password: str) -> None: ...
    def logout(self) -> None: ...
    def execute_auth_command(self, command: dict, throw_on_error: bool = ...) -> dict: ...

class Auth(IAuth):
    def __init__(self, auth_ui: IAuthUI, storage: Optional[IConfigurationStorage] = ...) -> None: ...
    def refresh_session_token(self) -> None: ...
