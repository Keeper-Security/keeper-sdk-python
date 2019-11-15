from typing import Optional, List, Protocol, Iterable, Dict, Any


class IUserConfiguration(Protocol):
    username: str
    password: Optional[str]
    two_factor_token: Optional[str]

class IServerConfiguration(Protocol):
    server: str
    device_id: Optional[bytes]
    server_key_id: Optional[int]

class IConfiguration(Protocol):
    last_username: Optional[str]
    last_server: Optional[str]
    users: Iterable[IUserConfiguration]
    servers: Iterable[IServerConfiguration]

class IConfigurationStorage(Protocol):
    def get_configuration(self) -> Configuration:  ...
    def put_configuration(self, configuration: Configuration) -> None: ...


class UserConfiguration(IUserConfiguration):
    def __init__(self, username: str, password:Optional[str] = ..., two_factor_token: Optional[str] = ...) -> None: ...
    @staticmethod
    def adjust_name(username: str) -> str: ...

class ServerConfiguration(IServerConfiguration):
    def __init__(self, server: str, device_id: Optional[bytes] = ..., server_key_id: int = ...) -> None: ...
    @staticmethod
    def adjust_name(server: str) -> str: ...

class Configuration(IConfiguration):
    users: List[UserConfiguration]
    servers: List[ServerConfiguration]

    def merge_user_configuration(self, user_config: IUserConfiguration) -> None: ...
    def merge_server_configuration(self, server_config: IServerConfiguration) -> None: ...
    def merge_configuration(self, configuration: IConfiguration) -> None: ...
    def get_user_configuration(self, username: str) -> Optional[UserConfiguration]: ...
    def get_server_configuration(self, server: str) -> Optional[ServerConfiguration]: ...


class InMemoryConfiguration(IConfigurationStorage):
    def __init__(self, configuration: Optional[IConfiguration] = ...) -> None: ...

class JsonConfiguration(IConfigurationStorage):
    def __init__(self, filename: str) -> None: ...
    @staticmethod
    def json_to_config(json_config: Dict[str, Any]) -> Configuration: ...
    @staticmethod
    def config_to_json(config: IConfiguration, json_config: Dict[str, Any]) -> None: ...
