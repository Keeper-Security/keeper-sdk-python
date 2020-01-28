from typing import Union, Optional, Dict, Any

from .APIRequest_pb2 import NewUserMinimumParams, ApiRequestPayload

DEFAULT_KEEPER_SERVER = ...

class KeeperEndpoint:
    client_version: str
    device_name: str
    locale: str
    server: str
    server_key_id: int
    encrypted_device_token: Optional[bytes]
    transmission_key: Optional[bytes]

    def execute_rest(self, endpoint: str, payload: ApiRequestPayload) -> Union[bytes, Dict[str, Any]]: ...
    def v2_execute(self, rq: Dict[str, Any]) -> Dict[str, Any]: ...
    def get_device_token(self) -> bytes: ...
    def get_new_user_params(self, username: str) -> NewUserMinimumParams : ...
