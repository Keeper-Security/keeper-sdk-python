"""PAM Types for PAM Plugin."""

from dataclasses import dataclass

from ...proto import enterprise_pb2
from ...storage import storage_types


@dataclass
class PamController(storage_types.IUid[str]):
    """PAM Controller information."""
    controller_uid: str
    controller_name: str
    device_token: str
    device_name: str
    node_id: int
    created: int
    last_modified: int
    application_uid: str
    app_client_type: enterprise_pb2.AppClientType
    is_initialized: bool
    def uid(self) -> str:
        return self.controller_uid
