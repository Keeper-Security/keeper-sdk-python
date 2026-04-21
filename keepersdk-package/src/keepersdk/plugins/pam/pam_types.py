from __future__ import annotations

import attrs

from ...proto import enterprise_pb2
from ...storage import storage_types


@attrs.define(kw_only=True, frozen=True)
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


@attrs.define(kw_only=True, frozen=True)
class PamRecordRotationInfo(storage_types.IUid[str]):
    """Vault record rotation row exposed by :class:`~keepersdk.plugins.pam.pam_plugin.PamPlugin`."""

    record_uid: str
    revision: int
    configuration_uid: str
    schedule: str
    pwd_complexity: bytes
    disabled: bool
    resource_uid: str
    last_rotation: int
    last_rotation_status: int

    def uid(self) -> str:
        return self.record_uid
