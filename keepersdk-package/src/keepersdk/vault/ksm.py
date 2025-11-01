from datetime import datetime
from dataclasses import dataclass
from typing import Optional, List


@dataclass(frozen=True)
class ClientDevice:
    name: str
    short_id: str
    created_on: datetime
    expires_on: datetime
    first_access: datetime
    last_access: datetime
    ip_lock: bool
    ip_address: str


@dataclass(frozen=True)
class SharedSecretsInfo:
    type: str
    uid: str
    name: str
    permissions: str


@dataclass(frozen=True)
class SecretsManagerApp:
    name: str
    uid: str
    records: int
    folders: int
    count: int
    last_access: datetime
    client_devices: Optional[List[ClientDevice]] = None
    shared_secrets: Optional[List[SharedSecretsInfo]] = None
