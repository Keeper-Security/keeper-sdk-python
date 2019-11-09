
from .vault_data import VaultData
from .storage import IKeeperStorage
from .auth import Auth

class VaultSyncDown(VaultData):
    auth: Auth
    def __init__(self, auth: Auth, storage: IKeeperStorage): ...
    def sync_down(self) -> None: ...

