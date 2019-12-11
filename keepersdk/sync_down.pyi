
from .vault_data import RebuildTask
from .storage import IKeeperStorage
from .auth import Auth

def sync_down_command(auth: Auth, storage: IKeeperStorage) -> RebuildTask: ...


