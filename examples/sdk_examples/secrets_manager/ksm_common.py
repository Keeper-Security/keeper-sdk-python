#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper SDK for Python — shared helpers for Secrets Manager SDK examples.
#

import importlib.util
import sqlite3
from pathlib import Path
from typing import Tuple

from keepersdk.authentication import keeper_auth
from keepersdk.vault import sqlite_storage, vault_online


def run_login():
    """
    Run the standard SDK login flow from examples/sdk_examples/auth/login.py.

    Returns:
        (KeeperAuth, KeeperEndpoint) or (None, None) on failure.
    """
    login_path = Path(__file__).resolve().parent.parent / 'auth' / 'login.py'
    spec = importlib.util.spec_from_file_location('sdk_auth_login', login_path)
    if spec is None or spec.loader is None:
        raise ImportError(f'Cannot load login module from {login_path}')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.login()


def open_vault(keeper_auth_context: keeper_auth.KeeperAuth) -> Tuple[vault_online.VaultOnline, sqlite3.Connection]:
    """Create an in-memory vault and sync down. Caller must vault.close() and auth.close()."""
    conn = sqlite3.connect('file::memory:', uri=True)
    vault_storage = sqlite_storage.SqliteVaultStorage(
        lambda: conn,
        vault_owner=bytes(keeper_auth_context.auth_context.username, 'utf-8'),
    )
    vault = vault_online.VaultOnline(keeper_auth_context, vault_storage)
    vault.sync_down()
    return vault, conn
