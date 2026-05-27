#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper SDK for Python
# Copyright 2025 Keeper Security Inc.
# Contact: commander@keepersecurity.com
#
# Shared helpers for MSP SDK examples (keepersdk.enterprise.msp_auth).
#

import importlib.util
import sqlite3
from pathlib import Path
from typing import Any, Optional, Tuple

from keepersdk.authentication import keeper_auth
from keepersdk.enterprise import enterprise_loader, msp_auth, sqlite_enterprise_storage


def load_sdk_login():
    """Load the interactive login() from examples/sdk_examples/auth/login.py."""
    login_path = Path(__file__).resolve().parent.parent / 'auth' / 'login.py'
    spec = importlib.util.spec_from_file_location('keeper_sdk_example_login', login_path)
    if spec is None or spec.loader is None:
        raise ImportError(f'Cannot load login module from {login_path}')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.login, mod.enable_persistent_login


def login_with_enterprise() -> Tuple[Optional[keeper_auth.KeeperAuth], Optional[enterprise_loader.EnterpriseLoader]]:
    """Login and return (auth, enterprise_loader). Closes auth on failure paths."""
    login_fn, enable_persistent = load_sdk_login()
    auth, _endpoint = login_fn()
    if not auth:
        return None, None
    if not auth.auth_context.is_enterprise_admin:
        print('ERROR: MSP examples require an enterprise administrator account.')
        auth.close()
        return None, None
    try:
        loader = create_enterprise_loader(auth)
        return auth, loader
    except Exception:
        auth.close()
        raise


def create_enterprise_loader(auth: keeper_auth.KeeperAuth) -> enterprise_loader.EnterpriseLoader:
    conn = sqlite3.Connection('file::memory:', uri=True)
    enterprise_id = auth.auth_context.enterprise_id or 0
    storage = sqlite_enterprise_storage.SqliteEnterpriseStorage(lambda: conn, enterprise_id)
    return enterprise_loader.EnterpriseLoader(auth, storage)


def close_loader_and_auth(
    loader: Optional[enterprise_loader.EnterpriseLoader],
    auth: Optional[keeper_auth.KeeperAuth],
) -> None:
    if loader is not None:
        loader.close()
    if auth is not None:
        auth.close()


def print_msp_info_report(report: msp_auth.MspInfoReport) -> None:
    if report.message:
        print(report.message)
        return
    headers = list(report.headers)
    rows = list(report.rows)
    if report.row_numbers:
        if not headers or headers[0].lower() != '#':
            headers = ['#'] + headers
        rows = [tuple([i, *row]) for i, row in enumerate(rows, 1)]
    _print_table(headers, tuple(rows))


def print_msp_billing_report(report: msp_auth.MspBillingReport) -> None:
    print(report.title)
    _print_table(list(report.headers), report.rows)


def print_msp_legacy_report(report: msp_auth.MspLegacyReport) -> None:
    if report.title:
        print(report.title)
    _print_table(list(report.headers), report.rows)


def _print_table(headers: list, rows: tuple) -> None:
    if not headers:
        return
    widths = [len(str(h)) for h in headers]
    str_rows = []
    for row in rows:
        cells = [str(c) for c in row]
        str_rows.append(cells)
        for i, cell in enumerate(cells):
            if i < len(widths):
                widths[i] = max(widths[i], len(cell))
    fmt = '  '.join(f'{{:{w}}}' for w in widths)
    print(fmt.format(*[str(h) for h in headers]))
    print(fmt.format(*['-' * w for w in widths]))
    for cells in str_rows:
        padded = cells + [''] * (len(headers) - len(cells))
        print(fmt.format(*padded[: len(headers)]))
