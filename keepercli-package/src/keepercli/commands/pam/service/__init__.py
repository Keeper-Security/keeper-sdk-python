from __future__ import annotations
from keepersdk.helpers.keeper_dag.dag_utils import value_to_boolean
from keepersdk.vault import vault_online
from ....api import get_logger
import os
from typing import  TYPE_CHECKING

if TYPE_CHECKING:
    from keepersdk.helpers.keeper_dag.connection import ConnectionBase


def get_connection(vault: vault_online.VaultOnline) -> ConnectionBase:
    if value_to_boolean(os.environ.get("USE_LOCAL_DAG", False)) is False:
        from keepersdk.helpers.keeper_dag.connection.commander import Connection as CommanderConnection
        return CommanderConnection(vault=vault, logger=get_logger())
    else:
        from keepersdk.helpers.keeper_dag.connection.local import Connection as LocalConnection
        return LocalConnection(vault=vault, logger=get_logger())