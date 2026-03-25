from __future__ import annotations
from keepersdk.helpers.keeper_dag.dag_utils import value_to_boolean
import os
from typing import  TYPE_CHECKING

if TYPE_CHECKING:
    from ....params import KeeperParams
    from keepersdk.helpers.keeper_dag.connection import ConnectionBase


def get_connection(context: KeeperParams) -> ConnectionBase:
    if value_to_boolean(os.environ.get("USE_LOCAL_DAG", False)) is False:
        from keepersdk.helpers.keeper_dag.connection.commander import Connection as CommanderConnection
        return CommanderConnection(context=context)
    else:
        from keepersdk.helpers.keeper_dag.connection.local import Connection as LocalConnection
        return LocalConnection()