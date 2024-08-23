import attrs
from typing import Optional, Dict, Any, Set, FrozenSet, Union

from ...storage import storage_types


@attrs.define(kw_only=True)
class PedmAgent(storage_types.IUid[str]):
    agent_uid: str
    agent_name: str
    public_key: bytes = b''
    created: int = 0
    is_initialized: bool = False
    egress_uid: str
    ingress_uid: str
    def uid(self) -> str:
        return self.agent_uid


@attrs.define(kw_only=True)
class PedmPolicy(storage_types.IUid[str]):
    policy_uid: str
    policy_key: Optional[bytes] = None
    data: Dict[str, Any]
    agents: Optional[Union[Set[str], FrozenSet[str]]] = None
    def uid(self) -> str:
        return self.policy_uid


@attrs.define(kw_only=True)
class PedmOrganizationUnit(storage_types.IUid[str]):
    ou_uid: str
    parent_ou_uid: str       # OU or Enterprise
    data: Dict[str, Any]
    children_ou: Optional[Union[Set[str], FrozenSet[str]]] = None
    agents:  Optional[Union[Set[str], FrozenSet[str]]] = None
    def uid(self) -> str:
        return self.ou_uid
