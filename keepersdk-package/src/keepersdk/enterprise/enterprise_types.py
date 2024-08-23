from __future__ import annotations

import abc
import enum
from dataclasses import dataclass
from typing import Generic, Iterable, List, Optional, Set, Type, Tuple, Any

import attrs
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from ..authentication import keeper_auth
from ..storage.storage_types import T, IRecordStorage, ILinkStorage, IEntity, ILink


@attrs.define(kw_only=True)
class Node:
    node_id: int
    parent_id: Optional[int]
    bridge_id: Optional[int] = None
    scim_id: Optional[int] = None
    license_id: Optional[int] = None
    duo_enabled: bool = False
    rsa_enabled: bool = False
    restrict_visibility: bool = False
    sso_service_provided_ids: Optional[List[int]] = None
    encrypted_data: Optional[str] = None
    name: str = ''

@attrs.define(frozen=True)
class INode(Node):
    pass

@attrs.define(kw_only=True)
class Role:
    role_id: int
    name: str = ''
    node_id: int
    visible_below: bool = False
    new_user_inherit: bool = False
    role_type: Optional[str] = None
    key_type: str = ''
    encrypted_data: Optional[str] = None
# noinspection PyTypeChecker
IRole: Type[Role] = attrs.make_class('IRole', [], (Role,), frozen=True)


@attrs.define(kw_only=True)
class User:
    enterprise_user_id: int
    username: str
    node_id: int
    status: str
    lock: int = 0
    full_name: Optional[str] = None
    job_title: Optional[str] = None
    user_id: Optional[int] = None
    account_share_expiration: Optional[int] = None
    tfa_enabled: bool = False
    transfer_acceptance_status: Optional[int] = None
    key_type: str = ''
    encrypted_data: Optional[str] = None
# noinspection PyTypeChecker
IUser: Type[User] = attrs.make_class('IUser', [], (User,), frozen=True)


@attrs.define(kw_only=True)
class Team:
    team_uid: str
    name: str
    node_id: int
    restrict_edit: bool = False
    restrict_share: bool = False
    restrict_view: bool = False
    encrypted_team_key: Optional[bytes] = None
    encrypted_data: Optional[str] = None
# noinspection PyTypeChecker
ITeam: Type[Team] = attrs.make_class('ITeam', [], (Team,), frozen=True)


@attrs.define(kw_only=True)
class TeamUser:
    team_uid: str
    enterprise_user_id: int
    user_type: Optional[str] = None
# noinspection PyTypeChecker
ITeamUser: Type[TeamUser] = attrs.make_class('ITeamUser', [], (TeamUser,), frozen=True)


@attrs.define(kw_only=True)
class RoleUser:
    role_id: int
    enterprise_user_id: int
# noinspection PyTypeChecker
IRoleUser: Type[RoleUser] = attrs.make_class('IRoleUser', [], (RoleUser,), frozen=True)

@attrs.define(kw_only=True)
class RoleTeam:
    role_id: int
    team_uid: str
# noinspection PyTypeChecker
IRoleTeam: Type[RoleTeam] = attrs.make_class('IRoleTeam', [], (RoleTeam,), frozen=True)


class RolePrivilege(str, enum.Enum):
    ManageNodes = "MANAGE_NODES"
    ManageUsers = "MANAGE_USER"
    ManageLicences = "MANAGE_LICENCES"
    ManageRoles = "MANAGE_ROLES"
    ManageTeams = "MANAGE_TEAMS"
    RunSecurityReports = "RUN_REPORTS"
    ManageBridge = "MANAGE_BRIDGE"
    ApproveDevice = "APPROVE_DEVICE"
    ManageRecordTypes = "MANAGE_RECORD_TYPES"
    RunComplianceReports = "RUN_COMPLIANCE_REPORTS"
    ManageCompanies = "MANAGE_COMPANIES"
    TransferAccount = "TRANSFER_ACCOUNT"
    SharingAdministrator = "SHARING_ADMINISTRATOR"


@attrs.define(kw_only=True)
class RolePrivileges:
    role_id: int
    managed_node_id: int

    _manage_nodes: bool = False
    _manage_users: bool = False
    _manage_roles: bool = False
    _manage_teams: bool = False
    _run_reports: bool = False
    _manage_bridge: bool = False
    _approve_devices: bool = False
    _manage_record_types: bool = False
    _sharing_administrator: bool = False
    _run_compliance_report: bool = False
    _transfer_account: bool = False
    _manage_companies: bool = False

    @property
    def manage_nodes(self) -> bool:
        return self._manage_nodes

    @property
    def manage_users(self) -> bool:
        return self._manage_users
    @property
    def manage_roles(self) -> bool:
        return self._manage_roles
    @property
    def manage_teams(self) -> bool:
        return self._manage_teams
    @property
    def run_reports(self) -> bool:
        return self._run_reports
    @property
    def manage_bridge(self) -> bool:
        return self._manage_bridge
    @property
    def approve_devices(self) -> bool:
        return self._approve_devices
    @property
    def manage_record_types(self) -> bool:
        return self._manage_record_types
    @property
    def sharing_administrator(self) -> bool:
        return self._sharing_administrator
    @property
    def run_compliance_report(self) -> bool:
        return self._run_compliance_report
    @property
    def transfer_account(self) -> bool:
        return self._transfer_account
    @property
    def manage_companies(self) -> bool:
        return self._manage_companies

    def set_by_name(self, name: str, value: bool) -> bool:
        u_name = name.upper()
        if u_name == RolePrivilege.ManageNodes.value:
            self._manage_nodes = value
        elif u_name == RolePrivilege.ManageUsers.value:
            self._manage_users = value
        elif u_name == RolePrivilege.ManageRoles.value:
            self._manage_roles = value
        elif u_name == RolePrivilege.ManageTeams.value:
            self._manage_teams = value
        elif u_name == RolePrivilege.RunSecurityReports.value:
            self._run_reports = value
        elif u_name == RolePrivilege.ManageBridge.value:
            self._manage_bridge = value
        elif u_name == RolePrivilege.ApproveDevice.value:
            self._approve_devices = value
        elif u_name == RolePrivilege.ManageRecordTypes.value:
            self._manage_record_types = value
        elif u_name == RolePrivilege.RunComplianceReports.value:
            self._run_compliance_report = value
        elif u_name == RolePrivilege.ManageCompanies.value:
            self._manage_companies = value
        elif u_name == RolePrivilege.TransferAccount.value:
            self._transfer_account = value
        elif u_name == RolePrivilege.SharingAdministrator.value:
            self._sharing_administrator = value
        else:
            return False
        return True

    def to_set(self) -> Set[str]:
        result: Set[str] = set()
        if self._manage_nodes:
            result.add(RolePrivilege.ManageNodes.value)
        if self._manage_users:
            result.add(RolePrivilege.ManageUsers.value)
        if self._manage_roles:
            result.add(RolePrivilege.ManageRoles.value)
        if self._manage_teams:
            result.add(RolePrivilege.ManageTeams.value)
        if self._run_reports:
            result.add(RolePrivilege.RunSecurityReports.value)
        if self._manage_bridge:
            result.add(RolePrivilege.ManageBridge.value)
        if self._approve_devices:
            result.add(RolePrivilege.ApproveDevice.value)
        if self._manage_record_types:
            result.add(RolePrivilege.ManageRecordTypes.value)
        if self._sharing_administrator:
            result.add(RolePrivilege.SharingAdministrator.value)
        if self._run_compliance_report:
            result.add(RolePrivilege.RunComplianceReports.value)
        if self._transfer_account:
            result.add(RolePrivilege.TransferAccount.value)
        if self._manage_companies:
            result.add(RolePrivilege.ManageCompanies.value)
        return result


@attrs.define(kw_only=True)
class ManagedNode:
    role_id: int
    managed_node_id: int
    cascade_node_management: bool = True
# noinspection PyTypeChecker
IManagedNode: Type[ManagedNode] = attrs.make_class('IManagedNode', [], (ManagedNode,), frozen=True)


@attrs.define(kw_only=True)
class RoleEnforcement:
    role_id: int
    enforcement_type: str
    value: str
# noinspection PyTypeChecker
IRoleEnforcement: Type[RoleEnforcement] = attrs.make_class('IRoleEnforcement', [], (RoleEnforcement,), frozen=True)


@attrs.define(kw_only=True, frozen=True)
class LicenseAddOn:
    name: str
    enabled: bool
    included_in_product: bool
    is_trial: bool
    seats: int
    api_call_count: int
    created: int
    activation_time: int
    expiration: int


@attrs.define(kw_only=True, frozen=True)
class McDefault:
    mc_product: str
    file_plan_type: str
    max_licenses: int
    add_ons: Optional[List[str]] = None
    fixed_max_licenses: bool


@attrs.define(kw_only=True, frozen=True)
class MspPermits:
    restricted: bool
    max_file_plan_type: str
    allow_unlimited_licenses: bool
    allowed_mc_products: Optional[List[str]] = None
    allowed_add_ons: Optional[List[str]] = None
    mc_defaults: Optional[List[McDefault]] = None


@attrs.define(kw_only=True, frozen=True)
class MspContact:
    enterprise_id: int
    enterprise_name: str

@attrs.define(kw_only=True, frozen=True)
class License:
    enterprise_license_id: int
    license_key_id: int
    product_type_id: int
    file_plan_id: int
    name: str
    number_of_seats: int
    seats_allocated: int
    seats_pending: int
    add_ons: Optional[List[LicenseAddOn]] = None
    license_status: str
    next_billing_date: int
    expiration: int
    storage_expiration: int
    distributor: bool
    msp_permits: Optional[MspPermits] = None
    managed_by: Optional[MspContact] = None


@attrs.define(kw_only=True, frozen=True)
class UserAlias:
    enterprise_user_id: int
    username: str


@attrs.define(kw_only=True, frozen=True)
class SsoService:
    sso_service_provider_id: int
    node_id: int
    name: str
    sp_url: str
    invite_new_users: bool
    active: bool
    is_cloud: bool


@attrs.define(kw_only=True, frozen=True)
class Bridge:
    bridge_id: int
    node_id: int
    wan_ip_enforcement: str
    lan_ip_enforcement: str
    status: str


@attrs.define(kw_only=True, frozen=True)
class Scim:
    scim_id: int
    node_id: int
    status: str
    last_synced: int
    role_prefix: str
    unique_groups: bool


@attrs.define(kw_only=True)
class EmailProvision:
    id: int
    node_id: int
    domain: str
    method: str


@attrs.define(kw_only=True, frozen=True)
class ManagedCompany:
    mc_enterprise_id: int
    mc_enterprise_name: str
    msp_node_id: int
    number_of_seats: int
    number_of_users: int
    product_id: str
    is_expired: bool
    tree_key: str
    tree_key_role: int
    file_plan_type: str
    add_ons: Optional[List[LicenseAddOn]] = None


@attrs.define(kw_only=True)
class QueuedTeam:
    team_uid: str
    name: str
    node_id: int
    encrypted_data: str
# noinspection PyTypeChecker
IQueuedTeam: Type[QueuedTeam] = attrs.make_class('IQueuedTeam', [], (QueuedTeam,), frozen=True)


@attrs.define(kw_only=True, frozen=True)
class QueuedTeamUser:
    team_uid: str
    enterprise_user_id: int


class EnterpriseInfo:
    def __init__(self) -> None:
        self._enterprise_name = ''
        self._is_distributor = False
        self._tree_key = b''
        self._rsa_private_key: Optional[rsa.RSAPrivateKey] = None
        self._rsa_public_key: Optional[rsa.RSAPublicKey] = None
        self._ec_private_key: Optional[ec.EllipticCurvePrivateKey] = None
        self._ec_public_key: Optional[ec.EllipticCurvePublicKey] = None

    @property
    def tree_key(self):
        return self._tree_key

    @property
    def rsa_private_key(self):
        return self._rsa_private_key

    @property
    def rsa_public_key(self):
        return self._rsa_public_key

    @property
    def ec_private_key(self):
        return self._ec_private_key

    @property
    def ec_public_key(self):
        return self._ec_public_key

    @property
    def enterprise_name(self):
        return self._enterprise_name

    @property
    def is_distributor(self):
        return self._is_distributor


class IEnterpriseData(abc.ABC):
    @property
    @abc.abstractmethod
    def enterprise_info(self) -> EnterpriseInfo:
        pass

    @property
    @abc.abstractmethod
    def root_node(self) -> Node:
        pass

    @property
    @abc.abstractmethod
    def nodes(self) -> IEntity[Node, int]:
        pass

    @property
    @abc.abstractmethod
    def roles(self) -> IEntity[Role, int]:
        pass

    @property
    @abc.abstractmethod
    def users(self) -> IEntity[User, int]:
        pass

    @property
    @abc.abstractmethod
    def teams(self) -> IEntity[Team, str]:
        pass

    @property
    @abc.abstractmethod
    def team_users(self) -> ILink[TeamUser, str, int]:
        pass

    @property
    @abc.abstractmethod
    def queued_teams(self) -> IEntity[QueuedTeam, str]:
        pass

    @property
    @abc.abstractmethod
    def queued_team_users(self) -> ILink[QueuedTeamUser, str, int]:
        pass

    @property
    @abc.abstractmethod
    def role_users(self) -> ILink[RoleUser, int, int]:
        pass

    @property
    @abc.abstractmethod
    def role_teams(self) -> ILink[RoleTeam, int, str]:
        pass

    @property
    @abc.abstractmethod
    def managed_nodes(self) -> ILink[ManagedNode, int, int]:
        pass

    @property
    @abc.abstractmethod
    def role_privileges(self) -> ILink[RolePrivileges, int, int]:
        pass

    @property
    @abc.abstractmethod
    def role_enforcements(self) -> ILink[RoleEnforcement, int, str]:
        pass

    @property
    @abc.abstractmethod
    def licenses(self) -> IEntity[License, int]:
        pass

    @property
    @abc.abstractmethod
    def sso_services(self) -> IEntity[SsoService, int]:
        pass

    @property
    @abc.abstractmethod
    def bridges(self) -> IEntity[Bridge, int]:
        pass

    @property
    @abc.abstractmethod
    def scims(self) -> IEntity[Scim, int]:
        pass

    @property
    @abc.abstractmethod
    def email_provision(self) -> IEntity[EmailProvision, int]:
        pass

    @property
    @abc.abstractmethod
    def managed_companies(self) -> IEntity[ManagedCompany, int]:
        pass

    @property
    @abc.abstractmethod
    def user_aliases(self) -> ILink[UserAlias, int, str]:
        pass


@dataclass
class EnterpriseSettings:
    continuation_token: bytes = b''

@dataclass
class EnterpriseIdRange:
    id_start: int = 0
    id_count: int = 0


@dataclass
class EnterpriseEntityData:
    type: int = 0
    key: str = ''
    data: bytes = b''


class IEnterpriseStorage(abc.ABC):
    @property
    @abc.abstractmethod
    def id_range(self) -> IRecordStorage[EnterpriseIdRange]:
        pass

    @property
    @abc.abstractmethod
    def settings(self) -> IRecordStorage[EnterpriseSettings]:
        pass

    @property
    @abc.abstractmethod
    def entity_data(self) -> ILinkStorage[EnterpriseEntityData, int, str]:
        pass

    @abc.abstractmethod
    def clear(self) -> None:
        pass


class IEnterpriseLoader(abc.ABC):
    @property
    @abc.abstractmethod
    def enterprise_data(self) -> IEnterpriseData:
        pass

    @property
    @abc.abstractmethod
    def storage(self) -> Optional[IEnterpriseStorage]:
        pass

    @property
    @abc.abstractmethod
    def keeper_auth(self) -> keeper_auth.KeeperAuth:
        pass

    @abc.abstractmethod
    def load(self, reset: Optional[bool] = False) -> Set[int]:
        pass

    @abc.abstractmethod
    def load_role_keys(self, ids: Iterable[int]) -> None:
        pass

    @abc.abstractmethod
    def get_role_keys(self, role_id: int) -> Optional[bytes]:
        pass

    @abc.abstractmethod
    def get_enterprise_id(self) -> int:
        pass

    @abc.abstractmethod
    def close(self) -> None:
        pass

class IEnterpriseDataPlugin(abc.ABC):
    @abc.abstractmethod
    def store_data(self, data: bytes, key: bytes) -> Tuple[str, bytes]:
        pass
    @abc.abstractmethod
    def delete_data(self, data: bytes) -> Tuple[str, bytes]:
        pass

    @abc.abstractmethod
    def clear(self) -> None:
        pass

class IEnterprisePlugin(Generic[T], IEnterpriseDataPlugin, abc.ABC):
    @abc.abstractmethod
    def put_entity(self, entity: T) -> None:
        pass

    @abc.abstractmethod
    def delete_entity(self, entity: T) -> None:
        pass

    @abc.abstractmethod
    def convert_entity(self, data: bytes) -> T:
        pass

    @abc.abstractmethod
    def storage_key(self, entity: T) -> str:
        pass

    def decrypt_entity(self, entity: T, key: bytes) -> None:
        pass

    @classmethod
    def frozen_entity_type(cls) -> Optional[Type[T]]:
        return None

    def store_data(self, data: bytes, key: bytes) -> Tuple[str, bytes]:
        e = self.convert_entity(data)
        self.decrypt_entity(e, key)
        frozen_type = self.frozen_entity_type()
        if frozen_type:
            o: Any = e
            e = frozen_type(**attrs.asdict(o))
        self.put_entity(e)
        return self.storage_key(e), data

    def delete_data(self, data: bytes) -> Tuple[str, bytes]:
        e = self.convert_entity(data)
        self.delete_entity(e)
        return self.storage_key(e), b''
