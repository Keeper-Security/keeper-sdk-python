from typing import Dict, Optional, Iterable

from . import enterprise_types, private_data
from .. import utils
from ..proto import enterprise_pb2


class EnterpriseData(enterprise_types.IEnterpriseData):
    def __init__(self) -> None:
        self._enterprise_info = enterprise_types.EnterpriseInfo()
        self._root_node: Optional[enterprise_types.Node] = None
        self._nodes = private_data.NodeEntity()
        self._roles = private_data.RoleEntity()
        self._users = private_data.UserEntity()
        self._teams = private_data.TeamEntity()
        self._queued_teams = private_data.QueuedTeamEntity()
        self._team_users = private_data.TeamUserLink()
        self._queued_team_users = private_data.QueuedTeamUserLinkReader()
        self._role_users = private_data.RoleUserLink()
        self._role_privileges = private_data.RolePrivilegeLinkReader()
        self._role_enforcements = private_data.RoleEnforcementLink()
        self._role_teams = private_data.RoleTeamLink()
        self._licenses = private_data.LicenseEntity()
        self._managed_nodes = private_data.ManagedNodeLink()
        self._managed_companies = private_data.ManagedCompanyEntity()
        self._user_aliases = private_data.UserAliasLink()
        self._bridges = private_data.BridgeEntity()
        self._scims = private_data.ScimEntity()
        self._sso_services = private_data.SsoServiceEntity()
        self._email_provision = private_data.EmailProvisionEntity()
        self._logger = utils.get_logger()

        self._entities: Dict[int, enterprise_types.IEnterpriseDataPlugin] = {
            enterprise_pb2.EnterpriseDataEntity.NODES: self._nodes,
            enterprise_pb2.EnterpriseDataEntity.ROLES: self._roles,
            enterprise_pb2.EnterpriseDataEntity.USERS: self._users,
            enterprise_pb2.EnterpriseDataEntity.TEAMS: self._teams,
            enterprise_pb2.EnterpriseDataEntity.QUEUED_TEAMS: self._queued_teams,
            enterprise_pb2.EnterpriseDataEntity.ROLE_USERS: self._role_users,
            enterprise_pb2.EnterpriseDataEntity.ROLE_PRIVILEGES: self._role_privileges,
            enterprise_pb2.EnterpriseDataEntity.ROLE_ENFORCEMENTS: self._role_enforcements,
            enterprise_pb2.EnterpriseDataEntity.ROLE_TEAMS: self._role_teams,
            enterprise_pb2.EnterpriseDataEntity.TEAM_USERS: self._team_users,
            enterprise_pb2.EnterpriseDataEntity.LICENSES: self._licenses,
            enterprise_pb2.EnterpriseDataEntity.MANAGED_NODES: self._managed_nodes,
            enterprise_pb2.EnterpriseDataEntity.MANAGED_COMPANIES: self._managed_companies,
            enterprise_pb2.EnterpriseDataEntity.QUEUED_TEAM_USERS: self._queued_team_users,
            enterprise_pb2.USER_ALIASES: self._user_aliases,
            enterprise_pb2.BRIDGES: self._bridges,
            enterprise_pb2.SCIMS: self._scims,
            enterprise_pb2.SSO_SERVICES: self._sso_services,
            enterprise_pb2.EMAIL_PROVISION: self._email_provision,
        }

    def get_plugin(self, entity_id: int) -> Optional[enterprise_types.IEnterpriseDataPlugin]:
        return self._entities.get(entity_id)

    @property
    def team_user_plugin(self) -> enterprise_types.IEnterprisePlugin[enterprise_types.TeamUser]:
        return self._team_users

    @property
    def role_team_plugin(self) -> enterprise_types.IEnterprisePlugin[enterprise_types.RoleTeam]:
        return self._role_teams

    @property
    def role_user_plugin(self) -> enterprise_types.IEnterprisePlugin[enterprise_types.RoleUser]:
        return self._role_users

    @property
    def user_alias_plugin(self) -> enterprise_types.IEnterprisePlugin[enterprise_types.UserAlias]:
        return self._user_aliases

    @property
    def role_enforcement_plugin(self) -> enterprise_types.IEnterprisePlugin[enterprise_types.RoleEnforcement]:
        return self._role_enforcements

    @property
    def role_privilege_plugin(self) -> private_data.RolePrivilegeLinkReader:
        return self._role_privileges

    def get_supported_entities(self) -> Iterable[int]:
        yield from self._entities.keys()

    @property
    def enterprise_info(self):
        return self._enterprise_info

    @property
    def root_node(self):
        assert self._root_node is not None
        return self._root_node

    @property
    def nodes(self):
        return self._nodes

    @property
    def roles(self):
        return self._roles

    @property
    def users(self):
        return self._users

    @property
    def teams(self):
        return self._teams

    @property
    def queued_teams(self):
        return self._queued_teams

    @property
    def role_users(self):
        return self._role_users

    @property
    def role_privileges(self):
        return self._role_privileges

    @property
    def role_enforcements(self):
        return self._role_enforcements

    @property
    def role_teams(self):
        return self._role_teams

    @property
    def team_users(self):
        return self._team_users

    @property
    def queued_team_users(self):
        return self._queued_team_users

    @property
    def licenses(self):
        return self._licenses

    @property
    def managed_nodes(self):
        return self._managed_nodes

    @property
    def managed_companies(self):
        return self._managed_companies

    @property
    def user_aliases(self):
        return self._user_aliases

    @property
    def bridges(self):
        return self._bridges

    @property
    def scims(self):
        return self._scims

    @property
    def sso_services(self):
        return self._sso_services

    @property
    def email_provision(self):
        return self._email_provision
