#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper SDK
# Copyright 2023 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import abc
from typing import Tuple, Dict, Type, Iterator

from google.protobuf.message import Message

from ..proto import enterprise_pb2


class EnterprisePlugin(abc.ABC):
    @abc.abstractmethod
    def put_entity(self, entity_type, data):  # type: (enterprise_pb2.EnterpriseDataEntity, bytes) -> None
        pass

    @abc.abstractmethod
    def delete_entity(self, entity_type, data):  # type: (enterprise_pb2.EnterpriseDataEntity, bytes) -> None
        pass

    @abc.abstractmethod
    def clear(self):
        pass


class EnterpriseInfo:
    def __init__(self):
        self._enterprise_name = ''
        self._is_distributor = False
        self._tree_key = b''
        self._rsa_key = None
        self._ec_key = None

    @property
    def tree_key(self):
        return self._tree_key

    @property
    def rsa_key(self):
        return self._rsa_key

    @property
    def ec_key(self):
        return self._ec_key

    @property
    def enterprise_name(self):
        return self._enterprise_name

    @property
    def is_distributor(self):
        return self._is_distributor


class EnterpriseData(EnterprisePlugin, abc.ABC):
    @property
    @abc.abstractmethod
    def enterprise_info(self):
        pass

    @abc.abstractmethod
    def put_role_key(self, role_id, key_type, encrypted_key):
        # type: (int, enterprise_pb2.EncryptedKeyType, bytes) -> None
        pass

    @abc.abstractmethod
    def put_role_key2(self, role_id, encrypted_key):  # type: (int, bytes) -> None
        pass


class EnterpriseStorage(EnterprisePlugin, abc.ABC):
    @abc.abstractmethod
    def get_continuation_token(self):   # type: () -> bytes
        pass

    @abc.abstractmethod
    def set_continuation_token(self, token):   # type: (bytes) -> None
        pass

    @abc.abstractmethod
    def get_all(self):  # type: () -> Iterator[Tuple[enterprise_pb2.EnterpriseDataEntity, bytes]]
        pass

    @abc.abstractmethod
    def flush(self):
        pass


EnterpriseEntityMap = {
    enterprise_pb2.NODES: enterprise_pb2.Node,
    enterprise_pb2.ROLES: enterprise_pb2.Role,
    enterprise_pb2.USERS: enterprise_pb2.User,
    enterprise_pb2.TEAMS: enterprise_pb2.Team,
    enterprise_pb2.TEAM_USERS: enterprise_pb2.TeamUser,
    enterprise_pb2.ROLE_USERS: enterprise_pb2.RoleUser,
    enterprise_pb2.ROLE_PRIVILEGES: enterprise_pb2.RolePrivilege,
    enterprise_pb2.ROLE_ENFORCEMENTS: enterprise_pb2.RoleEnforcement,
    enterprise_pb2.ROLE_TEAMS: enterprise_pb2.RoleTeam,
    enterprise_pb2.LICENSES: enterprise_pb2.License,
    enterprise_pb2.MANAGED_NODES: enterprise_pb2.ManagedNode,
    enterprise_pb2.MANAGED_COMPANIES: enterprise_pb2.ManagedCompany,
    enterprise_pb2.BRIDGES: enterprise_pb2.Bridge,
    enterprise_pb2.SCIMS: enterprise_pb2.Scim,
    enterprise_pb2.EMAIL_PROVISION: enterprise_pb2.EmailProvision,
    enterprise_pb2.QUEUED_TEAMS: enterprise_pb2.QueuedTeam,
    enterprise_pb2.QUEUED_TEAM_USERS: enterprise_pb2.QueuedTeamUser,
    enterprise_pb2.SSO_SERVICES: enterprise_pb2.SsoService,
    enterprise_pb2.DEVICES_REQUEST_FOR_ADMIN_APPROVAL: enterprise_pb2.DeviceRequestForAdminApproval,
    enterprise_pb2.USER_ALIASES: enterprise_pb2.UserAlias,
    enterprise_pb2.COMPLIANCE_REPORT_CRITERIA_AND_FILTER: enterprise_pb2.ComplianceReportCriteriaAndFilter,
    enterprise_pb2.COMPLIANCE_REPORTS: enterprise_pb2.ComplianceReportMetaData,
}   # type: Dict[enterprise_pb2.EnterpriseDataEntity, Type[Message]]
