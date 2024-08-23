from __future__ import annotations

import abc
from typing import Optional, Any, Dict, Iterable

import attrs

from . import enterprise_types


@attrs.define(kw_only=True)
class NodeEdit:
    _node_id: int
    name: Optional[str] = None
    parent_id: Optional[int] = None
    restrict_visibility: Optional[bool] = None
    @property
    def node_id(self) -> int:
        return self._node_id


@attrs.define(kw_only=True)
class UserEdit:
    _enterprise_user_id: int
    username: Optional[str] = None
    node_id: Optional[int] = None
    full_name: Optional[str] = None
    job_title: Optional[str] = None
    @property
    def enterprise_user_id(self) -> int:
        return self._enterprise_user_id

@attrs.define(kw_only=True)
class TeamEdit:
    _team_uid: str
    name: Optional[str] = None
    node_id: Optional[int] = None
    restrict_edit: Optional[bool] = None
    restrict_share: Optional[bool] = None
    restrict_view: Optional[bool] = None
    extra: Optional[Dict[str, Any]] = None
    @property
    def team_uid(self) -> str:
        return self._team_uid


@attrs.define(kw_only=True)
class RoleEdit:
    _role_id: int
    node_id: Optional[int] = None
    name: Optional[str] = None
    visible_below: Optional[bool] = None
    new_user_inherit: Optional[bool] = None
    @property
    def role_id(self) -> int:
        return self._role_id


@attrs.define(kw_only=True)
class TeamUserEdit:
    _team_uid: str
    _enterprise_user_id: int
    user_type: Optional[int] = None
    @property
    def team_uid(self) -> str:
        return self._team_uid
    @property
    def enterprise_user_id(self) -> int:
        return self._enterprise_user_id


@attrs.define(kw_only=True)
class RoleUserEdit:
    _role_id: int
    _enterprise_user_id: int
    @property
    def role_id(self) -> int:
        return self._role_id
    @property
    def enterprise_user_id(self) -> int:
        return self._enterprise_user_id


@attrs.define(kw_only=True)
class RoleTeamEdit:
    _role_id: int
    _team_uid: str
    @property
    def role_id(self) -> int:
        return self._role_id
    @property
    def team_uid(self) -> str:
        return self._team_uid


@attrs.define(kw_only=True)
class ManagedNodeEdit:
    _role_id: int
    _managed_node_id: int
    cascade_node_management: Optional[bool] = None
    privileges: Optional[Dict[enterprise_types.RolePrivilege, bool]] = None

    @property
    def role_id(self) -> int:
        return self._role_id
    @property
    def managed_node_id(self) -> int:
        return self._managed_node_id


@attrs.define(kw_only=True)
class RoleEnforcementEdit:
    _role_id: int
    name: str
    value: Optional[Any] = None

    @property
    def role_id(self) -> int:
        return self._role_id


class IEnterpriseManagementLogger(abc.ABC):
    @abc.abstractmethod
    def warning(self, message: str) -> None:
        pass

class IEnterpriseManagement(abc.ABC):
    @abc.abstractmethod
    def modify_nodes(self, *,
                     to_add: Optional[Iterable[NodeEdit]] = None,
                     to_update: Optional[Iterable[NodeEdit]] = None,
                     to_remove: Optional[Iterable[NodeEdit]] = None,
                     ) -> None:
        pass

    @abc.abstractmethod
    def modify_roles(self, *,
                     to_add: Optional[Iterable[RoleEdit]] = None,
                     to_update: Optional[Iterable[RoleEdit]] = None,
                     to_remove: Optional[Iterable[RoleEdit]] = None) -> None:
        pass

    @abc.abstractmethod
    def modify_teams(self, *,
                     to_add: Optional[Iterable[TeamEdit]] = None,
                     to_update: Optional[Iterable[TeamEdit]] = None,
                     to_remove: Optional[Iterable[TeamEdit]] = None) -> None:
        pass

    @abc.abstractmethod
    def modify_users(self, *,
                     to_add: Optional[Iterable[UserEdit]] = None,
                     to_update: Optional[Iterable[UserEdit]] = None,
                     to_remove: Optional[Iterable[UserEdit]] = None) -> None:
        pass

    @abc.abstractmethod
    def user_actions(self, *,
                     to_lock: Optional[Iterable[int]] = None,
                     to_unlock: Optional[Iterable[int]] = None,
                     to_extend_transfer: Optional[Iterable[int]] = None,
                     to_expire_password: Optional[Iterable[int]] = None) -> None:
        pass

    @abc.abstractmethod
    def modify_team_users(self, *,
                          to_add: Optional[Iterable[TeamUserEdit]] = None,
                          to_remove: Optional[Iterable[TeamUserEdit]] = None) -> None:
        pass

    @abc.abstractmethod
    def modify_role_users(self, *,
                          to_add: Optional[Iterable[RoleUserEdit]] = None,
                          to_remove: Optional[Iterable[RoleUserEdit]] = None) -> None:
        pass

    @abc.abstractmethod
    def modify_role_teams(self, *,
                          to_add: Optional[Iterable[RoleTeamEdit]] = None,
                          to_remove: Optional[Iterable[RoleTeamEdit]] = None) -> None:
        pass

    @abc.abstractmethod
    def modify_managed_nodes(self, *,
                             to_add: Optional[Iterable[ManagedNodeEdit]] = None,
                             to_update: Optional[Iterable[ManagedNodeEdit]] = None,
                             to_remove: Optional[Iterable[ManagedNodeEdit]] = None) -> None:
        pass

    @abc.abstractmethod
    def modify_role_enforcements(self, *,
                                 enforcements: Optional[Iterable[RoleEnforcementEdit]] = None) -> None:
        pass

    @abc.abstractmethod
    def apply(self) -> None:
        pass
