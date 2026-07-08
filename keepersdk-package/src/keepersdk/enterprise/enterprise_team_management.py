#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper SDK for Python — enterprise team read/query operations.
#

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .. import utils
from ..authentication import keeper_auth
from ..proto import enterprise_pb2
from ..vault import share_management_utils, vault_data, vault_online, vault_types, vault_utils
from . import enterprise_types

TEAM_MEMBERS_ENDPOINT = 'vault/get_team_members'

ERROR_MSG_TEAM_NOT_FOUND = "Team '{}' not found"
ERROR_MSG_TEAM_NOT_FOUND_BY_UID = "Team with UID '{}' not found"
ERROR_MSG_MULTIPLE_TEAMS = "Multiple teams found with name '{}'. Use Team UID instead."


class EnterpriseTeamManagementError(ValueError):
    pass


@dataclass(frozen=True)
class TeamMemberInfo:
    """Live team member from vault/get_team_members."""

    enterprise_user_id: int
    email: str
    enterprise_username: str
    is_share_admin: bool


@dataclass(frozen=True)
class EnterpriseTeamUserInfo:
    enterprise_user_id: int
    username: str
    full_name: Optional[str] = None


@dataclass(frozen=True)
class EnterpriseTeamRoleInfo:
    role_id: int
    role_name: str


@dataclass(frozen=True)
class EnterpriseTeamSummary:
    team_uid: str
    team_name: str
    node_id: int
    node_name: str
    restrict_edit: bool
    restrict_share: bool
    restrict_view: bool
    user_count: int = 0
    role_count: int = 0


@dataclass
class TeamResolveResult:
    team_uid: Optional[str] = None
    vault_team: Optional[vault_types.TeamInfo] = None
    enterprise_team: Optional[enterprise_types.Team] = None
    share_team: Optional[vault_types.TeamInfo] = None
    multiple_found: bool = False

    @property
    def found(self) -> bool:
        return self.team_uid is not None


@dataclass
class EnterpriseTeamInfo:
    team_uid: str
    team_name: str
    node_id: int
    node_name: str
    restrict_edit: bool
    restrict_share: bool
    restrict_view: bool
    access_level: str = 'enterprise_admin'
    is_member: bool = True
    team_roles: List[EnterpriseTeamRoleInfo] = field(default_factory=list)
    team_users: List[EnterpriseTeamUserInfo] = field(default_factory=list)
    queued_team_users: List[EnterpriseTeamUserInfo] = field(default_factory=list)
    members: List[TeamMemberInfo] = field(default_factory=list)

    def to_dict(self) -> dict:
        result = {
            'team_uid': self.team_uid,
            'team_name': self.team_name,
            'node_id': self.node_id,
            'node_name': self.node_name,
            'restrict_edit': self.restrict_edit,
            'restrict_share': self.restrict_share,
            'restrict_view': self.restrict_view,
            'access_level': self.access_level,
            'is_member': self.is_member,
        }
        if self.team_roles:
            result['team_roles'] = [
                {'role_id': x.role_id, 'role_name': x.role_name} for x in self.team_roles
            ]
        if self.team_users:
            result['team_users'] = [
                {'enterprise_user_id': x.enterprise_user_id, 'username': x.username}
                for x in self.team_users
            ]
        if self.queued_team_users:
            result['queued_team_users'] = [
                {'enterprise_user_id': x.enterprise_user_id, 'username': x.username}
                for x in self.queued_team_users
            ]
        if self.members:
            result['members'] = [
                {
                    'enterprise_user_id': x.enterprise_user_id,
                    'email': x.email,
                    'enterprise_username': x.enterprise_username,
                    'is_share_admin': x.is_share_admin,
                }
                for x in self.members
            ]
        return result


def _get_node_path(
    enterprise_data: enterprise_types.IEnterpriseData,
    node_id: int,
    *,
    omit_root: bool = False,
) -> str:
    nodes: List[str] = []
    n_id = node_id
    while isinstance(n_id, int) and n_id > 0:
        node = enterprise_data.nodes.get_entity(n_id)
        if not node:
            break
        n_id = node.parent_id or 0
        if not omit_root or n_id > 0:
            node_name = node.name
            if not node_name and node.node_id == enterprise_data.root_node.node_id:
                node_name = enterprise_data.enterprise_info.enterprise_name
            nodes.append(node_name)
    nodes.reverse()
    return '\\'.join(nodes)


def _teams_by_name(
    teams: List[enterprise_types.Team],
    team_name: str,
) -> List[enterprise_types.Team]:
    name_lower = team_name.lower()
    return [t for t in teams if t.name.lower() == name_lower]


def _vault_teams_by_name(
    vault_data_obj: vault_data.VaultData,
    team_name: str,
) -> List[vault_types.TeamInfo]:
    name_lower = team_name.lower()
    return [t for t in vault_data_obj.teams() if t.name.lower() == name_lower]


def _shareable_teams_by_name(
    teams: List[vault_types.TeamInfo],
    team_name: str,
) -> List[vault_types.TeamInfo]:
    name_lower = team_name.lower()
    return [t for t in teams if t.name.lower() == name_lower]


def _collect_shareable_teams(
    *,
    auth: Optional[keeper_auth.KeeperAuth] = None,
    vault: Optional[vault_online.VaultOnline] = None,
) -> List[vault_types.TeamInfo]:
    """Teams visible via share objects and get_available_teams (same sources as list-team)."""
    teams: List[vault_types.TeamInfo] = []
    seen: set = set()

    if vault is not None:
        share_objects = share_management_utils.get_share_objects(vault=vault)
        for team_uid, team_info in share_objects.get('teams', {}).items():
            if team_uid in seen:
                continue
            seen.add(team_uid)
            teams.append(
                vault_types.TeamInfo(
                    team_uid=team_uid,
                    name=team_info.get('name') or '',
                )
            )

    if auth is not None:
        for team in vault_utils.load_available_teams(auth):
            if team.team_uid in seen:
                continue
            seen.add(team.team_uid)
            teams.append(team)

    return teams


def resolve_team(
    team_name_or_uid: str,
    *,
    vault_data_obj: Optional[vault_data.VaultData] = None,
    enterprise_data: Optional[enterprise_types.IEnterpriseData] = None,
    is_enterprise_admin: bool = False,
    auth: Optional[keeper_auth.KeeperAuth] = None,
    vault: Optional[vault_online.VaultOnline] = None,
) -> TeamResolveResult:
    """
    Resolve a team by UID or case-insensitive name.

    Resolution order matches Keeper Commander (.NET):
    1. Vault cache by UID
    2. Vault cache by name
    3. Enterprise cache by UID (enterprise admin)
    4. Enterprise cache by name (enterprise admin)
    5. Share objects / available teams by UID
    6. Share objects / available teams by name
    """
    if not team_name_or_uid:
        return TeamResolveResult()

    if vault_data_obj is not None:
        vault_team = vault_data_obj.get_team(team_name_or_uid)
        if vault_team is not None:
            return TeamResolveResult(team_uid=vault_team.team_uid, vault_team=vault_team)

        vault_matches = _vault_teams_by_name(vault_data_obj, team_name_or_uid)
        if len(vault_matches) > 1:
            return TeamResolveResult(multiple_found=True)
        if len(vault_matches) == 1:
            team = vault_matches[0]
            return TeamResolveResult(team_uid=team.team_uid, vault_team=team)

    if enterprise_data is not None and is_enterprise_admin:
        enterprise_team = enterprise_data.teams.get_entity(team_name_or_uid)
        if enterprise_team is not None:
            return TeamResolveResult(
                team_uid=enterprise_team.team_uid,
                enterprise_team=enterprise_team,
            )

        enterprise_matches = _teams_by_name(
            list(enterprise_data.teams.get_all_entities()),
            team_name_or_uid,
        )
        if len(enterprise_matches) > 1:
            return TeamResolveResult(multiple_found=True)
        if len(enterprise_matches) == 1:
            team = enterprise_matches[0]
            return TeamResolveResult(team_uid=team.team_uid, enterprise_team=team)

    if auth is not None or vault is not None:
        shareable_teams = _collect_shareable_teams(auth=auth, vault=vault)
        share_team = next(
            (team for team in shareable_teams if team.team_uid == team_name_or_uid),
            None,
        )
        if share_team is not None:
            return TeamResolveResult(
                team_uid=share_team.team_uid,
                share_team=share_team,
            )

        share_matches = _shareable_teams_by_name(shareable_teams, team_name_or_uid)
        if len(share_matches) > 1:
            return TeamResolveResult(multiple_found=True)
        if len(share_matches) == 1:
            team = share_matches[0]
            return TeamResolveResult(team_uid=team.team_uid, share_team=team)

    return TeamResolveResult()


def resolve_enterprise_team(
    enterprise_data: enterprise_types.IEnterpriseData,
    team_name_or_uid: str,
) -> enterprise_types.Team:
    """Resolve an enterprise team by UID or case-insensitive name."""
    team = enterprise_data.teams.get_entity(team_name_or_uid)
    if team is not None:
        return team

    matches = _teams_by_name(list(enterprise_data.teams.get_all_entities()), team_name_or_uid)
    if not matches:
        raise EnterpriseTeamManagementError(
            ERROR_MSG_TEAM_NOT_FOUND.format(team_name_or_uid)
        )
    if len(matches) > 1:
        raise EnterpriseTeamManagementError(
            ERROR_MSG_MULTIPLE_TEAMS.format(team_name_or_uid)
        )
    return matches[0]


def get_team_members(
    auth: keeper_auth.KeeperAuth,
    team_uid: str,
) -> List[TeamMemberInfo]:
    """Return team members from vault/get_team_members."""
    if not team_uid:
        return []

    request = enterprise_pb2.GetTeamMemberRequest()
    request.teamUid = utils.base64_url_decode(team_uid)
    response = auth.execute_auth_rest(
        rest_endpoint=TEAM_MEMBERS_ENDPOINT,
        request=request,
        response_type=enterprise_pb2.GetTeamMemberResponse,
    )
    if response is None or not response.enterpriseUser:
        return []

    return [
        TeamMemberInfo(
            enterprise_user_id=user.enterpriseUserId,
            email=user.email or '',
            enterprise_username=user.enterpriseUsername or '',
            is_share_admin=bool(user.isShareAdmin),
        )
        for user in response.enterpriseUser
    ]


def _build_team_users(
    enterprise_data: enterprise_types.IEnterpriseData,
    user_ids: set,
) -> List[EnterpriseTeamUserInfo]:
    users: List[EnterpriseTeamUserInfo] = []
    for user_id in user_ids:
        user = enterprise_data.users.get_entity(user_id)
        if user is None:
            continue
        users.append(
            EnterpriseTeamUserInfo(
                enterprise_user_id=user.enterprise_user_id,
                username=user.username,
                full_name=user.full_name,
            )
        )
    users.sort(key=lambda x: x.username.lower())
    return users


def _build_team_roles(
    enterprise_data: enterprise_types.IEnterpriseData,
    role_ids: set,
) -> List[EnterpriseTeamRoleInfo]:
    roles: List[EnterpriseTeamRoleInfo] = []
    for role_id in role_ids:
        role = enterprise_data.roles.get_entity(role_id)
        if role is None:
            continue
        roles.append(EnterpriseTeamRoleInfo(role_id=role.role_id, role_name=role.name))
    roles.sort(key=lambda x: x.role_name.lower())
    return roles


def _user_is_team_member(
    auth: Optional[keeper_auth.KeeperAuth],
    members: List[TeamMemberInfo],
) -> bool:
    if auth is None:
        return False
    username = auth.auth_context.username.lower()
    if not username:
        return False
    return any(
        username in (member.email.lower(), member.enterprise_username.lower())
        for member in members
    )


def _build_basic_team_info(
    team_uid: str,
    team_name: str,
    *,
    auth: Optional[keeper_auth.KeeperAuth],
    fetch_live_members: bool,
    access_level: str,
    is_member: Optional[bool] = None,
) -> EnterpriseTeamInfo:
    members: List[TeamMemberInfo] = []
    if auth is not None and fetch_live_members:
        members = get_team_members(auth, team_uid)
    if is_member is None:
        is_member = access_level == 'full_member' or _user_is_team_member(auth, members)
    return EnterpriseTeamInfo(
        team_uid=team_uid,
        team_name=team_name,
        node_id=0,
        node_name='',
        restrict_edit=False,
        restrict_share=False,
        restrict_view=False,
        access_level=access_level,
        is_member=is_member,
        members=members,
    )


def get_team(
    team_name_or_uid: str,
    *,
    enterprise_data: Optional[enterprise_types.IEnterpriseData] = None,
    vault_data_obj: Optional[vault_data.VaultData] = None,
    auth: Optional[keeper_auth.KeeperAuth] = None,
    vault: Optional[vault_online.VaultOnline] = None,
    is_enterprise_admin: bool = False,
    include_roles: bool = True,
    include_users: bool = True,
    include_queued_users: bool = True,
    fetch_live_members: bool = False,
) -> EnterpriseTeamInfo:
    """
    Get detailed information for a team by UID or name.

    When enterprise_data is available the result includes cached roles and users.
    When auth is provided and fetch_live_members is True, members are loaded from
    vault/get_team_members (same as .NET VaultOnline.GetTeamMembers).
    """
    resolved = resolve_team(
        team_name_or_uid,
        vault_data_obj=vault_data_obj,
        enterprise_data=enterprise_data,
        is_enterprise_admin=is_enterprise_admin,
        auth=auth,
        vault=vault,
    )
    if resolved.multiple_found:
        raise EnterpriseTeamManagementError(
            ERROR_MSG_MULTIPLE_TEAMS.format(team_name_or_uid)
        )
    if not resolved.found:
        raise EnterpriseTeamManagementError(
            ERROR_MSG_TEAM_NOT_FOUND.format(team_name_or_uid)
        )

    enterprise_team = resolved.enterprise_team
    if enterprise_team is None and enterprise_data is not None and resolved.team_uid:
        enterprise_team = enterprise_data.teams.get_entity(resolved.team_uid)

    if enterprise_team is not None and enterprise_data is not None:
        access_level = 'full_member' if resolved.vault_team is not None else 'enterprise_admin'
        node_name = _get_node_path(enterprise_data, enterprise_team.node_id, omit_root=False)

        team_roles: List[EnterpriseTeamRoleInfo] = []
        team_users: List[EnterpriseTeamUserInfo] = []
        queued_team_users: List[EnterpriseTeamUserInfo] = []

        if include_roles:
            role_ids = {
                x.role_id
                for x in enterprise_data.role_teams.get_links_by_object(enterprise_team.team_uid)
            }
            team_roles = _build_team_roles(enterprise_data, role_ids)

        if include_users:
            user_ids = {
                x.enterprise_user_id
                for x in enterprise_data.team_users.get_links_by_subject(enterprise_team.team_uid)
            }
            team_users = _build_team_users(enterprise_data, user_ids)

        if include_queued_users:
            queued_user_ids = {
                x.enterprise_user_id
                for x in enterprise_data.queued_team_users.get_links_by_subject(enterprise_team.team_uid)
            }
            queued_team_users = _build_team_users(enterprise_data, queued_user_ids)

        members: List[TeamMemberInfo] = []
        if auth is not None and fetch_live_members:
            members = get_team_members(auth, enterprise_team.team_uid)

        return EnterpriseTeamInfo(
            team_uid=enterprise_team.team_uid,
            team_name=enterprise_team.name,
            node_id=enterprise_team.node_id,
            node_name=node_name,
            restrict_edit=enterprise_team.restrict_edit,
            restrict_share=enterprise_team.restrict_share,
            restrict_view=enterprise_team.restrict_view,
            access_level=access_level,
            is_member=True,
            team_roles=team_roles,
            team_users=team_users,
            queued_team_users=queued_team_users,
            members=members,
        )

    if resolved.vault_team is not None:
        return _build_basic_team_info(
            resolved.vault_team.team_uid,
            resolved.vault_team.name,
            auth=auth,
            fetch_live_members=fetch_live_members,
            access_level='full_member',
        )

    if resolved.share_team is not None:
        return _build_basic_team_info(
            resolved.share_team.team_uid,
            resolved.share_team.name,
            auth=auth,
            fetch_live_members=fetch_live_members,
            access_level='share_reference',
        )

    raise EnterpriseTeamManagementError(
        ERROR_MSG_TEAM_NOT_FOUND.format(team_name_or_uid)
    )


def list_teams(
    enterprise_data: enterprise_types.IEnterpriseData,
    pattern: Optional[str] = None,
) -> List[EnterpriseTeamSummary]:
    """List enterprise teams, optionally filtered by case-insensitive substring."""
    pattern_lower = (pattern or '').lower()

    user_teams: dict = {}
    for team_user in enterprise_data.team_users.get_all_links():
        user_teams.setdefault(team_user.team_uid, set()).add(team_user.enterprise_user_id)

    role_teams: dict = {}
    for role_team in enterprise_data.role_teams.get_all_links():
        role_teams.setdefault(role_team.team_uid, set()).add(role_team.role_id)

    summaries: List[EnterpriseTeamSummary] = []
    for team in enterprise_data.teams.get_all_entities():
        if pattern_lower:
            searchable = ' '.join(
                str(x)
                for x in (
                    team.team_uid,
                    team.name,
                    team.node_id,
                    team.restrict_edit,
                    team.restrict_share,
                    team.restrict_view,
                )
            ).lower()
            if pattern_lower not in searchable:
                continue

        node_name = _get_node_path(enterprise_data, team.node_id, omit_root=True)
        user_count = len(user_teams.get(team.team_uid, set()))
        role_count = len(role_teams.get(team.team_uid, set()))
        summaries.append(
            EnterpriseTeamSummary(
                team_uid=team.team_uid,
                team_name=team.name,
                node_id=team.node_id,
                node_name=node_name,
                restrict_edit=team.restrict_edit,
                restrict_share=team.restrict_share,
                restrict_view=team.restrict_view,
                user_count=user_count,
                role_count=role_count,
            )
        )

    summaries.sort(key=lambda x: x.team_name.lower())
    return summaries
