import unittest
from unittest.mock import MagicMock

from keepersdk.enterprise import enterprise_team_management, enterprise_types


def _enterprise_data(
    teams=None,
    users=None,
    roles=None,
    team_users=None,
    role_teams=None,
    queued_team_users=None,
    nodes=None,
):
    enterprise_data = MagicMock()
    enterprise_data.teams = MagicMock()
    enterprise_data.users = MagicMock()
    enterprise_data.roles = MagicMock()
    enterprise_data.team_users = MagicMock()
    enterprise_data.role_teams = MagicMock()
    enterprise_data.queued_team_users = MagicMock()
    enterprise_data.nodes = MagicMock()
    enterprise_data.root_node = enterprise_types.Node(node_id=1, parent_id=0, name='Root')
    enterprise_data.enterprise_info = MagicMock()
    enterprise_data.enterprise_info.enterprise_name = 'Metronlabs'

    team_map = {t.team_uid: t for t in (teams or [])}
    user_map = {u.enterprise_user_id: u for u in (users or [])}
    role_map = {r.role_id: r for r in (roles or [])}
    node_map = {n.node_id: n for n in (nodes or [])}

    enterprise_data.teams.get_entity.side_effect = lambda uid: team_map.get(uid)
    enterprise_data.teams.get_all_entities.return_value = list(team_map.values())
    enterprise_data.users.get_entity.side_effect = lambda uid: user_map.get(uid)
    enterprise_data.roles.get_entity.side_effect = lambda role_id: role_map.get(role_id)
    enterprise_data.nodes.get_entity.side_effect = lambda node_id: node_map.get(node_id)
    enterprise_data.team_users.get_links_by_subject.return_value = team_users or []
    enterprise_data.team_users.get_all_links.return_value = team_users or []
    enterprise_data.role_teams.get_links_by_object.return_value = role_teams or []
    enterprise_data.role_teams.get_all_links.return_value = role_teams or []
    enterprise_data.queued_team_users.get_links_by_subject.return_value = queued_team_users or []
    return enterprise_data


class EnterpriseTeamManagementTests(unittest.TestCase):
    def test_resolve_enterprise_team_by_uid(self):
        team = enterprise_types.Team(team_uid='uid-1', name='Testing Team', node_id=10)
        enterprise_data = _enterprise_data(teams=[team])

        resolved = enterprise_team_management.resolve_enterprise_team(enterprise_data, 'uid-1')
        self.assertEqual(resolved.team_uid, 'uid-1')

    def test_resolve_enterprise_team_by_name(self):
        team = enterprise_types.Team(team_uid='uid-1', name='Testing Team', node_id=10)
        enterprise_data = _enterprise_data(teams=[team])

        resolved = enterprise_team_management.resolve_enterprise_team(enterprise_data, 'testing team')
        self.assertEqual(resolved.name, 'Testing Team')

    def test_resolve_enterprise_team_multiple_matches(self):
        teams = [
            enterprise_types.Team(team_uid='uid-1', name='Testing Team', node_id=10),
            enterprise_types.Team(team_uid='uid-2', name='testing team', node_id=10),
        ]
        enterprise_data = _enterprise_data(teams=teams)

        with self.assertRaises(enterprise_team_management.EnterpriseTeamManagementError):
            enterprise_team_management.resolve_enterprise_team(enterprise_data, 'Testing Team')

    def test_get_team_includes_roles_and_users(self):
        team = enterprise_types.Team(
            team_uid='uid-1',
            name='Testing Team',
            node_id=10,
            restrict_edit=True,
        )
        user = enterprise_types.User(
            enterprise_user_id=100,
            username='user@example.com',
            node_id=10,
            status='active',
            full_name='Test User',
        )
        role = enterprise_types.Role(role_id=200, name='Role Name', node_id=10)
        node = enterprise_types.Node(node_id=10, parent_id=1, name='TestNode')
        team_user = enterprise_types.TeamUser(team_uid='uid-1', enterprise_user_id=100)
        role_team = enterprise_types.RoleTeam(role_id=200, team_uid='uid-1')

        enterprise_data = _enterprise_data(
            teams=[team],
            users=[user],
            roles=[role],
            nodes=[node, enterprise_types.Node(node_id=1, parent_id=0, name='Root')],
            team_users=[team_user],
            role_teams=[role_team],
        )

        info = enterprise_team_management.get_team(
            'Testing Team',
            enterprise_data=enterprise_data,
            is_enterprise_admin=True,
        )

        self.assertEqual(info.team_name, 'Testing Team')
        self.assertEqual(info.node_name, 'Root\\TestNode')
        self.assertTrue(info.restrict_edit)
        self.assertEqual(len(info.team_users), 1)
        self.assertEqual(info.team_users[0].username, 'user@example.com')
        self.assertEqual(len(info.team_roles), 1)
        self.assertEqual(info.team_roles[0].role_name, 'Role Name')

    def test_list_teams_with_pattern(self):
        teams = [
            enterprise_types.Team(team_uid='uid-1', name='Testing Team', node_id=10),
            enterprise_types.Team(team_uid='uid-2', name='Developers', node_id=10),
        ]
        node = enterprise_types.Node(node_id=10, parent_id=1, name='TestNode')
        enterprise_data = _enterprise_data(
            teams=teams,
            nodes=[node, enterprise_types.Node(node_id=1, parent_id=0, name='Root')],
        )

        summaries = enterprise_team_management.list_teams(enterprise_data, pattern='testing')
        self.assertEqual(len(summaries), 1)
        self.assertEqual(summaries[0].team_name, 'Testing Team')

    def test_get_team_members(self):
        auth = MagicMock()
        response = MagicMock()
        user = MagicMock()
        user.enterpriseUserId = 100
        user.email = 'user@example.com'
        user.enterpriseUsername = 'User Name'
        user.isShareAdmin = True
        response.enterpriseUser = [user]
        auth.execute_auth_rest.return_value = response

        members = enterprise_team_management.get_team_members(auth, 'dGVhbQ')
        self.assertEqual(len(members), 1)
        self.assertEqual(members[0].email, 'user@example.com')
        self.assertTrue(members[0].is_share_admin)

    def test_resolve_team_prefers_vault_cache(self):
        vault_data_obj = MagicMock()
        vault_team = MagicMock()
        vault_team.team_uid = 'vault-uid'
        vault_team.name = 'Vault Team'
        vault_data_obj.get_team.return_value = vault_team
        vault_data_obj.teams.return_value = [vault_team]

        resolved = enterprise_team_management.resolve_team(
            'vault-uid',
            vault_data_obj=vault_data_obj,
            enterprise_data=_enterprise_data(),
            is_enterprise_admin=True,
        )
        self.assertEqual(resolved.team_uid, 'vault-uid')
        self.assertIsNotNone(resolved.vault_team)

    def test_resolve_team_from_share_objects(self):
        vault = MagicMock()
        with unittest.mock.patch(
            'keepersdk.enterprise.enterprise_team_management.share_management_utils.get_share_objects',
            return_value={
                'teams': {
                    'IuiVKCcPSjW1BZ-85o9bwA': {
                        'name': 'Testing Team',
                        'enterprise_id': 123,
                    }
                }
            },
        ):
            resolved = enterprise_team_management.resolve_team(
                'Testing Team',
                vault=vault,
            )
        self.assertEqual(resolved.team_uid, 'IuiVKCcPSjW1BZ-85o9bwA')
        self.assertIsNotNone(resolved.share_team)
        self.assertEqual(resolved.share_team.name, 'Testing Team')

    def test_get_team_marks_non_member_for_share_reference(self):
        auth = MagicMock()
        auth.auth_context.username = 'user@example.com'
        auth.execute_auth_rest.return_value = MagicMock(enterpriseUser=[])

        vault = MagicMock()
        with unittest.mock.patch(
            'keepersdk.enterprise.enterprise_team_management.share_management_utils.get_share_objects',
            return_value={
                'teams': {
                    'team-uid': {'name': 'Developers', 'enterprise_id': 123},
                }
            },
        ):
            info = enterprise_team_management.get_team(
                'Developers',
                auth=auth,
                vault=vault,
                fetch_live_members=True,
            )

        self.assertFalse(info.is_member)
        self.assertEqual(info.access_level, 'share_reference')

    def test_get_team_marks_member_when_listed_in_team_members(self):
        auth = MagicMock()
        auth.auth_context.username = 'user@example.com'
        member = MagicMock()
        member.enterpriseUserId = 100
        member.email = 'user@example.com'
        member.enterpriseUsername = 'user@example.com'
        member.isShareAdmin = False
        auth.execute_auth_rest.return_value = MagicMock(enterpriseUser=[member])

        vault = MagicMock()
        with unittest.mock.patch(
            'keepersdk.enterprise.enterprise_team_management.share_management_utils.get_share_objects',
            return_value={
                'teams': {
                    'team-uid': {'name': 'Testing Team', 'enterprise_id': 123},
                }
            },
        ):
            info = enterprise_team_management.get_team(
                'Testing Team',
                auth=auth,
                vault=vault,
                fetch_live_members=True,
            )

        self.assertTrue(info.is_member)
        self.assertEqual(len(info.members), 1)


if __name__ == '__main__':
    unittest.main()
