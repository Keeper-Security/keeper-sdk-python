import unittest
from unittest.mock import MagicMock, patch

from keepersdk import utils
from keepersdk.proto import folder_access_pb2, folder_pb2, record_details_pb2
from keepersdk.vault import memory_nsf_storage, nsf_common, nsf_management, nsf_storage_types as nsf


class TestNsfPermissions(unittest.TestCase):
    def _vault(self, *, username='alice@example.com', account_uid=None):
        vault = MagicMock()
        vault.keeper_auth.auth_context.username = username
        vault.keeper_auth.auth_context.account_uid = account_uid or utils.base64_url_decode(
            utils.generate_uid())
        return vault

    def test_folder_share_denied_for_viewer(self):
        folder_uid = utils.generate_uid()
        account_uid = utils.generate_uid()
        storage = memory_nsf_storage.InMemoryNSFStorage()
        storage.folder_accesses.put_links([
            nsf.NSFFolderAccess(
                folder_uid=folder_uid,
                access_type_uid=account_uid,
                access_type=int(folder_pb2.AT_USER),
                permissions_json='{"canUpdateAccess":false,"canViewRecords":true}',
            ),
        ])
        vault = self._vault(account_uid=utils.base64_url_decode(account_uid))
        vault.nsf_data.storage = storage

        with self.assertRaisesRegex(ValueError, 'permission to share'):
            nsf_common.require_nsf_folder_share_permission(vault, folder_uid)

    def test_folder_share_allowed_for_share_manager(self):
        folder_uid = utils.generate_uid()
        account_uid = utils.generate_uid()
        storage = memory_nsf_storage.InMemoryNSFStorage()
        storage.folder_accesses.put_links([
            nsf.NSFFolderAccess(
                folder_uid=folder_uid,
                access_type_uid=account_uid,
                access_type=int(folder_pb2.AT_USER),
                permissions_json='{"canUpdateAccess":true}',
            ),
        ])
        vault = self._vault(account_uid=utils.base64_url_decode(account_uid))
        vault.nsf_data.storage = storage

        nsf_common.require_nsf_folder_share_permission(vault, folder_uid)

    def test_folder_share_allowed_for_owner_row(self):
        folder_uid = utils.generate_uid()
        account_uid = utils.generate_uid()
        storage = memory_nsf_storage.InMemoryNSFStorage()
        storage.folders.put_entities([nsf.NSFFolder(
            folder_uid=folder_uid,
            owner_account_uid=account_uid,
            owner_username='alice@example.com',
        )])
        vault = self._vault(account_uid=utils.base64_url_decode(account_uid))
        vault.nsf_data.storage = storage

        nsf_common.require_nsf_folder_share_permission(vault, folder_uid)

    def test_record_share_denied_without_permission(self):
        record_uid = utils.generate_uid()
        account_uid = utils.generate_uid()
        storage = memory_nsf_storage.InMemoryNSFStorage()
        storage.record_accesses.put_links([
            nsf.NSFRecordAccess(
                record_uid=record_uid,
                access_type_uid=account_uid,
                can_update_access=False,
            ),
        ])
        vault = self._vault(account_uid=utils.base64_url_decode(account_uid))
        vault.nsf_data.storage = storage

        with self.assertRaisesRegex(ValueError, 'permission to share'):
            nsf_common.require_nsf_record_share_permission(vault, record_uid)

    def test_record_access_inheritance_helpers(self):
        record_uid = utils.generate_uid()
        vault = self._vault()
        api_access = [{
            'record_uid': record_uid,
            'accessor_name': 'alice@example.com',
            'access_type': 'AT_USER',
            'inherited': True,
            'denied_access': False,
            'owner': False,
        }]
        with patch.object(
                nsf_common, 'collect_nsf_record_accessors', return_value=api_access):
            accesses = nsf_common.find_record_user_accesses(
                vault, record_uid, 'alice@example.com')
            self.assertTrue(nsf_common.record_user_has_inherited_access(accesses))
            self.assertFalse(nsf_common.record_user_has_direct_access(accesses))

    def test_folder_inherit_detection(self):
        parent_uid = utils.generate_uid()
        folder_uid = utils.generate_uid()
        storage = memory_nsf_storage.InMemoryNSFStorage()
        storage.folders.put_entities([
            nsf.NSFFolder(
                folder_uid=parent_uid,
                inherit_user_permissions=int(folder_pb2.BOOLEAN_TRUE),
            ),
            nsf.NSFFolder(
                folder_uid=folder_uid,
                parent_uid=parent_uid,
                inherit_user_permissions=int(folder_pb2.BOOLEAN_TRUE),
            ),
        ])
        vault = self._vault()
        vault.nsf_data.storage = storage

        self.assertTrue(nsf_common.folder_inherits_parent_permissions(vault, folder_uid))

        storage.folders.put_entities([
            nsf.NSFFolder(
                folder_uid=folder_uid,
                parent_uid=parent_uid,
                inherit_user_permissions=int(folder_pb2.BOOLEAN_FALSE),
            ),
        ])
        self.assertFalse(nsf_common.folder_inherits_parent_permissions(vault, folder_uid))


class TestNsfAccessListingFilters(unittest.TestCase):
    """Exercise the real SDK filters (not a copy of their logic)."""

    _ROWS = (
        ('direct@example.com', False, False),
        ('inherited@example.com', True, False),
        ('denied@example.com', False, True),
        ('inherited-denied@example.com', True, True),
    )

    def setUp(self):
        self.record_uid = utils.generate_uid()
        self.folder_uid = utils.generate_uid()
        self.vault = MagicMock()
        for target in ('resolve_nsf_record_uid', 'resolve_nsf_folder_uid'):
            p = patch('keepersdk.vault.nsf_management.' + target, side_effect=lambda _v, u: u)
            p.start()
            self.addCleanup(p.stop)
        p = patch('keepersdk.vault.nsf_management._resolve_uid_to_username',
                  side_effect=lambda _v, uid: f'user-{uid}')
        self.resolve_username = p.start()
        self.addCleanup(p.stop)

    def _record_response(self):
        rs = record_details_pb2.RecordAccessResponse()
        for name, inherited, denied in self._ROWS:
            ra = rs.recordAccesses.add()
            ra.accessorInfo.name = name
            ra.data.recordUid = utils.base64_url_decode(self.record_uid)
            ra.data.accessTypeUid = utils.base64_url_decode(utils.generate_uid())
            ra.data.accessType = folder_pb2.AT_USER
            ra.data.inherited = inherited
            ra.data.deniedAccess = denied
        return rs

    def _folder_response(self):
        rs = folder_access_pb2.GetFolderAccessResponse()
        fr = rs.folderAccessResults.add()
        fr.folderUid = utils.base64_url_decode(self.folder_uid)
        for _name, inherited, denied in self._ROWS:
            a = fr.accessors.add()
            a.folderUid = fr.folderUid
            a.accessTypeUid = utils.base64_url_decode(utils.generate_uid())
            a.accessType = folder_pb2.AT_USER
            a.accessRoleType = folder_pb2.VIEWER
            a.inherited = inherited
            a.deniedAccess = denied
        return rs

    def _records(self, **kwargs):
        self.vault.keeper_auth.execute_auth_rest.return_value = self._record_response()
        rs = nsf_management.get_nsf_record_accesses(self.vault, [self.record_uid], **kwargs)
        return [a['accessor_name'] for a in rs['record_accesses']]

    def _folders(self, **kwargs):
        self.vault.keeper_auth.execute_auth_rest.return_value = self._folder_response()
        rs = nsf_management.get_nsf_folder_access(self.vault, [self.folder_uid], **kwargs)
        accessors = rs['results'][0]['accessors']
        self.assertTrue(all(accessors), 'filtered rows must be dropped, not left as {}')
        return [(a['inherited'], a['denied_access']) for a in accessors]

    def test_record_default_hides_inherited_and_denied(self):
        self.assertEqual(['direct@example.com'], self._records())

    def test_record_show_all(self):
        self.assertEqual([r[0] for r in self._ROWS],
                         self._records(show_inherited=True, show_denied=True))

    def test_record_hide_inherited_and_denied(self):
        self.assertEqual(['direct@example.com'],
                         self._records(show_inherited=False, show_denied=False))

    def test_record_hide_inherited_only(self):
        self.assertEqual(['direct@example.com', 'denied@example.com'],
                         self._records(show_inherited=False, show_denied=True))

    def test_record_hide_denied_only(self):
        self.assertEqual(['direct@example.com', 'inherited@example.com'],
                         self._records(show_inherited=True, show_denied=False))

    def test_record_rows_keep_state_flags(self):
        self.vault.keeper_auth.execute_auth_rest.return_value = self._record_response()
        rows = nsf_management.get_nsf_record_accesses(
            self.vault, [self.record_uid], show_inherited=True, show_denied=True)['record_accesses']
        self.assertEqual([(r['inherited'], r['denied_access']) for r in rows],
                         [(i, d) for _n, i, d in self._ROWS])

    def test_folder_default_hides_inherited_and_denied(self):
        self.assertEqual([(False, False)], self._folders())

    def test_folder_show_all(self):
        self.assertEqual([(i, d) for _n, i, d in self._ROWS],
                         self._folders(show_inherited=True, show_denied=True))

    def test_folder_hide_inherited_and_denied(self):
        self.assertEqual([(False, False)], self._folders(show_inherited=False, show_denied=False))

    def test_folder_hide_inherited_only(self):
        self.assertEqual([(False, False), (False, True)],
                         self._folders(show_inherited=False, show_denied=True))

    def test_folder_hide_denied_only(self):
        self.assertEqual([(False, False), (True, False)],
                         self._folders(show_inherited=True, show_denied=False))

    def test_folder_filtered_rows_skip_username_lookup(self):
        self._folders(show_inherited=False, show_denied=False)
        self.assertEqual(1, self.resolve_username.call_count)


class TestNsfLoadAccessDetails(unittest.TestCase):

    def test_load_always_requests_inherited_and_denied(self):
        view = MagicMock()
        view.folders.return_value = [MagicMock(folder_uid='f1')]
        view.records.return_value = [MagicMock(record_uid='r1')]
        vault = MagicMock()
        with patch('keepersdk.vault.nsf_management._nsf_view', return_value=view), \
                patch('keepersdk.vault.nsf_management.get_nsf_folder_access',
                      return_value={'results': [{'folder_uid': 'f1', 'success': True, 'accessors': []}]}) as gfa, \
                patch('keepersdk.vault.nsf_management.get_nsf_record_accesses',
                      return_value={'record_accesses': []}) as gra:
            loaded = nsf_management.load_nsf_access_details(vault, load_folder=True, load_record=True)
        self.assertEqual(loaded, {'folders': 1, 'records': 1})
        self.assertEqual(gfa.call_args.kwargs, {'show_inherited': True, 'show_denied': True})
        self.assertEqual(gra.call_args.kwargs, {'show_inherited': True, 'show_denied': True})


class TestEncryptForTeam(unittest.TestCase):
    def test_prefer_asymmetric_then_aes_fallback(self):
        from keepersdk.authentication.keeper_auth import UserKeys
        from keepersdk import crypto

        folder_key = utils.generate_aes_key()
        team_aes = utils.generate_aes_key()
        keys = UserKeys(aes=team_aes, rsa=None, ec=None)
        encrypted, key_type = nsf_common.encrypt_for_team(
            folder_key, keys, forbid_rsa=False)
        self.assertEqual(crypto.decrypt_aes_v1(encrypted, team_aes), folder_key)
        self.assertEqual(key_type, folder_pb2.encrypted_by_data_key)

    def test_invalid_aes_size_is_not_used_as_fallback(self):
        from keepersdk.authentication.keeper_auth import UserKeys

        keys = UserKeys(aes=b'x' * 480, rsa=None, ec=None)
        with self.assertRaisesRegex(ValueError, 'No public key found for team'):
            nsf_common.encrypt_for_team(
                utils.generate_aes_key(), keys, forbid_rsa=False)


if __name__ == '__main__':
    unittest.main()
