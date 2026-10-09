"""Child-folder access transitions for NSF folder sharing (inherited / denied / direct)."""

import unittest
from unittest import mock

from keepersdk import utils
from keepersdk.errors import KeeperApiError
from keepersdk.proto import folder_pb2
from keepersdk.vault import nsf_common, nsf_management, nsf_sharing

_S = 'keepersdk.vault.nsf_sharing.'


def _row(uid_b64, *, inherited=False, denied=False, role='VIEWER', access_type='AT_USER'):
    return {'accessor_uid': uid_b64, 'access_type': access_type, 'role': role,
            'inherited': inherited, 'denied_access': denied}


def _response(status=None):
    rs = folder_pb2.FolderAccessResponse()
    if status is not None:
        r = rs.folderAccessResults.add()
        r.status = status
    return rs


_FAILURE = next(v for v in folder_pb2.FolderModifyStatus.values() if v != 0)


class TestPlanFolderAccessChange(unittest.TestCase):

    def test_state_from_accessors(self):
        f = nsf_common.folder_access_state_from_accessors
        self.assertEqual(f([]), 'none')
        self.assertEqual(f([{'inherited': True}]), 'inherited')
        self.assertEqual(f([{'inherited': True}, {'inherited': False}]), 'direct')
        self.assertEqual(f([{'inherited': False}, {'denied_access': True}]), 'denied')

    def test_transitions(self):
        plan = nsf_common.plan_folder_access_change
        reqs = lambda st, act: [s['request'] for s in plan(st, act)]
        self.assertEqual(reqs('inherited', 'grant'), ['folderAccessAdds'])
        self.assertEqual(reqs('none', 'grant'), ['folderAccessAdds'])
        self.assertEqual(reqs('denied', 'grant'), ['folderAccessRemoves', 'folderAccessAdds'])
        self.assertEqual(reqs('direct', 'grant'), ['folderAccessUpdates'])
        self.assertEqual(reqs('inherited', 'deny'), ['folderAccessUpdates'])
        self.assertEqual(reqs('denied', 'remove'), [])
        self.assertEqual(reqs('direct', 'remove'), ['folderAccessRemoves'])
        self.assertTrue(plan('inherited', 'grant')[0]['include_folder_key'])
        self.assertFalse(plan('direct', 'grant')[0]['include_folder_key'])
        deny = plan('inherited', 'deny')[0]
        self.assertTrue(deny['denied_access'])
        self.assertFalse(deny['include_folder_key'])
        with self.assertRaises(ValueError):
            plan('inherited', 'remove')
        with self.assertRaises(ValueError):
            plan('direct', 'deny')


class TestNsfFolderAccessTransitions(unittest.TestCase):

    def setUp(self):
        self.folder_uid = utils.generate_uid()
        self.uid_bytes = utils.base64_url_decode(utils.generate_uid())
        self.uid_b64 = utils.base64_url_encode(self.uid_bytes)
        self.email = 'user@example.com'
        self.vault = mock.Mock()
        self.fake_key = folder_pb2.EncryptedDataKey(
            encryptedKey=b'enc', encryptedKeyType=folder_pb2.encrypted_by_public_key)
        patches = [
            mock.patch(_S + 'resolve_nsf_folder_uid', return_value=self.folder_uid),
            mock.patch(_S + 'is_nsf_folder', return_value=True),
            mock.patch(_S + '_ensure_folder_share_permission'),
            mock.patch(_S + '_request_sync'),
            mock.patch(_S + '_resolve_folder_accessor',
                       return_value=(self.uid_bytes, self.email, folder_pb2.AT_USER)),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.enc = mock.patch(_S + '_encrypted_folder_key_for', return_value=self.fake_key).start()
        self.addCleanup(mock.patch.stopall)

    def _rows(self, *rows):
        info = {'results': [{'folder_uid': self.folder_uid, 'success': True,
                             'accessors': list(rows)}]}
        p = mock.patch(_S + 'get_nsf_folder_access', return_value=info)
        p.start()
        self.addCleanup(p.stop)

    def _access(self, *responses):
        p = mock.patch(_S + '_folder_access_update', side_effect=list(responses))
        m = p.start()
        self.addCleanup(p.stop)
        return m

    def test_grant_inherited_becomes_add_with_folder_key(self):
        self._rows(_row(self.uid_b64, inherited=True))
        upd = self._access(_response(0))
        result = nsf_sharing.grant_nsf_folder_access(
            self.vault, self.folder_uid, self.email, role='content-manager')
        self.assertTrue(result['success'])
        self.assertEqual(result['previous_access_state'], 'inherited')
        upd.assert_called_once()
        kw = upd.call_args.kwargs
        self.assertIsNone(kw['updates'])
        ad = kw['adds'][0]
        self.assertTrue(ad.HasField('folderKey'))
        self.assertEqual(ad.folderKey.encryptedKeyType, folder_pb2.encrypted_by_public_key)
        self.enc.assert_called_once()

    def test_grant_inherited_same_role_still_creates_direct_grant(self):
        self._rows(_row(self.uid_b64, inherited=True, role='CONTENT_MANAGER'))
        upd = self._access(_response(0))
        result = nsf_sharing.grant_nsf_folder_access(
            self.vault, self.folder_uid, self.email, role='content-manager')
        self.assertNotEqual(result['action_taken'], 'already_had_access')
        self.assertTrue(upd.call_args.kwargs['adds'])

    def test_grant_denied_same_role_is_not_already_had_access(self):
        self._rows(_row(self.uid_b64, inherited=True, denied=True))
        upd = self._access(_response(0), _response(0))
        result = nsf_sharing.grant_nsf_folder_access(
            self.vault, self.folder_uid, self.email, role='viewer')
        self.assertEqual(result['action_taken'], 'granted')
        self.assertEqual(upd.call_count, 2)
        first, second = upd.call_args_list
        self.assertTrue(first.kwargs['removes'])
        self.assertFalse(first.kwargs['removes'][0].HasField('folderKey'))
        add = second.kwargs['adds'][0]
        self.assertTrue(add.HasField('folderKey'))
        self.assertFalse(add.deniedAccess)

    def test_grant_denied_skips_add_when_removal_fails(self):
        self._rows(_row(self.uid_b64, denied=True))
        upd = self._access(_response(_FAILURE))
        with self.assertRaises(KeeperApiError):
            nsf_sharing.grant_nsf_folder_access(
                self.vault, self.folder_uid, self.email, role='viewer')
        upd.assert_called_once()
        self.assertTrue(upd.call_args.kwargs['removes'])

    def test_grant_none_adds_with_key(self):
        self._rows()
        upd = self._access(_response(0))
        nsf_sharing.grant_nsf_folder_access(self.vault, self.folder_uid, self.email)
        self.assertTrue(upd.call_args.kwargs['adds'][0].HasField('folderKey'))

    def test_grant_direct_same_role_is_noop(self):
        self._rows(_row(self.uid_b64))
        upd = self._access()
        result = nsf_sharing.grant_nsf_folder_access(
            self.vault, self.folder_uid, self.email, role='viewer')
        self.assertEqual(result['action_taken'], 'already_had_access')
        upd.assert_not_called()

    def test_grant_direct_new_role_updates_without_key(self):
        self._rows(_row(self.uid_b64))
        upd = self._access(_response(0))
        result = nsf_sharing.grant_nsf_folder_access(
            self.vault, self.folder_uid, self.email, role='content-manager')
        self.assertEqual(result['action_taken'], 'updated')
        ad = upd.call_args.kwargs['updates'][0]
        self.assertFalse(ad.HasField('folderKey'))
        self.enc.assert_not_called()

    def test_update_inherited_requires_explicit_role(self):
        self._rows(_row(self.uid_b64, inherited=True))
        upd = self._access()
        with self.assertRaises(nsf_management.NsfError):
            nsf_sharing.update_nsf_folder_access(
                self.vault, self.folder_uid, self.email, expiration_timestamp=1_900_000_000_000)
        upd.assert_not_called()

    def test_update_inherited_with_role_adds_key(self):
        self._rows(_row(self.uid_b64, inherited=True))
        upd = self._access(_response(0))
        nsf_sharing.update_nsf_folder_access(
            self.vault, self.folder_uid, self.email, role='viewer',
            expiration_timestamp=1_900_000_000_000)
        ad = upd.call_args.kwargs['adds'][0]
        self.assertEqual(ad.accessRoleType, folder_pb2.VIEWER)
        self.assertTrue(ad.HasField('folderKey'))
        self.assertEqual(ad.tlaProperties.expiration, 1_900_000_000_000)

    def test_update_direct_uses_update(self):
        self._rows(_row(self.uid_b64))
        upd = self._access(_response(0))
        nsf_sharing.update_nsf_folder_access(
            self.vault, self.folder_uid, self.email, hidden=True)
        ad = upd.call_args.kwargs['updates'][0]
        self.assertTrue(ad.hidden)
        self.assertFalse(ad.HasField('folderKey'))

    def test_revoke_inherited_sends_denial_without_key(self):
        self._rows(_row(self.uid_b64, inherited=True))
        upd = self._access(_response(0))
        result = nsf_sharing.revoke_nsf_folder_access(self.vault, self.folder_uid, self.email)
        self.assertEqual(result['action_taken'], 'denied')
        ad = upd.call_args.kwargs['updates'][0]
        self.assertTrue(ad.deniedAccess)
        self.assertFalse(ad.HasField('folderKey'))

    def test_revoke_direct_sends_remove(self):
        self._rows(_row(self.uid_b64))
        upd = self._access(_response(0))
        result = nsf_sharing.revoke_nsf_folder_access(self.vault, self.folder_uid, self.email)
        self.assertEqual(result['action_taken'], 'revoked')
        self.assertTrue(upd.call_args.kwargs['removes'])

    def test_revoke_already_denied_sends_nothing(self):
        self._rows(_row(self.uid_b64, denied=True))
        upd = self._access()
        result = nsf_sharing.revoke_nsf_folder_access(self.vault, self.folder_uid, self.email)
        self.assertEqual(result['action_taken'], 'already_denied')
        upd.assert_not_called()

    def test_revoke_failure_raises(self):
        self._rows(_row(self.uid_b64))
        self._access(_response(_FAILURE))
        with self.assertRaises(KeeperApiError):
            nsf_sharing.revoke_nsf_folder_access(self.vault, self.folder_uid, self.email)

    def test_grant_denied_restores_denial_when_add_fails(self):
        self._rows(_row(self.uid_b64, inherited=True, denied=True))
        upd = self._access(_response(0), _response(_FAILURE), _response(0))
        with self.assertRaises(KeeperApiError) as ctx:
            nsf_sharing.grant_nsf_folder_access(
                self.vault, self.folder_uid, self.email, role='viewer')
        self.assertEqual(upd.call_count, 3)
        restore = upd.call_args_list[2].kwargs['updates'][0]
        self.assertTrue(restore.deniedAccess)
        self.assertFalse(restore.HasField('folderKey'))
        self.assertIn('denial was restored', str(ctx.exception))

    def test_grant_denied_warns_when_denial_cannot_be_restored(self):
        self._rows(_row(self.uid_b64, denied=True))
        self._access(_response(0), _response(_FAILURE), _response(_FAILURE))
        with self.assertRaises(KeeperApiError) as ctx:
            nsf_sharing.grant_nsf_folder_access(
                self.vault, self.folder_uid, self.email, role='viewer')
        self.assertIn('could not be restored', str(ctx.exception))

    def test_grant_denied_key_failure_sends_nothing(self):
        self._rows(_row(self.uid_b64, denied=True))
        upd = self._access()
        self.enc.side_effect = nsf_management.NsfError('no public key')
        with self.assertRaises(nsf_management.NsfError):
            nsf_sharing.grant_nsf_folder_access(
                self.vault, self.folder_uid, self.email, role='viewer')
        upd.assert_not_called()

    def test_lookup_failure_raises_instead_of_assuming_none(self):
        p = mock.patch(_S + 'get_nsf_folder_access', side_effect=RuntimeError('network'))
        p.start()
        self.addCleanup(p.stop)
        upd = self._access()
        with self.assertRaises(nsf_management.NsfError):
            nsf_sharing.grant_nsf_folder_access(self.vault, self.folder_uid, self.email)
        upd.assert_not_called()

    def test_lookup_error_result_raises(self):
        info = {'results': [{'folder_uid': self.folder_uid, 'success': False,
                             'error': {'status': 'ACCESS_DENIED', 'message': 'nope'}}]}
        p = mock.patch(_S + 'get_nsf_folder_access', return_value=info)
        p.start()
        self.addCleanup(p.stop)
        upd = self._access()
        with self.assertRaises(nsf_management.NsfError):
            nsf_sharing.revoke_nsf_folder_access(self.vault, self.folder_uid, self.email)
        upd.assert_not_called()

    def test_revoke_owner_is_refused(self):
        self._rows(_row(self.uid_b64, access_type='AT_OWNER', role='MANAGER'))
        upd = self._access()
        with self.assertRaises(nsf_management.NsfError):
            nsf_sharing.revoke_nsf_folder_access(self.vault, self.folder_uid, self.email)
        upd.assert_not_called()

    def test_grant_owner_is_refused(self):
        self._rows(_row(self.uid_b64, access_type='AT_OWNER', role='MANAGER'))
        upd = self._access()
        with self.assertRaises(nsf_management.NsfError):
            nsf_sharing.grant_nsf_folder_access(self.vault, self.folder_uid, self.email)
        upd.assert_not_called()


class TestNsfApplicationFolderAccess(unittest.TestCase):

    def setUp(self):
        self.folder_uid = utils.generate_uid()
        self.app_uid = utils.generate_uid()
        self.vault = mock.Mock()
        self.vault.vault_data.get_record_key.return_value = b'\x01' * 32
        for target, kw in (
                ('resolve_nsf_folder_uid', {'return_value': self.folder_uid}),
                ('is_nsf_folder', {'return_value': True}),
                ('_ensure_folder_share_permission', {}),
                ('_request_sync', {}),
                ('_get_folder_key', {'return_value': b'\x02' * 32})):
            p = mock.patch(_S + target, **kw)
            p.start()
            self.addCleanup(p.stop)

    def _rows(self, *rows):
        info = {'results': [{'folder_uid': self.folder_uid, 'success': True,
                             'accessors': list(rows)}]}
        p = mock.patch(_S + 'get_nsf_folder_access', return_value=info)
        p.start()
        self.addCleanup(p.stop)

    def _access(self, *responses):
        p = mock.patch(_S + '_folder_access_update', side_effect=list(responses))
        m = p.start()
        self.addCleanup(p.stop)
        return m

    def test_grant_inherited_app_adds_with_key(self):
        self._rows(_row(self.app_uid, inherited=True, access_type='AT_APPLICATION'))
        upd = self._access(_response(0))
        result = nsf_sharing.grant_nsf_folder_to_application(
            self.vault, self.folder_uid, self.app_uid)
        self.assertEqual(result['previous_access_state'], 'inherited')
        ad = upd.call_args.kwargs['adds'][0]
        self.assertTrue(ad.HasField('folderKey'))
        self.assertEqual(ad.folderKey.encryptedKeyType, folder_pb2.encrypted_by_data_key_gcm)
        self.assertEqual(ad.accessType, folder_pb2.AT_APPLICATION)

    def test_grant_direct_app_same_role_is_noop(self):
        self._rows(_row(self.app_uid, access_type='AT_APPLICATION'))
        upd = self._access()
        result = nsf_sharing.grant_nsf_folder_to_application(
            self.vault, self.folder_uid, self.app_uid)
        self.assertEqual(result['action_taken'], 'already_had_access')
        upd.assert_not_called()

    def test_grant_direct_app_new_role_updates(self):
        self._rows(_row(self.app_uid, access_type='AT_APPLICATION'))
        upd = self._access(_response(0))
        nsf_sharing.grant_nsf_folder_to_application(
            self.vault, self.folder_uid, self.app_uid, is_editable=True)
        ad = upd.call_args.kwargs['updates'][0]
        self.assertEqual(ad.accessRoleType, folder_pb2.CONTENT_MANAGER)
        self.assertFalse(ad.HasField('folderKey'))

    def test_update_inherited_app_becomes_direct_grant(self):
        self._rows(_row(self.app_uid, inherited=True, access_type='AT_APPLICATION'))
        upd = self._access(_response(0))
        nsf_sharing.update_nsf_folder_application_access(
            self.vault, self.folder_uid, self.app_uid, is_editable=True)
        self.assertTrue(upd.call_args.kwargs['adds'][0].HasField('folderKey'))

    def test_revoke_inherited_app_is_denied(self):
        self._rows(_row(self.app_uid, inherited=True, access_type='AT_APPLICATION'))
        upd = self._access(_response(0))
        result = nsf_sharing.revoke_nsf_folder_from_application(
            self.vault, self.folder_uid, self.app_uid)
        self.assertEqual(result['action_taken'], 'denied')
        self.assertTrue(upd.call_args.kwargs['updates'][0].deniedAccess)


if __name__ == '__main__':
    unittest.main()
