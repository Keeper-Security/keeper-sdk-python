import unittest
from unittest.mock import MagicMock, patch

from keepersdk.vault import nsf_management
from keepersdk.vault.nsf_data import NSFFolderNode


class _FakeNsfView:
    """Minimal stand-in for NSFData exposing only what move validation needs."""

    def __init__(self, folders):
        self._folders = {f.folder_uid: f for f in folders}

    def get_folder(self, folder_uid):
        return self._folders.get(folder_uid)

    def folders(self):
        return list(self._folders.values())


class TestNsfFolderMoveDepth(unittest.TestCase):
    ROOT = nsf_management.ROOT_FOLDER_UID

    def _vault(self, folders):
        vault = MagicMock()
        vault.nsf_data = _FakeNsfView(folders)
        return vault

    def _chain_vault(self):
        # root -> A -> B -> C -> D -> E  (E is at depth 5)
        # root -> X (leaf, depth 1, no children)
        a = NSFFolderNode(folder_uid='A', parent_uid=self.ROOT, subfolder_uids=['B'])
        b = NSFFolderNode(folder_uid='B', parent_uid='A', subfolder_uids=['C'])
        c = NSFFolderNode(folder_uid='C', parent_uid='B', subfolder_uids=['D'])
        d = NSFFolderNode(folder_uid='D', parent_uid='C', subfolder_uids=['E'])
        e = NSFFolderNode(folder_uid='E', parent_uid='D')
        x = NSFFolderNode(folder_uid='X', parent_uid=self.ROOT)
        return self._vault([a, b, c, d, e, x])

    def test_folder_depth(self):
        vault = self._chain_vault()
        self.assertEqual(nsf_management._nsf_folder_depth(vault, 'A'), 1)
        self.assertEqual(nsf_management._nsf_folder_depth(vault, 'E'), 5)
        self.assertEqual(nsf_management._nsf_folder_depth(vault, self.ROOT), 0)

    def test_folder_subtree_height(self):
        vault = self._chain_vault()
        self.assertEqual(nsf_management._nsf_folder_subtree_height(vault, 'E'), 0)
        self.assertEqual(nsf_management._nsf_folder_subtree_height(vault, 'X'), 0)
        self.assertEqual(nsf_management._nsf_folder_subtree_height(vault, 'A'), 4)

    def test_move_leaf_into_max_depth_folder_raises(self):
        vault = self._chain_vault()
        with self.assertRaisesRegex(nsf_management.NsfError, 'exceed the maximum of 5'):
            nsf_management._validate_nsf_folder_move_depth(vault, 'X', 'E')

    def test_move_leaf_into_folder_at_limit_ok(self):
        vault = self._chain_vault()
        # X under D -> new depth 5, exactly at the limit.
        nsf_management._validate_nsf_folder_move_depth(vault, 'X', 'D')

    def test_move_subtree_to_root_ok(self):
        vault = self._chain_vault()
        # A (with its B/C/D/E subtree, height 4) to root -> new depth 5.
        nsf_management._validate_nsf_folder_move_depth(vault, 'A', self.ROOT)

    def test_move_subtree_into_nested_folder_raises(self):
        vault = self._chain_vault()
        # A's subtree height is 4; moving under X (depth 1) would reach depth 6.
        with self.assertRaisesRegex(nsf_management.NsfError, 'exceed the maximum of 5'):
            nsf_management._validate_nsf_folder_move_depth(vault, 'A', 'X')


class TestNsfMoveTypeValidation(unittest.TestCase):
    def _vault(self):
        return MagicMock()

    @patch.object(nsf_management, 'resolve_nsf_folder_uid', return_value=None)
    @patch.object(nsf_management, 'is_nsf_folder', return_value=False)
    def test_move_folder_rejects_non_nsf_source(self, mock_is_folder, mock_resolve):
        vault = self._vault()
        with self.assertRaisesRegex(nsf_management.NsfError, 'NSF source folder not found'):
            nsf_management.move_nsf_folder(vault, 'legacy-folder-uid', 'dest')

    @patch.object(nsf_management, 'resolve_nsf_folder_uid',
                  side_effect=lambda _v, ident: ident if ident == 'source-uid' else None)
    @patch.object(nsf_management, 'is_nsf_folder',
                  side_effect=lambda _v, uid: uid == 'source-uid')
    def test_move_folder_rejects_non_nsf_destination(self, mock_is_folder, mock_resolve):
        vault = self._vault()
        with self.assertRaisesRegex(nsf_management.NsfError, 'NSF destination folder not found'):
            nsf_management.move_nsf_folder(vault, 'source-uid', 'legacy-destination-uid')

    @patch.object(nsf_management, 'resolve_nsf_record_uid', return_value=None)
    @patch.object(nsf_management, 'is_nsf_record', return_value=False)
    def test_move_record_rejects_non_nsf_source(self, mock_is_record, mock_resolve):
        vault = self._vault()
        with self.assertRaisesRegex(nsf_management.NsfError, 'NSF record not found'):
            nsf_management.move_nsf_record(vault, 'legacy-record-uid', 'dest')

    @patch.object(nsf_management, 'resolve_nsf_record_uid', return_value='record-uid')
    @patch.object(nsf_management, 'is_nsf_record', return_value=True)
    @patch.object(nsf_management, 'resolve_nsf_folder_uid', return_value=None)
    @patch.object(nsf_management, 'is_nsf_folder', return_value=False)
    def test_move_record_rejects_non_nsf_destination(
            self, mock_is_folder, mock_resolve_folder, mock_is_record, mock_resolve_record):
        vault = self._vault()
        with self.assertRaisesRegex(nsf_management.NsfError, 'NSF destination folder not found'):
            nsf_management.move_nsf_record(vault, 'record-uid', 'legacy-destination-uid')


if __name__ == '__main__':
    unittest.main()
