from enum import Enum
from typing import Dict, Optional, Set, Union

from . import vault_online, vault_record, vault_utils


# Constants
TEXT_EDIT = 'Edit'
TEXT_SHARE = 'Share'
BIT_MASK_EDIT = 1 << 0
BIT_MASK_SHARE = 1 << 1
BITS_TEXT_LOOKUP = {BIT_MASK_EDIT: TEXT_EDIT, BIT_MASK_SHARE: TEXT_SHARE}
SHARE_PERMISSIONS_TYPE = Enum('SharePermissionsType', ['USER', 'SF_USER', 'TEAM', 'TEAM_USER'])


class SharePermissions:
    """Manages share permissions for records, including edit, share, and view capabilities."""

    SharePermissionsType = SHARE_PERMISSIONS_TYPE
    bits_text_lookup = BITS_TEXT_LOOKUP

    def __init__(self, sp_types=None, to_name='', permissions_text='', types=None):
        """Initialize SharePermissions with default values and process provided types."""
        self._initialize_default_attributes(to_name, permissions_text)
        self._process_initial_types(types)
        self._process_share_permission_types(sp_types)

    def _initialize_default_attributes(self, to_name: str, permissions_text: str) -> None:
        """Initialize all attributes with default values."""
        self.to_uid = ''
        self.to_name = to_name
        self.can_edit = False
        self.can_share = False
        self.can_view = True
        self.expiration = 0
        self.folder_path = ''
        self.types: Set = set()
        self.bits = 0
        self.is_admin = False
        self.team_members: Dict = {}
        self.user_perms: Dict[str, 'SharePermissions'] = {}
        self.team_perms: Dict[str, 'SharePermissions'] = {}
        self.permissions_text = permissions_text

    def _process_initial_types(self, types: Optional[Union[list, object]]) -> None:
        """Process and add initial types to the types set."""
        if types is None:
            return
        
        if isinstance(types, list):
            self.types.update(types)
        else:
            self.types.add(types)

    def _process_share_permission_types(self, sp_types: Optional[Union[Set, object]]) -> None:
        """Process and add share permission types to the types set."""
        if sp_types is None:
            return
        
        if isinstance(sp_types, set):
            self.types.update(sp_types)
        else:
            self.types.add(sp_types)

    def update_types(self, sp_types: Optional[Union[Set, object]]) -> None:
        """Update the types set with new share permission types."""
        self._process_share_permission_types(sp_types)


class SharedRecord:
    """Defines a Keeper Shared Record (shared either via Direct-Share or as a child of a Shared-Folder node)"""

    def __init__(
        self,
        vault: vault_online.VaultOnline,
        record: vault_record.KeeperRecordInfo,
        sf_sharing_admins: Optional[Dict] = None,
        team_members: Optional[Dict] = None,
        role_restricted_members: Optional[Set] = None
    ):
        """Initialize SharedRecord with record information and sharing data."""
        self._initialize_record_attributes(record)
        self._initialize_sharing_attributes()
        self._initialize_folder_info(vault)
        self._initialize_sharing_data(sf_sharing_admins, team_members, role_restricted_members)

    def _initialize_record_attributes(self, record: vault_record.KeeperRecordInfo) -> None:
        """Initialize attributes from the record object."""
        self.record = record
        self.uid = record.record_uid
        self.name = record.title

    def _initialize_sharing_attributes(self) -> None:
        """Initialize sharing-related attributes with default values."""
        self.shared_folders = None
        self.sf_shares: Dict = {}
        self.permissions: Dict[str, SharePermissions] = {}
        self.team_permissions: Dict[str, SharePermissions] = {}
        self.user_permissions: Dict[str, SharePermissions] = {}
        self.revision = None
        self.folder_uids: list = []
        self.folder_paths: list = []

    def _initialize_folder_info(self, vault: vault_online.VaultOnline) -> None:
        """Initialize folder information for the record."""
        folders = vault_utils.get_folders_for_record(vault.vault_data, self.uid)
        self.folder_uids = [folder.folder_uid for folder in folders]

    def _initialize_sharing_data(
        self,
        sf_sharing_admins: Optional[Dict],
        team_members: Optional[Dict],
        role_restricted_members: Optional[Set]
    ) -> None:
        """Initialize sharing data with provided values or defaults."""
        self.team_members = team_members or {}
        _ = sf_sharing_admins or {}
        _ = role_restricted_members or set()
