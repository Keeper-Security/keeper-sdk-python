from enum import Enum
from typing import Dict

from keepersdk.vault import vault_online, vault_record

from .. import api
from ..params import KeeperParams
logger = api.get_logger() 

TEXT_EDIT = 'Edit'
TEXT_SHARE = 'Share'

class SharePermissions:
    SharePermissionsType = Enum('SharePermissionsType', ['USER', 'SF_USER', 'TEAM', 'TEAM_USER'])
    bits_text_lookup = {(1 << 0): TEXT_EDIT, (1 << 1): TEXT_SHARE}

    def __init__(self, sp_types=None, to_name='', permissions_text='', types=None):
        self.to_uid = ''
        self.to_name = to_name
        self.can_edit = False
        self.can_share = False
        self.can_view = True
        self.expiration = 0
        self.folder_path = ''
        self.types = set()
        self.bits = 0
        self.is_admin = False
        self.team_members = dict()
        self.user_perms: Dict[str, 'SharePermissions'] = {}
        self.team_perms: Dict[str, 'SharePermissions'] = {}
        self.permissions_text = permissions_text
        
        if types is not None:
            if isinstance(types, list):
                self.types.update(types)
            else:
                self.types.add(types)
        
        self.update_types(sp_types)

    def update_types(self, sp_types):
        if sp_types is not None:
            update_types_fn = self.types.update if isinstance(sp_types, set) else self.types.add
            update_types_fn(sp_types)


class SharedRecord:
    """Defines a Keeper Shared Record (shared either via Direct-Share or as a child of a Shared-Folder node)"""

    def __init__(self, context: KeeperParams, record: vault_record.KeeperRecordInfo, sf_sharing_admins=None, team_members=None, role_restricted_members=None):
        """Initialize SharedRecord with proper error handling."""
        try:
            self.context = context
            self.record = record
            self.uid = record.record_uid
            
            self.name = record.title
            self.shared_folders = None
            self.sf_shares = {}
            self.permissions: Dict[str, SharePermissions] = {}
            self.team_permissions: Dict[str, SharePermissions] = {}
            self.user_permissions: Dict[str, SharePermissions] = {}
            self.revision = None
            self.folder_uids = []
            self.folder_paths = []
            
            self._initialize_folder_info(context.vault)
            self.team_members = team_members or {}

            if sf_sharing_admins is None:
                sf_sharing_admins = {}
            if role_restricted_members is None:
                role_restricted_members = set()

        except Exception as e:
            logger.error(f"Failed to initialize SharedRecord: {e}")

    def _initialize_folder_info(self, vault: vault_online.VaultOnline):
        """Initialize folder information for the record."""
        try:
            from keepersdk.vault import vault_utils
            folders = vault_utils.get_folders_for_record(vault.vault_data, self.uid)
            self.folder_uids = [f.folder_uid for f in folders]
        except Exception as e:
            logger.debug(f"Failed to initialize folder info: {e}")
