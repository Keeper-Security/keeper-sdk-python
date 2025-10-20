from enum import Enum
from typing import Dict

from .. import api
from .share_utils import (
    KEY_USERNAME, KEY_TEAM_UID, KEY_RECORD_UID, KEY_SHARED_FOLDER_UID,
    KEY_USER_PERMISSIONS, KEY_SHARED_FOLDER_PERMISSIONS,
    KEY_SHARES, KEY_UID, KEY_NAME, KEY_EDITABLE, KEY_SHAREABLE,
    KEY_MANAGE_RECORDS, KEY_MANAGE_USERS, KEY_SHARE_ADMIN, KEY_IS_ADMIN,
    KEY_EXPIRATION, KEY_OWNER, KEY_VIEW, KEY_ENTERPRISE, KEY_ENTERPRISE_USER_ID,
    KEY_USER_TYPE, KEY_ROLE_ID, KEY_ROLE_ENFORCEMENTS, KEY_ROLE_USERS,
    KEY_ROLE_TEAMS, KEY_TEAM_USERS, KEY_USERS, KEY_TEAMS, KEY_ENFORCEMENTS,
    KEY_VAULT, KEY_VAULT_DATA, KEY_SHARED_FOLDER_CACHE, KEY_RECORD_CACHE,
    KEY_RECORD_OWNER_CACHE, KEY_TITLE, KEY_RESTRICT_EDIT, KEY_RESTRICT_SHARING,
    KEY_RESTRICT_VIEW, KEY_RESTRICT_SHARING_ALL, PERMISSION_EDIT, PERMISSION_SHARE,
    PERMISSION_VIEW, TEXT_EDIT, TEXT_SHARE, TEXT_READ_ONLY, TEXT_LAUNCH_ONLY,
    TEXT_CAN_PREFIX, TEXT_TEAM_PREFIX, TEXT_TEAM_USER_PREFIX, USER_TYPE_INACTIVE,
    ShareManagementError
)

logger = api.get_logger() 


def _safe_get_attr(obj, attr_name, default=None):
    """Safely get attribute from object or dict."""
    if isinstance(obj, dict):
        return obj.get(attr_name, default)
    return getattr(obj, attr_name, default)


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

    def get_target(self, show_team_info):
        return self.get_team_view_name() if show_team_info else self.to_name

    def get_team_view_name(self):
        prefix_lookup = {
            SharePermissions.SharePermissionsType.TEAM: TEXT_TEAM_PREFIX,
            SharePermissions.SharePermissionsType.TEAM_USER: TEXT_TEAM_USER_PREFIX,
            SharePermissions.SharePermissionsType.USER: '',
            SharePermissions.SharePermissionsType.SF_USER: ''
        }
        prefix = ''.join(prefix_lookup.get(t) for t in self.types)
        return f'{prefix} {self.to_name}'.strip()

    @property
    def permissions_text_property(self):
        if not self.can_edit and not self.can_share:
            return TEXT_READ_ONLY if self.can_view else TEXT_LAUNCH_ONLY
        else:
            privs = [self.can_share and TEXT_SHARE, self.can_edit and TEXT_EDIT]
            return f'{TEXT_CAN_PREFIX}{" & ".join([p for p in privs if p])}'

    @staticmethod
    def load_permissions(perms, sp_type):
        sp = SharePermissions(sp_type)
        sp.to_uid = perms.get(KEY_UID) or perms.get(KEY_TEAM_UID)
        sp.to_name = perms.get(KEY_USERNAME) or perms.get(KEY_NAME)
        sp.is_admin = perms.get(KEY_SHARE_ADMIN) or perms.get(KEY_IS_ADMIN)
        sp.can_edit = perms.get(KEY_EDITABLE) or perms.get(KEY_MANAGE_RECORDS) or sp.is_admin
        sp.can_share = perms.get(KEY_SHAREABLE) or perms.get(KEY_MANAGE_USERS) or sp.is_admin
        sp.can_view = perms.get(KEY_VIEW, True)
        exp = perms.get(KEY_EXPIRATION)
        if isinstance(exp, int) and exp > 0:
            sp.expiration = exp
        return sp

    def apply_restrictions(self, *restrictions):
        """Apply restrictions to permissions."""
        try:
            for member in self.team_members.values():
                member.apply_restrictions(*restrictions)
            restrictions_str = ','.join(restrictions).lower()
            if PERMISSION_EDIT in restrictions_str:
                self.can_edit = False
            if PERMISSION_SHARE in restrictions_str:
                self.can_share = False
            if PERMISSION_VIEW in restrictions_str:
                self.can_view = False
        except Exception as e:
            logger.debug(f"Failed to apply restrictions: {e}")


class SharedRecord:
    """Defines a Keeper Shared Record (shared either via Direct-Share or as a child of a Shared-Folder node)"""

    def __init__(self, params, record, sf_sharing_admins=None, team_members=None, role_restricted_members=None):
        """Initialize SharedRecord with proper error handling."""
        try:
            self.params = params
            self.record = record
            self.uid = getattr(record, KEY_RECORD_UID, getattr(record, KEY_UID, ''))
            
            self.owner = self._determine_owner(params)
            self.name = getattr(record, KEY_TITLE, '')
            self.shared_folders = None
            self.sf_shares = {}
            self.permissions: Dict[str, SharePermissions] = {}
            self.team_permissions: Dict[str, SharePermissions] = {}
            self.user_permissions: Dict[str, SharePermissions] = {}
            self.revision = None
            self.folder_uids = []
            self.folder_paths = []
            
            self._initialize_folder_info(params)
            self.team_members = team_members or {}

            if sf_sharing_admins is None:
                sf_sharing_admins = {}
            if role_restricted_members is None:
                role_restricted_members = set()

            self.load(params, sf_sharing_admins, team_members, role_restricted_members)
        except Exception as e:
            logger.error(f"Failed to initialize SharedRecord: {e}")

    def _determine_owner(self, params):
        """Determine the owner of the record."""
        try:
            record_owner_cache = _safe_get_attr(params, KEY_RECORD_OWNER_CACHE)
            has_owner = record_owner_cache and self.uid in record_owner_cache
            user_owned = has_owner and record_owner_cache.get(self.uid).owner
            owner = _safe_get_attr(params, 'user', '') if user_owned else ''
            if not owner:
                auth = _safe_get_attr(params, 'auth')
                if auth and hasattr(auth, 'auth_context') and auth.auth_context:
                    owner = auth.auth_context.username
            return owner
        except Exception as e:
            logger.debug(f"Failed to determine owner: {e}")
            return ''

    def _initialize_folder_info(self, params):
        """Initialize folder information for the record."""
        try:
            from keepersdk.vault import vault_utils
            vault = _safe_get_attr(params, KEY_VAULT)
            if vault and hasattr(vault, KEY_VAULT_DATA):
                folders = vault_utils.get_folders_for_record(vault.vault_data, self.uid)
                self.folder_uids = [f.folder_uid for f in folders]
        except Exception as e:
            logger.debug(f"Failed to initialize folder info: {e}")

    def get_ordered_permissions(self):
        """
        Get ordered permissions.
        """
        ordered = list(self.permissions.values())
        for user_perms in self.user_permissions.values():
            if user_perms.to_uid:
                if user_perms in ordered:
                    ordered.remove(user_perms)
                team_perms = self.team_permissions.get(user_perms.to_uid)
                if team_perms and team_perms in ordered:
                    ordered.insert(ordered.index(team_perms) + 1, user_perms)
        return ordered

    def merge_permissions(self, share_target, perms_to_merge, sp_type):
        """
        Merge permissions for a given share target.
        """
        new_perms = SharePermissions.load_permissions(perms_to_merge, sp_type)
        existing = self.permissions.get(share_target) or new_perms
        existing.to_uid = new_perms.to_uid or existing.to_uid
        existing.is_admin = existing.is_admin or new_perms.is_admin
        existing.can_share = existing.can_share or new_perms.can_share
        existing.can_edit = existing.can_edit or new_perms.can_edit
        existing.update_types(new_perms.types)
        if existing.expiration > 0:
            if new_perms.expiration > 0:
                if new_perms.expiration > existing.expiration:
                    existing.expiration = new_perms.expiration
            else:
                existing.expiration = 0

        self.permissions[share_target] = existing
        return existing

    def merge_user_permissions(self, email, user_perms, sp_type=None):
        new_perms = self.merge_permissions(email, user_perms, sp_type or SharePermissions.SharePermissionsType.USER)
        self.user_permissions[email] = new_perms
        return new_perms

    def merge_team_permissions(self, team_uid, team_perms):
        new_perms = self.merge_permissions(team_uid, team_perms, SharePermissions.SharePermissionsType.TEAM)
        self.team_permissions[team_uid] = new_perms
        return new_perms

    def load(self, params, sf_sharing_admins, team_members, role_restricted_members, share_info=None):
        """Load share information for the record with proper error handling."""
        try:
            shares = self._get_shares_data(params, share_info)
            self._load_user_permissions(shares, sf_sharing_admins)
            self._load_shared_folder_permissions(params, shares, sf_sharing_admins, team_members)
            self._apply_role_restrictions(role_restricted_members)
        except Exception as e:
            logger.debug(f"Failed to load share information: {e}")

    def _get_shares_data(self, params, share_info):
        """Get shares data from various sources."""
        if share_info:
            return share_info.get(KEY_SHARES, {})
        
        try:
            record_cache = _safe_get_attr(params, KEY_RECORD_CACHE)
            if record_cache and self.uid in record_cache:
                rec_cached = record_cache.get(self.uid, {})
                return rec_cached.get(KEY_SHARES, {})
        except Exception as e:
            logger.debug(f"Failed to get cached shares data: {e}")
        
        return {}

    def _load_user_permissions(self, shares, sf_sharing_admins):
        """Load user permissions from shares data."""
        user_perms = list(shares.get(KEY_USER_PERMISSIONS, []))
        if len(user_perms) > 0:
            owner_user = next((up.get(KEY_USERNAME) for up in user_perms if up.get(KEY_OWNER)), '')
            if owner_user:
                self.owner = owner_user
            self._process_user_permissions_list(user_perms, sf_sharing_admins=sf_sharing_admins)

    def _process_user_permissions_list(self, user_perms, sf_uid=None, sp_type=None, sf_sharing_admins=None):
        """Process a list of user permissions."""
        for up in user_perms:
            if isinstance(up, dict):
                email = up.get(KEY_USERNAME)
                if not email:
                    continue
                self._update_sf_shares(email, sf_uid)
                self._apply_share_admin_permissions(up, sf_uid, sf_sharing_admins)
                self.merge_user_permissions(email, up, sp_type)
            else:
                self._process_user_permission_object(up, sf_uid, sp_type, sf_sharing_admins)

    def _process_user_permission_object(self, up, sf_uid, sp_type, sf_sharing_admins=None):
        """Process a user permission object."""
        email = getattr(up, KEY_NAME, '')
        if not email:
            return
        
        self._update_sf_shares(email, sf_uid)
        share_admins = sf_sharing_admins.get(sf_uid, []) if sf_sharing_admins and sf_uid else []
        is_admin = share_admins and email in share_admins
        
        up_dict = {
            KEY_USERNAME: email,
            KEY_EDITABLE: (getattr(up, KEY_MANAGE_RECORDS, False) 
                          if sp_type == SharePermissions.SharePermissionsType.SF_USER 
                          else getattr(up, KEY_EDITABLE, False)),
            KEY_SHAREABLE: (getattr(up, KEY_MANAGE_USERS, False) 
                           if sp_type == SharePermissions.SharePermissionsType.SF_USER 
                           else getattr(up, KEY_SHAREABLE, False)),
            KEY_SHARE_ADMIN: is_admin,
            KEY_EXPIRATION: getattr(up, KEY_EXPIRATION, 0)
        }
        
        if is_admin:
            up_dict[KEY_EDITABLE] = True
            up_dict[KEY_SHAREABLE] = True
            up_dict[KEY_SHARE_ADMIN] = True
        
        self.merge_user_permissions(email, up_dict, sp_type)

    def _update_sf_shares(self, share_to, sf_uid):
        """Update shared folder shares."""
        if sf_uid:
            sf_shares = self.sf_shares.get(sf_uid, set())
            sf_shares.add(share_to)
            self.sf_shares[sf_uid] = sf_shares

    def _apply_share_admin_permissions(self, up, sf_uid, sf_sharing_admins):
        """Apply share admin permissions."""
        if sf_uid:
            share_admins = sf_sharing_admins.get(sf_uid, [])
            is_admin = share_admins and up.get(KEY_USERNAME) in share_admins
            if is_admin:
                up[KEY_EDITABLE] = True
                up[KEY_SHAREABLE] = True
                up[KEY_SHARE_ADMIN] = True

    def _load_shared_folder_permissions(self, params, shares, sf_sharing_admins, team_members):
        """Load shared folder permissions."""
        sf_perms = shares.get(KEY_SHARED_FOLDER_PERMISSIONS, [])
        sf_cache = getattr(params, KEY_SHARED_FOLDER_CACHE, {})
        shared_folders = {sfp.get(KEY_SHARED_FOLDER_UID): sf_cache.get(sfp.get(KEY_SHARED_FOLDER_UID)) 
                         for sfp in sf_perms}
        shared_folders = {k: v for k, v in shared_folders.items() if v}

        shared_folder_found = self._load_from_vault_folders(params, sf_sharing_admins, team_members)
        
        if not shared_folder_found and shared_folders:
            self._load_from_shared_folders(shared_folders, sf_sharing_admins, team_members)

    def _load_from_vault_folders(self, params, sf_sharing_admins, team_members):
        """Load permissions from vault folders."""
        vault = _safe_get_attr(params, KEY_VAULT)
        if not vault or not hasattr(vault, KEY_VAULT_DATA):
            return False

        try:
            for folder_uid in self.folder_uids:
                folder = vault.vault_data.get_folder(folder_uid)
                if folder and folder.folder_type == 'shared_folder':
                    self._load_shared_folder_permissions(folder_uid, params, sf_sharing_admins, team_members)
                    return True
                elif folder and folder.folder_type == 'shared_folder_folder':
                    if folder.folder_scope_uid:
                        self._load_shared_folder_permissions(
                            folder.folder_scope_uid, params, sf_sharing_admins, team_members)
                        return True
        except Exception as e:
            logger.debug(f"Failed to load from vault folders: {e}")
        
        return False

    def _load_shared_folder_permissions(self, folder_uid, params, sf_sharing_admins, team_members):
        """Load permissions for a specific shared folder."""
        vault = _safe_get_attr(params, KEY_VAULT)
        if not vault or not hasattr(vault, KEY_VAULT_DATA):
            return
            
        sf = vault.vault_data.load_shared_folder(shared_folder_uid=folder_uid)
        if sf and sf.user_permissions:
            # Only clear if we're going to replace with shared folder permissions
            self.permissions.clear()
            self.user_permissions.clear()
            self.team_permissions.clear()
            
            # Split permissions by user_type (1=User, 2=Team)
            user_perms = [p for p in sf.user_permissions if p.user_type == 1]
            team_perms = [p for p in sf.user_permissions if p.user_type == 2]
            
            if user_perms:
                self._process_user_permissions_list(
                    user_perms, folder_uid, SharePermissions.SharePermissionsType.SF_USER, sf_sharing_admins)
            if team_perms:
                self._process_team_permissions_list(team_perms, folder_uid, team_members, sf_sharing_admins)

    def _load_from_shared_folders(self, shared_folders, sf_sharing_admins, team_members):
        """Load permissions from shared folders data."""
        self.permissions.clear()
        self.user_permissions.clear()
        self.team_permissions.clear()

        sf_user_perms = {sf_uid: sf.get(KEY_USERS, []) 
                        for sf_uid, sf in shared_folders.items() if sf.get(KEY_USERS)}
        team_perms = {sf_uid: sf.get(KEY_TEAMS, []) 
                     for sf_uid, sf in shared_folders.items() if sf.get(KEY_TEAMS)}

        for sf_uid, sf_ups in sf_user_perms.items():
            self._process_user_permissions_list(
                sf_ups, sf_uid, SharePermissions.SharePermissionsType.SF_USER, sf_sharing_admins)
        for sf_uid, teams in team_perms.items():
            self._process_team_permissions_list(teams, sf_uid, team_members, sf_sharing_admins)

    def _process_team_permissions_list(self, t_perms, sf_uid, team_members, sf_sharing_admins=None):
        """Process a list of team permissions."""
        for tp in t_perms:
            if isinstance(tp, dict):
                self._process_team_permission_dict(tp, sf_uid, team_members, sf_sharing_admins)
            else:
                self._process_team_permission_object(tp, sf_uid, team_members, sf_sharing_admins)

    def _process_team_permission_dict(self, tp, sf_uid, team_members, sf_sharing_admins=None):
        """Process team permission dictionary."""
        team_uid = tp.get(KEY_TEAM_UID)
        team_name = tp.get(KEY_NAME)
        if not team_uid:
            return
        
        self._update_sf_shares(team_name, sf_uid)
        tp = self._apply_team_restrictions(tp)
        merged = self.merge_team_permissions(team_uid, tp)

        t_users = team_members.get(team_uid, set()) if team_members else set()
        ups = [{**tp, KEY_USERNAME: t_username} for t_username in t_users]
        self._process_user_permissions_list(ups, sf_uid, SharePermissions.SharePermissionsType.TEAM_USER, sf_sharing_admins)
        
        if merged:
            merged.team_members.update({t_username: self.permissions.get(t_username) 
                                      for t_username in t_users})

    def _process_team_permission_object(self, tp, sf_uid, team_members, sf_sharing_admins=None):
        """Process team permission object."""
        team_uid = getattr(tp, KEY_TEAM_UID, '')
        team_name = getattr(tp, KEY_NAME, '')
        if not team_uid:
            return
        
        self._update_sf_shares(team_name, sf_uid)
        
        tp_dict = {
            KEY_TEAM_UID: team_uid,
            KEY_NAME: team_name,
            KEY_MANAGE_RECORDS: getattr(tp, KEY_MANAGE_RECORDS, False),
            KEY_MANAGE_USERS: getattr(tp, KEY_MANAGE_USERS, False),
            KEY_EXPIRATION: getattr(tp, KEY_EXPIRATION, 0)
        }
        tp_dict = self._apply_team_restrictions(tp_dict)
        merged = self.merge_team_permissions(team_uid, tp_dict)

        t_users = team_members.get(team_uid, set()) if team_members else set()
        ups = [{**tp_dict, KEY_USERNAME: t_username} for t_username in t_users]
        self._process_user_permissions_list(ups, sf_uid, SharePermissions.SharePermissionsType.TEAM_USER, sf_sharing_admins)
        
        if merged:
            merged.team_members.update({t_username: self.permissions.get(t_username) 
                                      for t_username in t_users})

    def _apply_team_restrictions(self, team_perms):
        """Apply team restrictions to permissions."""
        enterprise = _safe_get_attr(self.params, KEY_ENTERPRISE)
        if not enterprise:
            return team_perms

        restriction_permission_lookup = {
            KEY_RESTRICT_EDIT: KEY_MANAGE_RECORDS,
            KEY_RESTRICT_SHARING: KEY_MANAGE_USERS,
            KEY_RESTRICT_VIEW: KEY_VIEW
        }

        teams_cache = enterprise.get(KEY_TEAMS, {}) if isinstance(enterprise, dict) else getattr(enterprise, KEY_TEAMS, {})
        perms = team_perms.copy()
        team_info = next((t for t in teams_cache 
                         if t.get(KEY_TEAM_UID) == perms.get(KEY_TEAM_UID)), {})
        
        for restriction, permission in restriction_permission_lookup.items():
            if team_info.get(restriction):
                perms[permission] = False
        
        return perms

    def _apply_role_restrictions(self, role_restricted_members):
        """Apply role restrictions to permissions."""
        for restricted_target in role_restricted_members:
            perms = self.permissions.get(restricted_target)
            if perms:
                perms.apply_restrictions(PERMISSION_SHARE)
        


def get_shared_records(params, record_uids, cache_only=False):
    """Get shared records information with enterprise features."""
    try:
        from . import share_utils
        vault = _safe_get_attr(params, KEY_VAULT)
        share_infos = share_utils.get_record_shares(vault=vault, record_uids=record_uids) or [] if vault else []
    except Exception as e:
        logger.debug(f"Failed to get record shares: {e}")
        share_infos = []

    try:
        vault = _safe_get_attr(params, KEY_VAULT)
        if vault and hasattr(vault, KEY_VAULT_DATA):
            shared_folder_cache = _safe_get_attr(params, KEY_SHARED_FOLDER_CACHE)
            if not shared_folder_cache:
                shared_folder_cache = {}
                # Set it back on params if possible
                if isinstance(params, dict):
                    params[KEY_SHARED_FOLDER_CACHE] = shared_folder_cache
                else:
                    setattr(params, KEY_SHARED_FOLDER_CACHE, shared_folder_cache)
                    
                for sf_info in vault.vault_data.shared_folders():
                    sf_uid = sf_info.shared_folder_uid
                    try:
                        sf = vault.vault_data.load_shared_folder(shared_folder_uid=sf_uid)
                        if sf:
                            # Split permissions by user_type
                            user_perms = [p for p in sf.user_permissions if p.user_type == 1] if sf.user_permissions else []
                            team_perms = [p for p in sf.user_permissions if p.user_type == 2] if sf.user_permissions else []
                            shared_folder_cache[sf_uid] = {
                                KEY_USERS: user_perms,
                                KEY_TEAMS: team_perms,
                                KEY_NAME: sf.name
                            }
                    except Exception as e:
                        logger.debug(f"Failed to load shared folder {sf_uid}: {e}")
    except Exception as e:
        logger.debug(f"Failed to initialize shared folder cache: {e}")

    sf_teams = []
    try:
        shared_folder_cache = _safe_get_attr(params, KEY_SHARED_FOLDER_CACHE)
        if shared_folder_cache:
            sf_teams = [shared_folder.get(KEY_TEAMS, []) 
                       for shared_folder in shared_folder_cache.values()]
    except Exception as e:
        logger.debug(f"Failed to get shared folder teams: {e}")

    sf_share_admins = _fetch_sf_admins(params) if not cache_only else {}
    team_uids = {t.get(KEY_TEAM_UID) for teams in sf_teams for t in teams}
    
    enterprise_users = []
    try:
        enterprise = _safe_get_attr(params, KEY_ENTERPRISE)
        if enterprise:
            enterprise_users = enterprise.get(KEY_USERS, []) if isinstance(enterprise, dict) else getattr(enterprise, KEY_USERS, [])
    except Exception as e:
        logger.debug(f"Failed to get enterprise users: {e}")
    
    username_lookup = {u.get(KEY_ENTERPRISE_USER_ID): u.get(KEY_USERNAME) 
                      for u in enterprise_users}
    restricted_role_members = _get_restricted_role_members(params, username_lookup)
    team_members = _get_cached_team_members(params, team_uids, username_lookup)
    
    records = _load_records_safely(params, record_uids)
    
    shared_records = []
    for r in records:
        try:
            uid = getattr(r, KEY_RECORD_UID, getattr(r, KEY_UID, ''))
            record_share_info = _find_record_share_info(share_infos, uid)
            
            shared_record = SharedRecord(params, r, sf_share_admins, team_members, restricted_role_members)
            if record_share_info:
                shared_record.load(params, sf_share_admins, team_members, restricted_role_members, record_share_info)
            shared_records.append(shared_record)
        except Exception as e:
            logger.debug(f"Failed to process record: {e}")
            uid = getattr(r, KEY_RECORD_UID, getattr(r, KEY_UID, ''))
            if uid:
                shared_record = SharedRecord(params, r, sf_share_admins, team_members, restricted_role_members)
                shared_records.append(shared_record)
    
    return {shared_record.uid: shared_record for shared_record in shared_records}


def _fetch_sf_admins(params):
    """Fetch shared folder administrators."""
    sf_admins = {}
    try:
        shared_folder_cache = _safe_get_attr(params, KEY_SHARED_FOLDER_CACHE)
        if shared_folder_cache:
            sf_uids = [uid for uid in shared_folder_cache]
            for sf_uid in sf_uids:
                sf_admins[sf_uid] = []
    except Exception as e:
        logger.debug(f"Failed to fetch shared folder admins: {e}")
    return sf_admins


def _get_restricted_role_members(params, username_lookup):
    """Get usernames with restricted sharing permissions."""
    members = set()
    enterprise = _safe_get_attr(params, KEY_ENTERPRISE)
    if not enterprise:
        return members

    try:
        restrict_key = KEY_RESTRICT_SHARING_ALL
        enf_key = KEY_ENFORCEMENTS
        r_enforcements = enterprise.get(KEY_ROLE_ENFORCEMENTS, []) if isinstance(enterprise, dict) else getattr(enterprise, KEY_ROLE_ENFORCEMENTS, [])
        no_share_roles = {re.get(KEY_ROLE_ID) for re in r_enforcements 
                         if re.get(enf_key, {}).get(restrict_key) == 'true'}
        r_users_data = enterprise.get(KEY_ROLE_USERS, []) if isinstance(enterprise, dict) else getattr(enterprise, KEY_ROLE_USERS, [])
        r_users = [u for u in r_users_data if u.get(KEY_ROLE_ID) in no_share_roles]
        r_teams_data = enterprise.get(KEY_ROLE_TEAMS, []) if isinstance(enterprise, dict) else getattr(enterprise, KEY_ROLE_TEAMS, [])
        r_teams = [t for t in r_teams_data if t.get(KEY_ROLE_ID) in no_share_roles]
        no_share_users = {username_lookup.get(u.get(KEY_ENTERPRISE_USER_ID)) for u in r_users}
        no_share_teams = {t.get(KEY_TEAM_UID) for t in r_teams}
        cached_team_members = _get_cached_team_members(params, no_share_teams, username_lookup)
        no_share_team_members = {t for team_uid in no_share_teams 
                                for t in cached_team_members.get(team_uid, set())}
        members = no_share_users.union(no_share_teams).union(no_share_team_members)
    except Exception as e:
        logger.debug(f"Failed to get restricted role members: {e}")
    return members


def _get_cached_team_members(params, t_uids, uname_lookup):
    """Get team members from cached enterprise data."""
    members = {}
    enterprise = _safe_get_attr(params, KEY_ENTERPRISE)
    if not enterprise:
        return members

    try:
        team_users_data = enterprise.get(KEY_TEAM_USERS) if isinstance(enterprise, dict) else getattr(enterprise, KEY_TEAM_USERS, [])
        team_users = team_users_data or []
        team_users = [tu for tu in team_users 
                     if tu.get(KEY_USER_TYPE) != USER_TYPE_INACTIVE and 
                        tu.get(KEY_TEAM_UID) in t_uids]

        for tu in team_users:
            user_id = tu.get(KEY_ENTERPRISE_USER_ID)
            username = uname_lookup.get(user_id)
            team_uid = tu.get(KEY_TEAM_UID)
            if username and team_uid:
                t_members = members.get(team_uid, set())
                t_members.add(username)
                members[team_uid] = t_members
    except Exception as e:
        logger.debug(f"Failed to get cached team members: {e}")

    return members


def _load_records_safely(params, record_uids):
    """Load records safely with error handling."""
    records = []
    vault = _safe_get_attr(params, KEY_VAULT)
    if not vault or not hasattr(vault, KEY_VAULT_DATA):
        return records
        
    try:
        records = [vault.vault_data.load_record(uid) for uid in record_uids]
        records = [r for r in records if r]
    except Exception as e:
        logger.debug(f"Failed to load records in batch: {e}")
        records = []
        for uid in record_uids:
            try:
                record = vault.vault_data.load_record(uid)
                if record:
                    records.append(record)
            except Exception as e:
                logger.debug(f"Failed to load record {uid}: {e}")
    return records


def _find_record_share_info(share_infos, uid):
    """Find share info for a specific record UID."""
    # Normalize UID to handle different base64 encodings (URL-safe vs standard)
    uid_normalized = uid.rstrip('=').replace('+', '-').replace('/', '_')
    
    for share_info in share_infos:
        info_uid = share_info.get(KEY_RECORD_UID, '')
        info_uid_normalized = info_uid.rstrip('=').replace('+', '-').replace('/', '_')
        if info_uid_normalized == uid_normalized:
            return share_info
    return None
