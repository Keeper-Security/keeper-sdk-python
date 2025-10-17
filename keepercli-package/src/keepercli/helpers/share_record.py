from enum import Enum
from typing import Dict
from .. import api

logger = api.get_logger()

KEY_USERNAME = 'username'
KEY_TEAM_UID = 'team_uid'
KEY_RECORD_UID = 'record_uid'
KEY_SHARED_FOLDER_UID = 'shared_folder_uid'
KEY_USER_PERMISSIONS = 'user_permissions'
KEY_TEAM_PERMISSIONS = 'team_permissions'
KEY_SHARED_FOLDER_PERMISSIONS = 'shared_folder_permissions'
KEY_SHARES = 'shares'
KEY_UID = 'uid'
KEY_NAME = 'name'

KEY_EDITABLE = 'editable'
KEY_SHAREABLE = 'shareable'
KEY_MANAGE_RECORDS = 'manage_records'
KEY_MANAGE_USERS = 'manage_users'
KEY_SHARE_ADMIN = 'share_admin'
KEY_IS_ADMIN = 'is_admin'
KEY_EXPIRATION = 'expiration'
KEY_OWNER = 'owner'
KEY_VIEW = 'view'

KEY_ENTERPRISE = 'enterprise'
KEY_ENTERPRISE_USER_ID = 'enterprise_user_id'
KEY_USER_TYPE = 'user_type'
KEY_ROLE_ID = 'role_id'
KEY_ROLE_ENFORCEMENTS = 'role_enforcements'
KEY_ROLE_USERS = 'role_users'
KEY_ROLE_TEAMS = 'role_teams'
KEY_TEAM_USERS = 'team_users'
KEY_USERS = 'users'
KEY_TEAMS = 'teams'
KEY_ENFORCEMENTS = 'enforcements'

KEY_VAULT = 'vault'
KEY_VAULT_DATA = 'vault_data'
KEY_SHARED_FOLDER_CACHE = 'shared_folder_cache'
KEY_RECORD_CACHE = 'record_cache'
KEY_RECORD_OWNER_CACHE = 'record_owner_cache'
KEY_TITLE = 'title'

KEY_RESTRICT_EDIT = 'restrict_edit'
KEY_RESTRICT_SHARING = 'restrict_sharing'
KEY_RESTRICT_VIEW = 'restrict_view'
KEY_RESTRICT_SHARING_ALL = 'restrict_sharing_all'

PERMISSION_EDIT = 'edit'
PERMISSION_SHARE = 'share'
PERMISSION_VIEW = 'view'

TEXT_EDIT = 'Edit'
TEXT_SHARE = 'Share'
TEXT_READ_ONLY = 'Read Only'
TEXT_LAUNCH_ONLY = 'Launch Only'
TEXT_CAN_PREFIX = 'Can '
TEXT_TEAM_PREFIX = '(Team)'
TEXT_TEAM_USER_PREFIX = '(Team User)'

USER_TYPE_INACTIVE = 2 

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
        for member in self.team_members.values():
            member.apply_restrictions(*restrictions)
        restrictions = ','.join(restrictions).lower()
        if PERMISSION_EDIT in restrictions:
            self.can_edit = False
        if PERMISSION_SHARE in restrictions:
            self.can_share = False
        if PERMISSION_VIEW in restrictions:
            self.can_view = False


class SharedRecord:
    """Defines a Keeper Shared Record (shared either via Direct-Share or as a child of a Shared-Folder node)"""

    def __init__(self, params, record, sf_sharing_admins=None, team_members=None, role_restricted_members=None):
        self.params = params
        self.record = record
        self.uid = getattr(record, KEY_RECORD_UID, getattr(record, KEY_UID, ''))
        
        has_owner = hasattr(params, KEY_RECORD_OWNER_CACHE) and self.uid in params.record_owner_cache
        user_owned = has_owner and params.record_owner_cache.get(self.uid).owner
        self.owner = getattr(params, 'user', '') if user_owned else ''
        if not self.owner:
            self.owner = params.auth.auth_context.username if params.auth and params.auth.auth_context else ''
        
        self.name = getattr(record, KEY_TITLE, '')
        self.shared_folders = None
        self.sf_shares = {}
        self.permissions: Dict[str, SharePermissions] = {}
        self.team_permissions: Dict[str, SharePermissions] = {}
        self.user_permissions: Dict[str, SharePermissions] = {}
        self.revision = None
        self.folder_uids = []
        self.folder_paths = []
        try:
            from keepersdk.vault import vault_utils
            if hasattr(params, KEY_VAULT) and params.vault and hasattr(params.vault, KEY_VAULT_DATA):
                folders = vault_utils.get_folders_for_record(params.vault.vault_data, self.uid)
                self.folder_uids = [f.folder_uid for f in folders]
        except Exception:
            pass
        self.team_members = team_members or {}

        if sf_sharing_admins is None:
            sf_sharing_admins = {}
        if role_restricted_members is None:
            role_restricted_members = set()

        self.load(params, sf_sharing_admins, team_members, role_restricted_members)

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
        def apply_team_restrictions(team_perms):
            if not hasattr(params, KEY_ENTERPRISE) or not params.enterprise:
                return team_perms

            restriction_permission_lookup = {
                KEY_RESTRICT_EDIT: KEY_MANAGE_RECORDS,
                KEY_RESTRICT_SHARING: KEY_MANAGE_USERS,
                KEY_RESTRICT_VIEW: KEY_VIEW
            }

            teams_cache = params.enterprise.get(KEY_TEAMS, {})
            perms = team_perms.copy()
            team_info = next((t for t in teams_cache if t.get(KEY_TEAM_UID) == perms.get(KEY_TEAM_UID)), {})
            for restriction, permission in restriction_permission_lookup.items():
                if team_info.get(restriction):
                    perms[permission] = False
            return perms

        def apply_role_restrictions():
            for restricted_target in role_restricted_members:
                perms = self.permissions.get(restricted_target)
                if perms:
                    perms.apply_restrictions(PERMISSION_SHARE)

        def update_sf_shares(share_to, sf_uid):
            if sf_uid:
                sf_shares = self.sf_shares.get(sf_uid, set())
                sf_shares.add(share_to)
                self.sf_shares[sf_uid] = sf_shares

        def load_user_permissions(u_perms, sf_uid=None, sp_type=None):
            for up in u_perms:
                if isinstance(up, dict):
                    email = up.get(KEY_USERNAME)
                    if not email:
                        continue
                    update_sf_shares(email, sf_uid)
                    share_admins = sf_sharing_admins.get(sf_uid, [])
                    is_admin = share_admins and email in share_admins
                    if is_admin:
                        up[KEY_EDITABLE] = True
                        up[KEY_SHAREABLE] = True
                        up[KEY_SHARE_ADMIN] = True
                    self.merge_user_permissions(email, up, sp_type)
                else:
                    email = getattr(up, KEY_NAME, '')
                    if not email:
                        continue
                    update_sf_shares(email, sf_uid)
                    share_admins = sf_sharing_admins.get(sf_uid, [])
                    is_admin = share_admins and email in share_admins
                    
                    up_dict = {
                        KEY_USERNAME: email,
                        KEY_EDITABLE: getattr(up, KEY_MANAGE_RECORDS, False) if sp_type == SharePermissions.SharePermissionsType.SF_USER else getattr(up, KEY_EDITABLE, False),
                        KEY_SHAREABLE: getattr(up, KEY_MANAGE_USERS, False) if sp_type == SharePermissions.SharePermissionsType.SF_USER else getattr(up, KEY_SHAREABLE, False),
                        KEY_SHARE_ADMIN: is_admin,
                        KEY_EXPIRATION: getattr(up, KEY_EXPIRATION, 0)
                    }
                    if is_admin:
                        up_dict[KEY_EDITABLE] = True
                        up_dict[KEY_SHAREABLE] = True
                        up_dict[KEY_SHARE_ADMIN] = True
                    self.merge_user_permissions(email, up_dict, sp_type)

        def load_team_permissions(t_perms, sf_uid):
            for tp in t_perms:
                # Handle both dict and object types
                if isinstance(tp, dict):
                    team_uid = tp.get(KEY_TEAM_UID)
                    team_name = tp.get(KEY_NAME)
                    if not team_uid:
                        continue
                    update_sf_shares(team_name, sf_uid)
                    tp = apply_team_restrictions(tp)
                    merged = self.merge_team_permissions(team_uid, tp)

                    t_users = team_members.get(team_uid, set()) if team_members else set()
                    ups = [{**tp, KEY_USERNAME: t_username} for t_username in t_users]
                    load_user_permissions(ups, sf_uid, SharePermissions.SharePermissionsType.TEAM_USER)
                    if merged:
                        merged.team_members.update({t_username: self.permissions.get(t_username) for t_username in t_users})
                else:
                    team_uid = getattr(tp, KEY_TEAM_UID, '')
                    team_name = getattr(tp, KEY_NAME, '')
                    if not team_uid:
                        continue
                    update_sf_shares(team_name, sf_uid)
                    
                    tp_dict = {
                        KEY_TEAM_UID: team_uid,
                        KEY_NAME: team_name,
                        KEY_MANAGE_RECORDS: getattr(tp, KEY_MANAGE_RECORDS, False),
                        KEY_MANAGE_USERS: getattr(tp, KEY_MANAGE_USERS, False),
                        KEY_EXPIRATION: getattr(tp, KEY_EXPIRATION, 0)
                    }
                    tp_dict = apply_team_restrictions(tp_dict)
                    merged = self.merge_team_permissions(team_uid, tp_dict)

                    t_users = team_members.get(team_uid, set()) if team_members else set()
                    ups = [{**tp_dict, KEY_USERNAME: t_username} for t_username in t_users]
                    load_user_permissions(ups, sf_uid, SharePermissions.SharePermissionsType.TEAM_USER)
                    if merged:
                        merged.team_members.update({t_username: self.permissions.get(t_username) for t_username in t_users})

        shares = {}
        if share_info:
            shares = share_info.get(KEY_SHARES, {})
        else:
            try:
                if hasattr(params, KEY_RECORD_CACHE) and self.uid in params.record_cache:
                    rec_cached = params.record_cache.get(self.uid, {})
                    shares = rec_cached.get(KEY_SHARES, {})
            except Exception:
                pass

        user_perms = list(shares.get(KEY_USER_PERMISSIONS, []))
        if len(user_perms) > 0:
            owner_user = next((up.get(KEY_USERNAME) for up in user_perms if up.get(KEY_OWNER)), '')
            if owner_user:
                self.owner = owner_user
            load_user_permissions(user_perms)

        sf_perms = shares.get(KEY_SHARED_FOLDER_PERMISSIONS, [])
        SF_UID = KEY_SHARED_FOLDER_UID
        sf_cache = getattr(params, KEY_SHARED_FOLDER_CACHE, {})
        shared_folders = {sfp.get(SF_UID): sf_cache.get(sfp.get(SF_UID)) for sfp in sf_perms}
        shared_folders = {k: v for k, v in shared_folders.items() if v}

        shared_folder_found = False
        if hasattr(params, KEY_VAULT) and params.vault and hasattr(params.vault, KEY_VAULT_DATA):
            try:
                for folder_uid in self.folder_uids:
                    folder = params.vault.vault_data.get_folder(folder_uid)
                    if folder and folder.folder_type == 'shared_folder':
                        shared_folder_found = True
                        self.permissions.clear()
                        self.user_permissions.clear()
                        self.team_permissions.clear()
                        
                        sf = params.vault.vault_data.load_shared_folder(shared_folder_uid=folder_uid)
                        if sf:
                            if sf.user_permissions:
                                load_user_permissions(sf.user_permissions, folder_uid, SharePermissions.SharePermissionsType.SF_USER)
                            if sf.team_permissions:
                                load_team_permissions(sf.team_permissions, folder_uid)
                    elif folder and folder.folder_type == 'shared_folder_folder':
                        if folder.folder_scope_uid:
                            shared_folder_found = True
                            self.permissions.clear()
                            self.user_permissions.clear()
                            self.team_permissions.clear()
                            
                            sf = params.vault.vault_data.load_shared_folder(shared_folder_uid=folder.folder_scope_uid)
                            if sf:
                                if sf.user_permissions:
                                    load_user_permissions(sf.user_permissions, folder.folder_scope_uid, SharePermissions.SharePermissionsType.SF_USER)
                                if sf.team_permissions:
                                    load_team_permissions(sf.team_permissions, folder.folder_scope_uid)
            except Exception:
                pass

        if not shared_folder_found:
            if shared_folders:
                self.permissions.clear()
                self.user_permissions.clear()
                self.team_permissions.clear()

            sf_user_perms = {sf_uid: sf.get(KEY_USERS, []) for sf_uid, sf in shared_folders.items() if sf.get(KEY_USERS)}
            team_perms = {sf_uid: sf.get(KEY_TEAMS, []) for sf_uid, sf in shared_folders.items() if sf.get(KEY_TEAMS)}

            for sf_uid, sf_ups in sf_user_perms.items():
                share_type = SharePermissions.SharePermissionsType.SF_USER
                load_user_permissions(sf_ups, sf_uid, share_type)
            for sf_uid, teams in team_perms.items():
                load_team_permissions(teams, sf_uid)

        apply_role_restrictions()
        


def get_shared_records(params, record_uids, cache_only=False):
    """Get shared records information with enterprise features"""

    def get_cached_team_members(t_uids, uname_lookup):
        members = {}
        if not hasattr(params, KEY_ENTERPRISE) or not params.enterprise:
            return members

        try:
            team_users = params.enterprise.get(KEY_TEAM_USERS) or []
            team_users = [tu for tu in team_users if tu.get(KEY_USER_TYPE) != USER_TYPE_INACTIVE and tu.get(KEY_TEAM_UID) in t_uids]

            for tu in team_users:
                user_id = tu.get(KEY_ENTERPRISE_USER_ID)
                username = uname_lookup.get(user_id)
                team_uid = tu.get(KEY_TEAM_UID)
                t_members = members.get(team_uid, set())
                t_members.add(username)
                members[team_uid] = t_members
        except Exception:
            pass

        return members

    def fetch_sf_admins():
        sf_admins = {}
        try:
            if hasattr(params, KEY_SHARED_FOLDER_CACHE):
                sf_uids = [uid for uid in params.shared_folder_cache]
                for sf_uid in sf_uids:
                    sf_admins[sf_uid] = []
        except Exception:
            pass
        return sf_admins

    def get_restricted_role_members(uname_lookup):
        members = set()
        if not hasattr(params, KEY_ENTERPRISE) or not params.enterprise:
            return members

        try:
            restrict_key = KEY_RESTRICT_SHARING_ALL
            enf_key = KEY_ENFORCEMENTS
            r_enforcements = params.enterprise.get(KEY_ROLE_ENFORCEMENTS, [])
            no_share_roles = {re.get(KEY_ROLE_ID) for re in r_enforcements if re.get(enf_key, {}).get(restrict_key) == 'true'}
            r_users = [u for u in params.enterprise.get(KEY_ROLE_USERS, []) if u.get(KEY_ROLE_ID) in no_share_roles]
            r_teams = [t for t in params.enterprise.get(KEY_ROLE_TEAMS, []) if t.get(KEY_ROLE_ID) in no_share_roles]
            no_share_users = {uname_lookup.get(u.get(KEY_ENTERPRISE_USER_ID)) for u in r_users}
            no_share_teams = {t.get(KEY_TEAM_UID) for t in r_teams}
            cached_team_members = get_cached_team_members(no_share_teams, uname_lookup)
            no_share_team_members = {t for team_uid in no_share_teams for t in cached_team_members.get(team_uid, set())}
            members = no_share_users.union(no_share_teams).union(no_share_team_members)
        except Exception:
            pass
        return members

    share_infos = []
    try:
        from ..helpers import share_utils
        share_infos = share_utils.get_record_shares(vault=params.vault, record_uids=record_uids) or []
    except Exception as e:
        pass

    try:
        if hasattr(params, KEY_VAULT) and params.vault and hasattr(params.vault, KEY_VAULT_DATA):
            if not hasattr(params, KEY_SHARED_FOLDER_CACHE) or not params.shared_folder_cache:
                params.shared_folder_cache = {}
                for sf_info in params.vault.vault_data.shared_folders():
                    sf_uid = sf_info.shared_folder_uid
                    try:
                        sf = params.vault.vault_data.load_shared_folder(shared_folder_uid=sf_uid)
                        if sf:
                            params.shared_folder_cache[sf_uid] = {
                                KEY_USERS: sf.user_permissions or [],
                                KEY_TEAMS: sf.team_permissions or [],
                                KEY_NAME: sf.name
                            }
                    except Exception:
                        pass
    except Exception:
        pass

    sf_teams = []
    try:
        if hasattr(params, KEY_SHARED_FOLDER_CACHE):
            sf_teams = [shared_folder.get(KEY_TEAMS, []) for shared_folder in params.shared_folder_cache.values()]
    except Exception:
        pass

    sf_share_admins = fetch_sf_admins() if not cache_only else {}
    team_uids = {t.get(KEY_TEAM_UID) for teams in sf_teams for t in teams}
    
    enterprise_users = []
    try:
        if hasattr(params, KEY_ENTERPRISE) and params.enterprise:
            enterprise_users = params.enterprise.get(KEY_USERS, [])
    except Exception:
        pass
    
    username_lookup = {u.get(KEY_ENTERPRISE_USER_ID): u.get(KEY_USERNAME) for u in enterprise_users}
    restricted_role_members = get_restricted_role_members(username_lookup)
    team_members = get_cached_team_members(team_uids, username_lookup)
    
    records = []
    try:
        records = [params.vault.vault_data.load_record(uid) for uid in record_uids]
        records = [r for r in records if r]
    except Exception:
        records = []
        for uid in record_uids:
            try:
                record = params.vault.vault_data.load_record(uid)
                if record:
                    records.append(record)
            except Exception:
                pass
    
    shared_records = []
    for r in records:
        try:
            uid = getattr(r, KEY_RECORD_UID, getattr(r, KEY_UID, ''))
            record_share_info = None
            for share_info in share_infos:
                if share_info.get(KEY_RECORD_UID) == uid:
                    record_share_info = share_info
                    break
            
            shared_record = SharedRecord(params, r, sf_share_admins, team_members, restricted_role_members)
            if record_share_info:
                shared_record.load(params, sf_share_admins, team_members, restricted_role_members, record_share_info)
            shared_records.append(shared_record)
        except Exception:
            uid = getattr(r, KEY_RECORD_UID, getattr(r, KEY_UID, ''))
            if uid:
                shared_record = SharedRecord(params, r, sf_share_admins, team_members, restricted_role_members)
                shared_records.append(shared_record)
    
    return {shared_record.uid: shared_record for shared_record in shared_records}
