from enum import Enum
from typing import Dict


class SharePermissions:
    SharePermissionsType = Enum('SharePermissionsType', ['USER', 'SF_USER', 'TEAM', 'TEAM_USER'])
    bits_text_lookup = {(1 << 0): 'Edit', (1 << 1): 'Share'}

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
        
        # Handle legacy types parameter
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
            SharePermissions.SharePermissionsType.TEAM: '(Team)',
            SharePermissions.SharePermissionsType.TEAM_USER: '(Team User)',
            SharePermissions.SharePermissionsType.USER: '',
            SharePermissions.SharePermissionsType.SF_USER: ''
        }
        prefix = ''.join(prefix_lookup.get(t) for t in self.types)
        return f'{prefix} {self.to_name}'.strip()

    @property
    def permissions_text_property(self):
        if not self.can_edit and not self.can_share:
            return 'Read Only' if self.can_view else 'Launch Only'
        else:
            privs = [self.can_share and 'Share', self.can_edit and 'Edit']
            return f'Can {" & ".join([p for p in privs if p])}'

    @staticmethod
    def load_permissions(perms, sp_type):
        sp = SharePermissions(sp_type)
        sp.to_uid = perms.get('uid') or perms.get('team_uid')
        sp.to_name = perms.get('username') or perms.get('name')
        sp.is_admin = perms.get('share_admin') or perms.get('is_admin')
        sp.can_edit = perms.get('editable') or perms.get('manage_records') or sp.is_admin
        sp.can_share = perms.get('shareable') or perms.get('manage_users') or sp.is_admin
        sp.can_view = perms.get('view', True)
        exp = perms.get('expiration')
        if isinstance(exp, int) and exp > 0:
            sp.expiration = exp
        return sp

    def apply_restrictions(self, *restrictions):
        for member in self.team_members.values():
            member.apply_restrictions(*restrictions)
        restrictions = ','.join(restrictions).lower()
        if 'edit' in restrictions:
            self.can_edit = False
        if 'share' in restrictions:
            self.can_share = False
        if 'view' in restrictions:
            self.can_view = False


class SharedRecord:
    """Defines a Keeper Shared Record (shared either via Direct-Share or as a child of a Shared-Folder node)"""

    def __init__(self, params, record, sf_sharing_admins=None, team_members=None, role_restricted_members=None):
        self.params = params
        self.record = record
        self.uid = getattr(record, 'record_uid', getattr(record, 'uid', ''))
        
        # Initialize owner
        has_owner = hasattr(params, 'record_owner_cache') and self.uid in params.record_owner_cache
        user_owned = has_owner and params.record_owner_cache.get(self.uid).owner
        self.owner = getattr(params, 'user', '') if user_owned else ''
        if not self.owner:
            self.owner = params.auth.auth_context.username if params.auth and params.auth.auth_context else ''
        
        self.name = getattr(record, 'title', '')
        self.shared_folders = None
        self.sf_shares = {}
        self.permissions: Dict[str, SharePermissions] = {}
        self.team_permissions: Dict[str, SharePermissions] = {}
        self.user_permissions: Dict[str, SharePermissions] = {}
        self.revision = None
        self.folder_uids = []
        self.folder_paths = []
        try:
            if hasattr(params, 'vault') and params.vault and hasattr(params.vault, 'vault_data'):
                from keepersdk.vault import vault_utils
                folders = vault_utils.get_folders_for_record(params.vault.vault_data, self.uid)
                self.folder_uids = [f.folder_uid for f in folders]
                print(f"DEBUG: Record {self.uid} is in folders: {self.folder_uids}")
        except Exception as e:
            print(f"DEBUG: Error getting folders for record {self.uid}: {e}")
            pass
        self.team_members = team_members or {}

        # Initialize with default values if parameters are None
        if sf_sharing_admins is None:
            sf_sharing_admins = {}
        if role_restricted_members is None:
            role_restricted_members = set()

        self.load(params, sf_sharing_admins, team_members, role_restricted_members)

    def get_ordered_permissions(self):
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
        print(f"DEBUG: Added permission for {share_target}: {existing.to_name} (types: {existing.types})")
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
            if not hasattr(params, 'enterprise') or not params.enterprise:
                return team_perms

            restriction_permission_lookup = {
                'restrict_edit': 'manage_records',
                'restrict_sharing': 'manage_users',
                'restrict_view': 'view'
            }

            teams_cache = params.enterprise.get('teams', {})
            perms = team_perms.copy()
            team_info = next((t for t in teams_cache if t.get('team_uid') == perms.get('team_uid')), {})
            for restriction, permission in restriction_permission_lookup.items():
                if team_info.get(restriction):
                    perms[permission] = False
            return perms

        def apply_role_restrictions():
            for restricted_target in role_restricted_members:
                perms = self.permissions.get(restricted_target)
                if perms:
                    perms.apply_restrictions('share')

        def update_sf_shares(share_to, sf_uid):
            if sf_uid:
                sf_shares = self.sf_shares.get(sf_uid, set())
                sf_shares.add(share_to)
                self.sf_shares[sf_uid] = sf_shares

        def load_user_permissions(u_perms, sf_uid=None, sp_type=None):
            for up in u_perms:
                # Handle both dict and object types
                if isinstance(up, dict):
                    email = up.get('username')
                    if not email:
                        continue
                    update_sf_shares(email, sf_uid)
                    share_admins = sf_sharing_admins.get(sf_uid, [])
                    is_admin = share_admins and email in share_admins
                    if is_admin:
                        up['editable'] = True
                        up['shareable'] = True
                        up['share_admin'] = True
                    self.merge_user_permissions(email, up, sp_type)
                else:
                    # Handle object types (like SharedFolderPermission)
                    email = getattr(up, 'name', '')
                    if not email:
                        continue
                    update_sf_shares(email, sf_uid)
                    share_admins = sf_sharing_admins.get(sf_uid, [])
                    is_admin = share_admins and email in share_admins
                    
                    # Convert object to dict format
                    up_dict = {
                        'username': email,
                        'editable': getattr(up, 'manage_records', False) if sp_type == SharePermissions.SharePermissionsType.SF_USER else getattr(up, 'editable', False),
                        'shareable': getattr(up, 'manage_users', False) if sp_type == SharePermissions.SharePermissionsType.SF_USER else getattr(up, 'shareable', False),
                        'share_admin': is_admin,
                        'expiration': getattr(up, 'expiration', 0)
                    }
                    if is_admin:
                        up_dict['editable'] = True
                        up_dict['shareable'] = True
                        up_dict['share_admin'] = True
                    print(f"DEBUG: Processing SF permission for {email}: {up_dict}")
                    self.merge_user_permissions(email, up_dict, sp_type)

        def load_team_permissions(t_perms, sf_uid):
            for tp in t_perms:
                # Handle both dict and object types
                if isinstance(tp, dict):
                    team_uid = tp.get('team_uid')
                    team_name = tp.get('name')
                    if not team_uid:
                        continue
                    update_sf_shares(team_name, sf_uid)
                    tp = apply_team_restrictions(tp)
                    merged = self.merge_team_permissions(team_uid, tp)

                    # load team-members' permissions
                    t_users = team_members.get(team_uid, set()) if team_members else set()
                    ups = [{**tp, 'username': t_username} for t_username in t_users]
                    load_user_permissions(ups, sf_uid, SharePermissions.SharePermissionsType.TEAM_USER)
                    if merged:
                        merged.team_members.update({t_username: self.permissions.get(t_username) for t_username in t_users})
                else:
                    # Handle object types (like SharedFolderTeamPermission)
                    team_uid = getattr(tp, 'team_uid', '')
                    team_name = getattr(tp, 'name', '')
                    if not team_uid:
                        continue
                    update_sf_shares(team_name, sf_uid)
                    
                    # Convert object to dict format
                    tp_dict = {
                        'team_uid': team_uid,
                        'name': team_name,
                        'manage_records': getattr(tp, 'manage_records', False),
                        'manage_users': getattr(tp, 'manage_users', False),
                        'expiration': getattr(tp, 'expiration', 0)
                    }
                    tp_dict = apply_team_restrictions(tp_dict)
                    merged = self.merge_team_permissions(team_uid, tp_dict)

                    # load team-members' permissions
                    t_users = team_members.get(team_uid, set()) if team_members else set()
                    ups = [{**tp_dict, 'username': t_username} for t_username in t_users]
                    load_user_permissions(ups, sf_uid, SharePermissions.SharePermissionsType.TEAM_USER)
                    if merged:
                        merged.team_members.update({t_username: self.permissions.get(t_username) for t_username in t_users})

        # Use provided share_info or try to get from record cache
        shares = {}
        if share_info:
            shares = share_info.get('shares', {})
        else:
            # Fallback to record cache
            try:
                if hasattr(params, 'record_cache') and self.uid in params.record_cache:
                    rec_cached = params.record_cache.get(self.uid, {})
                    shares = rec_cached.get('shares', {})
            except Exception:
                pass

        user_perms = list(shares.get('user_permissions', []))
        if len(user_perms) > 0:
            owner_user = next((up.get('username') for up in user_perms if up.get('owner')), '')
            if owner_user:
                self.owner = owner_user
            load_user_permissions(user_perms)

        sf_perms = shares.get('shared_folder_permissions', [])
        SF_UID = 'shared_folder_uid'
        sf_cache = getattr(params, 'shared_folder_cache', {})
        shared_folders = {sfp.get(SF_UID): sf_cache.get(sfp.get(SF_UID)) for sfp in sf_perms}
        shared_folders = {k: v for k, v in shared_folders.items() if v}

        # Always check if record is in any shared folders via folder structure first
        shared_folder_found = False
        if hasattr(params, 'vault') and params.vault and hasattr(params.vault, 'vault_data'):
            try:
                print(f"DEBUG: Checking folder structure for record {self.uid}, folder_uids: {self.folder_uids}")
                # Check if record is in any shared folders by examining folder structure
                for folder_uid in self.folder_uids:
                    folder = params.vault.vault_data.get_folder(folder_uid)
                    print(f"DEBUG: Folder {folder_uid}: type={getattr(folder, 'folder_type', 'unknown') if folder else 'None'}")
                    if folder and folder.folder_type == 'shared_folder':
                        print(f"DEBUG: Record {self.uid} is in shared folder {folder_uid} via folder structure")
                        shared_folder_found = True
                        # Clear direct record permissions and use shared folder permissions instead
                        print(f"DEBUG: Clearing permissions for record {self.uid} (was in shared folder {folder_uid})")
                        self.permissions.clear()
                        self.user_permissions.clear()
                        self.team_permissions.clear()
                        
                        # Load shared folder permissions
                        sf = params.vault.vault_data.load_shared_folder(shared_folder_uid=folder_uid)
                        if sf:
                            print(f"DEBUG: Loaded shared folder {folder_uid}: name={sf.name}")
                            if sf.user_permissions:
                                print(f"DEBUG: Loading {len(sf.user_permissions)} user permissions from shared folder {folder_uid}")
                                for up in sf.user_permissions:
                                    print(f"DEBUG: SF user permission: {up.name} (manage_records: {up.manage_records}, manage_users: {up.manage_users})")
                                load_user_permissions(sf.user_permissions, folder_uid, SharePermissions.SharePermissionsType.SF_USER)
                            if sf.team_permissions:
                                print(f"DEBUG: Loading {len(sf.team_permissions)} team permissions from shared folder {folder_uid}")
                                for tp in sf.team_permissions:
                                    print(f"DEBUG: SF team permission: {tp.team_uid} (manage_records: {tp.manage_records}, manage_users: {tp.manage_users})")
                                load_team_permissions(sf.team_permissions, folder_uid)
                        else:
                            print(f"DEBUG: Failed to load shared folder {folder_uid}")
                    elif folder and folder.folder_type == 'shared_folder_folder':
                        # Check if this is a subfolder of a shared folder
                        print(f"DEBUG: Record {self.uid} is in shared folder subfolder {folder_uid}")
                        if folder.folder_scope_uid:
                            print(f"DEBUG: Subfolder scope UID: {folder.folder_scope_uid}")
                            shared_folder_found = True
                            # Clear direct record permissions and use shared folder permissions instead
                            print(f"DEBUG: Clearing permissions for record {self.uid} (was in shared folder subfolder {folder_uid})")
                            self.permissions.clear()
                            self.user_permissions.clear()
                            self.team_permissions.clear()
                            
                            # Load parent shared folder permissions
                            sf = params.vault.vault_data.load_shared_folder(shared_folder_uid=folder.folder_scope_uid)
                            if sf:
                                print(f"DEBUG: Loaded parent shared folder {folder.folder_scope_uid}: name={sf.name}")
                                if sf.user_permissions:
                                    print(f"DEBUG: Loading {len(sf.user_permissions)} user permissions from parent shared folder {folder.folder_scope_uid}")
                                    for up in sf.user_permissions:
                                        print(f"DEBUG: SF user permission: {up.name} (manage_records: {up.manage_records}, manage_users: {up.manage_users})")
                                    load_user_permissions(sf.user_permissions, folder.folder_scope_uid, SharePermissions.SharePermissionsType.SF_USER)
                                if sf.team_permissions:
                                    print(f"DEBUG: Loading {len(sf.team_permissions)} team permissions from parent shared folder {folder.folder_scope_uid}")
                                    for tp in sf.team_permissions:
                                        print(f"DEBUG: SF team permission: {tp.team_uid} (manage_records: {tp.manage_records}, manage_users: {tp.manage_users})")
                                    load_team_permissions(sf.team_permissions, folder.folder_scope_uid)
                            else:
                                print(f"DEBUG: Failed to load parent shared folder {folder.folder_scope_uid}")
            except Exception as e:
                print(f"DEBUG: Error checking folder structure: {e}")
                pass

        # If no shared folder found via folder structure, check via share_info
        if not shared_folder_found:
            print(f"DEBUG: No shared folder found via folder structure, checking share_info")
            if shared_folders:
                print(f"DEBUG: Record {self.uid} is in {len(shared_folders)} shared folders via share_info")
                # Clear direct record permissions and use shared folder permissions instead
                self.permissions.clear()
                self.user_permissions.clear()
                self.team_permissions.clear()

            sf_user_perms = {sf_uid: sf.get('users', []) for sf_uid, sf in shared_folders.items() if sf.get('users')}
            team_perms = {sf_uid: sf.get('teams', []) for sf_uid, sf in shared_folders.items() if sf.get('teams')}

            for sf_uid, sf_ups in sf_user_perms.items():
                share_type = SharePermissions.SharePermissionsType.SF_USER
                print(f"DEBUG: Loading {len(sf_ups)} user permissions from shared folder {sf_uid}")
                load_user_permissions(sf_ups, sf_uid, share_type)
            for sf_uid, teams in team_perms.items():
                print(f"DEBUG: Loading {len(teams)} team permissions from shared folder {sf_uid}")
                load_team_permissions(teams, sf_uid)
        else:
            print(f"DEBUG: Shared folder found via folder structure, skipping share_info processing")

        apply_role_restrictions()
        
        # Final debug: show all permissions
        print(f"DEBUG: Final permissions for record {self.uid}: {list(self.permissions.keys())}")
        for key, perm in self.permissions.items():
            print(f"DEBUG: Final permission {key}: {perm.to_name} (types: {perm.types})")


def get_shared_records(params, record_uids, cache_only=False):
    """Get shared records information with enterprise features"""
    
    def fetch_team_members(t_uids):
        members = {}
        # Skip enterprise team fetching if not available
        if not hasattr(params, 'enterprise_ec_key') or not params.enterprise_ec_key:
            return members
            
        try:
            for team_uid in t_uids:
                team_users = members.get(team_uid, set())
                # Use vault's execute_auth_rest if available
                if hasattr(params.vault, 'keeper_auth'):
                    # Simplified team member fetching - skip if protobuf not available
                    pass
                members[team_uid] = team_users
        except Exception:
            # If enterprise features fail, return empty members
            pass
        return members

    def get_cached_team_members(t_uids, uname_lookup):
        members = {}
        if not hasattr(params, 'enterprise') or not params.enterprise:
            return members

        try:
            team_users = params.enterprise.get('team_users') or []
            team_users = [tu for tu in team_users if tu.get('user_type') != 2 and tu.get('team_uid') in t_uids]

            for tu in team_users:
                user_id = tu.get('enterprise_user_id')
                username = uname_lookup.get(user_id)
                team_uid = tu.get('team_uid')
                t_members = members.get(team_uid, set())
                t_members.add(username)
                members[team_uid] = t_members
        except Exception:
            # If enterprise data access fails, return empty members
            pass

        return members

    def fetch_sf_admins():
        sf_admins = {}
        try:
            if hasattr(params, 'shared_folder_cache'):
                sf_uids = [uid for uid in params.shared_folder_cache]
                # Skip if API function not available
                for sf_uid in sf_uids:
                    sf_admins[sf_uid] = []
        except Exception:
            # If shared folder admin fetching fails, return empty
            pass
        return sf_admins

    def get_restricted_role_members(uname_lookup):
        # Get team_uids and usernames (assigned directly and indirectly) in share-restricted roles
        members = set()
        if not hasattr(params, 'enterprise') or not params.enterprise:
            return members

        try:
            restrict_key = 'restrict_sharing_all'
            enf_key = 'enforcements'
            r_enforcements = params.enterprise.get('role_enforcements', [])
            no_share_roles = {re.get('role_id') for re in r_enforcements if re.get(enf_key, {}).get(restrict_key) == 'true'}
            r_users = [u for u in params.enterprise.get('role_users', []) if u.get('role_id') in no_share_roles]
            r_teams = [t for t in params.enterprise.get('role_teams', []) if t.get('role_id') in no_share_roles]
            no_share_users = {uname_lookup.get(u.get('enterprise_user_id')) for u in r_users}
            no_share_teams = {t.get('team_uid') for t in r_teams}
            cached_team_members = get_cached_team_members(no_share_teams, uname_lookup)
            no_share_team_members = {t for team_uid in no_share_teams for t in cached_team_members.get(team_uid, set())}
            members = no_share_users.union(no_share_teams).union(no_share_team_members)
        except Exception:
            # If role restriction logic fails, return empty set
            pass
        return members

    # Load record shares using share_utils
    share_infos = []
    try:
        from ..helpers import share_utils
        share_infos = share_utils.get_record_shares(vault=params.vault, record_uids=record_uids) or []
        print(f"DEBUG: Loaded {len(share_infos)} share infos")
        for share_info in share_infos:
            record_uid = share_info.get('record_uid')
            shares = share_info.get('shares', {})
            user_perms = shares.get('user_permissions', [])
            print(f"DEBUG: Record {record_uid} has {len(user_perms)} user permissions in share_info")
            for up in user_perms:
                print(f"DEBUG: Share permission: {up.get('username')} (owner: {up.get('owner')})")
    except Exception as e:
        print(f"DEBUG: Error loading share infos: {e}")
        pass

    # Ensure shared folder cache is populated
    try:
        if hasattr(params, 'vault') and params.vault and hasattr(params.vault, 'vault_data'):
            # Load shared folders if not already cached
            if not hasattr(params, 'shared_folder_cache') or not params.shared_folder_cache:
                params.shared_folder_cache = {}
                for sf_info in params.vault.vault_data.shared_folders():
                    sf_uid = sf_info.shared_folder_uid
                    try:
                        sf = params.vault.vault_data.load_shared_folder(shared_folder_uid=sf_uid)
                        if sf:
                            params.shared_folder_cache[sf_uid] = {
                                'users': sf.user_permissions or [],
                                'teams': sf.team_permissions or [],
                                'name': sf.name
                            }
                    except Exception:
                        pass
    except Exception:
        pass

    # Get shared folder teams
    sf_teams = []
    try:
        if hasattr(params, 'shared_folder_cache'):
            sf_teams = [shared_folder.get('teams', []) for shared_folder in params.shared_folder_cache.values()]
    except Exception:
        pass

    sf_share_admins = fetch_sf_admins() if not cache_only else {}
    team_uids = {t.get('team_uid') for teams in sf_teams for t in teams}
    
    # Get enterprise users
    enterprise_users = []
    try:
        if hasattr(params, 'enterprise') and params.enterprise:
            enterprise_users = params.enterprise.get('users', [])
    except Exception:
        pass
    
    username_lookup = {u.get('enterprise_user_id'): u.get('username') for u in enterprise_users}
    restricted_role_members = get_restricted_role_members(username_lookup)
    team_members = get_cached_team_members(team_uids, username_lookup) if cache_only or hasattr(params, 'enterprise') \
        else fetch_team_members(team_uids)
    
    # Get records
    records = []
    try:
        # Use vault data loading directly
        records = [params.vault.vault_data.load_record(uid) for uid in record_uids]
        records = [r for r in records if r]
    except Exception:
        # If record loading fails, create minimal records
        records = []
        for uid in record_uids:
            try:
                record = params.vault.vault_data.load_record(uid)
                if record:
                    records.append(record)
            except Exception:
                pass
    
    # Create SharedRecord objects
    shared_records = []
    for r in records:
        try:
            uid = getattr(r, 'record_uid', getattr(r, 'uid', ''))
            # Find share info for this record
            record_share_info = None
            for share_info in share_infos:
                if share_info.get('record_uid') == uid:
                    record_share_info = share_info
                    break
            
            shared_record = SharedRecord(params, r, sf_share_admins, team_members, restricted_role_members)
            # Load share information if available
            if record_share_info:
                shared_record.load(params, sf_share_admins, team_members, restricted_role_members, record_share_info)
            shared_records.append(shared_record)
        except Exception:
            # If SharedRecord creation fails, create minimal one
            uid = getattr(r, 'record_uid', getattr(r, 'uid', ''))
            if uid:
                shared_record = SharedRecord(params, r, sf_share_admins, team_members, restricted_role_members)
                shared_records.append(shared_record)
    
    return {shared_record.uid: shared_record for shared_record in shared_records}
