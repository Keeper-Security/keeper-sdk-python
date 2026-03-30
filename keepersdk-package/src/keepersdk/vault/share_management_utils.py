import datetime
import itertools
import logging
from re import findall
from typing import Optional, Dict, List, Any, Generator, Iterable, Set, Tuple, Union

from .. import crypto, utils
from ..proto import enterprise_pb2, record_pb2
from ..vault import vault_online, vault_record, vault_types, vault_utils
from ..enterprise import enterprise_data


TIMEOUT_DEFAULT_UNIT = 'minutes'
TIMEOUT_ALLOWED_UNITS = ('days', 'hours', 'minutes')

# API Endpoints
RECORD_DETAILS_URL = 'vault/get_records_details'
SHARE_OBJECTS_API = 'vault/get_share_objects'
TEAM_MEMBERS_ENDPOINT = 'vault/get_team_members'
SHARING_ADMINS_ENDPOINT = 'enterprise/get_sharing_admins'

# Record Processing Constants
CHUNK_SIZE = 999
RECORD_KEY_LENGTH_V2 = 60
DEFAULT_EXPIRATION = 0
NEVER_EXPIRES = -1

# Record Version Constants
MAX_V2_VERSION = 2
V3_VERSION = 3
V4_VERSION = 4

# User Type Constants
TEAM_USER_TYPE = 2
USER_TYPE_INACTIVE = 2

# Permission Field Names
CAN_SHARE = 'can_share'
CAN_EDIT = 'can_edit'
CAN_VIEW_FIELD = 'can_view'
RECORD_UID_FIELD = 'record_uid'
SHARED_FOLDER_UID_FIELD = 'shared_folder_uid'
TEAM_UID_FIELD = 'team_uid'

KEY_RESTRICT_SHARING_ALL = 'restrict_sharing_all'

# Default Values
EMPTY_SHARE_OBJECTS = {'users': {}, 'enterprises': {}, 'teams': {}}


logger = logging.getLogger()


class ShareManagementError(Exception):
    """Base exception for share management operations."""
    pass


class ShareValidationError(ShareManagementError):
    """Raised when share validation fails."""
    pass


class ShareNotFoundError(ShareManagementError):
    """Raised when a share or record is not found."""
    pass


def get_share_expiration(expire_at: Optional[str], expire_in: Optional[str]) -> int:

    if not expire_at and not expire_in:
        return DEFAULT_EXPIRATION

    try:
        dt = None
        if isinstance(expire_at, str):
            if expire_at == 'never':
                return NEVER_EXPIRES
            dt = datetime.datetime.fromisoformat(expire_at)
        elif isinstance(expire_in, str):
            if expire_in == 'never':
                return NEVER_EXPIRES
            td = parse_timeout(expire_in)
            dt = datetime.datetime.now() + td
            
        if dt is None:
            raise ShareValidationError(f'Incorrect expiration: {expire_at or expire_in}')

        return int(dt.timestamp())
    except Exception as e:
        if isinstance(e, ShareValidationError):
            raise
        raise ShareValidationError(f'Invalid expiration format: {e}') from e


def get_share_objects(vault: vault_online.VaultOnline) -> Dict[str, Dict[str, Any]]:
    try:
        request = record_pb2.GetShareObjectsRequest()
        
        response = vault.keeper_auth.execute_auth_rest(
            rest_endpoint=SHARE_OBJECTS_API, 
            request=request, 
            response_type=record_pb2.GetShareObjectsResponse
        )
        
        if not response:
            return EMPTY_SHARE_OBJECTS
        
        users_by_type = {
            'relationship': response.shareRelationships,
            'family': response.shareFamilyUsers,
            'enterprise': response.shareEnterpriseUsers,
            'mc': response.shareMCEnterpriseUsers,
        }
        
        users = {}
        for category, users_data in users_by_type.items():
            users.update(_process_users(users_data, category))
        
        enterprises = {
            str(enterprise.enterpriseId): enterprise.enterprisename 
            for enterprise in response.shareEnterpriseNames
        }
        
        teams = _process_teams(response.shareTeams)
        teams_mc = _process_teams(response.shareMCTeams)
        
        return {
            'users': users,
            'enterprises': enterprises,
            'teams': {**teams, **teams_mc}
        }
    except Exception as e:
        logger.error(f"Failed to get share objects: {e}")
        return EMPTY_SHARE_OBJECTS


def _process_users(users_data: Iterable[Any], category: str) -> Dict[str, Dict[str, Any]]:
    """Process user data and add category information."""
    return {
        user.username: {
            'name': user.fullname,
            'is_sa': user.isShareAdmin,
            'enterprise_id': user.enterpriseId,
            'status': user.status,
            'category': category
        } for user in users_data
    }


def _process_teams(teams_data: Iterable[Any]) -> Dict[str, Dict[str, Any]]:
    """Process team data."""
    return {
        utils.base64_url_encode(team.teamUid): {
            'name': team.teamname,
            'enterprise_id': team.enterpriseId
        } for team in teams_data
    }


def load_records_in_shared_folder(
    vault: vault_online.VaultOnline, 
    shared_folder_uid: str, 
    record_uids: Optional[Set[str]] = None
) -> None:
    try:
        shared_folder = _find_shared_folder(vault, shared_folder_uid)
        if not shared_folder:
            raise ShareNotFoundError(f'Shared folder "{shared_folder_uid}" is not loaded.')
        
        shared_folder_key = vault.vault_data._shared_folders[shared_folder_uid].shared_folder_key
        record_keys = _decrypt_record_keys(vault, shared_folder, shared_folder_key)

        record_cache = {x.record_uid for x in vault.vault_data.records()}

        candidates = record_uids or record_keys.keys()
        record_set = {uid for uid in candidates if uid in record_keys and uid not in record_cache}

        _load_records_in_batches(vault, record_set, record_keys)
        
    except ShareNotFoundError:
        raise
    except Exception as e:
        raise ShareManagementError(f"Failed to load records in shared folder: {e}") from e


def _find_shared_folder(vault: vault_online.VaultOnline, shared_folder_uid: str):
    """Find shared folder by UID."""
    for shared_folder_info in vault.vault_data.shared_folders():
        if shared_folder_uid == shared_folder_info.shared_folder_uid:
            return vault.vault_data.load_shared_folder(shared_folder_uid=shared_folder_uid)
    return None


def _decode_record_key(record_key_attr) -> bytes:
    if isinstance(record_key_attr, bytes):
        return utils.base64_url_decode(str(record_key_attr, 'utf-8'))
    else:
        return utils.base64_url_decode(str(record_key_attr))


def _decrypt_single_record_key(key: bytes, shared_folder_key: bytes) -> bytes:
    if len(key) == RECORD_KEY_LENGTH_V2:
        return crypto.decrypt_aes_v2(key, shared_folder_key)
    else:
        return crypto.decrypt_aes_v1(key, shared_folder_key)


def _decrypt_record_keys(vault: vault_online.VaultOnline, shared_folder, shared_folder_key: bytes) -> Dict[str, bytes]:

    record_keys = {}
    sf_record_keys = vault.vault_data.storage.record_keys.get_links_by_object(
        shared_folder.shared_folder_uid
    ) or []
    
    for record_key_link in sf_record_keys:
        record_uid = getattr(record_key_link, 'record_uid', None)
        if not record_uid:
            continue
            
        try:
            record_key_attr = getattr(record_key_link, 'record_key', b'')
            key = _decode_record_key(record_key_attr)
            record_key = _decrypt_single_record_key(key, shared_folder_key)
            record_keys[record_uid] = record_key
        except Exception as e:
            logger.error(f'Cannot decrypt record "{record_uid}" key: {e}')
    
    return record_keys


def _build_record_details_request(record_uids: set) -> record_pb2.GetRecordDataWithAccessInfoRequest:

    request = record_pb2.GetRecordDataWithAccessInfoRequest()
    request.clientTime = utils.current_milli_time()
    request.recordDetailsInclude = record_pb2.DATA_PLUS_SHARE
    
    for uid in record_uids:
        try:
            request.recordUid.append(utils.base64_url_decode(uid))
        except Exception as e:
            logger.debug('Incorrect record UID "%s": %s', uid, e)
    
    return request


def _load_records_in_batches(vault: vault_online.VaultOnline, record_set: set, record_keys: dict):

    while record_set:
        request = _build_record_details_request(record_set)
        record_set.clear()

        response = vault.keeper_auth.execute_auth_rest(
            rest_endpoint=RECORD_DETAILS_URL, 
            request=request, 
            response_type=record_pb2.GetRecordDataWithAccessInfoResponse
        )
        
        if not response or not response.recordDataWithAccessInfo:
            logger.warning("No record data received from API")
            break
            
        _process_record_batch(vault, response, record_keys, record_set)


def _process_record_owner_key(record_data, record_uid: str, record_keys: dict):

    if record_data.recordUid and record_data.recordKey:
        owner_id = utils.base64_url_encode(record_data.recordUid)
        if owner_id in record_keys:
            record_keys[record_uid] = crypto.decrypt_aes_v2(
                record_data.recordKey, 
                record_keys[owner_id]
            )


def _process_record_batch(vault: vault_online.VaultOnline, response, record_keys: dict, record_set: set):

    for record_info in response.recordDataWithAccessInfo:
        record_uid = utils.base64_url_encode(record_info.recordUid)
        record_data = record_info.recordData
        
        try:
            _process_record_owner_key(record_data, record_uid, record_keys)

            if record_uid not in record_keys:
                continue

            record_key = record_keys[record_uid]
            version = record_data.version
            record = _create_record_dict(record_uid, record_data, record_key, version)
            
            _handle_record_versions(vault, record, record_data, version, record_set)
            _add_share_permissions(record, record_info)
            record_set.add(record_uid)
            
        except Exception as e:
            logger.debug('Error decrypting record "%s": %s', record_uid, e)


def _create_record_dict(record_uid: str, record_data, record_key: bytes, version: int) -> dict:
    """Create record dictionary from API data."""
    return {
        'record_uid': record_uid,
        'revision': record_data.revision,
        'version': version,
        'shared': record_data.shared,
        'data': record_data.encryptedRecordData,
        'record_key_unencrypted': record_key,
        'client_modified_time': record_data.clientModifiedTime,
    }


def _decrypt_record_data(record_data, record_key: bytes, version: int) -> bytes:

    data_decoded = utils.base64_url_decode(record_data.encryptedRecordData)
    
    if version <= MAX_V2_VERSION:
        return crypto.decrypt_aes_v1(data_decoded, record_key)
    else:
        return crypto.decrypt_aes_v2(data_decoded, record_key)


def _process_v2_extra_data(record: dict, record_data, record_key: bytes):

    if record_data.encryptedExtraData:
        record['extra'] = record_data.encryptedExtraData
        extra_decoded = utils.base64_url_decode(record_data.encryptedExtraData)
        record['extra_unencrypted'] = crypto.decrypt_aes_v1(extra_decoded, record_key)


def _process_v3_record_references(vault: vault_online.VaultOnline, record: dict, record_set: set):

    v3_record = vault.vault_data.load_record(record_uid=record['record_uid'])
    if isinstance(v3_record, vault_record.TypedRecord):
        for ref in itertools.chain(v3_record.fields, v3_record.custom):
            if ref.type.endswith('Ref') and isinstance(ref.value, list):
                record_set.update(ref.value)


def _process_v4_record_metadata(record: dict, record_data):

    if record_data.fileSize > 0:
        record['file_size'] = record_data.fileSize
    if record_data.thumbnailSize > 0:
        record['thumbnail_size'] = record_data.thumbnailSize


def _process_record_owner_info(record: dict, record_data):

    if record_data.recordUid and record_data.recordKey:
        record['owner_uid'] = utils.base64_url_encode(record_data.recordUid)
        record['link_key'] = utils.base64_url_encode(record_data.recordKey)


def _handle_record_versions(vault: vault_online.VaultOnline, record: dict, record_data, version: int, record_set: set):

    record_key = record['record_key_unencrypted']
    record['data_unencrypted'] = _decrypt_record_data(record_data, record_key, version)

    if version <= MAX_V2_VERSION:
        _process_v2_extra_data(record, record_data, record_key)
    
    if version == V3_VERSION:
        _process_v3_record_references(vault, record, record_set)
    elif version == V4_VERSION:
        _process_v4_record_metadata(record, record_data)
    
    _process_record_owner_info(record, record_data)


def _add_share_permissions(record: dict, record_info):
    """Add share permissions to record."""
    record['shares'] = {
        'user_permissions': [{
            'username': up.username,
            'owner': up.owner,
            'share_admin': up.shareAdmin,
            'shareable': up.sharable,
            'editable': up.editable,
            'awaiting_approval': up.awaitingApproval,
            'expiration': up.expiration,
        } for up in record_info.userPermission],
        'shared_folder_permissions': [{
            'shared_folder_uid': utils.base64_url_encode(sp.sharedFolderUid),
            'reshareable': sp.resharable,
            'editable': sp.editable,
            'revision': sp.revision,
            'expiration': sp.expiration,
        } for sp in record_info.sharedFolderPermission],
    }
        
        
def get_record_shares(
    vault: vault_online.VaultOnline, 
    record_uids: List[str], 
    is_share_admin: bool = False
) -> Optional[List[Dict[str, Any]]]:

    try:
        record_cache = {x.record_uid: x for x in vault.vault_data.records()}
        
        uids_needing_info = [
            uid for uid in record_uids 
            if _needs_share_info(uid, record_cache, is_share_admin)
        ]
        
        if not uids_needing_info:
            return None
        
        return _fetch_record_shares_batch(vault, uids_needing_info)
        
    except Exception as e:
        raise ValueError(f"Error fetching record shares: {e}")


def _needs_share_info(uid: str, record_cache: dict, is_share_admin: bool) -> bool:
    """Check if a record needs share information."""
    if uid in record_cache:
        record = record_cache[uid]
        return not hasattr(record, 'shares')
    return is_share_admin


def _fetch_record_shares_batch(vault: vault_online.VaultOnline, uids_needing_info: List[str]) -> List[Dict[str, Any]]:
    """Fetch record shares in batches."""
    result = []
    
    for i in range(0, len(uids_needing_info), CHUNK_SIZE):
        chunk = uids_needing_info[i:i + CHUNK_SIZE]
        
        request = record_pb2.GetRecordDataWithAccessInfoRequest()
        request.clientTime = utils.current_milli_time()
        request.recordUid.extend([utils.base64_url_decode(uid) for uid in chunk])
        request.recordDetailsInclude = record_pb2.SHARE_ONLY
        
        response = vault.keeper_auth.execute_auth_rest(
            rest_endpoint=RECORD_DETAILS_URL, 
            request=request, 
            response_type=record_pb2.GetRecordDataWithAccessInfoResponse
        )
        
        if not response or not response.recordDataWithAccessInfo:
            logger.error("No response or missing recordDataWithAccessInfo from Keeper API.")
            continue
            
        for info in response.recordDataWithAccessInfo:
            record_uid = utils.base64_url_encode(info.recordUid)
            rec = _create_record_info(record_uid)
            
            if isinstance(rec, dict):
                rec['shares'] = {
                    'user_permissions': _process_user_permissions(info),
                    'shared_folder_permissions': _process_shared_folder_permissions(info)
                }
            
            result.append(rec)
    
    return result


def _create_record_info(record_uid: str) -> Dict[str, Any]:
    """Create basic record information dictionary."""
    return {RECORD_UID_FIELD: record_uid}


def _process_user_permissions(info) -> List[Dict[str, Any]]:
    """Process user permissions from record info."""
    user_permissions = []
    for up in info.userPermission:
        permission = {
            'username': up.username,
            'owner': up.owner,
            'share_admin': up.shareAdmin,
            'shareable': up.sharable,
            'editable': up.editable,
        }
        if up.awaitingApproval:
            permission['awaiting_approval'] = up.awaitingApproval
        if up.expiration > 0:
            permission['expiration'] = str(up.expiration)
        user_permissions.append(permission)
    return user_permissions


def _process_shared_folder_permissions(info) -> List[Dict[str, Any]]:
    """Process shared folder permissions from record info."""
    shared_folder_permissions = []
    for sp in info.sharedFolderPermission:
        permission = {
            'shared_folder_uid': utils.base64_url_encode(sp.sharedFolderUid),
            'reshareable': sp.resharable,
            'editable': sp.editable,
            'revision': sp.revision,
        }
        if sp.expiration > 0:
            permission['expiration'] = sp.expiration
        shared_folder_permissions.append(permission)
    return shared_folder_permissions


def resolve_record_share_path(vault: vault_online.VaultOnline, enterprise: enterprise_data.EnterpriseData, record_uid: str) -> Optional[Dict[str, str]]:
    return resolve_record_permission_path(vault=vault, enterprise=enterprise, record_uid=record_uid, permission=CAN_SHARE)


def resolve_record_permission_path(
    vault: vault_online.VaultOnline,
    enterprise: enterprise_data.EnterpriseData,
    record_uid: str, 
    permission: str
) -> Optional[Dict[str, str]]:
    for ap in enumerate_record_access_paths(vault=vault, enterprise=enterprise, record_uid=record_uid):
        if ap.get(permission):
            path = {
                RECORD_UID_FIELD: record_uid
            }
            if SHARED_FOLDER_UID_FIELD in ap:
                path[SHARED_FOLDER_UID_FIELD] = ap[SHARED_FOLDER_UID_FIELD]
            if TEAM_UID_FIELD in ap:
                path[TEAM_UID_FIELD] = ap[TEAM_UID_FIELD]
            return path

    return None


def _create_access_path(
    record_uid: str,
    shared_folder_uid: str, 
    can_edit: bool, 
    can_share: bool, 
    team_uid: Optional[str] = None
) -> Dict[str, Any]:

    path = {
        RECORD_UID_FIELD: record_uid,
        SHARED_FOLDER_UID_FIELD: shared_folder_uid,
        CAN_EDIT: can_edit,
        CAN_SHARE: can_share,
        CAN_VIEW_FIELD: True
    }
    if team_uid:
        path[TEAM_UID_FIELD] = team_uid
    return path


def _process_team_permissions_for_shared_folder(
    shared_folder: Any,
    record_uid: str,
    enterprise: enterprise_data.EnterpriseData,
    base_can_edit: bool, 
    base_can_share: bool
) -> Generator[Dict[str, Any], None, None]:

    for user_permission in shared_folder.user_permissions:
        if user_permission.user_type != TEAM_USER_TYPE:
            continue
            
        team_uid = user_permission.user_uid
        team = enterprise.teams.get_entity(team_uid)
        
        if team:
            yield _create_access_path(
                record_uid=record_uid,
                shared_folder_uid=shared_folder.shared_folder_uid,
                can_edit=base_can_edit and not team.restrict_edit,
                can_share=base_can_share and not team.restrict_share,
                team_uid=team_uid
            )


def enumerate_record_access_paths(
    vault: vault_online.VaultOnline,
    enterprise: enterprise_data.EnterpriseData,
    record_uid: str
) -> Generator[Dict[str, Any], None, None]:

    record = vault.vault_data.get_record(record_uid)
    is_owner = record.flags == vault_record.RecordFlags.IsOwner

    for shared_folder_info in vault.vault_data.shared_folders():
        shared_folder_uid = shared_folder_info.shared_folder_uid
        shared_folder = vault.vault_data.load_shared_folder(
            shared_folder_uid=shared_folder_uid
        )
            
        can_edit, can_share = is_owner, is_owner
        
        if hasattr(shared_folder, 'key_type'):
            yield _create_access_path(
                record_uid=record_uid,
                shared_folder_uid=shared_folder_uid,
                can_edit=can_edit,
                can_share=can_share
            )
        else:
            yield from _process_team_permissions_for_shared_folder(
                shared_folder, record_uid, enterprise, can_edit, can_share
            )


def _fetch_team_members_from_api(vault: vault_online.VaultOnline, team_uids: Set[str]) -> Dict[str, Set[str]]:

    members = {}
    
    if not vault.keeper_auth.auth_context.enterprise_ec_public_key:
        return members
        
    for team_uid in team_uids:
        try:
            request = enterprise_pb2.GetTeamMemberRequest()
            request.teamUid = utils.base64_url_decode(team_uid)
            
            response = vault.keeper_auth.execute_auth_rest(
                rest_endpoint=TEAM_MEMBERS_ENDPOINT,
                request=request,
                response_type=enterprise_pb2.GetTeamMemberResponse
            )
            
            if response and response.enterpriseUser:
                team_members = {user.email for user in response.enterpriseUser}
                members[team_uid] = team_members
                
        except Exception as e:
            logger.debug(f"Failed to fetch team members for {team_uid}: {e}")
            
    return members


def _get_cached_team_members(enterprise: enterprise_data.EnterpriseData, team_uids: Set[str], username_lookup: Dict[str, str]) -> Dict[str, Set[str]]:

    members = {}
    team_user_links = enterprise.team_users.get_all_links() or []
    
    relevant_team_users = [
        link for link in team_user_links 
        if link.user_type != USER_TYPE_INACTIVE and link.team_uid in team_uids
    ]

    for team_user in relevant_team_users:
        username = username_lookup.get(team_user.enterprise_user_id.__str__())
        if username:
            team_uid = team_user.team_uid
            if team_uid not in members:
                members[team_uid] = set()
            members[team_uid].add(username)

    return members


def _fetch_all_shared_folder_admins(vault: vault_online.VaultOnline) -> Dict[str, List[str]]:
    sf_uids = list(vault.vault_data._shared_folders.keys())
    return {
        sf_uid: get_share_admins_for_shared_folder(vault, sf_uid) or []
        for sf_uid in sf_uids
    }


def _get_restricted_role_members(enterprise: enterprise_data.EnterpriseData, username_lookup: Dict[str, str]) -> Set[str]:

    role_enforcements = enterprise.role_enforcements.get_all_links()
    restricted_roles = {
        re.role_id for re in role_enforcements 
        if re.enforcement_type == 'enforcements' and re.value == KEY_RESTRICT_SHARING_ALL
    }

    if not restricted_roles:
        return set()

    restricted_users = enterprise.role_users.get_links_by_object(restricted_roles)
    restricted_teams = enterprise.role_teams.get_links_by_object(restricted_roles)

    restricted_members = set()
    
    for user_link in restricted_users:
        username = username_lookup.get(user_link.enterprise_user_id)
        if username:
            restricted_members.add(username)

    team_uids = {team_link.team_uid for team_link in restricted_teams}
    if team_uids:
        team_members = _get_cached_team_members(enterprise, team_uids, username_lookup)
        for members in team_members.values():
            restricted_members.update(members)

    return restricted_members


def _extract_team_uids_from_shares(shares: Optional[List[Dict[str, Any]]]) -> Set[str]:
    if not shares:
        return set()
    
    sf_teams = [share.get('teams', []) for share in shares]
    return {
        team.get('team_uid') 
        for teams in sf_teams 
        for team in teams 
        if team.get('team_uid')
    }


def _build_username_lookup(enterprise: enterprise_data.EnterpriseData) -> Union[Dict[int, str], Dict[Any, Any]]:
    if not enterprise:
        return {}
    
    enterprise_users = enterprise.users.get_all_entities()
    return {user.enterprise_user_id: user.username for user in enterprise_users}


def get_shared_records(vault: vault_online.VaultOnline, enterprise: enterprise_data.EnterpriseData, record_uids, cache_only=False):
    try:
        shares = get_record_shares(vault, record_uids)
        team_uids = _extract_team_uids_from_shares(shares)
        username_lookup = _build_username_lookup(enterprise)

        sf_share_admins = _fetch_all_shared_folder_admins(vault) if not cache_only else {}
        restricted_role_members = _get_restricted_role_members(enterprise, username_lookup)

        if cache_only or enterprise:
            team_members = _get_cached_team_members(enterprise, team_uids, username_lookup)
        else:
            team_members = _fetch_team_members_from_api(vault, team_uids)

        records = [vault.vault_data.get_record(uid) for uid in record_uids]
        valid_records = [record for record in records if record is not None]

        from .shared_record import SharedRecord
        
        shared_records = [
            SharedRecord(vault, record, sf_share_admins, team_members, restricted_role_members)
            for record in valid_records
        ]

        return {shared_record.uid: shared_record for shared_record in shared_records}

    except Exception as e:
        raise ValueError(f"Error in get_shared_records: {e}")


def get_share_admins_for_shared_folder(vault: vault_online.VaultOnline, shared_folder_uid: str) -> Optional[List[str]]:

    if not vault.keeper_auth.auth_context.enterprise_ec_public_key:
        return None
        
    try:
        request = enterprise_pb2.GetSharingAdminsRequest()
        request.sharedFolderUid = utils.base64_url_decode(shared_folder_uid)
        
        response = vault.keeper_auth.execute_auth_rest(
            rest_endpoint=SHARING_ADMINS_ENDPOINT,
            request=request,
            response_type=enterprise_pb2.GetSharingAdminsResponse
        )
        
        admins = [
            x.email for x in response.userProfileExts 
            if x.isShareAdminForSharedFolderOwner and x.isInSharedFolder
        ]
        return admins
    except Exception as e:
        logger.debug(f"Failed to get share admins for shared folder {shared_folder_uid}: {e}")
        return None


def _find_folders_by_name(vault: vault_online.VaultOnline, name: str) -> Set[str]:
    folder_uids = set()
    for folder in vault.vault_data.folders():
        if folder.name == name:
            folder_uids.add(folder.folder_uid)
    return folder_uids


def _resolve_folder_by_path(vault: vault_online.VaultOnline, name: str) -> Optional[str]:
    try:
        folder, _ = try_resolve_path(vault, name)
        if folder:
            return folder.folder_uid
    except Exception:
        pass
    return None


def get_folder_uids(vault: vault_online.VaultOnline, name: str) -> Set[str]:

    folder_uids = set()
    
    if name in vault.vault_data._folders:
        folder_uids.add(name)
        return folder_uids
    
    folder_uids = _find_folders_by_name(vault, name)
    
    if not folder_uids:
        resolved_uid = _resolve_folder_by_path(vault, name)
        if resolved_uid:
            folder_uids.add(resolved_uid)
    
    return folder_uids


def _add_folder_records(vault: vault_online.VaultOnline, folder_uid: str, records_by_folder: Dict[str, Set[str]]):
    folder = vault.vault_data.get_folder(folder_uid)
    if folder:
        records_by_folder[folder_uid] = folder.records


def _create_folder_traversal_callback(
    vault: vault_online.VaultOnline,
    root_folder_uids: Set[str],
    children_only: bool,
    records_by_folder: Dict[str, Set[str]]
):
    def on_folder(folder):
        folder_uid = folder.folder_uid or ''
        if not children_only or folder_uid in root_folder_uids:
            _add_folder_records(vault, folder_uid, records_by_folder)
    
    return on_folder


def get_contained_record_uids(vault: vault_online.VaultOnline, name: str, children_only: bool = True) -> Dict[str, Set[str]]:

    records_by_folder = {}
    root_folder_uids = get_folder_uids(vault, name)
    on_folder = _create_folder_traversal_callback(vault, root_folder_uids, children_only, records_by_folder)

    for uid in root_folder_uids:
        folder = vault.vault_data.get_folder(uid)
        if folder:
            vault_utils.traverse_folder_tree(vault.vault_data, folder, on_folder)

    return records_by_folder


def _normalize_path_input(path: str) -> str:
    if not isinstance(path, str):
        return ''
    return path


def _handle_root_path(path: str, folder: Optional[vault_types.Folder], vault: vault_online.VaultOnline) -> Tuple[Optional[vault_types.Folder], str]:

    if path.startswith('/') and not path.startswith('//'):
        folder = vault.vault_data.root_folder
        path = path[1:]
    
    if folder is None:
        folder = vault.vault_data.root_folder
    
    return folder, path


def _split_path_components(path: str) -> List[str]:
    return [s.replace('\0', '/') for s in path.replace('//', '\0').split('/')]


def _handle_parent_directory(folder: vault_types.Folder, vault: vault_online.VaultOnline) -> vault_types.Folder:

    parent_uid = folder.parent_uid
    if parent_uid:
        parent_folder = vault.vault_data.get_folder(parent_uid)
        if parent_folder:
            return parent_folder
    return vault.vault_data.root_folder


def _find_subfolder_by_name(folder: vault_types.Folder, component: str, vault: vault_online.VaultOnline) -> Optional[vault_types.Folder]:

    if component in folder.subfolders:
        subfolder = vault.vault_data.get_folder(component)
        if subfolder:
            return subfolder
    
    folders = [f for f in (vault.vault_data.get_folder(x) for x in folder.subfolders) if f]
    
    exact_match = next((x for x in folders if x.name.strip() == component), None)
    if exact_match:
        return exact_match
    
    case_insensitive_match = next(
        (x for x in folders if x.name.strip().casefold() == component.casefold()), 
        None
    )
    return case_insensitive_match


def _traverse_path_components(
    folder: vault_types.Folder, 
    components: List[str], 
    vault: vault_online.VaultOnline
) -> Tuple[vault_types.Folder, List[str]]:

    remaining_components = []
    
    for component in components:
        component = component.strip()
        
        if component == '..':
            folder = _handle_parent_directory(folder, vault)
        elif component in ('', '.'):
            continue
        else:
            subfolder = _find_subfolder_by_name(folder, component, vault)
            if subfolder:
                folder = subfolder
            else:
                remaining_components.append(component)
                break
    
    return folder, remaining_components


def _reconstruct_remaining_path(components: List[str]) -> str:
    return '/'.join(component.replace('/', '//') for component in components)


def try_resolve_path(vault: vault_online.VaultOnline, path: str) -> Tuple[vault_types.Folder, str]:
    
    path = _normalize_path_input(path)
    
    folder = vault.vault_data.get_folder(path)
    if folder is not None:
        return folder, ''

    folder, path = _handle_root_path(path, None, vault)
    components = _split_path_components(path)
    
    folder, remaining_components = _traverse_path_components(folder, components, vault)
    remaining_path = _reconstruct_remaining_path(remaining_components)

    return folder, remaining_path


def _parse_timeout_units(timeout_input: str) -> Dict[str, int]:
    
    tdelta_kwargs = {}
    for value, input_unit in findall(r'(\d+)\s*([a-zA-Z]+)\s*', timeout_input):
        matching_units = [unit for unit in TIMEOUT_ALLOWED_UNITS if unit.startswith(input_unit)]
        
        if not matching_units:
            raise ValueError(
                f'{input_unit} is not allowed as a unit for the timeout value. '
                f'Valid units for the timeout value are {TIMEOUT_ALLOWED_UNITS}.'
            )
        
        unit_key = matching_units[0]
        tdelta_kwargs[unit_key] = int(value)
    
    return tdelta_kwargs


def parse_timeout(timeout_input: str) -> datetime.timedelta:

    timeout_input = timeout_input.strip()
    
    if timeout_input.isnumeric():
        return datetime.timedelta(**{TIMEOUT_DEFAULT_UNIT: int(timeout_input)})
    
    tdelta_kwargs = _parse_timeout_units(timeout_input)
    return datetime.timedelta(**tdelta_kwargs)