import datetime
import itertools
from typing import Optional, Dict, List, Any, Generator, Iterable, Set

from keepersdk import crypto, utils
from keepersdk.proto import enterprise_pb2, record_pb2
from keepersdk.vault import vault_online, vault_record, vault_utils

from .. import api
from ..commands import enterprise_utils
from ..helpers import timeout_utils, folder_utils
from ..params import KeeperParams

# API Endpoints
RECORD_DETAILS_URL = 'vault/get_records_details'
SHARE_OBJECTS_API = 'vault/get_share_objects'
TEAM_MEMBERS_ENDPOINT = 'vault/get_team_members'
SHARING_ADMINS_ENDPOINT = 'enterprise/get_sharing_admins'
SHARE_ADMIN_API = 'vault/am_i_share_admin'
SHARE_UPDATE_API = 'vault/records_share_update'
SHARE_FOLDER_UPDATE_API = 'vault/shared_folder_update_v3'
REMOVE_EXTERNAL_SHARE_API = 'vault/external_share_remove'

# Record Processing Constants
CHUNK_SIZE = 999
MAX_BATCH_SIZE = 990
RECORD_KEY_LENGTH_V2 = 60
DEFAULT_EXPIRATION = 0
NEVER_EXPIRES = -1
NEVER_EXPIRES_STRING = 'never'
TIMESTAMP_MILLISECONDS_FACTOR = 1000
TRUNCATE_SUFFIX = '...'
TRUNCATE_LENGTH = 20

# Record Version Constants
MAX_V2_VERSION = 2
V3_VERSION = 3
V4_VERSION = 4

# User Type Constants
TEAM_USER_TYPE = 2
USER_TYPE_INACTIVE = 2

# Permission Field Names
CAN_SHARE_PERMISSION = 'can_share'
CAN_EDIT_FIELD = 'can_edit'
CAN_SHARE_FIELD = 'can_share'
CAN_VIEW_FIELD = 'can_view'
RECORD_UID_FIELD = 'record_uid'
SHARED_FOLDER_UID_FIELD = 'shared_folder_uid'
TEAM_UID_FIELD = 'team_uid'

# Share Object Categories
RELATIONSHIP_CATEGORY = 'relationship'
FAMILY_CATEGORY = 'family'
ENTERPRISE_CATEGORY = 'enterprise'
MC_CATEGORY = 'mc'

# Record Field Names
TITLE_FIELD = 'title'
NAME_FIELD = 'name'
IS_SA_FIELD = 'is_sa'
ENTERPRISE_ID_FIELD = 'enterprise_id'
STATUS_FIELD = 'status'
CATEGORY_FIELD = 'category'
SHARES_FIELD = 'shares'
USER_PERMISSIONS_FIELD = 'user_permissions'
SHARED_FOLDER_PERMISSIONS_FIELD = 'shared_folder_permissions'

# Key Constants for Data Access
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

# Enterprise Keys
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

# Vault Keys
KEY_VAULT = 'vault'
KEY_VAULT_DATA = 'vault_data'
KEY_SHARED_FOLDER_CACHE = 'shared_folder_cache'
KEY_RECORD_CACHE = 'record_cache'
KEY_RECORD_OWNER_CACHE = 'record_owner_cache'

# Restriction Keys
KEY_RESTRICT_EDIT = 'restrict_edit'
KEY_RESTRICT_SHARING = 'restrict_sharing'
KEY_RESTRICT_VIEW = 'restrict_view'
KEY_RESTRICT_SHARING_ALL = 'restrict_sharing_all'

# Permission Constants
PERMISSION_EDIT = 'edit'
PERMISSION_SHARE = 'share'
PERMISSION_VIEW = 'view'

# Text Constants
TEXT_EDIT = 'Edit'
TEXT_SHARE = 'Share'
TEXT_READ_ONLY = 'Read Only'
TEXT_LAUNCH_ONLY = 'Launch Only'
TEXT_CAN_PREFIX = 'Can '
TEXT_TEAM_PREFIX = '(Team)'
TEXT_TEAM_USER_PREFIX = '(Team User)'

# Default Values
EMPTY_SHARE_OBJECTS = {'users': {}, 'enterprises': {}, 'teams': {}}

# Time Constants
SIX_MONTHS_IN_SECONDS = 182 * 24 * 60 * 60

# Status Messages
STATUS_SUCCESS = 'success'
STATUS_INVITED = 'invited'
STATUS_EXPIRED = 'Expired'
STATUS_OPENED = 'Opened'
STATUS_GENERATED = 'Generated'


logger = api.get_logger()


# =============================================================================
# CUSTOM EXCEPTIONS - Centralized exception handling for share management
# =============================================================================

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
    """
    Calculate share expiration timestamp from expire_at or expire_in parameters.
    
    Args:
        expire_at: ISO datetime string or 'never'
        expire_in: Time period string or 'never'
        
    Returns:
        Unix timestamp for expiration
        
    Raises:
        ShareValidationError: If expiration format is invalid
    """
    if not expire_at and not expire_in:
        return DEFAULT_EXPIRATION

    try:
        dt = None
        if isinstance(expire_at, str):
            if expire_at == NEVER_EXPIRES_STRING:
                return NEVER_EXPIRES
            dt = datetime.datetime.fromisoformat(expire_at)
        elif isinstance(expire_in, str):
            if expire_in == NEVER_EXPIRES_STRING:
                return NEVER_EXPIRES
            td = timeout_utils.parse_timeout(expire_in)
            dt = datetime.datetime.now() + td
            
        if dt is None:
            raise ShareValidationError(f'Incorrect expiration: {expire_at or expire_in}')

        return int(dt.timestamp())
    except Exception as e:
        if isinstance(e, ShareValidationError):
            raise
        raise ShareValidationError(f'Invalid expiration format: {e}') from e


def get_share_objects(vault: vault_online.VaultOnline) -> Dict[str, Dict[str, Any]]:
    """
    Retrieve share objects (users, enterprises, teams) from the vault.
    
    Args:
        vault: VaultOnline instance
        
    Returns:
        Dictionary containing users, enterprises, and teams
    """
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
            RELATIONSHIP_CATEGORY: response.shareRelationships,
            FAMILY_CATEGORY: response.shareFamilyUsers,
            ENTERPRISE_CATEGORY: response.shareEnterpriseUsers,
            MC_CATEGORY: response.shareMCEnterpriseUsers,
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
            NAME_FIELD: user.fullname,
            IS_SA_FIELD: user.isShareAdmin,
            ENTERPRISE_ID_FIELD: user.enterpriseId,
            STATUS_FIELD: user.status,
            CATEGORY_FIELD: category
        } for user in users_data
    }


def _process_teams(teams_data: Iterable[Any]) -> Dict[str, Dict[str, Any]]:
    """Process team data."""
    return {
        utils.base64_url_encode(team.teamUid): {
            NAME_FIELD: team.teamname,
            ENTERPRISE_ID_FIELD: team.enterpriseId
        } for team in teams_data
    }


def load_records_in_shared_folder(
    vault: vault_online.VaultOnline, 
    shared_folder_uid: str, 
    record_uids: Optional[set[str]] = None
) -> None:
    """
    Load records from a shared folder into the vault.
    
    Args:
        vault: VaultOnline instance
        shared_folder_uid: UID of the shared folder
        record_uids: Optional set of specific record UIDs to load
        
    Raises:
        ShareNotFoundError: If shared folder is not found
        ShareManagementError: If loading fails
    """
    try:
        shared_folder = _find_shared_folder(vault, shared_folder_uid)
        if not shared_folder:
            raise ShareNotFoundError(f'Shared folder "{shared_folder_uid}" is not loaded.')
        
        shared_folder_key = vault.vault_data._shared_folders[shared_folder_uid].shared_folder_key
        record_keys = _decrypt_record_keys(vault, shared_folder, shared_folder_key)
        
        record_cache = [x.record_uid for x in vault.vault_data.records()]
        
        if record_uids:
            record_set = set(record_uids)
            record_set.intersection_update(record_keys.keys())
        else:
            record_set = set(record_keys.keys())
        record_set.difference_update(record_cache)

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


def _decrypt_record_keys(vault: vault_online.VaultOnline, shared_folder, shared_folder_key):
    """Decrypt record keys for shared folder."""
    record_keys = {}
    sf_record_keys = vault.vault_data.storage.record_keys.get_links_by_object(shared_folder.shared_folder_uid) or []
    
    for rk in sf_record_keys:
        record_uid = getattr(rk, 'record_uid', None)
        try:
            key = utils.base64_url_decode(
                str(getattr(rk, 'record_key', b''), 'utf-8') 
                if isinstance(getattr(rk, 'record_key', b''), bytes) 
                else getattr(rk, 'record_key', '')
            )
            if len(key) == RECORD_KEY_LENGTH_V2:
                record_key = crypto.decrypt_aes_v2(key, shared_folder_key)
            else:
                record_key = crypto.decrypt_aes_v1(key, shared_folder_key)
            record_keys[record_uid] = record_key
        except Exception as e:
            logger.error(f'Cannot decrypt record "{record_uid}" key: {e}')
    
    return record_keys


def _load_records_in_batches(vault: vault_online.VaultOnline, record_set: set, record_keys: dict):
    """Load records in batches to avoid API limits."""
    while len(record_set) > 0:
        rq = record_pb2.GetRecordDataWithAccessInfoRequest()
        rq.clientTime = utils.current_milli_time()
        rq.recordDetailsInclude = record_pb2.DATA_PLUS_SHARE
        
        for uid in record_set:
            try:
                rq.recordUid.append(utils.base64_url_decode(uid))
            except Exception as e:
                logger.debug('Incorrect record UID "%s": %s', uid, e)
        record_set.clear()

        response = vault.keeper_auth.execute_auth_rest(
            rest_endpoint=RECORD_DETAILS_URL, 
            request=rq, 
            response_type=record_pb2.GetRecordDataWithAccessInfoResponse
        )
        
        if not response or not response.recordDataWithAccessInfo:
            logger.warning("No record data received from API")
            break
            
        _process_record_batch(vault, response, record_keys, record_set)


def _process_record_batch(vault: vault_online.VaultOnline, response, record_keys: dict, record_set: set):
    """Process a batch of records from API response."""
    for record_info in response.recordDataWithAccessInfo:
        record_uid = utils.base64_url_encode(record_info.recordUid)
        record_data = record_info.recordData
        
        try:
            if record_data.recordUid and record_data.recordKey:
                owner_id = utils.base64_url_encode(record_data.recordUid)
                if owner_id in record_keys:
                    record_keys[record_uid] = crypto.decrypt_aes_v2(record_data.recordKey, record_keys[owner_id])

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


def _handle_record_versions(vault: vault_online.VaultOnline, record: dict, record_data, version: int, record_set: set):
    """Handle different record versions and their specific features."""
    data_decoded = utils.base64_url_decode(record_data.encryptedRecordData)
    record_key = record['record_key_unencrypted']
    
    if version <= MAX_V2_VERSION:
        record['data_unencrypted'] = crypto.decrypt_aes_v1(data_decoded, record_key)
    else:
        record['data_unencrypted'] = crypto.decrypt_aes_v2(data_decoded, record_key)

    # Handle extra data for v2 records
    if record_data.encryptedExtraData and version <= MAX_V2_VERSION:
        record['extra'] = record_data.encryptedExtraData
        extra_decoded = utils.base64_url_decode(record_data.encryptedExtraData)
        record['extra_unencrypted'] = crypto.decrypt_aes_v1(extra_decoded, record_key)
    
    # Handle v3 typed records with references
    if version == V3_VERSION:
        v3_record = vault.vault_data.load_record(record_uid=record['record_uid'])
        if isinstance(v3_record, vault_record.TypedRecord):
            for ref in itertools.chain(v3_record.fields, v3_record.custom):
                if ref.type.endswith('Ref') and isinstance(ref.value, list):
                    record_set.update(ref.value)
    
    # Handle v4 records with file attachments
    elif version == V4_VERSION:
        if record_data.fileSize > 0:
            record['file_size'] = record_data.fileSize
        if record_data.thumbnailSize > 0:
            record['thumbnail_size'] = record_data.thumbnailSize
    
    # Handle linked record metadata
    if record_data.recordUid and record_data.recordKey:
        record['owner_uid'] = utils.base64_url_encode(record_data.recordUid)
        record['link_key'] = utils.base64_url_encode(record_data.recordKey)


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
    """
    Get share information for records.
    
    Args:
        vault: VaultOnline instance
        record_uids: List of record UIDs
        is_share_admin: Whether user is share admin
        
    Returns:
        List of record share information or None
    """
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
        logger.error(f"Error fetching record shares: {e}")
        return None


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


def resolve_record_share_path(context: KeeperParams, record_uid: str) -> Optional[Dict[str, str]]:
    return resolve_record_permission_path(context=context, record_uid=record_uid, permission=CAN_SHARE_PERMISSION)


def resolve_record_permission_path(
    context: KeeperParams, 
    record_uid: str, 
    permission: str
) -> Optional[Dict[str, str]]:
    for ap in enumerate_record_access_paths(context=context, record_uid=record_uid):
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


def enumerate_record_access_paths(
    context: KeeperParams, 
    record_uid: str
) -> Generator[Dict[str, Any], None, None]:
    
    def create_access_path(
        shared_folder_uid: str, 
        can_edit: bool, 
        can_share: bool, 
        team_uid: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create a standardized access path dictionary."""
        path = {
            RECORD_UID_FIELD: record_uid,
            SHARED_FOLDER_UID_FIELD: shared_folder_uid,
            CAN_EDIT_FIELD: can_edit,
            CAN_SHARE_FIELD: can_share,
            CAN_VIEW_FIELD: True
        }
        if team_uid:
            path[TEAM_UID_FIELD] = team_uid
        return path
    
    def process_team_permissions(
        shared_folder: Any, 
        base_can_edit: bool, 
        base_can_share: bool
    ) -> Generator[Dict[str, Any], None, None]:
        """Process team-based permissions for a shared folder."""
        if not context.enterprise_data:
            return
            
        for user_permission in shared_folder.user_permissions:
            if user_permission.user_type != TEAM_USER_TYPE:
                continue
                
            team_uid = user_permission.user_uid
            team = enterprise_utils.TeamUtils.resolve_single_team(
                context.enterprise_data, team_uid
            )
            
            if team:
                yield create_access_path(
                    shared_folder_uid=shared_folder.shared_folder_uid,
                    can_edit=base_can_edit and not team.restrict_edit,
                    can_share=base_can_share and not team.restrict_share,
                    team_uid=team_uid
                )
    
    for shared_folder_info in context.vault.vault_data.shared_folders():
        shared_folder_uid = shared_folder_info.shared_folder_uid
        
        shared_folder = context.vault.vault_data.load_shared_folder(
            shared_folder_uid=shared_folder_uid
        )

        is_owner = context.vault.vault_data.get_record(record_uid).flags == vault_record.RecordFlags.IsOwner
            
        can_edit, can_share = is_owner, is_owner
        
        if hasattr(shared_folder, 'key_type'):
            yield create_access_path(
                shared_folder_uid=shared_folder_uid,
                can_edit=can_edit,
                can_share=can_share
            )
        else:
            yield from process_team_permissions(shared_folder, can_edit, can_share)


def get_shared_records(context: KeeperParams, record_uids, cache_only=False):
    """
    Get shared record information for the specified record UIDs.
    
    Args:
        context: KeeperParams instance containing vault and enterprise data
        record_uids: Collection of record UIDs to process
        cache_only: If True, only use cached data without making API calls
        
    Returns:
        Dict mapping record UIDs to SharedRecord instances
    """
    
    def _fetch_team_members_from_api(team_uids: Set[str]) -> Dict[str, Set[str]]:
        """Fetch team members from the API for the given team UIDs."""
        members = {}
        
        if not context.vault.keeper_auth.auth_context.enterprise_ec_public_key:
            return members
            
        for team_uid in team_uids:
            try:
                request = enterprise_pb2.GetTeamMemberRequest()
                request.teamUid = utils.base64_url_decode(team_uid)
                
                response = context.vault.keeper_auth.execute_auth_rest(
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

    def _get_cached_team_members(team_uids: Set[str], username_lookup: Dict[str, str]) -> Dict[str, Set[str]]:
        """Get team members from cached enterprise data."""
        members = {}
        
        if not context.enterprise_data:
            return members

        team_user_links = context.enterprise_data.team_users.get_all_links() or []
        
        relevant_team_users = [
            link for link in team_user_links 
            if link.user_type != 2 and link.team_uid in team_uids
        ]

        for team_user in relevant_team_users:
            username = username_lookup.get(team_user.enterprise_user_id)
            if username:
                team_uid = team_user.team_uid
                if team_uid not in members:
                    members[team_uid] = set()
                members[team_uid].add(username)

        return members

    def _fetch_shared_folder_admins() -> Dict[str, List[str]]:
        """Fetch share administrators for all shared folders."""
        sf_uids = list(context.vault.vault_data._shared_folders.keys())
        return {
            sf_uid: get_share_admins_for_shared_folder(context.vault, sf_uid) or []
            for sf_uid in sf_uids
        }

    def _get_restricted_role_members(username_lookup: Dict[str, str]) -> Set[str]:
        """Get usernames with restricted sharing permissions."""
        if not context.enterprise_data:
            return set()

        role_enforcements = context.enterprise_data.role_enforcements.get_all_links()
        restricted_roles = {
            re.role_id for re in role_enforcements 
            if re.enforcement_type == 'enforcements' and re.value == 'restrict_sharing_all'
        }

        if not restricted_roles:
            return set()

        restricted_users = context.enterprise_data.role_users.get_links_by_object(restricted_roles)
        restricted_teams = context.enterprise_data.role_teams.get_links_by_object(restricted_roles)

        restricted_members = set()
        
        for user_link in restricted_users:
            username = username_lookup.get(user_link.enterprise_user_id)
            if username:
                restricted_members.add(username)

        team_uids = {team_link.team_uid for team_link in restricted_teams}
        if team_uids:
            team_members = _get_cached_team_members(team_uids, username_lookup)
            for members in team_members.values():
                restricted_members.update(members)

        return restricted_members

    try:
        shares = get_record_shares(context.vault, record_uids)
        
        sf_teams = [share.get('teams', []) for share in shares] if shares else []
        team_uids = {
            team.get('team_uid') 
            for teams in sf_teams 
            for team in teams 
            if team.get('team_uid')
        }

        enterprise_users = context.enterprise_data.users.get_all_entities() if context.enterprise_data else []
        username_lookup = {user.enterprise_user_id: user.username for user in enterprise_users}

        sf_share_admins = _fetch_shared_folder_admins() if not cache_only else {}

        restricted_role_members = _get_restricted_role_members(username_lookup)

        if cache_only or context.enterprise_data:
            team_members = _get_cached_team_members(team_uids, username_lookup)
        else:
            team_members = _fetch_team_members_from_api(team_uids)

        records = [context.vault.vault_data.get_record(uid) for uid in record_uids]
        valid_records = [record for record in records if record is not None]

        from .share_record import SharedRecord
        
        shared_records = [
            SharedRecord(record, sf_share_admins, team_members, restricted_role_members)
            for record in valid_records
        ]

        return {shared_record.record_uid: shared_record for shared_record in shared_records}

    except Exception as e:
        logger.error(f"Error in get_shared_records: {e}")
        return {}


def get_share_admins_for_shared_folder(vault: vault_online.VaultOnline, shared_folder_uid):
    if vault.keeper_auth.auth_context.enterprise_ec_public_key:
        try:
            rq = enterprise_pb2.GetSharingAdminsRequest()
            rq.sharedFolderUid = utils.base64_url_decode(shared_folder_uid)
            rs = vault.keeper_auth.execute_auth_rest(
                rest_endpoint=SHARING_ADMINS_ENDPOINT,
                request=rq,
                response_type=enterprise_pb2.GetSharingAdminsResponse
            )
            admins = [x.email for x in rs.userProfileExts if x.isShareAdminForSharedFolderOwner and x.isInSharedFolder]
        except Exception as e:
            logger.debug(e)
            return
        return admins


def get_folder_uids(context: KeeperParams, name: str) -> set[str]:
    """Get folder UIDs by name or path."""
    folder_uids = set()
    
    if not context.vault or not context.vault.vault_data:
        return folder_uids
    
    if name in context.vault.vault_data._folders:
        folder_uids.add(name)
        return folder_uids
    
    for folder in context.vault.vault_data.folders():
        if folder.name == name:
            folder_uids.add(folder.folder_uid)
    
    if not folder_uids:
        try:
            folder, _ = folder_utils.try_resolve_path(context, name)
            if folder:
                folder_uids.add(folder.folder_uid)
        except:
            pass
    
    return folder_uids


def get_contained_record_uids(vault: vault_online.VaultOnline, name: str, children_only: bool = True) -> Dict[str, Set[str]]:
    records_by_folder = dict()
    root_folder_uids = get_folder_uids(vault, name)

    def add_child_recs(f_uid):
        folder = vault.vault_data.get_folder(f_uid)
        child_recs = folder.records
        records_by_folder.update({f_uid: child_recs})

    def on_folder(f):
        f_uid = f.folder_uid or ''
        if not children_only or f_uid in root_folder_uids:
            add_child_recs(f_uid)

    for uid in root_folder_uids:
        folder = vault.vault_data.get_folder(uid)
        vault_utils.traverse_folder_tree(vault.vault_data, folder, on_folder)

    return records_by_folder
