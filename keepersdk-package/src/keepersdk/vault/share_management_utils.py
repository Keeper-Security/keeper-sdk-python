import datetime
import itertools
import json
import logging
from re import findall
from typing import Optional, Dict, List, Any, Generator, Iterable, Set, Tuple, Union

from .. import crypto, utils
from ..proto import enterprise_pb2, folder_pb2, record_pb2
from . import vault_data, storage_types, vault_online, vault_record, vault_types, vault_utils, sync_down
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


def parse_nsf_share_expiration(
        expire_at: Optional[str],
        expire_in: Optional[str]) -> Optional[int]:
    """Parse NSF TLA expiration as a millisecond timestamp (vault/records/v3/share)."""
    if not expire_at and not expire_in:
        return None
    value = get_share_expiration(expire_at, expire_in)
    if value == NEVER_EXPIRES:
        return NEVER_EXPIRES
    return value * 1000


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
) -> Set[str]:
    try:
        shared_folder = _find_shared_folder(vault, shared_folder_uid)
        if not shared_folder:
            raise ShareNotFoundError(f'Shared folder "{shared_folder_uid}" is not loaded.')
        
        shared_folder_key = vault.vault_data._shared_folders[shared_folder_uid].shared_folder_key
        record_keys = _decrypt_record_keys(vault, shared_folder, shared_folder_key)

        record_cache = {x.record_uid for x in vault.vault_data.records()}

        candidates = record_uids or record_keys.keys()
        record_set = {uid for uid in candidates if uid in record_keys and uid not in record_cache}

        loaded = _load_records_in_batches(vault, record_set, record_keys, shared_folder_uid)  # SF uid
        if loaded:
            changes = vault_data.RebuildTask(is_full_sync=False)
            changes.add_records(loaded)
            vault.vault_data.rebuild_data(changes)
        return loaded
        
    except ShareNotFoundError:
        raise
    except Exception as e:
        raise ShareManagementError(f"Failed to load records in shared folder: {e}") from e


def try_load_record_on_demand(vault: vault_online.VaultOnline, record_uid: str) -> bool:
    """
    Fetch and persist a record via vault/get_records_details when it is not in the
    local vault index (shared-folder metadata, personal record keys, or API key).
    """
    if not record_uid or vault.vault_data.get_record(record_uid):
        return vault.vault_data.get_record(record_uid) is not None

    for shared_folder_uid in _shared_folder_uids_for_record(vault, record_uid):
        try:
            load_records_in_shared_folder(vault, shared_folder_uid, {record_uid})
        except ShareManagementError as e:
            logger.debug('On-demand load for record "%s" in SF "%s": %s', record_uid, shared_folder_uid, e)
        if vault.vault_data.get_record(record_uid):
            return True

    plain_key = _get_plaintext_record_key_from_storage(vault, record_uid)
    record_keys = {record_uid: plain_key} if plain_key else {}
    encrypter_uid = vault.vault_data.storage.personal_scope_uid
    loaded = _load_records_in_batches(vault, {record_uid}, record_keys, encrypter_uid)
    if loaded:
        changes = vault_data.RebuildTask(is_full_sync=False)
        changes.add_records(loaded)
        vault.vault_data.rebuild_data(changes)
    return vault.vault_data.get_record(record_uid) is not None


def _get_plaintext_record_key_from_storage(
    vault: vault_online.VaultOnline, record_uid: str
) -> Optional[bytes]:
    for link in vault.vault_data.storage.record_keys.get_links_by_subject(record_uid):
        key = vault.vault_data.decrypt_record_key(link)
        if key:
            return key
    return None


def _resolve_record_key_for_details(
    vault: vault_online.VaultOnline,
    record_data,
    record_uid: str,
    record_keys: Dict[str, bytes],
) -> Optional[bytes]:
    _process_record_owner_key(record_data, record_uid, record_keys)
    if record_uid in record_keys and record_keys[record_uid]:
        return record_keys[record_uid]
    if not record_data.recordKey:
        return None
    try:
        return sync_down.decrypt_keeper_key(
            vault.keeper_auth.auth_context,
            record_data.recordKey,
            record_data.recordKeyType,
        )
    except Exception as e:
        logger.debug('Cannot resolve record key for "%s" from API: %s', record_uid, e)
        return None


def _shared_folder_uids_for_record(vault: vault_online.VaultOnline, record_uid: str) -> List[str]:
    sf_uids: List[str] = []
    seen: Set[str] = set()
    for link in vault.vault_data.storage.record_keys.get_links_by_subject(record_uid):
        if (link.key_type == storage_types.StorageKeyType.SharedFolderKey_AES_Any
                and link.encrypter_uid not in seen):
            seen.add(link.encrypter_uid)
            sf_uids.append(link.encrypter_uid)
    for sf_info in vault.vault_data.shared_folders():
        if sf_info.shared_folder_uid in seen:
            continue
        sf = vault.vault_data.load_shared_folder(shared_folder_uid=sf_info.shared_folder_uid)
        if sf and any(r.record_uid == record_uid for r in sf.record_permissions):
            seen.add(sf_info.shared_folder_uid)
            sf_uids.append(sf_info.shared_folder_uid)
    return sf_uids


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


def _load_records_in_batches(
    vault: vault_online.VaultOnline,
    record_set: Set[str],
    record_keys: Dict[str, bytes],
    key_encrypter_uid: str,
) -> Set[str]:

    loaded: Set[str] = set()
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
            
        batch_loaded = _process_record_batch(vault, response, record_keys, record_set, key_encrypter_uid)
        loaded.update(batch_loaded)
        record_set.difference_update({x.record_uid for x in vault.vault_data.records()})
    return loaded


def _process_record_owner_key(record_data: record_pb2.RecordData, record_uid: str, record_keys: Dict[str, bytes]):

    if record_data.recordUid and record_data.recordKey:
        owner_id = utils.base64_url_encode(record_data.recordUid)
        if owner_id in record_keys:
            record_keys[record_uid] = crypto.decrypt_aes_v2(
                record_data.recordKey, 
                record_keys[owner_id]
            )


def _process_record_batch(
    vault: vault_online.VaultOnline,
    response: record_pb2.GetRecordDataWithAccessInfoResponse,
    record_keys: Dict[str, bytes],
    record_set: set,
    key_encrypter_uid: str,
) -> Set[str]:

    batch_records: List[dict] = []
    for record_info in response.recordDataWithAccessInfo:
        record_uid = utils.base64_url_encode(record_info.recordUid)
        record_data = record_info.recordData
        
        try:
            record_key = _resolve_record_key_for_details(vault, record_data, record_uid, record_keys)
            if not record_key:
                continue
            record_keys[record_uid] = record_key
            version = record_data.version
            record = _create_record_dict(record_uid, record_data, record_key, version)
            
            _handle_record_versions(record, record_data, version)
            _add_share_permissions(record, record_info)
            record_set.update(_collect_typed_record_ref_uids(record))
            batch_records.append(record)
            
        except Exception as e:
            logger.debug('Error decrypting record "%s": %s', record_uid, e)

    return _persist_loaded_records(vault, batch_records, key_encrypter_uid)


def _create_record_dict(record_uid: str, record_data: record_pb2.RecordData, record_key: bytes, version: int) -> Dict:
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


def _decrypt_record_data(record_data: record_pb2.RecordData, record_key: bytes, version: int) -> bytes:

    data_decoded = utils.base64_url_decode(record_data.encryptedRecordData)
    
    if version <= MAX_V2_VERSION:
        return crypto.decrypt_aes_v1(data_decoded, record_key)
    else:
        return crypto.decrypt_aes_v2(data_decoded, record_key)


def _process_v2_extra_data(record: Dict, record_data: record_pb2.RecordData, record_key: bytes):

    if record_data.encryptedExtraData:
        record['extra'] = record_data.encryptedExtraData
        extra_decoded = utils.base64_url_decode(record_data.encryptedExtraData)
        record['extra_unencrypted'] = crypto.decrypt_aes_v1(extra_decoded, record_key)


def _collect_typed_record_ref_uids(record: Dict) -> Set[str]:
    version = record.get('version', 0)
    if version < V3_VERSION or version == V4_VERSION:
        return set()
    data_unencrypted = record.get('data_unencrypted')
    if not data_unencrypted:
        return set()
    try:
        data_dict = json.loads(data_unencrypted.decode())
    except Exception:
        return set()
    extra_dict = None
    extra_unencrypted = record.get('extra_unencrypted')
    if extra_unencrypted:
        try:
            extra_dict = json.loads(extra_unencrypted.decode())
        except Exception:
            extra_dict = None
    typed = vault_record.TypedRecord()
    typed.record_uid = record['record_uid']
    typed.version = version
    typed.load_record_data(data_dict, extra_dict)
    refs: Set[str] = set()
    for ref in itertools.chain(typed.fields, typed.custom):
        if ref.type.endswith('Ref') and isinstance(ref.value, list):
            refs.update(ref.value)
    return refs


def _encrypted_field_to_bytes(value: Union[str, bytes]) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return utils.base64_url_decode(value)
    return b''


def _dict_to_storage_record(record: Dict) -> storage_types.StorageRecord:
    sr = storage_types.StorageRecord()
    sr.record_uid = record['record_uid']
    sr.revision = record.get('revision', 0)
    sr.version = record.get('version', 0)
    sr.modified_time = record.get('client_modified_time', 0)
    sr.shared = record.get('shared', False)
    sr.data = _encrypted_field_to_bytes(record['data'])
    if record.get('extra'):
        sr.extra = _encrypted_field_to_bytes(record['extra'])
    return sr


def _ensure_record_key_link(
    vault: vault_online.VaultOnline,
    record: Dict,
    key_encrypter_uid: str,
) -> None:
    record_uid = record['record_uid']
    if list(vault.vault_data.storage.record_keys.get_links_by_subject(record_uid)):
        return
    record_key = record.get('record_key_unencrypted')
    if not record_key:
        return
    srk = storage_types.StorageRecordKey()
    srk.record_uid = record_uid
    srk.encrypter_uid = key_encrypter_uid
    personal_uid = vault.vault_data.storage.personal_scope_uid
    if key_encrypter_uid == personal_uid:
        srk.key_type = storage_types.StorageKeyType.UserClientKey_AES_GCM
        srk.record_key = crypto.encrypt_aes_v2(
            record_key, vault.keeper_auth.auth_context.client_key
        )
    else:
        srk.key_type = storage_types.StorageKeyType.SharedFolderKey_AES_Any
        sf = vault.vault_data._shared_folders.get(key_encrypter_uid)
        if not sf:
            return
        srk.record_key = crypto.encrypt_aes_v2(record_key, sf.shared_folder_key)
    vault.vault_data.storage.record_keys.put_links([srk])


def _persist_loaded_records(
    vault: vault_online.VaultOnline,
    records: List[Dict],
    key_encrypter_uid: str,
) -> Set[str]:
    if not records:
        return set()
    storage_records: List[storage_types.StorageRecord] = []
    loaded: Set[str] = set()
    for record in records:
        if not record.get('data_unencrypted'):
            continue
        storage_records.append(_dict_to_storage_record(record))
        _ensure_record_key_link(vault, record, key_encrypter_uid)
        loaded.add(record['record_uid'])
    if storage_records:
        vault.vault_data.storage.records.put_entities(storage_records)
    return loaded


def _process_v4_record_metadata(record: Dict, record_data: record_pb2.RecordData):

    if record_data.fileSize > 0:
        record['file_size'] = record_data.fileSize
    if record_data.thumbnailSize > 0:
        record['thumbnail_size'] = record_data.thumbnailSize


def _process_record_owner_info(record: Dict, record_data: record_pb2.RecordData):

    if record_data.recordUid and record_data.recordKey:
        record['owner_uid'] = utils.base64_url_encode(record_data.recordUid)
        record['link_key'] = utils.base64_url_encode(record_data.recordKey)


def _handle_record_versions(record: Dict, record_data: record_pb2.RecordData, version: int) -> None:

    record_key = record['record_key_unencrypted']
    record['data_unencrypted'] = _decrypt_record_data(record_data, record_key, version)

    if version <= MAX_V2_VERSION:
        _process_v2_extra_data(record, record_data, record_key)
    elif version == V4_VERSION:
        _process_v4_record_metadata(record, record_data)
    
    _process_record_owner_info(record, record_data)


def _add_share_permissions(record: Dict, record_info: record_pb2.RecordDataWithAccessInfo):
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


def _needs_share_info(uid: str, record_cache: Dict[str, Any], is_share_admin: bool) -> bool:
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


_SHARED_FOLDER_TYPES: Tuple[str, ...] = ('shared_folder', 'shared_folder_folder')
_AM_I_SHARE_ADMIN_ENDPOINT = 'vault/am_i_share_admin'
_RECORDS_SHARE_UPDATE_ENDPOINT = 'vault/records_share_update'
_SHARED_FOLDER_UPDATE_V3_ENDPOINT = 'vault/shared_folder_update_v3'
_DIRECT_SHARE_BATCH_SIZE = 900
_SHARED_FOLDER_RECORD_BATCH_SIZE = 490
_SHARED_FOLDER_CHUNK_ELEMENT_LIMIT = 500


def _resolve_folder_for_permission(
    vault: vault_online.VaultOnline,
    folder_uid_or_path: Optional[str]
) -> vault_types.Folder:
    """Resolve folder from UID or path. Returns root folder if folder_uid_or_path is None or empty."""
    if not folder_uid_or_path or not folder_uid_or_path.strip():
        return vault.vault_data.root_folder
    name = folder_uid_or_path.strip()
    if name in vault.vault_data._folders:
        folder = vault.vault_data.get_folder(name)
        if folder:
            return folder
    folder, remaining = try_resolve_path(vault, name)
    if remaining:
        raise ShareNotFoundError(f'Folder "{folder_uid_or_path}" not found')
    return folder


def _get_folders_to_process(
    vault: vault_online.VaultOnline,
    start_folder: vault_types.Folder,
    recursive: bool
) -> List[vault_types.Folder]:
    """Return list of folders to process, optionally including all subfolders."""
    folders = [start_folder]
    if not recursive:
        return folders
    visited: Set[str] = {start_folder.folder_uid}
    pos = 0
    while pos < len(folders):
        folder = folders[pos]
        if folder.subfolders:
            for sub_uid in folder.subfolders:
                if sub_uid not in visited:
                    sub = vault.vault_data.get_folder(sub_uid)
                    if sub:
                        folders.append(sub)
                    visited.add(sub_uid)
        pos += 1
    return folders


def _get_share_admin_folders(
    vault: vault_online.VaultOnline,
    folders: List[vault_types.Folder]
) -> Set[str]:
    """Return set of shared folder UIDs where the current user is share admin."""
    shared_folder_uids: Set[str] = set()
    for folder in folders:
        uid = None
        if folder.folder_type == 'shared_folder':
            uid = folder.folder_uid
        elif folder.folder_type == 'shared_folder_folder':
            uid = folder.folder_scope_uid
        if uid and uid not in shared_folder_uids and uid in vault.vault_data._shared_folders:
            shared_folder_uids.add(uid)
    if not shared_folder_uids:
        return set()
    try:
        rq = record_pb2.AmIShareAdmin()
        for sf_uid in shared_folder_uids:
            osa = record_pb2.IsObjectShareAdmin()
            osa.uid = utils.base64_url_decode(sf_uid)
            osa.objectType = record_pb2.CHECK_SA_ON_SF
            rq.isObjectShareAdmin.append(osa)
        rs = vault.keeper_auth.execute_auth_rest(
            rest_endpoint=_AM_I_SHARE_ADMIN_ENDPOINT,
            request=rq,
            response_type=record_pb2.AmIShareAdmin
        )
        return {utils.base64_url_encode(osa.uid) for osa in rs.isObjectShareAdmin if osa.isAdmin}
    except Exception:
        return set()


def _get_shared_folder_uid(folder: vault_types.Folder) -> Optional[str]:
    """Get shared folder UID from a folder (for shared_folder or shared_folder_folder)."""
    if folder.folder_type == 'shared_folder':
        return folder.folder_uid
    if folder.folder_type == 'shared_folder_folder':
        return folder.folder_scope_uid
    return None


def _has_manage_records_permission(
    vault: vault_online.VaultOnline,
    shared_folder: vault_types.SharedFolder,
    shared_folder_uid: str,
    is_share_admin: bool
) -> bool:
    """Return True if current user can manage records in this shared folder."""
    if is_share_admin:
        return True
    account_uid = utils.base64_url_encode(vault.keeper_auth.auth_context.account_uid)
    username = vault.keeper_auth.auth_context.username
    if shared_folder.user_permissions:
        if shared_folder.user_permissions[0].user_uid == account_uid:
            return True
        user = next(
            (u for u in shared_folder.user_permissions if u.name == username),
            None
        )
        if user and user.manage_records:
            return True
    return False


def _needs_shared_folder_record_update(
    rp: vault_types.SharedFolderRecord,
    should_have: bool,
    change_edit: bool,
    change_share: bool
) -> bool:
    """Return True if this shared folder record permission should be updated."""
    if change_edit and (should_have != rp.can_edit):
        return True
    if change_share and (should_have != rp.can_share):
        return True
    return False


def _build_shared_folder_record_update(
    record_uid: str,
    shared_folder_uid: str,
    should_have: bool,
    change_edit: bool,
    change_share: bool
) -> Any:
    """Build SharedFolderUpdateRecord protobuf for one record in a shared folder."""
    cmd = folder_pb2.SharedFolderUpdateRecord()
    cmd.recordUid = utils.base64_url_decode(record_uid)
    cmd.sharedFolderUid = utils.base64_url_decode(shared_folder_uid)
    cmd.canEdit = (
        folder_pb2.BOOLEAN_TRUE if should_have else folder_pb2.BOOLEAN_FALSE
    ) if change_edit else folder_pb2.BOOLEAN_NO_CHANGE
    cmd.canShare = (
        folder_pb2.BOOLEAN_TRUE if should_have else folder_pb2.BOOLEAN_FALSE
    ) if change_share else folder_pb2.BOOLEAN_NO_CHANGE
    return cmd


def _process_direct_share_updates(
    vault: vault_online.VaultOnline,
    folders: List[vault_types.Folder],
    should_have: bool,
    change_edit: bool,
    change_share: bool
) -> List[Dict[str, Any]]:
    """Collect direct record-share permission updates (record shared to users)."""
    record_uids: Set[str] = set()
    for folder in folders:
        if folder.records:
            record_uids.update(folder.records)
    if not record_uids:
        return []
    shared_records = get_record_shares(vault, list(record_uids))
    if not shared_records:
        return []
    current_username = vault.keeper_auth.auth_context.username
    updates: List[Dict[str, Any]] = []
    for sr in shared_records:
        shares = sr.get('shares', {})
        user_permissions = shares.get('user_permissions', [])
        for up in user_permissions:
            if up.get('owner'):
                continue
            username = up.get('username')
            if username == current_username:
                continue
            needs = (change_edit and (should_have != up.get('editable'))) or (
                change_share and (should_have != up.get('shareable'))
            )
            if needs:
                updates.append({
                    'record_uid': sr.get('record_uid'),
                    'to_username': username,
                    'editable': should_have if change_edit else up.get('editable'),
                    'shareable': should_have if change_share else up.get('shareable'),
                })
    return updates


def _process_shared_folder_permission_updates(
    vault: vault_online.VaultOnline,
    folders: List[vault_types.Folder],
    should_have: bool,
    change_edit: bool,
    change_share: bool
) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    """Collect shared-folder record permission updates and skipped (no permission)."""
    share_admin = _get_share_admin_folders(vault, folders)
    account_uid = utils.base64_url_encode(vault.keeper_auth.auth_context.account_uid)
    updates: Dict[str, Dict[str, Any]] = {}
    skipped: Dict[str, Dict[str, Any]] = {}
    for folder in folders:
        if folder.folder_type not in _SHARED_FOLDER_TYPES:
            continue
        shared_folder_uid = _get_shared_folder_uid(folder)
        if not shared_folder_uid or shared_folder_uid not in vault.vault_data._shared_folders:
            continue
        is_share_admin = shared_folder_uid in share_admin
        shared_folder = vault.vault_data.load_shared_folder(shared_folder_uid)
        if not shared_folder:
            continue
        has_manage = _has_manage_records_permission(
            vault, shared_folder, shared_folder_uid, is_share_admin
        )
        container = updates if (is_share_admin or has_manage) else skipped
        if not shared_folder.record_permissions:
            continue
        record_uids = folder.records if folder.records else set()
        for rp in shared_folder.record_permissions:
            record_uid = rp.record_uid
            if record_uid not in record_uids:
                continue
            if record_uid in container.get(shared_folder_uid, {}):
                continue
            if _needs_shared_folder_record_update(rp, should_have, change_edit, change_share):
                container.setdefault(shared_folder_uid, {})
                container[shared_folder_uid][record_uid] = _build_shared_folder_record_update(
                    record_uid, shared_folder_uid, should_have, change_edit, change_share
                )
    # drop empty dicts
    updates = {k: v for k, v in updates.items() if v}
    skipped = {k: v for k, v in skipped.items() if v}
    return updates, skipped


def _to_shared_record_proto(item: Dict[str, Any]) -> Any:
    """Build SharedRecord protobuf for records_share_update."""
    sr = record_pb2.SharedRecord()
    sr.toUsername = item['to_username']
    sr.recordUid = utils.base64_url_decode(item['record_uid'])
    if 'editable' in item:
        sr.editable = item['editable']
    if 'shareable' in item:
        sr.shareable = item['shareable']
    return sr


def _execute_direct_share_updates(
    vault: vault_online.VaultOnline,
    updates: List[Dict[str, Any]]
) -> List[List[Any]]:
    """Apply direct record share permission updates. Returns list of error rows [record_uid, username, status, message]."""
    errors: List[List[Any]] = []
    while updates:
        batch = updates[:_DIRECT_SHARE_BATCH_SIZE]
        updates = updates[_DIRECT_SHARE_BATCH_SIZE:]
        rq = record_pb2.RecordShareUpdateRequest()
        rq.updateSharedRecord.extend(_to_shared_record_proto(x) for x in batch)
        rs = vault.keeper_auth.execute_auth_rest(
            rest_endpoint=_RECORDS_SHARE_UPDATE_ENDPOINT,
            request=rq,
            response_type=record_pb2.RecordShareUpdateResponse
        )
        for status in rs.updateSharedRecordStatus:
            if status.status.lower() != 'success':
                errors.append([
                    utils.base64_url_encode(status.recordUid),
                    status.username,
                    status.status.lower(),
                    status.message
                ])
    return errors


def _execute_shared_folder_updates(
    vault: vault_online.VaultOnline,
    updates: Dict[str, Dict[str, Any]]
) -> List[List[Any]]:
    """Apply shared folder record permission updates. Returns list of error rows [shared_folder_uid, record_uid, status]."""
    errors: List[List[Any]] = []
    requests: List[Any] = []
    for shared_folder_uid in updates:
        commands = list(updates[shared_folder_uid].values())
        while commands:
            batch = commands[:_SHARED_FOLDER_RECORD_BATCH_SIZE]
            commands = commands[_SHARED_FOLDER_RECORD_BATCH_SIZE:]
            rq = folder_pb2.SharedFolderUpdateV3Request()
            rq.sharedFolderUid = utils.base64_url_decode(shared_folder_uid)
            rq.forceUpdate = True
            rq.sharedFolderUpdateRecord.extend(batch)
            if batch:
                rq.fromTeamUid = batch[0].teamUid
            requests.append(rq)
    # Chunk for API size limits
    chunks: List[Dict[bytes, Any]] = []
    current: Dict[bytes, Any] = {}
    total = 0
    for rq in requests:
        if rq.sharedFolderUid in current:
            chunks.append(current)
            current = {}
            total = 0
        n = len(rq.sharedFolderUpdateRecord)
        if total + n > _SHARED_FOLDER_CHUNK_ELEMENT_LIMIT:
            chunks.append(current)
            current = {}
            total = 0
        current[rq.sharedFolderUid] = rq
        total += n
    if current:
        chunks.append(current)
    for chunk in chunks:
        rqs = folder_pb2.SharedFolderUpdateV3RequestV2()
        rqs.sharedFoldersUpdateV3.extend(chunk.values())
        rss = vault.keeper_auth.execute_auth_rest(
            rest_endpoint=_SHARED_FOLDER_UPDATE_V3_ENDPOINT,
            request=rqs,
            response_type=folder_pb2.SharedFolderUpdateV3ResponseV2,
            payload_version=1
        )
        for rs in rss.sharedFoldersUpdateV3Response:
            sf_uid = utils.base64_url_encode(rs.sharedFolderUid)
            for status in rs.sharedFolderUpdateRecordStatus:
                if status.status != 'success':
                    errors.append([sf_uid, utils.base64_url_encode(status.recordUid), status.status])
    return errors


def update_record_permissions(
    vault: vault_online.VaultOnline,
    action: str,
    can_share: bool = False,
    can_edit: bool = False,
    *,
    folder_uid_or_path: Optional[str] = None,
    recursive: bool = False,
    share_record: bool = True,
    share_folder: bool = True,
    dry_run: bool = False,
    sync_after: bool = True
) -> Dict[str, Any]:
    """Update record permissions (can_edit / can_share) in a folder and optionally its subfolders.

    Args:
        vault: Connected vault.
        action: ``'grant'`` or ``'revoke'``.
        can_share: Whether to change the "can share" permission.
        can_edit: Whether to change the "can edit" permission.
        folder_uid_or_path: Folder UID or path; if None or empty, uses root.
        recursive: If True, include all subfolders.
        share_record: If True, update direct record shares (record shared to users).
        share_folder: If True, update shared folder record permissions.
        dry_run: If True, do not apply changes; only compute and return planned updates.
        sync_after: If True and changes were applied, sync vault down after updates.

    Returns:
        Dict with keys:
        - ``direct_share_updates``: list of direct-share updates (each a dict with
          record_uid, to_username, editable, shareable).
        - ``shared_folder_updates``: dict shared_folder_uid -> { record_uid -> update_cmd }.
        - ``direct_share_errors``: list of error rows for direct share API (if not dry_run).
        - ``shared_folder_errors``: list of error rows for shared folder API (if not dry_run).
        - ``skipped_shared_folders``: shared folder UIDs skipped due to insufficient permissions.

    Raises:
        ShareValidationError: If neither can_share nor can_edit is True, or action is invalid.
        ShareNotFoundError: If folder_uid_or_path is not found.
    """
    if action not in ('grant', 'revoke'):
        raise ShareValidationError(f'Invalid action: {action!r}; use "grant" or "revoke"')
    if not can_share and not can_edit:
        raise ShareValidationError('Specify at least one of can_share or can_edit')
    should_have = action == 'grant'
    folder = _resolve_folder_for_permission(vault, folder_uid_or_path)
    folders = _get_folders_to_process(vault, folder, recursive)
    direct_share_updates: List[Dict[str, Any]] = []
    shared_folder_updates: Dict[str, Dict[str, Any]] = {}
    skipped_shared_folders: Dict[str, Dict[str, Any]] = {}
    if share_record:
        direct_share_updates = _process_direct_share_updates(
            vault, folders, should_have, can_edit, can_share
        )
    if share_folder:
        shared_folder_updates, skipped_shared_folders = _process_shared_folder_permission_updates(
            vault, folders, should_have, can_edit, can_share
        )
    result: Dict[str, Any] = {
        'direct_share_updates': direct_share_updates,
        'shared_folder_updates': shared_folder_updates,
        'direct_share_errors': [],
        'shared_folder_errors': [],
        'skipped_shared_folders': skipped_shared_folders,
    }
    if dry_run:
        return result
    if direct_share_updates:
        result['direct_share_errors'] = _execute_direct_share_updates(vault, direct_share_updates)
    if shared_folder_updates:
        result['shared_folder_errors'] = _execute_shared_folder_updates(vault, shared_folder_updates)
    if sync_after and (direct_share_updates or shared_folder_updates):
        vault.sync_down(True)
    return result


