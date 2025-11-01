import fnmatch
import json
import re
from .. import utils, crypto
from ..proto import folder_pb2, record_pb2
from ..vault import vault_online
from typing import Callable, Dict, Any, Optional, Tuple, Set, List

logger = utils.get_logger()

# Constants
BATCH_SIZE_LIMIT = 1000
MIN_RECORDS_FOR_BATCH = 100
PASSWORD_FIELD_TYPE = 'password'
AES_V2_KEY_LENGTH = 60
RECORD_VERSION_THRESHOLD = 3


class TrashManagement:
    """Manages deleted records, orphaned records, and shared folders in the trash.
    
    This class provides functionality to:
    - Load and cache deleted records from various sources
    - Decrypt and process shared folder data
    - Manage restoration of deleted items
    - Handle both regular and orphaned records
    
    Attributes:
        deleted_record_cache: Cache for regular deleted records
        orphaned_record_cache: Cache for orphaned records (non-access)
        deleted_shared_folder_cache: Cache for deleted shared folders and their records
    """
    
    deleted_record_cache: Dict[str, Any] = {}
    orphaned_record_cache: Dict[str, Any] = {}
    deleted_shared_folder_cache: Dict[str, Any] = {}

    @staticmethod
    def _ensure_deleted_records_loaded(vault: vault_online.VaultOnline) -> None:
        """Load and cache all deleted records, orphaned records, and shared folders.
        
        This method orchestrates the loading of all trash data from different sources:
        - Deleted shared folders and their records from REST API
        - Regular deleted records from command API
        - Orphaned records from command API
        
        Args:
            vault: The vault instance to load deleted records from
        """
        # Load deleted shared folders and records
        folder_response = TrashManagement._fetch_deleted_shared_folders_and_records(vault)
        if not folder_response:
            return
            
        users = TrashManagement._extract_users(folder_response)
        folder_keys = TrashManagement._build_folder_keys(vault)
        
        # Process shared folders
        folders = TrashManagement._process_shared_folders(folder_response, vault, folder_keys)
        
        # Process shared folder records
        record_keys = TrashManagement._process_shared_folder_records(
            folder_response, folder_keys
        )
        
        # Process deleted record data
        records = TrashManagement._process_deleted_record_data(
            folder_response, record_keys, users
        )
        
        # Update shared folder cache
        TrashManagement._update_shared_folder_cache(folders, records)
        
        # Load and process deleted records from command
        TrashManagement._load_deleted_records_from_command(vault)

    @staticmethod
    def _fetch_deleted_shared_folders_and_records(vault: vault_online.VaultOnline) -> Optional[folder_pb2.GetDeletedSharedFoldersAndRecordsResponse]:
        """Fetch deleted shared folders and records from the server."""
        return vault.keeper_auth.execute_auth_rest(
            rest_endpoint='vault/get_deleted_shared_folders_and_records',
            request=None,
            response_type=folder_pb2.GetDeletedSharedFoldersAndRecordsResponse
        )

    @staticmethod
    def _extract_users(folder_response: folder_pb2.GetDeletedSharedFoldersAndRecordsResponse) -> Dict[str, str]:
        """Extract user mapping from the folder response."""
        return {
            utils.base64_url_encode(x.accountUid): x.username 
            for x in folder_response.usernames
        }

    @staticmethod
    def _build_folder_keys(vault: vault_online.VaultOnline) -> Dict[str, Tuple[bytes, str]]:
        """Build initial folder keys from existing shared folders."""
        folder_keys = {}
        for shared_folder_uid, sf in vault.vault_data._shared_folders.items():
            if sf.shared_folder_key:
                folder_keys[shared_folder_uid] = (sf.shared_folder_key, shared_folder_uid)
        return folder_keys

    @staticmethod
    def _decrypt_folder_key(sf: Any, vault: vault_online.VaultOnline, folder_keys: Dict[str, Tuple[bytes, str]]) -> Optional[bytes]:
        """Decrypt folder key based on encryption type."""
        try:
            return TrashManagement._decrypt_folder_key_by_type(sf, vault, folder_keys)
        except Exception as e:
            logger.debug('Folder key decryption failed: %s', e)
            return None

    @staticmethod
    def _decrypt_folder_key_by_type(sf: Any, vault: vault_online.VaultOnline, folder_keys: Dict[str, Tuple[bytes, str]]) -> Optional[bytes]:
        """Decrypt folder key based on specific encryption type."""
        key_type = sf.folderKeyType
        encrypted_key = sf.sharedFolderKey
        auth_context = vault.keeper_auth.auth_context
        
        # Direct key decryption
        if key_type == record_pb2.ENCRYPTED_BY_DATA_KEY:
            return crypto.decrypt_aes_v1(encrypted_key, auth_context.data_key)
        elif key_type == record_pb2.ENCRYPTED_BY_PUBLIC_KEY:
            return crypto.decrypt_rsa(encrypted_key, auth_context.rsa_private_key)
        elif key_type == record_pb2.ENCRYPTED_BY_DATA_KEY_GCM:
            return crypto.decrypt_aes_v2(encrypted_key, auth_context.data_key)
        elif key_type == record_pb2.ENCRYPTED_BY_PUBLIC_KEY_ECC:
            return crypto.decrypt_ec(encrypted_key, auth_context.ec_private_key)
        
        # Root key decryption
        elif key_type in (record_pb2.ENCRYPTED_BY_ROOT_KEY_CBC, record_pb2.ENCRYPTED_BY_ROOT_KEY_GCM):
            return TrashManagement._decrypt_with_root_key(sf, folder_keys)
        
        return None

    @staticmethod
    def _decrypt_with_root_key(sf: Any, folder_keys: Dict[str, Tuple[bytes, str]]) -> Optional[bytes]:
        """Decrypt folder key using root key."""
        shared_folder_uid = utils.base64_url_encode(sf.sharedFolderUid)
        if shared_folder_uid not in folder_keys:
            return None
        
        shared_folder_key, _ = folder_keys[shared_folder_uid]
        
        if sf.folderKeyType == record_pb2.ENCRYPTED_BY_ROOT_KEY_CBC:
            return crypto.decrypt_aes_v1(sf.sharedFolderKey, shared_folder_key)
        elif sf.folderKeyType == record_pb2.ENCRYPTED_BY_ROOT_KEY_GCM:
            return crypto.decrypt_aes_v2(sf.sharedFolderKey, shared_folder_key)
        
        return None

    @staticmethod
    def _process_shared_folders(folder_response: folder_pb2.GetDeletedSharedFoldersAndRecordsResponse, 
                               vault: vault_online.VaultOnline, 
                               folder_keys: Dict[str, Tuple[bytes, str]]) -> Dict[str, Dict[str, Any]]:
        """Process and decrypt shared folders."""
        folders = {}
        
        for shared_folder in folder_response.sharedFolders:
            folder_data = TrashManagement._process_single_shared_folder(shared_folder, vault, folder_keys)
            if folder_data:
                folder_uid = folder_data['folder_uid']
                folders[folder_uid] = folder_data
                
        return folders

    @staticmethod
    def _process_single_shared_folder(sf: Any, vault: vault_online.VaultOnline, folder_keys: Dict[str, Tuple[bytes, str]]) -> Optional[Dict[str, Any]]:
        """Process a single shared folder."""
        shared_folder_uid = utils.base64_url_encode(sf.sharedFolderUid)
        folder_uid = utils.base64_url_encode(sf.folderUid)
        
        folder_key = TrashManagement._decrypt_folder_key(sf, vault, folder_keys)
        if folder_key is None:
            return None
            
        try:
            folder_keys[folder_uid] = (folder_key, shared_folder_uid)
            decrypted_data = crypto.decrypt_aes_v1(sf.data, folder_key)
            
            folder_dict = TrashManagement._create_folder_dict(sf, shared_folder_uid, folder_uid, folder_key, decrypted_data)
            return folder_dict
            
        except Exception as e:
            logger.debug('Shared folder data decryption failed: %s', e)
            return None

    @staticmethod
    def _create_folder_dict(sf: Any, shared_folder_uid: str, folder_uid: str, folder_key: bytes, decrypted_data: bytes) -> Dict[str, Any]:
        """Create folder dictionary with all necessary data."""
        folder_dict = {
            'shared_folder_uid': shared_folder_uid,
            'folder_uid': folder_uid,
            'data': utils.base64_url_encode(sf.data),
            'data_unencrypted': decrypted_data,
            'folder_key_unencrypted': folder_key,
            'date_deleted': sf.dateDeleted,
        }
        
        if len(sf.parentUid) > 0:
            folder_dict['parent_uid'] = utils.base64_url_encode(sf.parentUid)
            
        return folder_dict

    @staticmethod
    def _process_shared_folder_records(folder_response: folder_pb2.GetDeletedSharedFoldersAndRecordsResponse,
                                      folder_keys: Dict[str, Tuple[bytes, str]]) -> Dict[str, Tuple[bytes, str, int]]:
        """Process and decrypt shared folder record keys."""
        record_keys = {}
        
        for record_key_data in folder_response.sharedFolderRecords:
            record_key_info = TrashManagement._process_single_shared_folder_record(record_key_data, folder_keys)
            if record_key_info:
                record_uid, key_data = record_key_info
                record_keys[record_uid] = key_data
                
        return record_keys

    @staticmethod
    def _process_single_shared_folder_record(rk: Any, folder_keys: Dict[str, Tuple[bytes, str]]) -> Optional[Tuple[str, Tuple[bytes, str, int]]]:
        """Process a single shared folder record key."""
        folder_uid = utils.base64_url_encode(rk.folderUid)
        if folder_uid not in folder_keys:
            return None
            
        _, shared_folder_uid = folder_keys[folder_uid]
        if shared_folder_uid not in folder_keys:
            return None
            
        folder_key, _ = folder_keys[shared_folder_uid]
        record_uid = utils.base64_url_encode(rk.recordUid)
        
        try:
            record_key = TrashManagement._decrypt_shared_record_key(rk.sharedRecordKey, folder_key)
            return record_uid, (record_key, folder_uid, rk.dateDeleted)
            
        except Exception as e:
            logger.debug('Record "%s" key decryption failed: %s', record_uid, e)
            return None

    @staticmethod
    def _decrypt_shared_record_key(encrypted_key: bytes, folder_key: bytes) -> bytes:
        """Decrypt shared record key based on key length."""

        if len(encrypted_key) == AES_V2_KEY_LENGTH:
            return crypto.decrypt_aes_v2(encrypted_key, folder_key)
        else:
            return crypto.decrypt_aes_v1(encrypted_key, folder_key)

    @staticmethod
    def _process_deleted_record_data(folder_response: folder_pb2.GetDeletedSharedFoldersAndRecordsResponse,
                                   record_keys: Dict[str, Tuple[bytes, str, int]],
                                   users: Dict[str, str]) -> Dict[str, Dict[str, Any]]:
        """Process and decrypt deleted record data."""
        records = {}
        
        for record_data in folder_response.deletedRecordData:
            record_info = TrashManagement._process_single_deleted_record(record_data, record_keys, users)
            if record_info:
                record_uid, record_dict = record_info
                records[record_uid] = record_dict
                
        return records

    @staticmethod
    def _process_single_deleted_record(r: Any, record_keys: Dict[str, Tuple[bytes, str, int]], users: Dict[str, str]) -> Optional[Tuple[str, Dict[str, Any]]]:
        """Process a single deleted record."""
        record_uid = utils.base64_url_encode(r.recordUid)
        if record_uid not in record_keys:
            return None
            
        record_key, folder_uid, time_deleted = record_keys[record_uid]
        
        try:
            decrypted_data = TrashManagement._decrypt_record_data_by_version(r.data, r.version, record_key)
            record_dict = TrashManagement._create_record_dict(r, record_uid, folder_uid, time_deleted, record_key, decrypted_data, users)
            return record_uid, record_dict
            
        except Exception as e:
            logger.debug('Record "%s" data decryption failed: %s', record_uid, e)
            return None

    @staticmethod
    def _decrypt_record_data_by_version(encrypted_data: bytes, version: int, record_key: bytes) -> bytes:
        """Decrypt record data based on version."""
        if version < RECORD_VERSION_THRESHOLD:
            return crypto.decrypt_aes_v1(encrypted_data, record_key)
        else:
            return crypto.decrypt_aes_v2(encrypted_data, record_key)

    @staticmethod
    def _create_record_dict(r: Any, record_uid: str, folder_uid: str, time_deleted: int, record_key: bytes, decrypted_data: bytes, users: Dict[str, str]) -> Dict[str, Any]:
        """Create record dictionary with all necessary data."""
        return {
            'record_uid': record_uid,
            'folder_uid': folder_uid,
            'revision': r.revision,
            'version': r.version,
            'owner': users.get(utils.base64_url_encode(r.ownerUid)),
            'client_modified_time': r.clientModifiedTime,
            'date_deleted': time_deleted,
            'data': utils.base64_url_encode(r.data),
            'data_unencrypted': decrypted_data,
            'record_key_unencrypted': record_key,
        }

    @staticmethod
    def _update_shared_folder_cache(folders: Dict[str, Dict[str, Any]], 
                                  records: Dict[str, Dict[str, Any]]) -> None:
        """Update the shared folder cache with processed data."""
        cache = TrashManagement.deleted_shared_folder_cache
        cache.clear()
        
        if folders:
            cache['folders'] = folders
        if records:
            cache['records'] = records

    @staticmethod
    def _decrypt_record_key(record: Dict[str, Any], vault: vault_online.VaultOnline) -> Optional[bytes]:
        """Decrypt record key based on key type."""
        try:
            key_type = record['record_key_type']
            record_key = utils.base64_url_decode(record['record_key'])
            
            if key_type == 1:
                return crypto.decrypt_aes_v1(record_key, vault.keeper_auth.auth_context.data_key)
            elif key_type == 2:
                return crypto.decrypt_rsa(record_key, vault.keeper_auth.auth_context.rsa_private_key)
            elif key_type == 3:
                return crypto.decrypt_aes_v2(record_key, vault.keeper_auth.auth_context.data_key)
            elif key_type == 4:
                return crypto.decrypt_ec(record_key, vault.keeper_auth.auth_context.ec_private_key)
            else:
                logger.debug('Unknown record key type %d for record %s', key_type, record['record_uid'])
                return None
                
        except Exception as e:
            logger.debug('Record key decryption failed for %s: %s', record['record_uid'], e)
            return None

    @staticmethod
    def _decrypt_record_data(record: Dict[str, Any], record_key: bytes) -> Optional[bytes]:
        """Decrypt record data using the provided key."""
        try:
            data = utils.base64_url_decode(record['data'])
            version = record['version']
            
            if version >= 3:
                return crypto.decrypt_aes_v2(data, record_key)
            else:
                return crypto.decrypt_aes_v1(data, record_key)
                
        except Exception as e:
            logger.debug('Record data decryption failed for %s: %s', record['record_uid'], e)
            return None

    @staticmethod
    def _load_deleted_records_from_command(vault: vault_online.VaultOnline) -> None:
        """Load deleted records using the get_deleted_records command."""
        request = {
            'command': 'get_deleted_records',
            'client_time': utils.current_milli_time()
        }
        
        response = vault.keeper_auth.execute_auth_command(request)
        
        # Process both regular and orphaned records
        TrashManagement._process_deleted_records_response(response, 'records', TrashManagement.deleted_record_cache, vault)
        TrashManagement._process_deleted_records_response(response, 'non_access_records', TrashManagement.orphaned_record_cache, vault)

    @staticmethod
    def _process_deleted_records_response(response: Dict[str, Any], record_type: str, cache: Dict[str, Any], vault: vault_online.VaultOnline) -> None:
        """Process deleted records response for a specific record type."""
        if record_type not in response:
            return
            
        deleted_uids = set()
        
        for record in response[record_type]:
            record_uid = record['record_uid']
            deleted_uids.add(record_uid)
            
            if record_uid in cache:
                continue
                
            if TrashManagement._process_single_deleted_record_from_command(record, vault):
                cache[record_uid] = record
        
        # Remove records that are no longer in the deleted list
        TrashManagement._cleanup_removed_records(cache, deleted_uids)

    @staticmethod
    def _process_single_deleted_record_from_command(record: Dict[str, Any], vault: vault_online.VaultOnline) -> bool:
        """Process a single deleted record from command response."""
        record_key = TrashManagement._decrypt_record_key(record, vault)
        if record_key is None:
            return False
            
        record['record_key_unencrypted'] = record_key
        
        decrypted_data = TrashManagement._decrypt_record_data(record, record_key)
        if decrypted_data is None:
            return False
            
        record['data_unencrypted'] = decrypted_data
        return True

    @staticmethod
    def _cleanup_removed_records(cache: Dict[str, Any], current_uids: Set[str]) -> None:
        """Remove records from cache that are no longer in the deleted list."""
        for record_uid in list(cache.keys()):
            if record_uid not in current_uids:
                del cache[record_uid]

    @staticmethod
    def get_deleted_records() -> Dict[str, Any]:
        """Get all deleted records from cache."""
        return TrashManagement.deleted_record_cache

    @staticmethod
    def get_orphaned_records() -> Dict[str, Any]:
        """Get all orphaned records from cache."""
        return TrashManagement.orphaned_record_cache

    @staticmethod
    def get_shared_folders() -> Dict[str, Any]:
        """Get all deleted shared folders from cache."""
        return TrashManagement.deleted_shared_folder_cache


def get_trash_record(vault: vault_online.VaultOnline, record_uid: str) -> Tuple[Optional[Dict[str, Any]], bool]:
    TrashManagement._ensure_deleted_records_loaded(vault)
    deleted_records = TrashManagement.get_deleted_records()
    orphaned_records = TrashManagement.get_orphaned_records()
    if len(deleted_records) == 0 and len(orphaned_records) == 0:
        logger.info('Trash is empty')
        return None, False

    is_shared = False
    record = deleted_records.get(record_uid)
    if not record:
        record = orphaned_records.get(record_uid)
        is_shared = True

    if not record:
        raise ValueError(f'{record_uid} is not a valid deleted record UID')

    return record, is_shared


def restore_trash_records(vault: vault_online.VaultOnline, records: List[str], confirm: Optional[Callable[[str], str]] = None) -> None:
    """Restore deleted records from trash.
    
    Args:
        vault: The vault instance
        records: List of record UIDs or patterns to restore
        confirm: Optional confirmation function
    """
    # Load all trash data
    trash_data = _load_trash_data(vault)
    if _is_trash_empty(trash_data):
        logger.info('Trash is empty')
        return

    # Identify records and folders to restore
    restore_plan = _create_restore_plan(records, trash_data)
    if _is_restore_plan_empty(restore_plan):
        logger.info('There are no records to restore')
        return

    # Confirm restoration if needed
    if confirm and not _confirm_restoration(restore_plan, confirm):
        return

    # Execute restoration
    _execute_record_restoration(vault, restore_plan, trash_data)
    _execute_shared_folder_restoration(vault, restore_plan)
    _post_restore_processing(vault, restore_plan, trash_data)


def _load_trash_data(vault: vault_online.VaultOnline) -> Dict[str, Any]:
    """Load all trash data from various sources."""
    TrashManagement._ensure_deleted_records_loaded(vault)
    shared_folders = TrashManagement.get_shared_folders()
    
    return {
        'deleted_records': TrashManagement.get_deleted_records(),
        'orphaned_records': TrashManagement.get_orphaned_records(),
        'deleted_shared_records': shared_folders.get('records', {}),
        'deleted_shared_folders': shared_folders.get('folders', {})
    }


def _is_trash_empty(trash_data: Dict[str, Any]) -> bool:
    """Check if trash is empty."""
    return (len(trash_data['deleted_records']) == 0 and 
            len(trash_data['orphaned_records']) == 0 and 
            len(trash_data['deleted_shared_records']) == 0 and 
            len(trash_data['deleted_shared_folders']) == 0)


def _create_restore_plan(records: List[str], trash_data: Dict[str, Any]) -> Dict[str, Any]:
    """Create a plan for what to restore based on the input records."""
    records_to_restore: Set[str] = set()
    folders_to_restore: Set[str] = set()
    folder_records_to_restore: Dict[str, List[str]] = {}
    
    for record_id in records:
        _process_single_record_for_restore(
            record_id, trash_data, records_to_restore, 
            folders_to_restore, folder_records_to_restore
        )
    
    # Remove folder records if the entire folder is being restored
    for folder_uid in folders_to_restore:
        folder_records_to_restore.pop(folder_uid, None)
    
    return {
        'records_to_restore': records_to_restore,
        'folders_to_restore': folders_to_restore,
        'folder_records_to_restore': folder_records_to_restore
    }


def _process_single_record_for_restore(
    record_id: str, 
    trash_data: Dict[str, Any], 
    records_to_restore: Set[str], 
    folders_to_restore: Set[str], 
    folder_records_to_restore: Dict[str, List[str]]
) -> None:
    """Process a single record ID to determine what should be restored."""
    deleted_records = trash_data['deleted_records']
    orphaned_records = trash_data['orphaned_records']
    deleted_shared_records = trash_data['deleted_shared_records']
    deleted_shared_folders = trash_data['deleted_shared_folders']
    
    # Direct UID matches
    if record_id in deleted_records or record_id in orphaned_records:
        records_to_restore.add(record_id)
    elif record_id in deleted_shared_records:
        _add_shared_record_to_restore(record_id, deleted_shared_records, folder_records_to_restore)
    elif record_id in deleted_shared_folders:
        folders_to_restore.add(record_id)
    else:
        # Pattern matching
        _process_pattern_matching(
            record_id, trash_data, records_to_restore, 
            folders_to_restore, folder_records_to_restore
        )


def _add_shared_record_to_restore(
    record_id: str, 
    deleted_shared_records: Dict[str, Any], 
    folder_records_to_restore: Dict[str, List[str]]
) -> None:
    """Add a shared record to the restore plan."""
    shared_record = deleted_shared_records.get(record_id)
    folder_uid = shared_record.get('folder_uid')
    record_uid = shared_record.get('record_uid')
    
    if folder_uid and record_uid:
        if folder_uid not in folder_records_to_restore:
            folder_records_to_restore[folder_uid] = []
        folder_records_to_restore[folder_uid].append(record_uid)


def _process_pattern_matching(
    pattern: str, 
    trash_data: Dict[str, Any], 
    records_to_restore: Set[str], 
    folders_to_restore: Set[str], 
    folder_records_to_restore: Dict[str, List[str]]
) -> None:
    """Process pattern matching for record titles."""
    title_pattern = re.compile(fnmatch.translate(pattern), re.IGNORECASE)
    
    # Match regular deleted records
    _match_records_by_title(trash_data['deleted_records'], title_pattern, records_to_restore)
    _match_records_by_title(trash_data['orphaned_records'], title_pattern, records_to_restore)
    
    # Match shared records
    _match_shared_records_by_title(trash_data['deleted_shared_records'], title_pattern, folder_records_to_restore)
    
    # Match shared folders
    _match_folders_by_title(trash_data['deleted_shared_folders'], title_pattern, folders_to_restore)


def _match_records_by_title(records: Dict[str, Any], pattern: re.Pattern, records_to_restore: Set[str]) -> None:
    """Match records by title pattern."""
    for record_uid, record in records.items():
        if record_uid in records_to_restore:
            continue
        if _record_title_matches(record, pattern):
            records_to_restore.add(record_uid)


def _match_shared_records_by_title(
    shared_records: Dict[str, Any], 
    pattern: re.Pattern, 
    folder_records_to_restore: Dict[str, List[str]]
) -> None:
    """Match shared records by title pattern."""
    for record_uid, shared_record in shared_records.items():
        if record_uid in folder_records_to_restore:
            continue
        if _record_title_matches(shared_record, pattern):
            folder_uid = shared_record.get('folder_uid')
            if folder_uid:
                if folder_uid not in folder_records_to_restore:
                    folder_records_to_restore[folder_uid] = []
                folder_records_to_restore[folder_uid].append(record_uid)


def _match_folders_by_title(folders: Dict[str, Any], pattern: re.Pattern, folders_to_restore: Set[str]) -> None:
    """Match folders by name pattern."""
    for folder_uid, folder in folders.items():
        if folder_uid in folders_to_restore:
            continue
        if _folder_name_matches(folder, pattern, folder_uid):
            folders_to_restore.add(folder_uid)


def _record_title_matches(record: Dict[str, Any], pattern: re.Pattern) -> bool:
    """Check if a record's title matches the pattern."""
    try:
        record_data_json = record.get('data_unencrypted')
        if not record_data_json:
            return False
        record_data = json.loads(record_data_json)
        title = record_data.get('title', '')
        return pattern.match(title) is not None
    except (json.JSONDecodeError, KeyError):
        return False


def _folder_name_matches(folder: Dict[str, Any], pattern: re.Pattern, folder_uid: str) -> bool:
    """Check if a folder's name matches the pattern."""
    try:
        data_json = folder.get('data_unencrypted')
        if not data_json:
            return False
        data = json.loads(data_json)
        folder_name = data.get('name') or folder_uid
        return pattern.match(folder_name) is not None
    except (json.JSONDecodeError, KeyError):
        return False


def _is_restore_plan_empty(restore_plan: Dict[str, Any]) -> bool:
    """Check if the restore plan is empty."""
    record_count = len(restore_plan['records_to_restore'])
    for folder_records in restore_plan['folder_records_to_restore'].values():
        record_count += len(folder_records)
    folder_count = len(restore_plan['folders_to_restore'])
    
    return record_count == 0 and folder_count == 0


def _confirm_restoration(restore_plan: Dict[str, Any], confirm_func: Callable[[str], str]) -> bool:
    """Confirm restoration with the user."""
    record_count = len(restore_plan['records_to_restore'])
    for folder_records in restore_plan['folder_records_to_restore'].values():
        record_count += len(folder_records)
    folder_count = len(restore_plan['folders_to_restore'])
    
    to_restore = []
    if record_count > 0:
        to_restore.append(f'{record_count} record(s)')
    if folder_count > 0:
        to_restore.append(f'{folder_count} folder(s)')
    
    question = f'Do you want to restore {" and ".join(to_restore)}?'
    answer = confirm_func(question)
    
    if answer.lower() == 'y':
        answer = 'yes'
    return answer.lower() == 'yes'


def _execute_record_restoration(vault: vault_online.VaultOnline, restore_plan: Dict[str, Any], trash_data: Dict[str, Any]) -> None:
    """Execute restoration of regular records."""
    records_to_restore = restore_plan['records_to_restore']
    if not records_to_restore:
        return
    
    deleted_records = trash_data['deleted_records']
    orphaned_records = trash_data['orphaned_records']
    
    batch = []
    for record_uid in records_to_restore:
        record = deleted_records.get(record_uid) or orphaned_records.get(record_uid)
        request = {
            'command': 'undelete_record',
            'record_uid': record_uid,
        }
        if 'revision' in record:
            request['revision'] = record['revision']
        batch.append(request)
    
    vault.keeper_auth.execute_batch(batch)


def _execute_shared_folder_restoration(vault: vault_online.VaultOnline, restore_plan: Dict[str, Any]) -> None:
    """Execute restoration of shared folders and their records."""
    folders_to_restore = restore_plan['folders_to_restore']
    folder_records_to_restore = restore_plan['folder_records_to_restore']
    
    if not folders_to_restore and not folder_records_to_restore:
        return
    
    shared_folder_requests = _create_shared_folder_requests(folders_to_restore)
    shared_folder_record_requests = _create_shared_folder_record_requests(folder_records_to_restore)
    
    _process_shared_folder_batches(vault, shared_folder_requests, shared_folder_record_requests)


def _create_shared_folder_requests(folders_to_restore: Set[str]) -> List[folder_pb2.RestoreSharedObject]:
    """Create requests for restoring shared folders."""
    requests = []
    for folder_uid in folders_to_restore:
        request = folder_pb2.RestoreSharedObject()
        request.folderUid = utils.base64_url_decode(folder_uid)
        requests.append(request)
    return requests


def _create_shared_folder_record_requests(folder_records_to_restore: Dict[str, List[str]]) -> List[folder_pb2.RestoreSharedObject]:
    """Create requests for restoring shared folder records."""
    requests = []
    for folder_uid, record_uids in folder_records_to_restore.items():
        request = folder_pb2.RestoreSharedObject()
        request.folderUid = utils.base64_url_decode(folder_uid)
        request.recordUids.extend((utils.base64_url_decode(uid) for uid in record_uids))
        requests.append(request)
    return requests


def _process_shared_folder_batches(
    vault: vault_online.VaultOnline, 
    shared_folder_requests: List[folder_pb2.RestoreSharedObject], 
    shared_folder_record_requests: List[folder_pb2.RestoreSharedObject]
) -> None:
    """Process shared folder restoration in batches."""
    while shared_folder_requests or shared_folder_record_requests:
        request = folder_pb2.RestoreDeletedSharedFoldersAndRecordsRequest()
        remaining_space = BATCH_SIZE_LIMIT
        
        # Add folder requests
        if shared_folder_requests:
            chunk_size = min(len(shared_folder_requests), remaining_space)
            chunk = shared_folder_requests[:chunk_size]
            shared_folder_requests = shared_folder_requests[chunk_size:]
            remaining_space -= len(chunk)
            request.folders.extend(chunk)
        
        # Add record requests if there's space
        if shared_folder_record_requests and remaining_space > MIN_RECORDS_FOR_BATCH:
            chunk_size = min(len(shared_folder_record_requests), remaining_space)
            chunk = shared_folder_record_requests[:chunk_size]
            shared_folder_record_requests = shared_folder_record_requests[chunk_size:]
            request.records.extend(chunk)
        
        vault.keeper_auth.execute_auth_rest(
            rest_endpoint='vault/restore_deleted_shared_folders_and_records',
            request=request,
            response_type=None
        )


def _post_restore_processing(vault: vault_online.VaultOnline, restore_plan: Dict[str, Any], trash_data: Dict[str, Any]) -> None:
    """Perform post-restoration processing like breach watch scanning."""
    vault.sync_down()
    
    records_to_restore = restore_plan['records_to_restore']
    if not records_to_restore:
        return
    
    deleted_records = trash_data['deleted_records']
    orphaned_records = trash_data['orphaned_records']
    breach_watch = vault.breach_watch_plugin()
    
    for record_uid in records_to_restore:
        record_key = vault.vault_data.get_record_key(record_uid)
        record = deleted_records.get(record_uid) or orphaned_records.get(record_uid)
        password = _extract_password_from_record(record)
        
        breach_watch.scan_and_store_record_status(record_uid, record_key, password)
        vault.client_audit_event_plugin().schedule_audit_event('record_restored', record_uid=record_uid)
    
    vault.sync_down()


def _extract_password_from_record(record: Dict[str, Any]) -> Optional[str]:
    """Extract password from record data."""
    try:
        record_data_json = record.get('data_unencrypted')
        if not record_data_json:
            return None
        
        record_data = json.loads(record_data_json)
        fields = record_data.get('fields', {})
        
        for field in fields:
            if field.get('type') == PASSWORD_FIELD_TYPE:
                password = field.get('value')
                if isinstance(password, list):
                    password = password[0]
                return password
        return None
    except (json.JSONDecodeError, KeyError):
        return None


def purge_trash(vault: vault_online.VaultOnline) -> None:
    """Permanently delete all records in trash.
    
    Args:
        vault: The vault instance
    """
    request = {
        'command': 'purge_deleted_records'
    }
    vault.keeper_auth.execute_auth_command(request)