import fnmatch
import json
import re
from .. import utils, crypto
from ..proto import folder_pb2, record_pb2, remove_pb2, trashcan_sync_pb2
from ..vault import vault_online, vault_utils, nsf_crypto, nsf_management
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
    nsf_trashcan_sync_point: int = 0
    nsf_trashcan_owner: Optional[str] = None
    nsf_trashcan_record_cache: Dict[str, Any] = {}
    nsf_trashcan_folder_cache: Dict[str, Any] = {}

    @staticmethod
    def clear_nsf_trashcan_cache() -> None:
        """Drop all cached NSF trash data so the next load performs a full sync."""
        TrashManagement.nsf_trashcan_sync_point = 0
        TrashManagement.nsf_trashcan_owner = None
        TrashManagement.nsf_trashcan_record_cache.clear()
        TrashManagement.nsf_trashcan_folder_cache.clear()

    @staticmethod
    def _decrypt_with_user_keys(
            vault: vault_online.VaultOnline, encrypted_key: bytes, key_type: int) -> Optional[bytes]:
        """Decrypt a trash-can key wrapped with the user's data key or private keys."""
        if not encrypted_key:
            return None
        auth_context = vault.keeper_auth.auth_context
        return nsf_crypto.try_decrypt_with_typed_key(
            encrypted_key, key_type,
            aes_key=auth_context.data_key,
            rsa_key=auth_context.rsa_private_key,
            ecc_key=auth_context.ec_private_key)

    @staticmethod
    def get_nsf_folder_key(vault: vault_online.VaultOnline, folder_uid: Optional[str]) -> Optional[bytes]:
        """Return an NSF folder key from the trash cache or the live NSF view."""
        if not folder_uid or folder_uid == nsf_management.ROOT_FOLDER_UID:
            return None
        trash_folder = TrashManagement.nsf_trashcan_folder_cache.get(folder_uid)
        if trash_folder and trash_folder.get('folder_key_unencrypted'):
            return trash_folder['folder_key_unencrypted']
        if vault.nsf_data is None:
            return None
        try:
            return nsf_management._get_folder_key(vault, folder_uid)
        except Exception as e:
            logger.debug('NSF folder key unavailable for %s: %s', folder_uid, e)
            return None

    @staticmethod
    def _decrypt_nsf_trashcan_keys(vault: vault_online.VaultOnline) -> None:
        """Decrypt cached trash keys. Folder and record keys inside a folder are
        wrapped with the parent/containing folder key, so folders are resolved
        top-down until no more keys can be unwrapped."""
        live_folder_keys: Dict[str, Optional[bytes]] = {}

        def folder_key(folder_uid: Optional[str]) -> Optional[bytes]:
            if not folder_uid:
                return None
            trash_folder = TrashManagement.nsf_trashcan_folder_cache.get(folder_uid)
            if trash_folder is not None:
                return trash_folder.get('folder_key_unencrypted')
            if folder_uid not in live_folder_keys:
                live_folder_keys[folder_uid] = TrashManagement.get_nsf_folder_key(vault, folder_uid)
            return live_folder_keys[folder_uid]

        def unwrap(encrypted_key: bytes, key_type: int, wrapping_folder_uid: Optional[str]) -> Optional[bytes]:
            key = TrashManagement._decrypt_with_user_keys(vault, encrypted_key, key_type)
            if key is None:
                wrapping_key = folder_key(wrapping_folder_uid)
                if wrapping_key:
                    key = nsf_crypto.try_decrypt_symmetric(encrypted_key, wrapping_key)
            return key

        progress = True
        while progress:
            progress = False
            for folder in TrashManagement.nsf_trashcan_folder_cache.values():
                if folder.get('folder_key_unencrypted') or not folder.get('folder_key_encrypted'):
                    continue
                key = unwrap(folder['folder_key_encrypted'], folder.get('folder_key_type', 0), folder.get('parent_uid'))
                if key:
                    folder['folder_key_unencrypted'] = key
                    progress = True

        for record in TrashManagement.nsf_trashcan_record_cache.values():
            if record.get('record_key_unencrypted') or not record.get('record_key_encrypted'):
                continue
            record['record_key_unencrypted'] = unwrap(
                record['record_key_encrypted'], record.get('record_key_type', 0), record.get('folder_uid'))

    @staticmethod
    def _ensure_nsf_trashcan_synced(
            vault: vault_online.VaultOnline,
            reload: bool = False) -> None:
        """Synchronize NSF trash can and update local trash caches."""
        owner = vault.keeper_auth.auth_context.username
        if reload or TrashManagement.nsf_trashcan_owner != owner:
            TrashManagement.clear_nsf_trashcan_cache()
            TrashManagement.nsf_trashcan_owner = owner
        sync_point = TrashManagement.nsf_trashcan_sync_point
        continuation_token = b''
        while True:
            request = trashcan_sync_pb2.TrashcanSyncRequest(
                sync_point=sync_point,
                max_count=999,
            )
            if continuation_token:
                request.continuationToken = continuation_token
            response = vault.keeper_auth.execute_auth_rest(
                'vault/folders/v3/trashcan/sync',
                request,
                response_type=trashcan_sync_pb2.TrashcanSyncResponse,
            )
            if response is None:
                break
            data = response.trashcan_data
            # Remove records/folders which are no longer in trash.
            for folder in data.removed_trashcan_folders:
                folder_uid = utils.base64_url_encode(folder.folder_uid)
                TrashManagement.nsf_trashcan_folder_cache.pop(folder_uid, None)
            for record in data.removed_trashcan_records:
                record_uid = utils.base64_url_encode(record.record_uid)
                TrashManagement.nsf_trashcan_record_cache.pop(record_uid, None)
            # Cache NSF deleted folders. Keys are decrypted after the sync completes.
            for folder in data.trashcan_folders:
                folder_uid = utils.base64_url_encode(folder.folder_uid)
                TrashManagement.nsf_trashcan_folder_cache[folder_uid] = {
                    'folder_uid': folder_uid,
                    'trashcan_uid': utils.base64_url_encode(folder.trashcan_uid) if folder.trashcan_uid else None,
                    'parent_uid': utils.base64_url_encode(folder.parent_uid) if folder.parent_uid else None,
                    'date_deleted': folder.date_deleted,
                    'folder_key_encrypted': folder.folder_key,
                    'folder_key_type': folder.folder_key_type,
                    'folder_key_unencrypted': None,
                }
            # Cache NSF deleted records.
            for record in data.trashcan_records:
                record_uid = utils.base64_url_encode(record.record_uid)
                folder_record_key = record.folder_record_key
                TrashManagement.nsf_trashcan_record_cache[record_uid] = {
                    'record_uid': record_uid,
                    'trashcan_uid': utils.base64_url_encode(record.trashcan_uid) if record.trashcan_uid else None,
                    'folder_uid': (
                        utils.base64_url_encode(folder_record_key.folder_uid)
                        if folder_record_key.folder_uid else None
                    ),
                    'date_deleted': record.date_deleted,
                    'record_key_encrypted': folder_record_key.record_key,
                    'record_key_type': folder_record_key.record_key_type,
                    'record_key_unencrypted': None,
                }
            previous_sync_point = sync_point
            if response.sync_point:
                sync_point = response.sync_point
            if not response.has_more:
                break
            continuation_token = response.continuationToken
            if not continuation_token and sync_point == previous_sync_point:
                logger.warning('NSF trash sync reported more data without advancing; stopping')
                break
        TrashManagement.nsf_trashcan_sync_point = sync_point
        TrashManagement._decrypt_nsf_trashcan_keys(vault)

    @staticmethod
    def load_nsf_trashcan(vault: vault_online.VaultOnline, reload: bool = False) -> bool:
        """Sync the NSF trash can. Returns False (keeping classic trash usable) when it cannot be loaded."""
        if vault.nsf_data is None:
            return False
        try:
            TrashManagement._ensure_nsf_trashcan_synced(vault, reload)
            return True
        except Exception as e:
            logger.warning('Unable to load NSF trash: %s', e)
            logger.debug(e, exc_info=True)
            return False

    @staticmethod
    def get_nsf_trashcan_records(vault: vault_online.VaultOnline, reload: bool = False) -> Dict[str, Any]:
        TrashManagement.load_nsf_trashcan(vault, reload)
        return TrashManagement.nsf_trashcan_record_cache

    @staticmethod
    def get_nsf_trashcan_folders(vault: vault_online.VaultOnline, reload: bool = False) -> Dict[str, Any]:
        TrashManagement.load_nsf_trashcan(vault, reload)
        return TrashManagement.nsf_trashcan_folder_cache

    @staticmethod
    def get_nsf_trashcan_record_details(
            vault: vault_online.VaultOnline, nsf_records: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """Return ``{record_uid: {'title', 'type'}}`` for NSF trash records.

        Titles are not part of the trash sync response, so they are fetched once
        through the record-details API (decrypted with the cached trash record
        keys) and memoized on the cache entries.
        """
        to_load = {uid: rec.get('record_key_unencrypted') for uid, rec in nsf_records.items()
                   if not rec.get('details_loaded')}
        if to_load:
            try:
                details = nsf_management.get_nsf_record_details(
                    vault, list(to_load), record_keys={k: v for k, v in to_load.items() if v})
                details_by_uid = {x.get('record_uid'): x for x in details.get('data') or []}
                for uid in to_load:
                    detail = details_by_uid.get(uid) or {}
                    nsf_records[uid]['title'] = detail.get('title', '')
                    nsf_records[uid]['type'] = detail.get('type', '')
                    nsf_records[uid]['details_loaded'] = True
            except Exception as e:
                logger.debug('Unable to load NSF trash record details: %s', e)
        return {uid: {'title': rec.get('title', ''), 'type': rec.get('type', '')}
                for uid, rec in nsf_records.items()}

    @staticmethod
    def get_nsf_trashcan_folder_name(vault: vault_online.VaultOnline, folder_uid: str) -> str:
        """Folder name from the local NSF view, or the folder UID when it is not available."""
        folder = vault.nsf_data.get_folder(folder_uid) if vault.nsf_data is not None else None
        return folder.name if folder and folder.name else folder_uid

    @staticmethod
    def find_nsf_trashcan_records_by_title(
            vault: vault_online.VaultOnline,
            title_pattern: re.Pattern,
            nsf_records: Optional[Dict[str, Any]] = None,
            exclude: Optional[Set[str]] = None) -> Set[str]:
        """Find NSF trash records by title using the NSF record-details API."""
        if nsf_records is None:
            nsf_records = TrashManagement.get_nsf_trashcan_records(vault)
        if not nsf_records:
            return set()
        details = TrashManagement.get_nsf_trashcan_record_details(vault, nsf_records)
        return {uid for uid, detail in details.items()
                if not (exclude and uid in exclude) and title_pattern.match(detail.get('title', ''))}

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


def restore_trash_records(
        vault: vault_online.VaultOnline,
        records: List[str],
        confirm: Optional[Callable[[str], str]] = None,
        *,
        target_folder_uid: Optional[str] = None,
        target_folder_name: Optional[str] = None) -> None:
    """Restore classic and NSF trash records/folders.
    ``target_folder_uid`` is supported only for NSF trash items. When omitted,
    NSF records return to their original folder and NSF folders return to their
    original parent.
    """
    trash_data = _load_trash_data(vault)
    if _is_trash_empty(trash_data):
        logger.info('Trash is empty')
        return
    restore_plan = _create_restore_plan(records, trash_data, vault)
    if _is_restore_plan_empty(restore_plan):
        logger.info('There are no records to restore')
        return
    has_classic = bool(
        restore_plan['records_to_restore']
        or restore_plan['folders_to_restore']
        or restore_plan['folder_records_to_restore'])
    has_nsf = bool(
        restore_plan.get('nsf_records_to_restore')
        or restore_plan.get('nsf_folders_to_restore'))
    if target_folder_uid is not None and has_classic:
        raise ValueError(
            'Restoring into a specific target folder is only supported for NSF '
            'record(s)/folder(s). Restore classic items to their original location.')
    if target_folder_uid is not None and not has_nsf:
        raise ValueError('A target folder can only be used when restoring NSF trash items')
    if confirm:
        question = _build_restore_confirmation(restore_plan, target_folder_name or target_folder_uid)
        if not _confirm_restoration_question(question, confirm):
            return
    if has_classic:
        _execute_record_restoration(vault, restore_plan, trash_data)
        _execute_shared_folder_restoration(vault, restore_plan)
    restored_nsf_records: Set[str] = set()
    if has_nsf:
        restored_nsf_records = _execute_nsf_restoration(
            vault,
            restore_plan.get('nsf_records_to_restore', set()),
            restore_plan.get('nsf_folders_to_restore', set()),
            trash_data['nsf_records'],
            trash_data['nsf_folders'],
            target_folder_uid=target_folder_uid,
        )
    _post_restore_processing(vault, restore_plan, trash_data, restored_nsf_records)


def _build_restore_confirmation(
        restore_plan: Dict[str, Any], target_folder_name: Optional[str] = None) -> str:
    record_count = len(restore_plan['records_to_restore']) + len(restore_plan.get('nsf_records_to_restore', ()))
    for folder_records in restore_plan['folder_records_to_restore'].values():
        record_count += len(folder_records)
    folder_count = len(restore_plan['folders_to_restore']) + len(restore_plan.get('nsf_folders_to_restore', ()))
    items = []
    if record_count:
        items.append(f'{record_count} record(s)')
    if folder_count:
        items.append(f'{folder_count} folder(s)')
    destination = f' into "{target_folder_name}"' if target_folder_name else ''
    return f'Do you want to restore {" and ".join(items)}{destination}?'


def _confirm_restoration_question(question: str, confirm_func: Callable[[str], str]) -> bool:
    answer = confirm_func(question)

    if answer.lower() == 'y':
        answer = 'yes'
    return answer.lower() == 'yes'


def resolve_nsf_trash_target_folder(vault: vault_online.VaultOnline, identifier: str) -> Optional[str]:
    """Resolve an NSF restore target by UID, name, or slash-delimited path."""
    if not identifier:
        return None
    resolved = nsf_management.resolve_nsf_folder_uid(vault, identifier)
    if resolved:
        return resolved
    parts = vault_utils.parse_folder_path(identifier.strip())
    if not parts:
        return None
    if parts[0].casefold() in ('root', 'my drive'):
        parts = parts[1:]
    if not parts:
        return nsf_management.ROOT_FOLDER_UID
    parent_uid: Optional[str] = nsf_management.ROOT_FOLDER_UID
    for part in parts:
        child_uid = nsf_management.find_nsf_child_folder(vault, part, parent_uid)
        if not child_uid:
            return None
        parent_uid = child_uid
    return parent_uid


_NSF_RESTORE_CHUNK = 999
_NSF_RESTORE_STATUS_NAMES = {
    remove_pb2.RS_NOT_IN_TRASHCAN: 'not in trashcan',
    remove_pb2.RS_ACCESS_DENIED: 'access denied',
    remove_pb2.RS_TARGET_FOLDER_NOT_FOUND: 'target folder not found',
    remove_pb2.RS_ALREADY_EXISTS_IN_TARGET: 'already exists in target',
    remove_pb2.RS_FAIL: 'failed',
}


def _get_nsf_target_key(vault: vault_online.VaultOnline, folder_uid: Optional[str]) -> Optional[bytes]:
    """Return the key that restored item keys must be wrapped with, or None if it is unavailable."""
    if not folder_uid or folder_uid == nsf_management.ROOT_FOLDER_UID:
        return vault.keeper_auth.auth_context.data_key
    return TrashManagement.get_nsf_folder_key(vault, folder_uid)


def _nsf_folder_depth(folder_uid: str, nsf_folders: Dict[str, Any]) -> int:
    """Number of deleted ancestors of a deleted NSF folder."""
    depth = 0
    seen = {folder_uid}
    parent_uid = nsf_folders[folder_uid].get('parent_uid')
    while parent_uid in nsf_folders and parent_uid not in seen:
        seen.add(parent_uid)
        depth += 1
        parent_uid = nsf_folders[parent_uid].get('parent_uid')
    return depth


def _send_nsf_restore_requests(
        vault: vault_online.VaultOnline,
        destination_uid: Optional[str],
        restore_records: List[remove_pb2.RestoreRecord],
        restore_folders: List[remove_pb2.RestoreFolder]) -> List[remove_pb2.RestoreResult]:
    """Send restore requests for one destination folder in chunks."""
    target_folder_uid_bytes = utils.base64_url_decode(destination_uid) if destination_uid else b''
    results: List[remove_pb2.RestoreResult] = []
    while restore_records or restore_folders:
        request = remove_pb2.TrashcanRestoreRequest()
        request.target_folder_uid = target_folder_uid_bytes
        left = _NSF_RESTORE_CHUNK
        if restore_records:
            chunk = restore_records[:left]
            del restore_records[:len(chunk)]
            left -= len(chunk)
            request.records.extend(chunk)
        if restore_folders and left > 0:
            chunk = restore_folders[:left]
            del restore_folders[:len(chunk)]
            request.folders.extend(chunk)
        response = vault.keeper_auth.execute_auth_rest(
            'vault/folders/v3/trashcan/restore',
            request,
            response_type=remove_pb2.TrashcanRestoreResponse,
        )
        if response is None:
            logger.warning('NSF trash restore returned no response')
            continue
        if response.error_message:
            logger.warning('NSF trash restore failed: %s', response.error_message)
            continue
        results.extend(response.results)
    return results


def _execute_nsf_restoration(
        vault: vault_online.VaultOnline,
        record_uids: Set[str],
        folder_uids: Set[str],
        nsf_records: Dict[str, Any],
        nsf_folders: Dict[str, Any],
        target_folder_uid: Optional[str] = None) -> Set[str]:
    """Restore NSF records/folders through ``vault/folders/v3/trashcan/restore``.

    Folders are restored first, parents before children, so that items restored
    to their original location find their parent folder back in place.
    """
    if not record_uids and not folder_uids:
        return set()
    restored_record_uids: Set[str] = set()
    restored_folder_uids: Set[str] = set()

    def handle_results(results: List[remove_pb2.RestoreResult]) -> None:
        for result in results:
            item_uid = utils.base64_url_encode(result.item_uid)
            if result.status == remove_pb2.RS_SUCCESS:
                if result.item_type == remove_pb2.RESTORE_ITEM_RECORD:
                    restored_record_uids.add(item_uid)
                elif result.item_type == remove_pb2.RESTORE_ITEM_FOLDER:
                    restored_folder_uids.add(item_uid)
                continue
            if result.status == remove_pb2.RS_NOT_IN_TRASHCAN and item_uid in nsf_records \
                    and nsf_records[item_uid].get('folder_uid') in restored_folder_uids:
                logger.debug('NSF record "%s" was restored with its folder', item_uid)
                continue
            reason = _NSF_RESTORE_STATUS_NAMES.get(result.status, 'unknown error')
            if result.error_message:
                reason = f'{reason}: {result.error_message}'
            logger.warning('Failed to restore NSF item "%s": %s', item_uid, reason)

    def target_key_for(destination_uid: Optional[str], item_count: int) -> Optional[bytes]:
        target_key = _get_nsf_target_key(vault, destination_uid)
        if not target_key:
            logger.warning('Cannot restore %d NSF item(s) into folder "%s": folder key is unavailable',
                           item_count, destination_uid)
        return target_key

    # Folders, one depth level at a time.
    folders = []
    for folder_uid in folder_uids:
        if folder_uid not in nsf_folders:
            logger.warning('NSF trash folder "%s" is no longer available', folder_uid)
            continue
        folders.append(folder_uid)
    depths = {uid: _nsf_folder_depth(uid, nsf_folders) for uid in folders}
    for depth in sorted(set(depths.values())):
        folder_groups: Dict[Optional[str], List[str]] = {}
        for folder_uid in folders:
            if depths[folder_uid] != depth:
                continue
            folder = nsf_folders[folder_uid]
            destination_uid = target_folder_uid if target_folder_uid is not None else folder.get('parent_uid')
            folder_groups.setdefault(destination_uid, []).append(folder_uid)
        for destination_uid, group in folder_groups.items():
            target_key = target_key_for(destination_uid, len(group))
            if not target_key:
                continue
            restore_folders: List[remove_pb2.RestoreFolder] = []
            for folder_uid in group:
                folder_key = nsf_folders[folder_uid].get('folder_key_unencrypted')
                if not folder_key:
                    logger.warning('Cannot restore NSF folder "%s": folder key is unavailable', folder_uid)
                    continue
                request_folder = remove_pb2.RestoreFolder()
                request_folder.folder_uid = utils.base64_url_decode(folder_uid)
                request_folder.encrypted_folder_key = crypto.encrypt_aes_v2(folder_key, target_key)
                restore_folders.append(request_folder)
            handle_results(_send_nsf_restore_requests(vault, destination_uid, [], restore_folders))

    # Records.
    record_groups: Dict[Optional[str], List[str]] = {}
    for record_uid in record_uids:
        record = nsf_records.get(record_uid)
        if not record:
            logger.warning('NSF trash record "%s" is no longer available', record_uid)
            continue
        destination_uid = target_folder_uid if target_folder_uid is not None else record.get('folder_uid')
        record_groups.setdefault(destination_uid, []).append(record_uid)
    for destination_uid, group in record_groups.items():
        target_key = target_key_for(destination_uid, len(group))
        if not target_key:
            continue
        restore_records: List[remove_pb2.RestoreRecord] = []
        for record_uid in group:
            record = nsf_records[record_uid]
            record_key = record.get('record_key_unencrypted')
            if not record_key:
                logger.warning('Cannot restore NSF record "%s": record key is unavailable', record_uid)
                continue
            # source_folder_uid must identify the actual source container in the
            # trash hierarchy. For root-level records, folder_record_key.folder_uid
            # can be empty; in that case use the trashcan container supplied by
            # the sync response. The NSF root UID is not a valid substitute here.
            source_folder_uid = record.get('folder_uid') or record.get('trashcan_uid')
            if not source_folder_uid:
                logger.warning(
                    'Cannot restore NSF record "%s": source folder and trashcan UID are unavailable',
                    record_uid,
                )
                continue
            request_record = remove_pb2.RestoreRecord()
            request_record.record_uid = utils.base64_url_decode(record_uid)
            request_record.encrypted_record_key = crypto.encrypt_aes_v2(record_key, target_key)
            request_record.source_folder_uid = utils.base64_url_decode(source_folder_uid)
            restore_records.append(request_record)
        handle_results(_send_nsf_restore_requests(vault, destination_uid, restore_records, []))

    TrashManagement.clear_nsf_trashcan_cache()
    return restored_record_uids


def _load_trash_data(vault: vault_online.VaultOnline) -> Dict[str, Any]:
    """Load all classic and NSF trash data."""
    TrashManagement._ensure_deleted_records_loaded(vault)
    shared_folders = TrashManagement.get_shared_folders()
    TrashManagement.load_nsf_trashcan(vault)
    return {
        'deleted_records': TrashManagement.get_deleted_records(),
        'orphaned_records': TrashManagement.get_orphaned_records(),
        'deleted_shared_records': shared_folders.get('records', {}),
        'deleted_shared_folders': shared_folders.get('folders', {}),
        'nsf_records': TrashManagement.nsf_trashcan_record_cache,
        'nsf_folders': TrashManagement.nsf_trashcan_folder_cache,
    }


def _is_trash_empty(trash_data: Dict[str, Any]) -> bool:
    """Check if all supported trash sources are empty."""
    return not any(trash_data.get(key) for key in (
        'deleted_records', 'orphaned_records', 'deleted_shared_records',
        'deleted_shared_folders', 'nsf_records', 'nsf_folders'))


def _create_restore_plan(
        records: List[str],
        trash_data: Dict[str, Any],
        vault: Optional[vault_online.VaultOnline] = None) -> Dict[str, Any]:
    """Create a restore plan for classic and NSF trash items.

    ``vault`` is needed to match NSF trash items by title.
    """
    records_to_restore: Set[str] = set()
    folders_to_restore: Set[str] = set()
    folder_records_to_restore: Dict[str, List[str]] = {}
    nsf_records_to_restore: Set[str] = set()
    nsf_folders_to_restore: Set[str] = set()
    for record_id in records:
        _process_single_record_for_restore(
            record_id, trash_data, records_to_restore, folders_to_restore,
            folder_records_to_restore, nsf_records_to_restore, nsf_folders_to_restore, vault)
    # Restoring a deleted shared folder restores its contents, so explicit
    # child-record restore requests are redundant.
    for folder_uid in folders_to_restore:
        folder_records_to_restore.pop(folder_uid, None)

    return {
        'records_to_restore': records_to_restore,
        'folders_to_restore': folders_to_restore,
        'folder_records_to_restore': folder_records_to_restore,
        'nsf_records_to_restore': nsf_records_to_restore,
        'nsf_folders_to_restore': nsf_folders_to_restore,
    }


def _process_single_record_for_restore(
        record_id: str,
        trash_data: Dict[str, Any],
        records_to_restore: Set[str],
        folders_to_restore: Set[str],
        folder_records_to_restore: Dict[str, List[str]],
        nsf_records_to_restore: Set[str],
        nsf_folders_to_restore: Set[str],
        vault: Optional[vault_online.VaultOnline] = None) -> None:
    """Add a UID directly or resolve it as a title pattern."""
    deleted_records = trash_data['deleted_records']
    orphaned_records = trash_data['orphaned_records']
    deleted_shared_records = trash_data['deleted_shared_records']
    deleted_shared_folders = trash_data['deleted_shared_folders']
    nsf_records = trash_data['nsf_records']
    nsf_folders = trash_data['nsf_folders']
    if record_id in deleted_records or record_id in orphaned_records:
        records_to_restore.add(record_id)
        return
    if record_id in deleted_shared_records:
        _add_shared_record_to_restore(record_id, deleted_shared_records, folder_records_to_restore)
        return
    if record_id in deleted_shared_folders:
        folders_to_restore.add(record_id)
        return
    if record_id in nsf_records:
        nsf_records_to_restore.add(record_id)
        return
    if record_id in nsf_folders:
        nsf_folders_to_restore.add(record_id)
        return
    _process_pattern_matching(
        record_id, trash_data, records_to_restore, folders_to_restore,
        folder_records_to_restore, nsf_records_to_restore, nsf_folders_to_restore, vault)


def _add_shared_record_to_restore(
        record_id: str,
        deleted_shared_records: Dict[str, Any],
        folder_records_to_restore: Dict[str, List[str]]) -> None:
    """Add a shared record to the restore plan."""
    shared_record = deleted_shared_records.get(record_id)
    if not shared_record:
        return
    folder_uid = shared_record.get('folder_uid')
    record_uid = shared_record.get('record_uid')

    if folder_uid and record_uid:
        folder_records_to_restore.setdefault(folder_uid, []).append(record_uid)


def _process_pattern_matching(
        pattern: str,
        trash_data: Dict[str, Any],
        records_to_restore: Set[str],
        folders_to_restore: Set[str],
        folder_records_to_restore: Dict[str, List[str]],
        nsf_records_to_restore: Set[str],
        nsf_folders_to_restore: Set[str],
        vault: Optional[vault_online.VaultOnline] = None) -> None:
    """Match classic and NSF trash records/folders by title pattern."""
    title_pattern = re.compile(fnmatch.translate(pattern), re.IGNORECASE)
    _match_records_by_title(trash_data['deleted_records'], title_pattern, records_to_restore)
    _match_records_by_title(trash_data['orphaned_records'], title_pattern, records_to_restore)
    _match_shared_records_by_title(trash_data['deleted_shared_records'], title_pattern, folder_records_to_restore)
    _match_folders_by_title(trash_data['deleted_shared_folders'], title_pattern, folders_to_restore)
    # NSF record titles are not present in the trash sync response; fetch their
    # record details through the existing SDK NSF API. Folder names are only
    # available if the deleted folder is still present in the local NSF view.
    if vault is not None and (trash_data['nsf_records'] or trash_data['nsf_folders']):
        nsf_records_to_restore.update(
            TrashManagement.find_nsf_trashcan_records_by_title(
                vault, title_pattern, trash_data['nsf_records'], exclude=nsf_records_to_restore))
        for folder_uid in trash_data['nsf_folders']:
            if folder_uid in nsf_folders_to_restore:
                continue
            if title_pattern.match(TrashManagement.get_nsf_trashcan_folder_name(vault, folder_uid)):
                nsf_folders_to_restore.add(folder_uid)


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
    record_count = len(restore_plan['records_to_restore']) + len(restore_plan.get('nsf_records_to_restore', ()))
    for folder_records in restore_plan['folder_records_to_restore'].values():
        record_count += len(folder_records)
    folder_count = len(restore_plan['folders_to_restore']) + len(restore_plan.get('nsf_folders_to_restore', ()))
    return record_count == 0 and folder_count == 0


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


def _post_restore_processing(
        vault: vault_online.VaultOnline,
        restore_plan: Dict[str, Any],
        trash_data: Dict[str, Any],
        restored_nsf_records: Optional[Set[str]] = None) -> None:
    """Sync restored data and perform BreachWatch/audit processing."""
    vault.sync_down()
    restored_nsf_records = restored_nsf_records or set()
    restored_classic_records = restore_plan['records_to_restore']
    all_restored_records = set(restored_classic_records) | set(restored_nsf_records)
    if not all_restored_records:
        return
    breach_watch = vault.breach_watch_plugin()
    audit_plugin = vault.client_audit_event_plugin()
    for record_uid in all_restored_records:
        record_key: Optional[bytes] = None
        password: Optional[str] = None
        if record_uid in restored_classic_records:
            record_key = vault.vault_data.get_record_key(record_uid)
            record = (trash_data['deleted_records'].get(record_uid)
                      or trash_data['orphaned_records'].get(record_uid))
            password = _extract_password_from_record(record or {})
        else:
            if vault.nsf_data is not None:
                entry = vault.nsf_data.get_record(record_uid)
                if entry is not None:
                    record_key = entry.record_key
                    password = _extract_password_from_nsf_entry(entry.decrypted_data)
        if breach_watch and record_key and password:
            breach_watch.scan_and_store_record_status(record_uid, record_key, password)
        if audit_plugin:
            audit_plugin.schedule_audit_event('record_restored', record_uid=record_uid)


def _extract_password_from_nsf_entry(data: Optional[str]) -> Optional[str]:
    """Extract a password field from a decrypted NSF record payload."""
    if not data:
        return None
    try:
        payload = json.loads(data)
        for field_group in ('fields', 'custom'):
            for field in payload.get(field_group) or []:
                if isinstance(field, dict) and field.get('type') == PASSWORD_FIELD_TYPE:
                    value = field.get('value')
                    if isinstance(value, list):
                        return str(value[0]) if value else None
                    return str(value) if value is not None else None
    except (json.JSONDecodeError, TypeError, ValueError):
        pass
    return None


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