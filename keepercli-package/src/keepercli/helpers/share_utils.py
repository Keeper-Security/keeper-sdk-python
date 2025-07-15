import datetime
import itertools
from typing import Optional, Dict, List, Any, Generator, Tuple, Iterable

from keepersdk import crypto, utils
from keepersdk.proto import record_pb2
from keepersdk.vault import storage_types, vault_online, vault_record

from .. import api
from ..commands import enterprise_utils
from ..helpers import timeout_utils
from ..params import KeeperParams


RECORD_DETAILS_URL = 'vault/get_records_details'
SHARE_OBJECTS_API = 'vault/get_share_objects'


logger = api.get_logger()


def get_share_expiration(expire_at: Optional[str], expire_in: Optional[str]) -> int:
    if not expire_at and not expire_in:
        return 0

    dt = None
    if isinstance(expire_at, str):
        if expire_at == 'never':
            return -1
        dt = datetime.datetime.fromisoformat(expire_at)
    elif isinstance(expire_in, str):
        if expire_in == 'never':
            return -1
        td = timeout_utils.parse_timeout(expire_in)
        dt = datetime.datetime.now() + td
    if dt is None:
        raise ValueError(f'Incorrect expiration: {expire_at or expire_in}')

    return int(dt.timestamp())


def get_share_objects(vault: vault_online.VaultOnline) -> Dict[str, Dict[str, Any]]:
    request = record_pb2.GetShareObjectsRequest()
    
    response = vault.keeper_auth.execute_auth_rest(
        rest_endpoint=SHARE_OBJECTS_API, 
        request=request, 
        response_type=record_pb2.GetShareObjectsResponse
    )
    
    if not response:
        return {'users': {}, 'enterprises': {}, 'teams': {}}
    
    users_by_type = {
        'relationship': response.shareRelationships,
        'family': response.shareFamilyUsers,
        'enterprise': response.shareEnterpriseUsers,
        'mc': response.shareMCEnterpriseUsers,
    }
    
    def process_users(users_data: Iterable[Any], category: str) -> Dict[str, Dict[str, Any]]:
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
    
    users = {}
    for category, users_data in users_by_type.items():
        users.update(process_users(users_data, category))
    
    enterprises = {
        str(enterprise.enterpriseId): enterprise.enterprisename 
        for enterprise in response.shareEnterpriseNames
    }
    
    def process_teams(teams_data: Iterable[Any]) -> Dict[str, Dict[str, Any]]:
        return {
            utils.base64_url_encode(team.teamUid): {
                'name': team.teamname,
                'enterprise_id': team.enterpriseId
            } for team in teams_data
        }
    
    teams = process_teams(response.shareTeams)
    teams_mc = process_teams(response.shareMCTeams)
    
    return {
        'users': users,
        'enterprises': enterprises,
        'teams': {**teams, **teams_mc}
    }


def load_records_in_shared_folder(
    vault: vault_online.VaultOnline, 
    shared_folder_uid: str, 
    record_uids: Optional[set[str]] = None
) -> None:
    shared_folder = None
    for shared_folder_info in vault.vault_data.shared_folders():
        if shared_folder_uid == shared_folder_info.shared_folder_uid:
            shared_folder = vault.vault_data.load_shared_folder(shared_folder_uid=shared_folder_uid)
            break
    
    if not shared_folder:
        raise Exception(f'Shared folder "{shared_folder_uid}" is not loaded.')
    
    shared_folder_key = vault.vault_data._shared_folders[shared_folder_uid].shared_folder_key
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
            if len(key) == 60:
                record_key = crypto.decrypt_aes_v2(key, shared_folder_key)
            else:
                record_key = crypto.decrypt_aes_v1(key, shared_folder_key)
            record_keys[record_uid] = record_key
        except Exception as e:
            logger.error(f'Cannot decrypt record "{record_uid}" key: {e}')

    record_cache = [x.record_uid for x in vault.vault_data.records()]

    if record_uids:
        record_set = set(record_uids)
        record_set.intersection_update(record_keys.keys())
    else:
        record_set = set(record_keys.keys())
    record_set.difference_update(record_cache)

    # Load records in batches
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

        rs = vault.keeper_auth.execute_auth_rest(
            rest_endpoint=RECORD_DETAILS_URL, 
            request=rq, 
            response_type=record_pb2.GetRecordDataWithAccessInfoResponse
        )
        
        if not rs or not rs.recordDataWithAccessInfo:
            logger.warning("No record data received from API")
            break
            
        for record_info in rs.recordDataWithAccessInfo:
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
                record = {
                    'record_uid': record_uid,
                    'revision': record_data.revision,
                    'version': version,
                    'shared': record_data.shared,
                    'data': record_data.encryptedRecordData,
                    'record_key_unencrypted': record_keys[record_uid],
                    'client_modified_time': record_data.clientModifiedTime,
                }
                data_decoded = utils.base64_url_decode(record_data.encryptedRecordData)
                if version <= 2:
                    record['data_unencrypted'] = crypto.decrypt_aes_v1(data_decoded, record_key)
                else:
                    record['data_unencrypted'] = crypto.decrypt_aes_v2(data_decoded, record_key)

                # Handle extra data for v2 records
                if record_data.encryptedExtraData and version <= 2:
                    record['extra'] = record_data.encryptedExtraData
                    extra_decoded = utils.base64_url_decode(record_data.encryptedExtraData)
                    record['extra_unencrypted'] = crypto.decrypt_aes_v1(extra_decoded, record_key)
                
                # Handle v3 typed records with references
                if version == 3:
                    v3_record = vault.vault_data.load_record(record_uid=record_uid)
                    if isinstance(v3_record, vault_record.TypedRecord):
                        for ref in itertools.chain(v3_record.fields, v3_record.custom):
                            if ref.type.endswith('Ref') and isinstance(ref.value, list):
                                record_set.update(ref.value)
                
                # Handle v4 records with file attachments
                elif version == 4:
                    if record_data.fileSize > 0:
                        record['file_size'] = record_data.fileSize
                    if record_data.thumbnailSize > 0:
                        record['thumbnail_size'] = record_data.thumbnailSize
                
                # Handle linked record metadata
                if record_data.recordUid and record_data.recordKey:
                    record['owner_uid'] = utils.base64_url_encode(record_data.recordUid)
                    record['link_key'] = utils.base64_url_encode(record_data.recordKey)

                # Add share permissions
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
                record_set.add(record_uid)
            except Exception as e:
                logger.debug('Error decrypting record "%s": %s', record_uid, e)
        
        
def get_record_shares(
    vault: vault_online.VaultOnline, 
    record_uids: List[str], 
    is_share_admin: bool = False
) -> Optional[List[Dict[str, Any]]]:
    record_cache = {x.record_uid: x for x in vault.vault_data.records()}
    
    def needs_share_info(uid: str) -> bool:
        """Check if a record needs share information."""
        if uid in record_cache:
            record = record_cache[uid]
            return not hasattr(record, 'shares')
        return is_share_admin
    
    def create_record_info(record_uid: str, keeper_record: Optional[Any] = None) -> Dict[str, Any]:
        """Create basic record information dictionary."""
        rec = {'record_uid': record_uid}
        
        if keeper_record:
            if hasattr(keeper_record, 'title'):
                rec['title'] = keeper_record.title
            if hasattr(keeper_record, 'data_unencrypted'):
                rec['data_unencrypted'] = keeper_record.data_unencrypted
                
        return rec
    
    def process_user_permissions(info: Any) -> List[Dict[str, Any]]:
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
    
    def process_shared_folder_permissions(info: Any) -> List[Dict[str, Any]]:
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
    
    uids_needing_info = [uid for uid in record_uids if needs_share_info(uid)]
    
    if not uids_needing_info:
        return None
    
    result = []
    try:
        chunk_size = 999
        for i in range(0, len(uids_needing_info), chunk_size):
            chunk = uids_needing_info[i:i + chunk_size]
            
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
                
                # Skip if record is already in cache
                if record_uid in record_cache:
                    continue
                
                rec = create_record_info(record_uid)
                
                if isinstance(rec, dict):
                    rec['shares'] = {
                        'user_permissions': process_user_permissions(info),
                        'shared_folder_permissions': process_shared_folder_permissions(info)
                    }
                
                result.append(rec)
                
    except Exception as e:
        logger.error(f"Error fetching record shares: {e}")
    
    return result if result else None


def resolve_record_share_path(context: KeeperParams, record_uid: str) -> Optional[Dict[str, str]]:
    return resolve_record_permission_path(context=context, record_uid=record_uid, permission='can_share')


def resolve_record_permission_path(
    context: KeeperParams, 
    record_uid: str, 
    permission: str
) -> Optional[Dict[str, str]]:
    for ap in enumerate_record_access_paths(context=context, record_uid=record_uid):
        if ap.get(permission):
            path = {
                'record_uid': record_uid
            }
            if 'shared_folder_uid' in ap:
                path['shared_folder_uid'] = ap['shared_folder_uid']
            if 'team_uid' in ap:
                path['team_uid'] = ap['team_uid']
            return path

    return None


def enumerate_record_access_paths(
    context: KeeperParams, 
    record_uid: str
) -> Generator[Dict[str, Any], None, None]:

    def get_record_permissions(shared_folder: Any) -> Optional[Any]:
        """Get permissions for the target record in a shared folder."""
        if not shared_folder or not shared_folder.record_permissions:
            return None
            
        for permission in shared_folder.record_permissions:
            if permission.record_uid == record_uid:
                return permission
        return None
    
    def determine_permissions(record_permission: Any) -> Tuple[bool, bool]:
        """Determine edit and share permissions based on record permission."""
        is_owner = record_permission.can_edit and record_permission.can_share
        if is_owner:
            return True, True
        return record_permission.can_edit, record_permission.can_share
    
    def create_access_path(
        shared_folder_uid: str, 
        can_edit: bool, 
        can_share: bool, 
        team_uid: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create a standardized access path dictionary."""
        path = {
            'record_uid': record_uid,
            'shared_folder_uid': shared_folder_uid,
            'can_edit': can_edit,
            'can_share': can_share,
            'can_view': True
        }
        if team_uid:
            path['team_uid'] = team_uid
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
            if user_permission.user_type != storage_types.SharedFolderUserType.Team:
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
        
        record_permission = get_record_permissions(shared_folder)
        if not record_permission:
            continue
            
        can_edit, can_share = determine_permissions(record_permission)
        
        if hasattr(shared_folder, 'key_type'):
            yield create_access_path(
                shared_folder_uid=shared_folder_uid,
                can_edit=can_edit,
                can_share=can_share
            )
        else:
            yield from process_team_permissions(shared_folder, can_edit, can_share)

