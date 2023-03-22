#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.coms
#

import itertools
import json
from typing import List, Tuple, Optional, Iterable

from . import vault_data
from .storage_types import (
    StorageRecord, StorageSharedFolder, StorageRecordKey, StorageTeam, StorageSharedFolderKey, StorageNonSharedData,
    StorageSharedFolderPermission, StorageFolder, StorageFolderRecordLink, StorageRecordType, KeyType,
    SharedFolderUserType, BreachWatchRecord)
from .. import crypto, utils
from ..login import auth
from ..proto import record_pb2
from ..storage import types


SHARED_FOLDER_SCOPE = ['shared_folder', 'sfheaders', 'sfrecords', 'sfusers', 'teams']
FOLDER_SCOPE = ['folders']
RECORD_SCOPE = ['record', 'typed_record', 'app_record', 'sharing_changes']
NON_SHARED_DATA_SCOPE = ['non_shared_data']
EXPLICIT = ['explicit']


def sync_down_command(keeper_auth, storage, sync_record_types=False):
    # type: (auth.KeeperAuth, vault_storage.IVaultStorage, bool) -> vault_data.RebuildTask
    logger = utils.get_logger()

    request = {
        "command": "sync_down",
        "include": RECORD_SCOPE + SHARED_FOLDER_SCOPE + FOLDER_SCOPE + EXPLICIT,
        "revision": storage.revision,
        "device_id": keeper_auth.keeper_endpoint.device_name,
        "device_name": keeper_auth.keeper_endpoint.device_name,
        "client_time": utils.current_milli_time()
    }

    response = keeper_auth.execute_auth_command(request)

    is_full_sync = response.get('full_sync', False)
    if is_full_sync:
        sync_record_types = True
        storage.clear()

    result = vault_data.RebuildTask(is_full_sync)

    if 'removed_records' in response:
        removed_records = response['removed_records']  # type: List[str]
        result.add_records(removed_records)
        storage.record_keys.delete_links(((x, storage.personal_scope_uid) for x in removed_records))

        # linked records
        record_links = []   # type: List[types.IUidLink]
        for record_uid in removed_records:
            record_links.extend(storage.record_keys.get_links_for_object(record_uid))
        storage.record_keys.delete_links(record_links)
        result.add_records((x.subject_uid() for x in record_links))

        # remove records from user_folders
        record_links.clear()
        for record_uid in removed_records:
            record_links.extend(storage.folder_records.get_links_for_object(record_uid))
        folder_uids = {x.subject_uid() for x in record_links}
        for folder_uid in list(folder_uids):
            if folder_uid == storage.personal_scope_uid:
                continue
            folder = storage.folders.get_entity(folder_uid)
            if folder:
                if folder.folder_type == 'user_folder':
                    folder_uids.remove(folder_uid)
                continue
            storage_folder = storage.folders.get_entity(folder_uid)
            if storage_folder:
                if storage_folder.folder_type != 'user_folder':
                    folder_uids.remove(folder_uid)
                continue
        if folder_uids:
            storage.record_keys.delete_links((x for x in record_links if x.subject_uid() in folder_uids))

        del record_links
        del folder_uids

    if 'removed_teams' in response:
        removed_teams = response['removed_teams']   # type: List[str]
        sf_links = []    # type: List[types.IUidLink]
        for team_uid in removed_teams:
            sf_links.extend(storage.shared_folder_keys.get_links_for_object(team_uid))
        result.add_shared_folders((x.subject_uid() for x in sf_links))
        storage.shared_folder_keys.delete_links(sf_links)
        storage.teams.delete_uids(removed_teams)
        del sf_links

    if 'removed_shared_folders' in response:
        removed_shared_folders = response['removed_shared_folders']   # type: List[str]
        rec_links = []    # type: List[types.IUidLink]
        for shared_folder_uid in removed_shared_folders:
            rec_links.extend(storage.record_keys.get_links_for_object(shared_folder_uid))
        result.add_shared_folders(removed_shared_folders)
        result.add_records((x.subject_uid() for x in rec_links))
        storage.shared_folder_keys.delete_links(
            (x, storage.personal_scope_uid) for x in removed_shared_folders)
        del rec_links

    if 'user_folders_removed' in response:
        storage.folder_records.delete_links_for_subjects(response['user_folders_removed'])
        storage.folders.delete_uids(response['user_folders_removed'])

    if 'shared_folder_folder_removed' in response:
        folder_uids = \
            {x.get('folder_uid') or x.get('shared_folder_uid') for x in response['shared_folder_folder_removed']}
        storage.folder_records.delete_links_for_subjects(folder_uids)
        storage.folders.delete_uids(folder_uids)
        del folder_uids

    if 'user_folder_shared_folders_removed' in response:
        ufsfr = response['user_folder_shared_folders_removed']
        shared_folder_uids = [x['shared_folder_uid'] for x in ufsfr]
        storage.folder_records.delete_links_for_subjects(shared_folder_uids)
        storage.folders.delete_uids(shared_folder_uids)
        del shared_folder_uids

    if 'user_folders_removed_records' in response:
        ufrr = response['user_folders_removed_records']
        storage.folder_records.delete_links(
            ((x.get('folder_uid') or x.storage.personal_scope_uid, x['record_uid']) for x in ufrr))

    if 'shared_folder_folder_records_removed' in response:
        sfrrr = response['shared_folder_folder_records_removed']
        storage.folder_records.delete_links(
            ((x.get('folder_uid') or x.get('shared_folder_uid'), x['record_uid']) for x in sfrrr))

    if 'removed_links' in response:
        rl = response['removed_links']
        result.add_records((x['records_uid'] for x in rl))
        storage.record_keys.delete_links(((x['owner_uid'], x['record_uid']) for x in rl))

    if not is_full_sync and 'shared_folders' in response:   # remove only
        sfs = response['shared_folders']
        result.add_shared_folders((x['shared_folder_uid'] for x in sfs))
        full_sync_sf = [x['shared_folder_uid'] for x in sfs if x.get('full_sync')]  # type: List[str]
        if full_sync_sf:
            storage.record_keys.delete_links_for_objects(full_sync_sf)
            storage.shared_folder_keys.delete_links_for_subjects(full_sync_sf)
            storage.shared_folder_permissions.delete_links_for_subjects(full_sync_sf)

        deleted_records = []  # type: List[Tuple[str, str]]
        deleted_teams = []    # type: List[Tuple[str, str]]
        deleted_users = []    # type: List[Tuple[str, str]]
        for sf in sfs:
            shared_folder_uid = sf['shared_folder_uid']
            if shared_folder_uid in full_sync_sf:
                continue
            if 'records_removed' in sf:
                for record_uid in sf['records_removed']:
                    deleted_records.append((record_uid, shared_folder_uid))
            if 'teams_removed' in sf:
                for team_uid in sf['teams_removed']:
                    deleted_teams.append((shared_folder_uid, team_uid))
            if 'users_removed' in sf:
                for username in sf['users_removed']:
                    deleted_users.append((shared_folder_uid, username))
        if deleted_records:
            storage.record_keys.delete_links(deleted_records)
            result.add_records((x[0] for x in deleted_records))
        if deleted_users or deleted_teams:
            storage.shared_folder_permissions.delete_links(itertools.chain(deleted_users, deleted_teams))
        if deleted_teams:
            storage.shared_folder_keys.delete_links(deleted_teams)

    if 'non_shared_data' in response:
        def to_non_shared_data(nsd):   # type: (dict) -> Optional[StorageNonSharedData]
            try:
                s_nsd = StorageNonSharedData()
                s_nsd.record_uid = nsd['record_uid']
                s_nsd.data = utils.base64_url_decode(nsd['data'])
                return s_nsd
            except Exception as e:
                logger.error('Non-Shared data for record UID %s decrypt error: %s', record_uid, e)

        storage.non_shared_data.put_entities(
            (y for y in (to_non_shared_data(x) for x in response['non_shared_data']) if y))

    record_owners = {}
    if 'record_meta_data' in response:
        for meta_data in response['record_meta_data']:
            record_owners[meta_data['record_uid']] = meta_data.get('owner', False)

    if 'records' in response:
        result.add_records((x['record_uid'] for x in response['records']))

        def to_record(rec):    # type: (dict) -> StorageRecord
            record = StorageRecord()
            record.record_uid = rec['record_uid']
            record.version = rec['version']
            record.revision = rec['revision']
            record.client_modified_time = rec['client_modified_time']
            record.data = utils.base64_url_decode(rec['data'])
            if 'extra' in rec:
                record.extra = utils.base64_url_decode(rec['extra'])
            if 'udata' in rec:
                record.udata = json.dumps(rec['udata'])
            record.shared = rec['shared']
            if record.record_uid in record_owners:
                record.owner = record_owners[record.record_uid]
                del record_owners[record.record_uid]
            return record
        storage.records.put_entities((to_record(x) for x in response['records']))

        def to_link_key(rec):   # type: (dict) -> Optional[StorageRecordKey]
            if 'owner_uid' in rec and 'link_key' in rec:
                record_key = StorageRecordKey()
                record_key.record_uid = rec['record_uid']
                record_key.record_key = utils.base64_url_decode(rec['link_key'])
                record_key.shared_folder_uid = rec['owner_uid']
                record_key.key_type = KeyType.RecordKey
                record_key.can_edit = False
                record_key.can_share = False
                return record_key
        link_keys = [lk for lk in (to_link_key(x) for x in response['records']) if lk is not None]
        if link_keys:
            storage.record_keys.put_links(link_keys)

    if len(record_owners) > 0:
        records = []
        for record_uid in record_owners:
            e_record = storage.records.get_entity(record_uid)
            if e_record and e_record.owner != record_owners[record_uid]:
                e_record.owner = record_owners[record_uid]
                records.append(e_record)
        if records:
            storage.records.put_entities(records)

    if 'record_meta_data' in response:
        record_meta_data = response['record_meta_data']
        result.add_records((x['record_uid'] for x in record_meta_data))

        def to_record_key(rmd):   # type: (dict) -> Optional[StorageRecordKey]
            key_type = rmd['record_key_type']
            record_key = utils.base64_url_decode(rmd['record_key'])
            try:
                if key_type == 0:
                    record_key = keeper_auth.auth_context.data_key
                elif key_type == 1:
                    record_key = crypto.decrypt_aes_v1(record_key, keeper_auth.auth_context.data_key)
                elif key_type == 2:
                    record_key = crypto.decrypt_rsa(record_key, keeper_auth.auth_context.rsa_private_key)
                elif key_type == 3:
                    record_key = crypto.decrypt_aes_v2(record_key, keeper_auth.auth_context.data_key)
                elif key_type == 4:
                    record_key = crypto.decrypt_ec(record_key, keeper_auth.auth_context.ec_private_key)
                else:
                    record_key = None
                    logger.error(f'Record metadata UID %s: unsupported key type %d', rmd['record_uid'], key_type)

                if record_key is not None:
                    sr_key = StorageRecordKey()
                    sr_key.record_uid = rmd['record_uid']
                    sr_key.record_key = crypto.encrypt_aes_v2(record_key, keeper_auth.auth_context.client_key)
                    sr_key.key_type = KeyType.DataKey
                    sr_key.shared_folder_uid = storage.personal_scope_uid
                    sr_key.can_edit = rmd['can_edit']
                    sr_key.can_share = rmd['can_share']
                    return sr_key
            except Exception as e:
                logger.error('Metadata for record UID %s key decrypt error: %s', rmd['record_uid'], e)

        storage.record_keys.put_links((y for y in (to_record_key(x) for x in record_meta_data) if y))

    if 'teams' in response:
        teams = response['teams']
        sf_removed_keys = []
        for team in teams:
            if 'removed_shared_folders' in team:
                for shared_folder_uid in team['removed_shared_folders']:
                    sf_removed_keys.append((shared_folder_uid, team['team_uid']))
        if sf_removed_keys:
            result.add_shared_folders((x[0] for x in sf_removed_keys))
            storage.shared_folder_keys.delete_links(sf_removed_keys)
        del sf_removed_keys

        def to_team(sync_down_team):   # type: (dict) -> Optional[StorageTeam]
            try:
                key_type = sync_down_team['team_key_type']
                team_key = utils.base64_url_decode(sync_down_team['team_key'])
                if key_type == 1:
                    team_key = crypto.decrypt_aes_v1(team_key, keeper_auth.auth_context.data_key)
                elif key_type == 2:
                    team_key = crypto.decrypt_rsa(team_key, keeper_auth.auth_context.rsa_private_key)
                elif key_type == 3:
                    team_key = crypto.decrypt_aes_v2(team_key, keeper_auth.auth_context.data_key)
                elif key_type == 4:
                    team_key = crypto.decrypt_ec(team_key, keeper_auth.auth_context.ec_private_key)
                else:
                    team_key = None
                    logger.debug('Team UID %s: unsupported key type %d', team_uid, key_type)
                if team_key is not None:
                    encrypted_team_key = crypto.encrypt_aes_v2(team_key, keeper_auth.auth_context.client_key)
                    s_team = StorageTeam()
                    s_team.team_uid = sync_down_team['team_uid']
                    s_team.name = sync_down_team['name']
                    s_team.team_key = encrypted_team_key
                    s_team.key_type = KeyType.DataKey
                    s_team.team_private_key = utils.base64_url_decode(sync_down_team['team_private_key'])
                    s_team.restrict_edit = sync_down_team['restrict_edit']
                    s_team.restrict_share = sync_down_team['restrict_share']
                    s_team.restrict_view = sync_down_team['restrict_view']
                    return s_team
            except Exception as e:
                logger.error('Team %s key decrypt error: %s', team_uid, e)

        storage.teams.put_entities((y for y in (to_team(x) for x in teams) if y))

        sf_keys = []    # type: List[StorageSharedFolderKey]
        for team in teams:
            if 'shared_folder_keys' in team:
                team_uid = team['team_uid']
                for sfk in team['shared_folder_keys']:
                    sshk = StorageSharedFolderKey()
                    sshk.shared_folder_uid = sfk['shared_folder_uid']
                    sshk.team_uid = team_uid
                    sshk.key_type = KeyType.TeamRsaPrivateKey if sfk['key_type'] == 2 else KeyType.TeamKey
                    sshk.shared_folder_key = utils.base64_url_decode(sfk['shared_folder_key'])
                    sf_keys.append(sshk)
        storage.shared_folder_keys.put_links(sf_keys)
        del sf_keys

    if 'shared_folders' in response:
        sfs = response['shared_folders']
        result.add_shared_folders((x['shared_folder_uid'] for x in sfs))

        def to_shared_folder(shared_folder):    # type: (dict) -> StorageSharedFolder
            s_sf = StorageSharedFolder()
            s_sf.shared_folder_uid = shared_folder['shared_folder_uid']
            s_sf.revision = shared_folder['revision']
            s_sf.name = utils.base64_url_decode(shared_folder['name'])
            s_sf.default_manage_records = shared_folder.get('default_manage_records', False)
            s_sf.default_manage_users = shared_folder.get('default_manage_users', False)
            s_sf.default_can_edit = shared_folder.get('default_can_edit', False)
            s_sf.default_can_share = shared_folder.get('default_can_share', False)
            return s_sf

        storage.shared_folders.put_entities((to_shared_folder(x) for x in sfs))

        # shared folder keys
        def to_shared_folder_key(shared_folder):   # type: (dict) -> StorageSharedFolderKey
            if 'shared_folder_key' in shared_folder:
                try:
                    key_type = shared_folder['key_type']
                    shared_folder_key = utils.base64_url_decode(shared_folder['shared_folder_key'])
                    if key_type == 1:
                        shared_folder_key = crypto.decrypt_aes_v1(
                            shared_folder_key, keeper_auth.auth_context.data_key)
                    elif key_type == 2:
                        shared_folder_key = crypto.decrypt_rsa(
                            shared_folder_key, keeper_auth.auth_context.rsa_private_key)
                    elif key_type == 3:
                        shared_folder_key = crypto.decrypt_aes_v2(
                            shared_folder_key, keeper_auth.auth_context.data_key)
                    elif key_type == 4:
                        shared_folder_key = crypto.decrypt_ec(
                            shared_folder_key, keeper_auth.auth_context.ec_private_key)
                    else:
                        shared_folder_key = None
                        logger.warning('Shared Folder UID %s: wrong key type %d}', shared_folder_uid, key_type)
                    if shared_folder_key:
                        shared_folder_key = \
                            crypto.encrypt_aes_v2(shared_folder_key, keeper_auth.auth_context.client_key)
                        s_sfkey = StorageSharedFolderKey()
                        s_sfkey.shared_folder_uid = shared_folder['shared_folder_uid']
                        s_sfkey.team_uid = storage.personal_scope_uid
                        s_sfkey.shared_folder_key = shared_folder_key
                        s_sfkey.key_type = KeyType.DataKey
                        return s_sfkey
                except Exception as e:
                    logger.error('Shared Folder %s key decrypt error: %s', shared_folder_uid, e)

        storage.shared_folder_keys.put_links((y for y in (to_shared_folder_key(x) for x in sfs) if y))

        # shared folder records
        result.add_records((y['record_uid'] for x in sfs if 'records' in x for y in x['records']))

        def to_shared_folder_record(sf_uid, sfr):  # type: (str, dict) -> StorageRecordKey
            s_rk = StorageRecordKey()
            s_rk.record_uid = sfr['record_uid']
            s_rk.shared_folder_uid = sf_uid
            s_rk.key_type = KeyType.SharedFolderKey
            s_rk.record_key = utils.base64_url_decode(sfr['record_key'])
            s_rk.can_edit = sfr['can_edit']
            s_rk.can_share = sfr['can_share']
            return s_rk

        storage.record_keys.put_links(
            (to_shared_folder_record(x['shared_folder_uid'], y) for x in sfs if 'records' in x for y in x['records']))

        # shared folder teams
        def to_shared_folder_team(sf_uid, sft):  # type: (str, dict) -> StorageSharedFolderPermission
            s_sfp = StorageSharedFolderPermission()
            s_sfp.shared_folder_uid = sf_uid
            s_sfp.user_type = SharedFolderUserType.Team
            s_sfp.user_uid = sft['team_uid']
            s_sfp.manage_records = sft['manage_records']
            s_sfp.manage_users = sft['manage_users']
            return s_sfp

        storage.shared_folder_permissions.put_links(
            (to_shared_folder_team(x['shared_folder_uid'], y) for x in sfs if 'teams' in x for y in x['teams']))

        # shared folder users
        def to_shared_folder_users(sf_uid, sfu):  # type: (str, dict) -> StorageSharedFolderPermission
            s_sfp = StorageSharedFolderPermission()
            s_sfp.shared_folder_uid = sf_uid
            s_sfp.user_type = SharedFolderUserType.User
            s_sfp.user_uid = sfu['username']
            s_sfp.manage_records = sfu['manage_records']
            s_sfp.manage_users = sfu['manage_users']
            return s_sfp

        storage.shared_folder_permissions.put_links(
            (to_shared_folder_users(x['shared_folder_uid'], y) for x in sfs if 'users' in x for y in x['users']))

    if 'user_folders' in response:
        def to_user_folder(uf):   # type: (dict) -> Optional[StorageFolder]
            key_type = uf['key_type']
            key = utils.base64_url_decode(uf['user_folder_key'])
            try:
                if key_type == 1:
                    key = crypto.decrypt_aes_v1(key, keeper_auth.auth_context.data_key)
                elif key_type == 2:
                    key = crypto.decrypt_rsa(key, keeper_auth.auth_context.rsa_private_key)
                elif key_type == 3:
                    key = crypto.decrypt_aes_v2(key, keeper_auth.auth_context.data_key)
                elif key_type == 4:
                    key = crypto.decrypt_ec(key, keeper_auth.auth_context.ec_private_key)
                else:
                    key = None
                    logger.warning('User Folder UID %s: wrong key type %d}', shared_folder_uid, key_type)
                if key:
                    key = crypto.encrypt_aes_v2(key, keeper_auth.auth_context.client_key)
                    s_f = StorageFolder()
                    s_f.folder_uid = uf['folder_uid']
                    s_f.revision = uf['revision']
                    s_f.folder_type = uf['type']
                    s_f.parent_uid = uf.get('parent_uid', '')
                    s_f.folder_key = key
                    s_f.data = utils.base64_url_decode(uf['data'])
                    return s_f
            except Exception as e:
                logger.error('User Folder %s key decrypt error: %s', uf['folder_uid'], e)

        storage.folders.put_entities((y for y in (to_user_folder(x) for x in response['user_folders']) if y))

    if 'shared_folder_folders' in response:
        def to_shared_folder_folder(sff):   # type: (dict) -> StorageFolder
            s_f = StorageFolder()
            s_f.folder_uid = sff['folder_uid']
            s_f.shared_folder_uid = sff['shared_folder_uid']
            s_f.revision = sff['revision']
            s_f.folder_type = sff['type']
            s_f.parent_uid = sff.get('parent_uid', '')
            s_f.folder_key = utils.base64_url_decode(sff['shared_folder_folder_key'])
            s_f.data = sff['data']
            return s_f

        storage.folders.put_entities((to_shared_folder_folder(x) for x in response['shared_folder_folders']))

    if 'user_folder_shared_folders' in response:
        def to_user_folder_shared_folders(ufsf):  # type: (dict) -> StorageFolder
            s_f = StorageFolder()
            s_f.folder_uid = ufsf['shared_folder_uid']
            s_f.shared_folder_uid = ufsf['shared_folder_uid']
            s_f.folder_type = 'shared_folder'
            s_f.parent_uid = ufsf.get('folder_uid', '')
            return s_f

        storage.folders.put_entities(
            (to_user_folder_shared_folders(x) for x in response['user_folder_shared_folders']))

    if 'user_folder_records' in response:
        def to_user_folder_record(ufr):   # type: (dict) -> StorageFolderRecordLink
            s_frl = StorageFolderRecordLink()
            s_frl.folder_uid = ufr['folder_uid'] if 'folder_uid' in ufr else storage.personal_scope_uid
            s_frl.record_uid = ufr['record_uid']
            return s_frl

        storage.folder_records.put_links(
            (to_user_folder_record(x) for x in response['user_folder_records']))

    if 'shared_folder_folder_records' in response:
        def to_shared_folder_folder_records(sffr):   # type: (dict) -> StorageFolderRecordLink
            s_frl = StorageFolderRecordLink()
            s_frl.folder_uid = sffr['folder_uid'] if 'folder_uid' in sffr else sffr['shared_folder_uid']
            s_frl.record_uid = sffr['record_uid']
            return s_frl

        storage.folder_records.put_links(
            (to_shared_folder_folder_records(x) for x in response['shared_folder_folder_records']))

    if 'sharing_changes' in response:
        result.add_records((x['record_uid'] for x in response['sharing_changes']))

        def set_shared():   # type: () -> Iterable[StorageRecord]
            for sharing_change in response['sharing_changes']:
                record = storage.records.get_entity(sharing_change['record_uid'])
                if record:
                    record.shared = sharing_change['shared'] or False
                    yield record
        storage.records.put_entities(set_shared())

    if 'breach_watch_records' in response:
        def to_breach_watch_record(bwr):   # type: (dict) -> BreachWatchRecord
            bw_record = BreachWatchRecord()
            bw_record.record_uid = bwr['record_uid']
            data = bwr['data']
            if data:
                bw_record.data = utils.base64_url_decode(data)
            bw_record.type = bwr['type']
            bw_record.revision = bwr['revision']
            return bw_record
        storage.breach_watch_records.put_entities(
            (to_breach_watch_record(x) for x in response['breach_watch_records']))

    storage.revision = response['revision']

    if sync_record_types:
        rq = record_pb2.RecordTypesRequest()
        rq.standard = True
        rq.user = True
        rq.enterprise = True
        rs = keeper_auth.execute_auth_rest('vault/get_record_types', rq, response_type=record_pb2.RecordTypesResponse)

        def to_record_type(rt):   # type: (record_pb2.RecordType) -> StorageRecordType
            record_type = StorageRecordType()
            record_type.id = rt.recordTypeId
            record_type.content = rt.content
            record_type.scope = rt.scope
            return record_type

        storage.record_types.put_entities((to_record_type(x) for x in rs.recordTypes))

    return result
