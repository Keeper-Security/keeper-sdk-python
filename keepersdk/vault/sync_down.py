#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2023 Keeper Security Inc.
# Contact: ops@keepersecurity.coms
#

from typing import List, Optional, Iterable, Dict

from . import vault_data, vault_storage
from .storage_types import (
    StorageRecord, StorageSharedFolder, StorageRecordKey, StorageTeam, StorageSharedFolderKey, StorageNonSharedData,
    StorageSharedFolderPermission, StorageFolder, StorageFolderRecordLink, StorageRecordType, KeyType, StorageUserEmail,
    SharedFolderUserType, BreachWatchRecord)
from .. import crypto, utils
from ..login import auth
from ..proto import SyncDown_pb2, record_pb2
from ..storage import types


def sync_down_request(keeper_auth, storage, sync_record_types=False):
    # type: (auth.KeeperAuth, vault_storage.IVaultStorage, bool) -> vault_data.RebuildTask
    logger = utils.get_logger()

    email_lookup = {}  # type: Dict[str, Optional[str]]

    def get_account_uid_by_email(email):  # type: (str) -> Optional[str]
        nonlocal email_lookup
        if email not in email_lookup:
            link = next(storage.user_emails.get_links_for_object(email), None)
            if link:
                email_lookup[email] = link.email
            else:
                email_lookup[email] = None

        return email_lookup[email]

    rq = SyncDown_pb2.SyncDownRequest()
    done = False
    token = storage.continuation_token
    result = None  # type: Optional[vault_data.RebuildTask]
    record_owners = {}  # type: Dict[str, bool]
    while not done:
        if token:
            rq.continuationToken = token
        response = keeper_auth.execute_auth_rest('vault/sync_down', rq, response_type=SyncDown_pb2.SyncDownResponse)
        assert response is not None
        done = not response.hasMore
        token = response.continuationToken
        if response.cacheStatus == SyncDown_pb2.CLEAR:
            sync_record_types = True
            storage.clear()
        if result is None:
            result = vault_data.RebuildTask(response.cacheStatus == SyncDown_pb2.CLEAR)

        if len(response.removedRecords) > 0:
            record_uids = [utils.base64_url_encode(x) for x in response.removedRecords]
            result.add_records(record_uids)
            storage.record_keys.delete_links(((x, storage.personal_scope_uid) for x in record_uids))

            # linked records
            record_links = []  # type: List[types.IUidLink]
            for record_uid in record_uids:
                record_links.extend(storage.record_keys.get_links_for_object(record_uid))
            storage.record_keys.delete_links(record_links)
            result.add_records((x.subject_uid() for x in record_links))

            # remove records from user_folders
            record_links.clear()
            for record_uid in record_uids:
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

        if len(response.removedTeams) > 0:
            removed_teams = [utils.base64_url_encode(x) for x in response.removedTeams]
            sf_links = []  # type: List[types.IUidLink]
            for team_uid in removed_teams:
                sf_links.extend(storage.shared_folder_keys.get_links_for_object(team_uid))
            result.add_shared_folders((x.subject_uid() for x in sf_links))
            storage.shared_folder_keys.delete_links(sf_links)
            storage.teams.delete_uids(removed_teams)
            del sf_links

        if len(response.removedSharedFolders) > 0:
            removed_shared_folders = [utils.base64_url_encode(x) for x in response.removedSharedFolders]
            rec_links = []  # type: List[types.IUidLink]
            for shared_folder_uid in removed_shared_folders:
                rec_links.extend(storage.record_keys.get_links_for_object(shared_folder_uid))
            result.add_shared_folders(removed_shared_folders)
            result.add_records((x.subject_uid() for x in rec_links))
            storage.shared_folder_keys.delete_links(
                (x, storage.personal_scope_uid) for x in removed_shared_folders)
            del rec_links

        if len(response.removedRecordLinks) > 0:
            links = [types.UidLink(utils.base64_url_encode(x.childRecordUid),
                                   utils.base64_url_encode(x.parentRecordUid))
                     for x in response.removedRecordLinks]
            result.add_records((x.subject_uid() for x in links))
            storage.record_keys.delete_links(links)
            del links

        if len(response.removedUserFolders) > 0:
            uids = [utils.base64_url_encode(x) for x in response.removedUserFolders]
            storage.folder_records.delete_links_for_subjects(uids)
            storage.folders.delete_uids(uids)
            del uids

        if len(response.removedSharedFolderFolders) > 0:
            uids = [utils.base64_url_encode(x.folderUid or x.sharedFolderUid)
                    for x in response.removedSharedFolderFolders]
            storage.folder_records.delete_links_for_subjects(uids)
            storage.folders.delete_uids(uids)
            del uids

        if len(response.removedUserFolderSharedFolders) > 0:
            shared_folder_uids = [utils.base64_url_encode(x.sharedFolderUid)
                                  for x in response.removedUserFolderSharedFolders]
            storage.folder_records.delete_links_for_subjects(shared_folder_uids)
            storage.folders.delete_uids(shared_folder_uids)
            del shared_folder_uids

        if len(response.removedUserFolderRecords) > 0:
            storage.folder_records.delete_links((types.UidLink(
                utils.base64_url_encode(x.folderUid) if x.folderUid else storage.personal_scope_uid,
                utils.base64_url_encode(x.recordUid))
                for x in response.removedUserFolderRecords))

        if len(response.removedSharedFolderFolderRecords) > 0:
            storage.folder_records.delete_links((types.UidLink(
                utils.base64_url_encode(x.folderUid or x.sharedFolderUid),
                utils.base64_url_encode(x.recordUid))
                for x in response.removedSharedFolderFolderRecords))

        if len(response.recordMetaData) > 0:
            record_owners.update(((utils.base64_url_encode(x.recordUid), x.owner) for x in response.recordMetaData))

            def to_record_key(rmd):  # type: (SyncDown_pb2.RecordMetaData) -> Optional[StorageRecordKey]
                r_uid = utils.base64_url_encode(rmd.recordUid)
                key_type = rmd.recordKeyType
                record_key = rmd.recordKey
                try:
                    if key_type == record_pb2.NO_KEY:
                        record_key = keeper_auth.auth_context.data_key
                    elif key_type == record_pb2.ENCRYPTED_BY_DATA_KEY:
                        record_key = crypto.decrypt_aes_v1(record_key, keeper_auth.auth_context.data_key)
                    elif key_type == record_pb2.ENCRYPTED_BY_PUBLIC_KEY:
                        assert keeper_auth.auth_context.rsa_private_key is not None
                        record_key = crypto.decrypt_rsa(record_key, keeper_auth.auth_context.rsa_private_key)
                    elif key_type == record_pb2.ENCRYPTED_BY_DATA_KEY_GCM:
                        record_key = crypto.decrypt_aes_v2(record_key, keeper_auth.auth_context.data_key)
                    elif key_type == record_pb2.ENCRYPTED_BY_PUBLIC_KEY_ECC:
                        assert keeper_auth.auth_context.ec_private_key is not None
                        record_key = crypto.decrypt_ec(record_key, keeper_auth.auth_context.ec_private_key)
                    else:
                        record_key = b''
                        logger.error(f'Record metadata UID %s: unsupported key type %d', r_uid, key_type)

                    if record_key:
                        sr_key = StorageRecordKey()
                        sr_key.record_uid = r_uid
                        sr_key.record_key = crypto.encrypt_aes_v2(record_key, keeper_auth.auth_context.client_key)
                        sr_key.key_type = KeyType.DataKey
                        sr_key.shared_folder_uid = storage.personal_scope_uid
                        sr_key.can_edit = rmd.canEdit
                        sr_key.can_share = rmd.canShare
                        return sr_key
                except Exception as e:
                    logger.error('Metadata for record UID %s key decrypt error: %s', record_uid, e)

            record_meta_data = [y for y in (to_record_key(x) for x in response.recordMetaData) if y]
            result.add_records((x.record_uid for x in record_meta_data))
            storage.record_keys.put_links(record_meta_data)

        if len(response.recordLinks) > 0:
            def to_link_key(rec):  # type: (SyncDown_pb2.RecordLink) -> StorageRecordKey
                record_key = StorageRecordKey()
                record_key.record_uid = utils.base64_url_encode(rec.childRecordUid)
                record_key.record_key = rec.recordKey
                record_key.shared_folder_uid = utils.base64_url_encode(rec.parentRecordUid)
                record_key.key_type = KeyType.RecordKey
                record_key.can_edit = False
                record_key.can_share = False
                return record_key

            link_keys = [to_link_key(x) for x in response.recordLinks]
            storage.record_keys.put_links(link_keys)
            result.add_records((x.record_uid for x in link_keys))
            del link_keys

        if len(response.records) > 0:
            def to_record(rec):  # type: (SyncDown_pb2.Record) -> StorageRecord
                record = StorageRecord()
                record.record_uid = utils.base64_url_encode(rec.recordUid)
                record.version = rec.version
                record.revision = rec.revision
                record.client_modified_time = rec.clientModifiedTime
                record.data = rec.data
                record.extra = rec.extra
                record.udata = rec.udata
                record.shared = rec.shared
                if record.record_uid in record_owners:
                    record.owner = record_owners[record.record_uid]
                    del record_owners[record.record_uid]
                return record

            recs = [to_record(x) for x in response.records]
            storage.records.put_entities(recs)
            result.add_records((x.record_uid for x in recs))
            del recs

        if len(response.nonSharedData) > 0:
            def to_non_shared_data(nsd):  # type: (SyncDown_pb2.NonSharedData) -> StorageNonSharedData
                s_nsd = StorageNonSharedData()
                s_nsd.record_uid = utils.base64_url_encode(nsd.recordUid)
                s_nsd.data = nsd.data
                return s_nsd

            storage.non_shared_data.put_entities((to_non_shared_data(x) for x in response.nonSharedData))

        if len(response.removedUsers) > 0:
            storage.user_emails.delete_links_for_subjects((utils.base64_url_encode(x) for x in response.removedUsers))

        if len(response.users) > 0:
            def to_user_emails(user):  # type: (SyncDown_pb2.User) -> StorageUserEmail
                sue = StorageUserEmail()
                sue.account_uid = utils.base64_url_encode(user.accountUid)
                sue.email = user.username
                return sue

            user_emails = [to_user_emails(x) for x in response.users]
            storage.user_emails.put_links(user_emails)

        if len(response.sharedFolders) > 0:
            uids = [utils.base64_url_encode(x.sharedFolderUid) for x in response.sharedFolders
                    if x.cacheStatus == SyncDown_pb2.CLEAR]
            storage.shared_folder_keys.delete_links_for_subjects(uids)
            storage.shared_folder_permissions.delete_links_for_subjects(uids)
            del uids

        if len(response.teams) > 0:
            sf_removed_keys = []  # type: List[types.UidLink]
            for team in response.teams:
                team_uid = utils.base64_url_encode(team.teamUid)
                sf_removed_keys.extend(
                    (types.UidLink(utils.base64_url_encode(x), team_uid) for x in team.removedSharedFolders))

            if sf_removed_keys:
                result.add_shared_folders((x.subject_uid() for x in sf_removed_keys))
                storage.shared_folder_keys.delete_links(sf_removed_keys)
            del sf_removed_keys

            def to_team(sync_down_team):  # type: (SyncDown_pb2.Team) -> Optional[StorageTeam]
                try:
                    key_type = sync_down_team.teamKeyType
                    team_key = sync_down_team.teamKey
                    if key_type == record_pb2.ENCRYPTED_BY_DATA_KEY:
                        team_key = crypto.decrypt_aes_v1(team_key, keeper_auth.auth_context.data_key)
                    elif key_type == record_pb2.ENCRYPTED_BY_PUBLIC_KEY:
                        assert keeper_auth.auth_context.rsa_private_key is not None
                        team_key = crypto.decrypt_rsa(team_key, keeper_auth.auth_context.rsa_private_key)
                    elif key_type == record_pb2.ENCRYPTED_BY_DATA_KEY_GCM:
                        team_key = crypto.decrypt_aes_v2(team_key, keeper_auth.auth_context.data_key)
                    elif key_type == record_pb2.ENCRYPTED_BY_PUBLIC_KEY_ECC:
                        assert keeper_auth.auth_context.ec_private_key is not None
                        team_key = crypto.decrypt_ec(team_key, keeper_auth.auth_context.ec_private_key)
                    else:
                        team_key = b''
                        logger.debug('Team UID %s: unsupported key type %d', team_uid, key_type)
                    if team_key:
                        encrypted_team_key = crypto.encrypt_aes_v2(team_key, keeper_auth.auth_context.client_key)
                        s_team = StorageTeam()
                        s_team.team_uid = utils.base64_url_encode(sync_down_team.teamUid)
                        s_team.name = sync_down_team.name
                        s_team.team_key = encrypted_team_key
                        s_team.key_type = KeyType.DataKey
                        s_team.team_private_key = sync_down_team.teamPrivateKey
                        s_team.restrict_edit = sync_down_team.restrictEdit
                        s_team.restrict_share = sync_down_team.restrictShare
                        s_team.restrict_view = sync_down_team.restrictView
                        return s_team
                except Exception as e:
                    logger.error('Team %s key decrypt error: %s', team_uid, e)

            storage.teams.put_entities((y for y in (to_team(x) for x in response.teams) if y))

            sf_keys = []  # type: List[StorageSharedFolderKey]

            def to_shared_folder_key_team(sfk):  # type: (SyncDown_pb2.SharedFolderKey) -> StorageSharedFolderKey
                sshk = StorageSharedFolderKey()
                sshk.shared_folder_uid = utils.base64_url_encode(sfk.sharedFolderUid)
                sshk.team_uid = team_uid
                sshk.key_type = KeyType.TeamRsaPrivateKey if sfk.keyType == 2 else KeyType.TeamKey
                sshk.shared_folder_key = sfk.sharedFolderKey
                return sshk

            sf_keys.extend((to_shared_folder_key_team(k) for team in response.teams for k in team.sharedFolderKeys))
            storage.shared_folder_keys.put_links(sf_keys)
            del sf_keys

        if len(response.sharedFolders) > 0:
            def to_shared_folder(shared_folder):  # type: (SyncDown_pb2.SharedFolder) -> StorageSharedFolder
                s_sf = StorageSharedFolder()
                s_sf.shared_folder_uid = utils.base64_url_encode(shared_folder.sharedFolderUid)
                s_sf.owner_account_uid = utils.base64_url_encode(shared_folder.ownerAccountUid)
                s_sf.revision = shared_folder.revision
                s_sf.name = shared_folder.name
                s_sf.data = shared_folder.data
                s_sf.default_manage_records = shared_folder.defaultManageRecords
                s_sf.default_manage_users = shared_folder.defaultManageUsers
                s_sf.default_can_edit = shared_folder.defaultCanEdit
                s_sf.default_can_share = shared_folder.defaultCanReshare
                return s_sf

            sfs = [to_shared_folder(x) for x in response.sharedFolders]
            result.add_shared_folders((x.shared_folder_uid for x in sfs))
            storage.shared_folders.put_entities(sfs)
            del sfs

            def to_shared_folder_key(shared_folder):
                # type: (SyncDown_pb2.SharedFolder) -> Optional[StorageSharedFolderKey]
                if len(shared_folder.sharedFolderKey) > 0:
                    try:
                        key_type = shared_folder.keyType
                        shared_folder_key = shared_folder.sharedFolderKey
                        if key_type == record_pb2.ENCRYPTED_BY_DATA_KEY:
                            shared_folder_key = crypto.decrypt_aes_v1(
                                shared_folder_key, keeper_auth.auth_context.data_key)
                        elif key_type == record_pb2.ENCRYPTED_BY_PUBLIC_KEY:
                            assert keeper_auth.auth_context.rsa_private_key is not None
                            shared_folder_key = crypto.decrypt_rsa(
                                shared_folder_key, keeper_auth.auth_context.rsa_private_key)
                        elif key_type == record_pb2.ENCRYPTED_BY_DATA_KEY_GCM:
                            shared_folder_key = crypto.decrypt_aes_v2(
                                shared_folder_key, keeper_auth.auth_context.data_key)
                        elif key_type == record_pb2.ENCRYPTED_BY_PUBLIC_KEY_ECC:
                            assert keeper_auth.auth_context.ec_private_key is not None
                            shared_folder_key = crypto.decrypt_ec(
                                shared_folder_key, keeper_auth.auth_context.ec_private_key)
                        else:
                            shared_folder_key = b''
                            logger.warning('Shared Folder UID %s: wrong key type %d}', shared_folder_uid, key_type)
                        if shared_folder_key:
                            shared_folder_key = \
                                crypto.encrypt_aes_v2(shared_folder_key, keeper_auth.auth_context.client_key)
                            s_sfkey = StorageSharedFolderKey()
                            s_sfkey.shared_folder_uid = utils.base64_url_encode(shared_folder.sharedFolderUid)
                            s_sfkey.team_uid = storage.personal_scope_uid
                            s_sfkey.shared_folder_key = shared_folder_key
                            s_sfkey.key_type = KeyType.DataKey
                            return s_sfkey
                    except Exception as e:
                        logger.error('Shared Folder %s key decrypt error: %s', shared_folder_uid, e)

            storage.shared_folder_keys.put_links(
                (y for y in (to_shared_folder_key(x) for x in response.sharedFolders) if y))

        # shared folder users
        if len(response.sharedFolderUsers) > 0:
            def to_sf_users(sfu):  # type: (SyncDown_pb2.SharedFolderUser) -> StorageSharedFolderPermission
                s_sfp = StorageSharedFolderPermission()
                s_sfp.shared_folder_uid = utils.base64_url_encode(sfu.sharedFolderUid)
                s_sfp.user_type = SharedFolderUserType.User
                s_sfp.user_uid = utils.base64_url_encode(sfu.accountUid)
                s_sfp.manage_records = sfu.manageRecords
                s_sfp.manage_users = sfu.manageUsers
                s_sfp.expiration = sfu.expiration
                return s_sfp

            storage.shared_folder_permissions.put_links((to_sf_users(x) for x in response.sharedFolderUsers))

        # shared folder teams
        if len(response.sharedFolderTeams) > 0:
            def to_sf_team(sft):  # type: (SyncDown_pb2.SharedFolderTeam) -> StorageSharedFolderPermission
                s_sfp = StorageSharedFolderPermission()
                s_sfp.shared_folder_uid = utils.base64_url_encode(sft.sharedFolderUid)
                s_sfp.user_type = SharedFolderUserType.Team
                s_sfp.user_uid = utils.base64_url_encode(sft.teamUid)
                s_sfp.manage_records = sft.manageRecords
                s_sfp.manage_users = sft.manageRecords
                s_sfp.expiration = sft.expiration
                return s_sfp

            storage.shared_folder_permissions.put_links((to_sf_team(x) for x in response.sharedFolderTeams))

        # shared folder records
        if len(response.sharedFolderRecords) > 0:
            def to_sf_record(sfr):  # type: (SyncDown_pb2.SharedFolderRecord) -> StorageRecordKey
                s_rk = StorageRecordKey()
                s_rk.record_uid = utils.base64_url_encode(sfr.recordUid)
                s_rk.shared_folder_uid = utils.base64_url_encode(sfr.sharedFolderUid)
                s_rk.key_type = KeyType.SharedFolderKey
                s_rk.record_key = sfr.recordKey
                s_rk.can_edit = sfr.canEdit
                s_rk.can_share = sfr.canShare
                s_rk.owner_account_uid = utils.base64_url_encode(sfr.ownerAccountUid)
                return s_rk

            sfrs = [to_sf_record(x) for x in response.sharedFolderRecords]
            result.add_records((x.record_uid for x in sfrs))
            storage.record_keys.put_links(sfrs)
            del sfrs

        if len(response.removedSharedFolderRecords) > 0:
            rsfrs = [types.UidLink(
                utils.base64_url_encode(x.recordUid),
                utils.base64_url_encode(x.sharedFolderUid),
            ) for x in response.removedSharedFolderRecords]
            storage.record_keys.delete_links(rsfrs)
            result.add_records((x.subject_uid() for x in rsfrs))
            del rsfrs

        if len(response.removedSharedFolderUsers) > 0:
            rsfus = []  # type: List[types.IUidLink]
            for x in response.removedSharedFolderUsers:
                shf_uid = utils.base64_url_encode(x.sharedFolderUid)
                if len(x.accountUid) > 0:
                    account_uid = utils.base64_url_encode(x.accountUid)  # type: Optional[str]
                else:
                    account_uid = get_account_uid_by_email(x.username)
                if account_uid:
                    rsfus.append(types.UidLink(shf_uid, account_uid))
            storage.shared_folder_permissions.delete_links(rsfus)

        if len(response.removedSharedFolderTeams) > 0:
            storage.shared_folder_keys.delete_links((types.UidLink(
                utils.base64_url_encode(x.sharedFolderUid),
                utils.base64_url_encode(x.teamUid)
            ) for x in response.removedSharedFolderTeams))

        if len(response.userFolders) > 0:
            def to_user_folder(uf):  # type: (SyncDown_pb2.UserFolder) -> Optional[StorageFolder]
                key_type = uf.keyType
                key = uf.userFolderKey
                try:
                    if key_type == record_pb2.ENCRYPTED_BY_DATA_KEY:
                        key = crypto.decrypt_aes_v1(key, keeper_auth.auth_context.data_key)
                    elif key_type == record_pb2.ENCRYPTED_BY_DATA_KEY:
                        assert keeper_auth.auth_context.rsa_private_key is not None
                        key = crypto.decrypt_rsa(key, keeper_auth.auth_context.rsa_private_key)
                    elif key_type == record_pb2.ENCRYPTED_BY_DATA_KEY_GCM:
                        key = crypto.decrypt_aes_v2(key, keeper_auth.auth_context.data_key)
                    elif key_type == record_pb2.ENCRYPTED_BY_PUBLIC_KEY_ECC:
                        assert keeper_auth.auth_context.ec_private_key is not None
                        key = crypto.decrypt_ec(key, keeper_auth.auth_context.ec_private_key)
                    else:
                        key = b''
                        logger.warning('User Folder UID %s: wrong key type %d}', shared_folder_uid, key_type)
                    if key:
                        key = crypto.encrypt_aes_v2(key, keeper_auth.auth_context.client_key)
                        s_f = StorageFolder()
                        s_f.folder_uid = utils.base64_url_encode(uf.folderUid)
                        s_f.revision = uf.revision
                        s_f.folder_type = 'user_folder'
                        s_f.parent_uid = utils.base64_url_encode(uf.parentUid) if uf.parentUid else ''
                        s_f.folder_key = key
                        s_f.data = uf.data
                        return s_f
                except Exception as e:
                    logger.error('User Folder %s key decrypt error: %s', utils.base64_url_encode(uf.folderUid), e)

            storage.folders.put_entities((y for y in (to_user_folder(x) for x in response.userFolders) if y))

        if len(response.userFolderSharedFolders) > 0:
            def to_user_folder_shared_folders(ufsf):  # type: (SyncDown_pb2.UserFolderSharedFolder) -> StorageFolder
                s_f = StorageFolder()
                s_f.folder_uid = utils.base64_url_encode(ufsf.sharedFolderUid)
                s_f.shared_folder_uid = utils.base64_url_encode(ufsf.sharedFolderUid)
                s_f.folder_type = 'shared_folder'
                s_f.parent_uid = utils.base64_url_encode(ufsf.folderUid) if ufsf.folderUid else ''
                return s_f

            storage.folders.put_entities(
                (to_user_folder_shared_folders(x) for x in response.userFolderSharedFolders))

        if len(response.sharedFolderFolders) > 0:
            def to_shared_folder_folder(sff):  # type: (SyncDown_pb2.SharedFolderFolder) -> StorageFolder
                s_f = StorageFolder()
                s_f.folder_uid = utils.base64_url_encode(sff.folderUid)
                s_f.shared_folder_uid = utils.base64_url_encode(sff.sharedFolderUid)
                s_f.revision = sff.revision
                s_f.folder_type = 'shared_folder_folder'
                s_f.parent_uid = utils.base64_url_encode(sff.parentUid) if sff.parentUid else ''
                s_f.folder_key = sff.sharedFolderFolderKey
                s_f.data = sff.data
                return s_f

            storage.folders.put_entities((to_shared_folder_folder(x) for x in response.sharedFolderFolders))

        if len(response.userFolderRecords) > 0:
            def to_user_folder_record(ufr):  # type: (SyncDown_pb2.UserFolderRecord) -> StorageFolderRecordLink
                s_frl = StorageFolderRecordLink()
                s_frl.folder_uid = utils.base64_url_encode(ufr.folderUid) \
                    if ufr.folderUid else storage.personal_scope_uid
                s_frl.record_uid = utils.base64_url_encode(ufr.recordUid)
                return s_frl

            storage.folder_records.put_links(
                (to_user_folder_record(x) for x in response.userFolderRecords))

        if len(response.sharedFolderFolderRecords) > 0:
            def to_shared_folder_folder_records(sffr):
                # type: (SyncDown_pb2.SharedFolderFolderRecord) -> StorageFolderRecordLink
                s_frl = StorageFolderRecordLink()
                s_frl.folder_uid = utils.base64_url_encode(sffr.folderUid or sffr.sharedFolderUid)
                s_frl.record_uid = utils.base64_url_encode(sffr.recordUid)
                return s_frl

            storage.folder_records.put_links(
                (to_shared_folder_folder_records(x) for x in response.sharedFolderFolderRecords))

        if len(response.sharingChanges) > 0:
            def set_shared(changes):  # type: (Iterable[SyncDown_pb2.SharingChange]) -> Iterable[StorageRecord]
                for sharing_change in changes:
                    r_uid = utils.base64_url_encode(sharing_change.recordUid)
                    record = storage.records.get_entity(r_uid)
                    if record:
                        record.shared = sharing_change.shared
                        yield record

            storage.records.put_entities(set_shared(response.sharingChanges))
            result.add_records((utils.base64_url_encode(x.recordUid) for x in response.sharingChanges))

        if len(response.breachWatchRecords) > 0:
            def to_breach_watch_record(bwr):  # type: (SyncDown_pb2.BreachWatchRecord) -> BreachWatchRecord
                bw_record = BreachWatchRecord()
                bw_record.record_uid = utils.base64_url_encode(bwr.recordUid)
                bw_record.data = bwr.data
                bw_record.type = bwr.type
                bw_record.revision = bwr.revision
                return bw_record

            storage.breach_watch_records.put_entities(
                (to_breach_watch_record(x) for x in response.breachWatchRecords))

    if len(record_owners) > 0:
        records = []
        for record_uid in record_owners:
            e_record = storage.records.get_entity(record_uid)
            if e_record and e_record.owner != record_owners[record_uid]:
                e_record.owner = record_owners[record_uid]
                records.append(e_record)
        if records:
            storage.records.put_entities(records)

    if sync_record_types:
        rt_rq = record_pb2.RecordTypesRequest()
        rt_rq.standard = True
        rt_rq.user = True
        rt_rq.enterprise = True
        rt_rs = keeper_auth.execute_auth_rest(
            'vault/get_record_types', rt_rq, response_type=record_pb2.RecordTypesResponse)
        assert rt_rs is not None

        def to_record_type(rt):  # type: (record_pb2.RecordType) -> StorageRecordType
            record_type = StorageRecordType()
            record_type.id = rt.recordTypeId
            record_type.content = rt.content
            record_type.scope = rt.scope
            return record_type

        storage.record_types.put_entities((to_record_type(x) for x in rt_rs.recordTypes))

    assert result is not None
    return result
