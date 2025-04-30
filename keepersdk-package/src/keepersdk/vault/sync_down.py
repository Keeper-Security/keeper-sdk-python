import json
from typing import List, Optional, Iterable

from . import vault_data, vault_storage
from .storage_types import (
    StorageRecord, StorageSharedFolder, StorageRecordKey, StorageTeam, StorageSharedFolderKey, StorageNonSharedData,
    StorageSharedFolderPermission, StorageFolder, StorageFolderRecord, StorageRecordType, StorageKeyType,
    StorageUserEmail, StorageNotification,
    SharedFolderUserType, BreachWatchRecord, BreachWatchSecurityData, UserSettings)
from .vault_plugins import IPendingSharePlugin, IAuditDataPlugin
from .. import crypto, utils
from ..authentication import keeper_auth
from ..proto import SyncDown_pb2, record_pb2, NotificationCenter_pb2
from ..storage import storage_types


def decrypt_keeper_key(auth_context: keeper_auth.AuthContext, encrypted: bytes, key_type: record_pb2.RecordKeyType) -> bytes:
    if key_type == record_pb2.NO_KEY:
        return auth_context.data_key
    elif key_type == record_pb2.ENCRYPTED_BY_DATA_KEY:
        return crypto.decrypt_aes_v1(encrypted, auth_context.data_key)
    elif key_type == record_pb2.ENCRYPTED_BY_PUBLIC_KEY:
        assert auth_context.rsa_private_key is not None
        return crypto.decrypt_rsa(encrypted, auth_context.rsa_private_key)
    elif key_type == record_pb2.ENCRYPTED_BY_DATA_KEY_GCM:
        return crypto.decrypt_aes_v2(encrypted, auth_context.data_key)
    elif key_type == record_pb2.ENCRYPTED_BY_PUBLIC_KEY_ECC:
        assert auth_context.ec_private_key is not None
        return crypto.decrypt_ec(encrypted, auth_context.ec_private_key)
    else:
        raise ValueError(f'unsupported key type {key_type}')


def sync_down_request(auth: keeper_auth.KeeperAuth,
                      storage: vault_storage.IVaultStorage,
                      *,
                      pending_shares: Optional[IPendingSharePlugin]=None,
                      audit_data: Optional[IAuditDataPlugin]=None,
                      sync_record_types: bool=False) -> vault_data.RebuildTask:
    logger = utils.get_logger()

    user_settings = storage.user_settings.load()
    if user_settings is None:
        user_settings = UserSettings()

    token = user_settings.continuation_token
    task: Optional[vault_data.RebuildTask] = None
    done = False
    rq = SyncDown_pb2.SyncDownRequest()
    while not done:
        rq.continuationToken = token
        response = auth.execute_auth_rest('vault/sync_down', rq, response_type=SyncDown_pb2.SyncDownResponse)
        assert response is not None
        done = not response.hasMore
        token = response.continuationToken
        if response.cacheStatus == SyncDown_pb2.CLEAR:
            sync_record_types = True
            storage.clear()
            logger.info('Syncing...')
        if task is None:
            task = vault_data.RebuildTask(response.cacheStatus == SyncDown_pb2.CLEAR)

        if len(response.removedRecords) > 0:
            record_uids = [utils.base64_url_encode(x) for x in response.removedRecords]
            task.add_records(record_uids)
            storage.record_keys.delete_links(((x, storage.personal_scope_uid) for x in record_uids))

            # linked records
            record_links: List[storage_types.IUidLink] = []
            for record_uid in record_uids:
                record_links.extend(storage.record_keys.get_links_by_object(record_uid))
            storage.record_keys.delete_links(record_links)
            task.add_records((x.subject_uid() for x in record_links))

            # remove records from user_folders
            record_links.clear()
            for record_uid in record_uids:
                record_links.extend(storage.folder_records.get_links_by_object(record_uid))
            folder_uids = {x.subject_uid() for x in record_links}
            for folder_uid in list(folder_uids):
                if folder_uid == storage.personal_scope_uid:
                    continue
                folder = storage.folders.get_entity(folder_uid)
                if folder:
                    if folder.folder_type == 'user_folder':
                        continue
                folder_uids.remove(folder_uid)
            if folder_uids:
                storage.folder_records.delete_links((x for x in record_links if x.subject_uid() in folder_uids))

            del record_links
            del folder_uids

        if len(response.removedTeams) > 0:
            removed_teams = [utils.base64_url_encode(x) for x in response.removedTeams]
            sf_links: List[storage_types.IUidLink] = []
            for team_uid in removed_teams:
                sf_links.extend(storage.shared_folder_keys.get_links_by_object(team_uid))
            task.add_shared_folders((x.subject_uid() for x in sf_links))
            storage.shared_folder_keys.delete_links(sf_links)
            storage.teams.delete_uids(removed_teams)
            del sf_links

        if len(response.removedSharedFolders) > 0:
            rsf = [utils.base64_url_encode(x) for x in response.removedSharedFolders]
            task.add_shared_folders(rsf)
            storage.shared_folder_keys.delete_links((storage_types.UidLink(x, storage.personal_scope_uid) for x in rsf))
            del rsf

        if len(response.removedRecordLinks) > 0:
            links = [storage_types.UidLink(utils.base64_url_encode(x.childRecordUid),
                                   utils.base64_url_encode(x.parentRecordUid))
                     for x in response.removedRecordLinks]
            task.add_records((x.subject_uid() for x in links))
            storage.record_keys.delete_links(links)
            del links

        if len(response.removedUserFolders) > 0:
            uids = [utils.base64_url_encode(x) for x in response.removedUserFolders]
            storage.folder_records.delete_links_by_subjects(uids)
            storage.folders.delete_uids(uids)
            del uids

        if len(response.removedSharedFolderFolders) > 0:
            uids = [utils.base64_url_encode(x.folderUid or x.sharedFolderUid)
                    for x in response.removedSharedFolderFolders]
            storage.folder_records.delete_links_by_subjects(uids)
            storage.folders.delete_uids(uids)
            del uids

        if len(response.removedUserFolderSharedFolders) > 0:
            # ?????
            pass

        if len(response.removedUserFolderRecords) > 0:
            storage.folder_records.delete_links((storage_types.UidLink(
                utils.base64_url_encode(x.folderUid) if x.folderUid else storage.personal_scope_uid,
                utils.base64_url_encode(x.recordUid))
                for x in response.removedUserFolderRecords))

        if len(response.removedSharedFolderFolderRecords) > 0:
            storage.folder_records.delete_links((storage_types.UidLink(
                utils.base64_url_encode(x.folderUid or x.sharedFolderUid),
                utils.base64_url_encode(x.recordUid))
                for x in response.removedSharedFolderFolderRecords))

        if len(response.removedUsers) > 0:
            storage.user_emails.delete_links_by_subjects((utils.base64_url_encode(x) for x in response.removedUsers))

        if len(response.users) > 0:
            def to_user_emails(user: SyncDown_pb2.User) -> StorageUserEmail:
                sue = StorageUserEmail()
                sue.account_uid = utils.base64_url_encode(user.accountUid)
                sue.email = user.username
                return sue

            user_emails = [to_user_emails(x) for x in response.users]
            storage.user_emails.put_links(user_emails)

        if len(response.recordMetaData) > 0:
            def to_record_key(rmd: SyncDown_pb2.RecordMetaData) -> Optional[StorageRecordKey]:
                r_uid = utils.base64_url_encode(rmd.recordUid)
                key_type = rmd.recordKeyType
                record_key = rmd.recordKey
                try:
                    record_key = decrypt_keeper_key(auth.auth_context, record_key, key_type)

                    sr_key = StorageRecordKey()
                    sr_key.record_uid = r_uid
                    sr_key.record_key = crypto.encrypt_aes_v2(record_key, auth.auth_context.client_key)
                    sr_key.key_type = StorageKeyType.UserClientKey_AES_GCM
                    sr_key.encrypter_uid = storage.personal_scope_uid
                    sr_key.can_edit = rmd.canEdit
                    sr_key.can_share = rmd.canShare
                    sr_key.owner = rmd.owner
                    sr_key.owner_account_uid = utils.base64_url_encode(rmd.ownerAccountUid)
                    return sr_key
                except Exception as e:
                    logger.debug('Metadata for record UID %s key decrypt error: %s', r_uid, e)

            record_meta_data = [y for y in (to_record_key(x) for x in response.recordMetaData) if y]
            task.add_records((x.record_uid for x in record_meta_data))
            storage.record_keys.put_links(record_meta_data)

        if len(response.recordLinks) > 0:
            def to_link_key(rec: SyncDown_pb2.RecordLink) -> StorageRecordKey:
                record_key = StorageRecordKey()
                record_key.record_uid = utils.base64_url_encode(rec.childRecordUid)
                record_key.record_key = rec.recordKey
                record_key.encrypter_uid = utils.base64_url_encode(rec.parentRecordUid)
                record_key.key_type = StorageKeyType.RecordKey_AES_GCM
                record_key.can_edit = False
                record_key.can_share = False
                return record_key

            link_keys = [to_link_key(x) for x in response.recordLinks]
            storage.record_keys.put_links(link_keys)
            task.add_records((x.record_uid for x in link_keys))
            del link_keys

        if len(response.records) > 0:
            def to_record(rec: SyncDown_pb2.Record) -> StorageRecord:
                record = StorageRecord()
                record.record_uid = utils.base64_url_encode(rec.recordUid)
                record.version = rec.version
                record.revision = rec.revision
                record.modified_time = rec.clientModifiedTime
                record.data = rec.data
                record.extra = rec.extra
                record.udata = rec.udata
                record.shared = rec.shared
                return record

            recs = [to_record(x) for x in response.records]
            storage.records.put_entities(recs)
            task.add_records((x.record_uid for x in recs))
            del recs

        if len(response.nonSharedData) > 0:
            def to_non_shared_data(nsd: SyncDown_pb2.NonSharedData) -> StorageNonSharedData:
                s_nsd = StorageNonSharedData()
                s_nsd.record_uid = utils.base64_url_encode(nsd.recordUid)
                s_nsd.data = nsd.data
                return s_nsd

            storage.non_shared_data.put_entities((to_non_shared_data(x) for x in response.nonSharedData))

        if len(response.teams) > 0:
            sf_removed_keys: List[storage_types.UidLink[str, str]] = []
            for team in response.teams:
                team_uid = utils.base64_url_encode(team.teamUid)
                sf_removed_keys.extend(
                    (storage_types.UidLink(utils.base64_url_encode(x), team_uid) for x in team.removedSharedFolders))

            if sf_removed_keys:
                task.add_shared_folders((x.subject_uid() for x in sf_removed_keys))
                storage.shared_folder_keys.delete_links(sf_removed_keys)
            del sf_removed_keys

            sf_keys: List[StorageSharedFolderKey] = []

            def to_team(sync_down_team: SyncDown_pb2.Team) -> Optional[StorageTeam]:
                try:
                    team_key = decrypt_keeper_key(auth.auth_context, sync_down_team.teamKey, sync_down_team.teamKeyType)

                    for sfk in sync_down_team.sharedFolderKeys:
                        sf_uid = utils.base64_url_encode(sfk.sharedFolderUid)
                        try:
                            sfkd = sfk.sharedFolderKey
                            if sfk.keyType == record_pb2.ENCRYPTED_BY_DATA_KEY:
                                sfkd = crypto.decrypt_aes_v1(sfkd, team_key)
                            elif sfk.keyType == record_pb2.ENCRYPTED_BY_PUBLIC_KEY:
                                team_private_key = crypto.decrypt_aes_v1(sync_down_team.teamPrivateKey, team_key)
                                rsa_private_key = crypto.load_rsa_private_key(team_private_key)
                                sfkd = crypto.decrypt_rsa(sfkd, rsa_private_key)
                            elif sfk.keyType == record_pb2.ENCRYPTED_BY_DATA_KEY_GCM:
                                sfkd = crypto.decrypt_aes_v2(sfkd, team_key)
                            elif sfk.keyType == record_pb2.ENCRYPTED_BY_PUBLIC_KEY_ECC:
                                team_private_key = crypto.decrypt_aes_v2(sync_down_team.teamEccPrivateKey, team_key)
                                ec_private_key = crypto.load_ec_private_key(team_private_key)
                                sfkd = crypto.decrypt_ec(sfkd, ec_private_key)
                            else:
                                raise ValueError(f'unsupported key type {sfk.keyType}')

                            sshk = StorageSharedFolderKey()
                            sshk.shared_folder_uid = sf_uid
                            sshk.encrypter_uid = team_uid
                            sshk.key_type = StorageKeyType.TeamKey_AES_GCM
                            sshk.shared_folder_key = crypto.encrypt_aes_v2(sfkd, team_key)
                            sf_keys.append(sshk)
                        except Exception as e:
                            logger.error('Shared Folder %s key decrypt error: %s', sf_uid, e)

                    s_team = StorageTeam()
                    s_team.team_uid = utils.base64_url_encode(sync_down_team.teamUid)
                    s_team.name = sync_down_team.name
                    s_team.team_key = crypto.encrypt_aes_v2(team_key, auth.auth_context.client_key)
                    s_team.key_type = StorageKeyType.UserClientKey_AES_GCM
                    s_team.rsa_private_key = sync_down_team.teamPrivateKey
                    s_team.ec_private_key = sync_down_team.teamEccPrivateKey
                    s_team.restrict_edit = sync_down_team.restrictEdit
                    s_team.restrict_share = sync_down_team.restrictShare
                    s_team.restrict_view = sync_down_team.restrictView
                    return s_team
                except Exception as e:
                    logger.error('Team %s key decrypt error: %s', team_uid, e)

            storage.teams.put_entities((y for y in (to_team(x) for x in response.teams) if y))
            storage.shared_folder_keys.put_links(sf_keys)
            task.add_shared_folders((x.shared_folder_uid for x in sf_keys))
            del sf_keys

        if len(response.sharedFolders) > 0:
            uids = [utils.base64_url_encode(x.sharedFolderUid) for x in response.sharedFolders
                    if x.cacheStatus == SyncDown_pb2.CLEAR]
            storage.shared_folder_permissions.delete_links_by_subjects(uids)

            sf_links = [link for uid in uids for link in storage.shared_folder_keys.get_links_by_subject(uid)
                     if link.encrypter_uid == storage.personal_scope_uid]
            storage.shared_folder_keys.delete_links(sf_links)
            del uids
            del sf_links

            def to_shared_folder(shared_folder: SyncDown_pb2.SharedFolder) -> StorageSharedFolder:
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
            task.add_shared_folders((x.shared_folder_uid for x in sfs))
            storage.shared_folders.put_entities(sfs)
            del sfs

            def to_shared_folder_key(shared_folder: SyncDown_pb2.SharedFolder) -> Optional[StorageSharedFolderKey]:
                if len(shared_folder.sharedFolderKey) > 0:
                    shared_folder_uid = utils.base64_url_encode(shared_folder.sharedFolderUid)
                    try:
                        shared_folder_key = decrypt_keeper_key(auth.auth_context, shared_folder.sharedFolderKey, shared_folder.keyType)
                        s_sfkey = StorageSharedFolderKey()
                        s_sfkey.shared_folder_uid = shared_folder_uid
                        s_sfkey.encrypter_uid = storage.personal_scope_uid
                        s_sfkey.shared_folder_key = crypto.encrypt_aes_v2(shared_folder_key, auth.auth_context.client_key)
                        s_sfkey.key_type = StorageKeyType.UserClientKey_AES_GCM
                        return s_sfkey
                    except Exception as e:
                        logger.error('Shared Folder %s key decrypt error: %s', shared_folder_uid, e)

            storage.shared_folder_keys.put_links(
                (y for y in (to_shared_folder_key(x) for x in response.sharedFolders) if y))

        # shared folder records
        if len(response.removedSharedFolderRecords) > 0:
            rsfrs = [storage_types.UidLink(
                utils.base64_url_encode(x.recordUid),
                utils.base64_url_encode(x.sharedFolderUid),
            ) for x in response.removedSharedFolderRecords]
            storage.record_keys.delete_links(rsfrs)
            task.add_records((x.subject_uid() for x in rsfrs))
            del rsfrs

        if len(response.sharedFolderRecords) > 0:
            def to_sf_record(sfr: SyncDown_pb2.SharedFolderRecord) -> StorageRecordKey:
                s_rk = StorageRecordKey()
                s_rk.record_uid = utils.base64_url_encode(sfr.recordUid)
                s_rk.encrypter_uid = utils.base64_url_encode(sfr.sharedFolderUid)
                s_rk.key_type = StorageKeyType.SharedFolderKey_AES_Any
                s_rk.record_key = sfr.recordKey
                s_rk.can_edit = sfr.canEdit
                s_rk.can_share = sfr.canShare
                s_rk.owner = sfr.owner
                s_rk.owner_account_uid = utils.base64_url_encode(sfr.ownerAccountUid)
                return s_rk

            sfrs = [to_sf_record(x) for x in response.sharedFolderRecords]
            task.add_records((x.record_uid for x in sfrs))
            storage.record_keys.put_links(sfrs)
            del sfrs

        # shared folder users
        if len(response.removedSharedFolderUsers) > 0:
            rsfus: List[storage_types.IUidLink] = []
            for x in response.removedSharedFolderUsers:
                shf_uid = utils.base64_url_encode(x.sharedFolderUid)
                account_uid = utils.base64_url_encode(x.accountUid or auth.auth_context.account_uid)
                rsfus.append(storage_types.UidLink(shf_uid, account_uid))
            storage.shared_folder_permissions.delete_links(rsfus)

        if len(response.sharedFolderUsers) > 0:
            def to_sf_users(sfu: SyncDown_pb2.SharedFolderUser) -> StorageSharedFolderPermission:
                s_sfp = StorageSharedFolderPermission()
                s_sfp.shared_folder_uid = utils.base64_url_encode(sfu.sharedFolderUid)
                s_sfp.user_type = SharedFolderUserType.User
                s_sfp.user_uid = utils.base64_url_encode(sfu.accountUid or auth.auth_context.account_uid)
                s_sfp.manage_records = sfu.manageRecords
                s_sfp.manage_users = sfu.manageUsers
                s_sfp.expiration_time = sfu.expiration
                return s_sfp

            storage.shared_folder_permissions.put_links((to_sf_users(x) for x in response.sharedFolderUsers))

        # shared folder teams
        if len(response.removedSharedFolderTeams) > 0:
            rsft = [storage_types.UidLink(utils.base64_url_encode(x.sharedFolderUid),utils.base64_url_encode(x.teamUid))
                    for x in response.removedSharedFolderTeams]
            storage.shared_folder_keys.delete_links(rsft)
            storage.shared_folder_permissions.delete_links(rsft)
            task.add_shared_folders((x.subject_uid() for x in rsft))

        if len(response.sharedFolderTeams) > 0:
            def to_sf_team(sft: SyncDown_pb2.SharedFolderTeam) -> StorageSharedFolderPermission:
                s_sfp = StorageSharedFolderPermission()
                s_sfp.shared_folder_uid = utils.base64_url_encode(sft.sharedFolderUid)
                s_sfp.user_type = SharedFolderUserType.Team
                s_sfp.user_uid = utils.base64_url_encode(sft.teamUid)
                s_sfp.manage_records = sft.manageRecords
                s_sfp.manage_users = sft.manageRecords
                s_sfp.expiration_time = sft.expiration
                return s_sfp

            storage.shared_folder_permissions.put_links((to_sf_team(x) for x in response.sharedFolderTeams))

        if len(response.userFolders) > 0:
            def to_user_folder(uf: SyncDown_pb2.UserFolder) -> Optional[StorageFolder]:
                key_type = uf.keyType
                key = uf.userFolderKey
                try:
                    key = decrypt_keeper_key(auth.auth_context, key, key_type)

                    key = crypto.encrypt_aes_v2(key, auth.auth_context.client_key)
                    s_f = StorageFolder()
                    s_f.folder_uid = utils.base64_url_encode(uf.folderUid)
                    s_f.revision = uf.revision
                    s_f.folder_type = 'user_folder'
                    s_f.parent_uid = utils.base64_url_encode(uf.parentUid) if uf.parentUid else ''
                    s_f.folder_key = key
                    s_f.key_type = StorageKeyType.UserClientKey_AES_GCM
                    s_f.data = uf.data
                    return s_f
                except Exception as e:
                    logger.error('User Folder %s key decrypt error: %s', utils.base64_url_encode(uf.folderUid), e)

            storage.folders.put_entities((y for y in (to_user_folder(x) for x in response.userFolders) if y))

        if len(response.userFolderSharedFolders) > 0:
            def to_user_folder_shared_folders(ufsf: SyncDown_pb2.UserFolderSharedFolder) -> StorageFolder:
                s_f = StorageFolder()
                s_f.folder_uid = utils.base64_url_encode(ufsf.sharedFolderUid)
                s_f.shared_folder_uid = utils.base64_url_encode(ufsf.sharedFolderUid)
                s_f.folder_type = 'shared_folder'
                s_f.parent_uid = utils.base64_url_encode(ufsf.folderUid) if ufsf.folderUid else ''
                return s_f

            storage.folders.put_entities(
                (to_user_folder_shared_folders(x) for x in response.userFolderSharedFolders))

        if len(response.sharedFolderFolders) > 0:
            def to_shared_folder_folder(sff: SyncDown_pb2.SharedFolderFolder) -> StorageFolder:
                s_f = StorageFolder()
                s_f.folder_uid = utils.base64_url_encode(sff.folderUid)
                s_f.shared_folder_uid = utils.base64_url_encode(sff.sharedFolderUid)
                s_f.revision = sff.revision
                s_f.folder_type = 'shared_folder_folder'
                s_f.parent_uid = utils.base64_url_encode(sff.parentUid) if sff.parentUid else s_f.shared_folder_uid
                s_f.folder_key = sff.sharedFolderFolderKey
                s_f.data = sff.data
                return s_f

            storage.folders.put_entities((to_shared_folder_folder(x) for x in response.sharedFolderFolders))

        if len(response.userFolderRecords) > 0:
            def to_user_folder_record(ufr: SyncDown_pb2.UserFolderRecord) -> StorageFolderRecord:
                s_frl = StorageFolderRecord()
                s_frl.folder_uid = utils.base64_url_encode(ufr.folderUid) \
                    if ufr.folderUid else storage.personal_scope_uid
                s_frl.record_uid = utils.base64_url_encode(ufr.recordUid)
                return s_frl

            storage.folder_records.put_links(
                (to_user_folder_record(x) for x in response.userFolderRecords))

        if len(response.sharedFolderFolderRecords) > 0:
            def to_shared_folder_folder_records(sffr: SyncDown_pb2.SharedFolderFolderRecord) -> StorageFolderRecord:
                s_frl = StorageFolderRecord()
                s_frl.folder_uid = utils.base64_url_encode(sffr.folderUid or sffr.sharedFolderUid)
                s_frl.record_uid = utils.base64_url_encode(sffr.recordUid)
                return s_frl

            storage.folder_records.put_links(
                (to_shared_folder_folder_records(x) for x in response.sharedFolderFolderRecords))

        if len(response.sharingChanges) > 0:
            def set_shared(changes: Iterable[SyncDown_pb2.SharingChange]) -> Iterable[StorageRecord]:
                for sharing_change in changes:
                    r_uid = utils.base64_url_encode(sharing_change.recordUid)
                    record = storage.records.get_entity(r_uid)
                    if record:
                        record.shared = sharing_change.shared
                        yield record

            storage.records.put_entities(set_shared(response.sharingChanges))
            task.add_records((utils.base64_url_encode(x.recordUid) for x in response.sharingChanges))

        if len(response.breachWatchRecords) > 0:
            def to_breach_watch_record(bwr: SyncDown_pb2.BreachWatchRecord) -> BreachWatchRecord:
                bw_record = BreachWatchRecord()
                bw_record.record_uid = utils.base64_url_encode(bwr.recordUid)
                bw_record.data = bwr.data
                bw_record.type = bwr.type
                bw_record.revision = bwr.revision
                return bw_record

            storage.breach_watch_records.put_entities(
                (to_breach_watch_record(x) for x in response.breachWatchRecords))

        if len(response.breachWatchSecurityData) > 0:
            def to_bw_security_data(bwsd: SyncDown_pb2.BreachWatchSecurityData) -> BreachWatchSecurityData:
                kbwsd = BreachWatchSecurityData()
                kbwsd.record_uid = utils.base64_url_encode(bwsd.recordUid)
                kbwsd.revision = bwsd.revision
                return kbwsd
            storage.breach_watch_security_data.put_entities(
                (to_bw_security_data(x) for x in response.breachWatchSecurityData))

        if response.profile.revision > 0:
            user_settings.profile_name = response.profile.profileName
            try:
                if len(response.profile.data) > 0:
                    profile_data = crypto.decrypt_aes_v1(response.profile.data, auth.auth_context.data_key)
                    user_settings.profile_data = crypto.encrypt_aes_v2(profile_data, auth.auth_context.client_key)
            except Exception as e:
                logger.debug('Decrypt profile data error: %s', e)

        if response.profilePic.revision > 0:
            user_settings.profile_url = response.profilePic.url

        if len(response.shareInvitations) > 0 and pending_shares:
            pending_shares.set_pending_shares((x.username for x in response.shareInvitations))

        if len(response.recordAddAuditData) > 0 and audit_data:
            audit_data.schedule_audit_data((utils.base64_url_encode(x) for x in response.recordAddAuditData))

        if len(response.notificationSync) > 0:
            def to_notification(nw: NotificationCenter_pb2.NotificationWrapper) -> StorageNotification:
                sn = StorageNotification()
                sn.notification_uid = utils.base64_url_encode(nw.uid)
                sn.notification_type = nw.content.notification.type
                sn.notification_category = nw.content.notification.category
                sn.sender_name = nw.content.notification.sender.name
                sn.encrypted_data = nw.content.notification.encryptedData.data
                sn.read_status = nw.content.readStatus
                sn.approval_status = nw.content.approvalStatus
                sn.created = nw.timestamp
                return sn

            notifications = [to_notification(x) for x in response.notificationSync]
            storage.notifications.put_entities(notifications)
            task.add_notifications((x.notification_uid for x in notifications))

        user_settings.continuation_token = token

    storage.user_settings.store(user_settings)

    assert task is not None

    if sync_record_types:
        rt_rq = record_pb2.RecordTypesRequest()
        rt_rq.standard = True
        rt_rq.user = True
        rt_rq.enterprise = True
        rt_rs = auth.execute_auth_rest(
            'vault/get_record_types', rt_rq, response_type=record_pb2.RecordTypesResponse)
        assert rt_rs is not None

        def to_record_type(rt: record_pb2.RecordType) -> Optional[StorageRecordType]:
            try:
                content = json.loads(rt.content)
            except Exception as e:
                logger.debug('Error parsing record type: %s', e)
                return None
            record_type = StorageRecordType()
            record_type.name = content['$id']
            record_type.id = rt.recordTypeId
            record_type.content = rt.content
            record_type.scope = rt.scope
            return record_type

        storage.record_types.put_entities((y for y in (to_record_type(x) for x in rt_rs.recordTypes) if y))
        task.record_types_loaded = True

    if len(task.notifications) > 0:
        old_notifications = [(x.notification_uid, x.created) for x in storage.notifications.get_all_entities() if x.notification_uid not in task.notifications]
        if len(old_notifications) + len(task.notifications) > 100:
            old_notifications.sort(key=lambda x: x[1])
            to_delete = len(old_notifications) + len(task.notifications) - 100
            old_notifications = old_notifications[:to_delete]
            storage.notifications.delete_uids([x[0] for x in old_notifications])

    return task
