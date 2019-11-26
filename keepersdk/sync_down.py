#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2019 Keeper Security Inc.
# Contact: ops@keepersecurity.coms
#
# https://keeper.atlassian.net/wiki/spaces/KA/pages/12616311/sync+down

import json
import logging

from .errors import KeeperError
from . import crypto, utils
from .storage import (StorageRecord, StorageSharedFolder, StorageRecordKey, StorageTeam, StorageSharedFolderKey,
                      StorageNonSharedData, StorageSharedFolderPermission, StorageFolder, StorageFolderRecordLink)
from .vault_data import VaultData, RebuildTask


class VaultSyncDown(VaultData):
    def __init__(self, auth, storage):
        super().__init__(auth.client_key, storage)
        self.auth = auth

    def sync_down(self):
        request = {
            "command": "sync_down",
            "include": ["sfheaders", "sfrecords", "sfusers", "teams", "folders"],
            "revision": self.storage.revision,
            "device_id": self.auth.endpoint.device_name,
            "device_name": self.auth.endpoint.device_name
        }

        response = self.auth.execute_auth_command(request)

        is_full_sync = response.get('full_sync') or False   # type: bool
        if is_full_sync:
            self.storage.clear()

        result = RebuildTask(is_full_sync)

        self.storage.revision = response['revision']

        if 'removed_records' in response:
            for record_uid in response['removed_records']:
                result.add_record(record_uid)
                self.storage.record_keys.delete(record_uid, self.storage.personal_scope_uid)
                record_links = [x for x in self.storage.folder_records.get_links_for_object(record_uid)]
                for link in record_links:
                    folder_uid = link.folder_uid
                    if folder_uid == self.storage.personal_scope_uid:
                        self.storage.folder_records.delete_link(link)
                    else:
                        folder = self.storage.folders.get(folder_uid)
                        if folder:
                            if folder.folder_type == 'user_folder':
                                self.storage.folder_records.delete_link(link)

        if 'removed_teams' in response:
            for team_uid in response['removed_teams']:
                sf_links = [x for x in self.storage.shared_folder_keys.get_links_for_object(team_uid)]
                for sf_link in sf_links:
                    shared_folder_uid = sf_link.shared_folder_uid
                    rec_links = [x for x in self.storage.record_keys.get_links_for_object(shared_folder_uid)]
                    for rec_link in rec_links:
                        record_uid = rec_link.record_uid
                        result.add_record(record_uid)

                    result.add_shared_folder(shared_folder_uid)
                self.storage.shared_folder_keys.delete_object(team_uid)
                self.storage.teams.delete(team_uid)

        if 'removed_shared_folders' in response:
            for shared_folder_uid in response['removed_shared_folders']:
                result.add_shared_folder(shared_folder_uid)

                rec_links = [x for x in self.storage.record_keys.get_links_for_object(shared_folder_uid)]
                for rec_link in rec_links:
                    result.add_record(rec_link.record_uid)

                self.storage.shared_folder_keys.delete(shared_folder_uid, self.storage.personal_scope_uid)

        if 'user_folders_removed' in response:
            for ufr in response['user_folders_removed']:
                folder_uid = ufr['folder_uid']
                self.storage.folder_records.delete_subject(folder_uid)
                self.storage.folders.delete(folder_uid)

        if 'shared_folder_folder_removed' in response:
            for sffr in response['shared_folder_folder_removed']:
                folder_uid = sffr['folder_uid'] if 'folder_uid' in sffr else sffr['shared_folder_uid']
                self.storage.folder_records.delete_subject(folder_uid)
                self.storage.folders.delete(folder_uid)

        if 'user_folder_shared_folders_removed' in response:
            for ufsfr in response['user_folder_shared_folders_removed']:
                folder_uid = ufsfr['shared_folder_uid']
                self.storage.folder_records.delete_subject(folder_uid)
                self.storage.folders.delete(folder_uid)

        if 'user_folders_removed_records' in response:
            for ufrr in response['user_folders_removed_records']:
                folder_uid = ufrr.get('folder_uid') or self.storage.personal_scope_uid
                record_uid = ufrr['record_uid']
                self.storage.folder_records.delete(folder_uid, record_uid)

        if 'shared_folder_folder_records_removed' in response:
            for sfrrr in response['shared_folder_folder_records_removed']:
                folder_uid = sfrrr['folder_uid'] if 'folder_uid' in sfrrr else sfrrr['shared_folder_uid']
                record_uid = sfrrr['record_uid']
                self.storage.folder_records.delete(record_uid, folder_uid)

        if 'shared_folders' in response:
            for shared_folder in response['shared_folders']:
                shared_folder_uid = shared_folder['shared_folder_uid']
                if shared_folder.get('full_sync'):
                    self.storage.record_keys.delete_object(shared_folder_uid)
                    self.storage.shared_folder_keys.delete_subject(shared_folder_uid)
                    self.storage.shared_folder_permissions.delete_subject(shared_folder_uid)
                else:
                    if 'records_removed' in shared_folder:
                        for record_uid in shared_folder['records_removed']:
                            result.add_record(record_uid)
                            self.storage.record_keys.delete(record_uid, shared_folder_uid)
                    if 'teams_removed' in shared_folder:
                        for team_uid in shared_folder['teams_removed']:
                            self.storage.shared_folder_keys.delete(shared_folder_uid, team_uid)
                            self.storage.shared_folder_permissions.delete(shared_folder, team_uid)
                    if 'users_removed' in shared_folder:
                        for username in shared_folder['users_removed']:
                            self.storage.shared_folder_permissions.delete(shared_folder, username)

        if 'non_shared_data' in response:
            for nsd in response['non_shared_data']:
                record_uid = nsd['record_uid']
                try:
                    data = utils.base64_url_decode(nsd['data'])
                    data = crypto.decrypt_aes_v1(data, self.auth.data_key)
                    data = crypto.encrypt_aes_v1(data, self.client_key)

                    s_nsd = StorageNonSharedData()
                    s_nsd.record_uid = record_uid
                    s_nsd.data = utils.base64_url_encode(data)
                    self.storage.non_shared_data.put(s_nsd)
                except Exception as e:
                    logging.error('Non-Shared data for record UID %s decrypt error: %s', record_uid, e)

        if 'records' in response:
            for rec in response['records']:
                record_uid = rec['record_uid']
                result.add_record(record_uid)
                record = StorageRecord()
                record.record_uid = record_uid
                record.revision = rec['revision']
                record.client_modified_time = rec['client_modified_time']
                record.data = rec['data']
                record.extra = rec.get('extra')
                if 'udata' in rec:
                    record.udata = json.dumps(rec['udata'])
                record.shared = rec['shared']
                self.storage.records.put(record)

        if 'record_meta_data' in response:
            for rmd in response['record_meta_data']:
                record_uid = rmd['record_uid']
                result.add_record(record_uid)
                record = self.storage.records.get(record_uid)
                if record:
                    if record.owner != rmd['owner']:
                        record.owner = rmd['owner']
                        self.storage.records.put(record)
                try:
                    key_type = rmd['record_key_type']
                    record_key = utils.base64_url_decode(rmd['record_key'])
                    if key_type == 0:
                        record_key = self.auth.data_key
                    elif key_type == 1:
                        record_key = crypto.decrypt_aes_v1(record_key, self.auth.data_key)
                    elif key_type == 2:
                        record_key = crypto.decrypt_rsa(record_key, self.auth.private_key)
                    else:
                        raise KeeperError('Record metadata UID %s: unsupported key type %s'.format(record_uid, key_type))
                    record_key = crypto.encrypt_aes_v1(record_key, self.client_key)
                    sr_key = StorageRecordKey()
                    sr_key.record_uid = record_uid
                    sr_key.record_key = utils.base64_url_encode(record_key)
                    sr_key.key_type = key_type
                    sr_key.shared_folder_uid = self.storage.personal_scope_uid
                    sr_key.can_edit = rmd['can_edit']
                    sr_key.can_share = rmd['can_share']
                    self.storage.record_keys.put(sr_key)
                except Exception as e:
                    logging.error('Metadata for record UID %s key decrypt error: %s', record_uid, e)

        if 'teams' in response:
            for team in response['teams']:
                team_uid = team['team_uid']

                if 'removed_shared_folders' in team:
                    for shared_folder_uid in team['removed_shared_folders']:
                        result.add_shared_folder(shared_folder_uid)
                        self.storage.shared_folder_keys.delete(shared_folder_uid, team_uid)
                try:
                    key_type = team['team_key_type']
                    team_key = utils.base64_url_decode(team['team_key'])
                    if key_type == 1:
                        team_key = crypto.decrypt_aes_v1(team_key, self.auth.data_key)
                    elif key_type == 2:
                        team_key = crypto.decrypt_rsa(team_key, self.auth.private_key)
                    else:
                        raise KeeperError('Team UID %s: unsupported key type %s'.format(team_uid, key_type))
                    encrypted_team_key = crypto.encrypt_aes_v1(team_key, self.client_key)

                    s_team = StorageTeam()
                    s_team.team_uid = team_uid
                    s_team.name = team['name']
                    s_team.team_key = utils.base64_url_encode(encrypted_team_key)
                    s_team.key_type = key_type
                    s_team.team_private_key = team['team_private_key']
                    s_team.restrict_edit = team['restrict_edit']
                    s_team.restrict_share = team['restrict_share']
                    s_team.restrict_view = team['restrict_view']
                    self.storage.teams.put(s_team)

                    if 'shared_folder_keys' in team:
                        team_private_key = None
                        for sfk in team['shared_folder_keys']:
                            shared_folder_uid = sfk['shared_folder_uid']
                            key_type = sfk['key_type']
                            shared_folder_key = utils.base64_url_decode(sfk['shared_folder_key'])
                            try:
                                if key_type == 1:
                                    pass
                                elif key_type == 2:
                                    if not team_private_key:
                                        team_private_key = utils.base64_url_decode(team['team_private_key'])
                                        team_private_key = crypto.decrypt_aes_v1(team_private_key, team_key)
                                        team_private_key = crypto.load_private_key(team_private_key)
                                    shared_folder_key = crypto.decrypt_rsa(shared_folder_key, team_private_key)
                                    shared_folder_key = crypto.encrypt_aes_v1(shared_folder_key, team_key)

                                s_sfkey = StorageSharedFolderKey()
                                s_sfkey.shared_folder_uid = shared_folder_uid
                                s_sfkey.team_uid = team_uid
                                s_sfkey.shared_folder_key = utils.base64_url_encode(shared_folder_key)
                                s_sfkey.key_type = 4
                                self.storage.shared_folder_keys.put(s_sfkey)
                            except Exception as e:
                                logging.error('Team %s; Shared Folder UID %s key decrypt error: %s',
                                              team_uid, shared_folder_uid, e)
                except Exception as e:
                    logging.error('Team %s key decrypt error: %s', team_uid, e)

        if 'shared_folders' in response:
            for shared_folder in response['shared_folders']:
                shared_folder_uid = shared_folder['shared_folder_uid']
                result.add_shared_folder(shared_folder_uid)
                if 'shared_folder_key' in shared_folder:
                    try:
                        key_type = shared_folder['key_type']
                        shared_folder_key = utils.base64_url_decode(shared_folder['shared_folder_key'])
                        if key_type == 1:
                            shared_folder_key = crypto.decrypt_aes_v1(shared_folder_key, self.auth.data_key)
                        elif key_type == 2:
                            shared_folder_key = crypto.decrypt_rsa(shared_folder_key, self.auth.private_key)
                        else:
                            raise KeeperError('Shared Folder UID (0): wrong key type {1}}'.format(shared_folder_uid, key_type))
                        shared_folder_key = crypto.encrypt_aes_v1(shared_folder_key, self.client_key)
                        s_sfkey = StorageSharedFolderKey()
                        s_sfkey.shared_folder_uid = shared_folder_uid
                        s_sfkey.team_uid = self.storage.personal_scope_uid
                        s_sfkey.shared_folder_key = utils.base64_url_encode(shared_folder_key)
                        s_sfkey.key_type = key_type
                        self.storage.shared_folder_keys.put(s_sfkey)
                    except Exception as e:
                        logging.error('Shared Folder %s key decrypt error: %s', shared_folder_uid, e)

                if 'records' in shared_folder:
                    for sfr in shared_folder['records']:
                        record_uid = sfr['record_uid']
                        result.add_record(record_uid)
                        s_rk = StorageRecordKey()
                        s_rk.record_uid = record_uid
                        s_rk.shared_folder_uid = shared_folder_uid
                        s_rk.key_type = 3
                        s_rk.record_key = sfr['record_key']
                        s_rk.can_edit = sfr['can_edit']
                        s_rk.can_share = sfr['can_share']
                        self.storage.record_keys.put(s_rk)

                if 'teams' in shared_folder:
                    for sft in shared_folder['teams']:
                        s_sfp = StorageSharedFolderPermission()
                        s_sfp.shared_folder_uid = shared_folder_uid
                        s_sfp.user_type = 2
                        s_sfp.user_uid = sft['team_uid']
                        s_sfp.manage_records = sft['manage_records']
                        s_sfp.manage_users = sft['manage_users']
                        self.storage.shared_folder_permissions.put(s_sfp)

                if 'users' in shared_folder:
                    for user in shared_folder['users']:
                        s_sfp = StorageSharedFolderPermission()
                        s_sfp.shared_folder_uid = shared_folder_uid
                        s_sfp.user_type = 1
                        s_sfp.user_uid = user['username']
                        s_sfp.manage_records = user['manage_records']
                        s_sfp.manage_users = user['manage_users']
                        self.storage.shared_folder_permissions.put(s_sfp)

                s_sf = StorageSharedFolder()
                s_sf.shared_folder_uid = shared_folder_uid
                s_sf.revision = shared_folder['revision']
                s_sf.name = shared_folder['name']
                s_sf.default_manage_records = shared_folder['default_manage_records']
                s_sf.default_manage_users = shared_folder['default_manage_users']
                s_sf.default_can_edit = shared_folder['default_can_edit']
                s_sf.default_can_share = shared_folder['default_can_share']
                self.storage.shared_folders.put(s_sf)

        if 'user_folders' in response:
            result.should_check_folder_convert = False
            for uf in response['user_folders']:
                folder_uid = uf['folder_uid']
                key_type = uf['key_type']
                key = utils.base64_url_decode(uf['user_folder_key'])
                if key_type == 2:
                    key = crypto.decrypt_rsa(key, self.auth.private_key)
                else:
                    key = crypto.decrypt_aes_v1(key, self.auth.data_key)
                key = crypto.encrypt_aes_v1(key, self.client_key)
                s_f = StorageFolder()
                s_f.folder_uid = folder_uid
                s_f.revision = uf['revision']
                s_f.folder_type = uf['type']
                s_f.parent_uid = uf['parent_uid'] if 'parent_uid' in uf else self.storage.personal_scope_uid
                s_f.folder_key = utils.base64_url_encode(key)
                s_f.data = uf['data']
                self.storage.folders.put(s_f)

        if 'shared_folder_folders' in response:
            result.should_check_folder_convert = False
            for sff in response['shared_folder_folders']:
                folder_uid = sff['folder_uid']
                s_f = StorageFolder()
                s_f.folder_uid = folder_uid
                s_f.shared_folder_uid = sff['shared_folder_uid']
                s_f.revision = sff['revision']
                s_f.folder_type = sff['type']
                s_f.parent_uid = sff['parent_uid'] if 'parent_uid' in sff else s_f.shared_folder_uid
                s_f.folder_key = sff['shared_folder_folder_key']
                s_f.data = sff['data']
                self.storage.folders.put(s_f)

        if 'user_folder_shared_folders' in response:
            result.should_check_folder_convert = False
            for ufsf in response['user_folder_shared_folders']:
                folder_uid = ufsf['shared_folder_uid']
                s_f = StorageFolder()
                s_f.folder_uid = folder_uid
                s_f.shared_folder_uid = folder_uid
                s_f.folder_type = 'shared_folder'
                s_f.parent_uid = ufsf['folder_uid'] if 'folder_uid' is ufsf else self.storage.personal_scope_uid
                self.storage.folders.put(s_f)

        if 'user_folder_records' in response:
            for ufr in response['user_folder_records']:
                s_frl = StorageFolderRecordLink()
                s_frl.folder_uid = ufr['folder_uid'] if 'folder_uid' in ufr else self.storage.personal_scope_uid
                s_frl.record_uid = ufr['record_uid']
                self.storage.folder_records.put(s_frl)

        if 'shared_folder_folder_records' in response:
            for sffr in response['shared_folder_folder_records']:
                s_frl = StorageFolderRecordLink()
                s_frl.folder_uid = sffr['folder_uid'] if 'folder_uid' in sffr else sffr['shared_folder_uid']
                s_frl.record_uid = sffr['record_uid']
                self.storage.folder_records.put(s_frl)

        self.rebuild_data(result)
