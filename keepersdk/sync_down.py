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

from typing import Set, NoReturn

import logging

from .errors import KeeperError
from . import crypto, utils
from .vault_types import PersonalFolderUid, Team, PasswordRecord, RecordPermission, SharedFolder
from .auth import Auth
from .storage import KeeperStorage
from .vault_data import VaultData


class SyncDownResult:
    def __init__(self, is_full_sync):
        self.is_full_sync = is_full_sync
        self.should_check_folder_convert = True
        self.records = set()            # type: Set[str]
        self.shared_folders = set()     # type: Set[str]
        self.teams = set()              # type: Set[str]

    def add_record(self, record_uid):
        if not self.is_full_sync:
            self.records.add(record_uid)

    def add_shared_folder(self, shared_folder_uid):
        if not self.is_full_sync:
            self.shared_folders.add(shared_folder_uid)

    def add_team(self, team_uid):
        if not self.is_full_sync:
            self.teams.add(team_uid)


class VaultSyncDown(VaultData):
    def __init__(self, auth, storage):         # type: (Auth, KeeperStorage) -> NoReturn
        super().__init__(storage)
        self.auth = auth
        self.should_convert_record_keys = False

    def sync_down_command(self):            # type: () -> SyncDownResult
        request = {
            "command": "sync_down",
            "include": ["sfheaders", "sfrecords", "sfusers", "teams", "folders"],
            "revision": self.storage.revision,
            "device_id": self.auth.endpoint.device_name,
            "device_name": self.auth.endpoint.device_name
        }

        response = self.auth.execute_auth_command(request)

        is_full_sync = response.get('full_sync') or False
        if is_full_sync:
            self.storage.clear()

        result = SyncDownResult(is_full_sync)

        self.storage.revision = response['revision']

        record_key_update = []

        if 'removed_records' in response:
            for record_uid in response['removed_records']:
                result.add_record(record_uid)
                self.storage.metadata.delete(record_uid)
                self.storage.folders.delete_record(record_uid, key_scope_uid=PersonalFolderUid)

        if 'removed_teams' in response:
            for team_uid in response['removed_teams']:
                result.add_team(team_uid)
                self.storage.teams.delete(team_uid)

        if 'removed_shared_folders' in response:
            for shared_folder_uid in response['removed_shared_folders']:
                result.add_shared_folder(shared_folder_uid)
                shared_folder = self.storage.shared_folders.get(shared_folder_uid)
                if shared_folder:
                    if 'shared_folder_key' in shared_folder:
                        del shared_folder['shared_folder_key']
                    if 'key_type' in shared_folder:
                        del shared_folder['key_type']
                    if 'users' in shared_folder:
                        shared_folder['users'] = [x for x in shared_folder['users'] if x['username'] != self.auth.username]
                    self.storage.shared_folders.put(shared_folder['shared_folder_uid'], shared_folder)

        if 'user_folders_removed' in response:
            for ufr in response['user_folders_removed']:
                f_uid = ufr['folder_uid']
                self.storage.folders.delete_folder(f_uid)

        if 'shared_folder_folder_removed' in response:
            for sffr in response['shared_folder_folder_removed']:
                f_uid = sffr['folder_uid'] if 'folder_uid' in sffr else sffr['shared_folder_uid']
                self.storage.folders.delete_folder(f_uid)

        if 'user_folder_shared_folders_removed' in response:
            for ufsfr in response['user_folder_shared_folders_removed']:
                f_uid = ufsfr['shared_folder_uid']
                self.storage.folders.delete_folder(f_uid)

        if 'user_folders_removed_records' in response:
            for ufrr in response['user_folders_removed_records']:
                folder_uid = ufrr.get('folder_uid') or PersonalFolderUid
                record_uid = ufrr['record_uid']
                self.storage.folders.delete_record(record_uid, folder_uid=folder_uid)

        if 'shared_folder_folder_records_removed' in response:
            for sfrrr in response['shared_folder_folder_records_removed']:
                folder_uid = sfrrr['folder_uid'] if 'folder_uid' in sfrrr else sfrrr['shared_folder_uid']
                record_uid = sfrrr['record_uid']
                self.storage.folders.delete_record(record_uid, folder_uid=folder_uid)

        if 'non_shared_data' in response:
            for non_shared_data in response['non_shared_data']:
                self.storage.non_shared_data.put(non_shared_data['record_uid'], non_shared_data)

        if 'records' in response:
            for record in response['records']:
                record_uid = record['record_uid']
                result.add_record(record_uid)
                self.storage.records.put(record_uid, record)

        if 'record_meta_data' in response:
            for rmd in response['record_meta_data']:
                record_uid = rmd['record_uid']
                result.add_record(record_uid)
                try:
                    key_type = rmd['record_key_type']
                    del rmd['record_key_type']
                    record_key = utils.base64_url_decode(rmd['record_key'])
                    if key_type == 0:
                        record = self.storage.records.get(record_uid)
                        if record:
                            if record['version'] == 1:
                                record_key = crypto.get_random_bytes(32)
                                data = utils.base64_url_decode(record['data'])
                                data = crypto.decrypt_aes_v1(data, self.auth.data_key)
                                data = crypto.encrypt_aes_v1(data, record_key)
                                record['data'] = utils.base64_url_encode(data)
                                self.storage.records.put(record_uid, record)
                                encrypted_record_key = crypto.encrypt_aes_v1(record_key, self.auth.data_key)
                                record_key_update.append({
                                    "record_uid": record_uid,
                                    "version": 2,
                                    "client_modified_time": utils.current_milli_time(),
                                    "record_key": utils.base64_url_encode(encrypted_record_key),
                                    "revision": record['revision'],
                                    "data": record['data']
                                })
                            else:
                                raise KeeperError('Record UID %s: incorrect record version.'.format(record_uid))
                        else:
                            raise KeeperError('Metadata UID %s: record is not found.'.format(record_uid))
                    elif key_type == 1:
                        record_key = crypto.decrypt_aes_v1(record_key, self.auth.data_key)
                    elif key_type == 2:
                        record_key = crypto.decrypt_rsa(record_key, self.auth.private_key)
                        encrypted_record_key = crypto.encrypt_aes_v1(record_key, self.auth.data_key)
                        record = self.storage.records.get(record_uid)
                        if record:
                            record_key_update.append({
                                "record_uid": record_uid,
                                "version": 2,
                                "client_modified_time": utils.current_milli_time(),
                                "record_key": utils.base64_url_encode(encrypted_record_key),
                                "revision": record['revision']
                            })
                    else:
                        raise KeeperError('Record metadata UID %s: unsupported key type %s'.format(record_uid, key_type))
                    record_key = crypto.encrypt_aes_v1(record_key, self.storage.client_key)
                    rmd['record_key'] = utils.base64_url_encode(record_key)
                    self.storage.metadata.put(record_uid, rmd)
                except Exception as e:
                    logging.error('Metadata for record UID %s key decrypt error: %s', record_uid, e)

        if 'teams' in response:
            for team in response['teams']:
                team_uid = team['team_uid']
                result.add_team(team_uid)
                if 'removed_shared_folders' in team:
                    for sf_uid in team['removed_shared_folders']:
                        result.add_shared_folder(sf_uid)
                    del team['removed_shared_folders']
                try:
                    key_type = team['team_key_type']
                    del team['team_key_type']
                    team_key = utils.base64_url_decode(team['team_key'])
                    if key_type == 1:
                        team_key = crypto.decrypt_aes_v1(team_key, self.auth.data_key)
                    elif key_type == 2:
                        team_key = crypto.decrypt_rsa(team_key, self.auth.private_key)
                    else:
                        raise KeeperError('Team UID %s: unsupported key type %s'.format(team_uid, key_type))
                    team_key = crypto.encrypt_aes_v1(team_key, self.storage.client_key)
                    team['team_key'] = utils.base64_url_encode(team_key)
                    self.storage.teams.put(team_uid, team)
                except Exception as e:
                    logging.error('Team %s key decrypt error: %s', team_uid, e)

        if 'shared_folders' in response:
            for shared_folder in response['shared_folders']:
                shared_folder_uid = shared_folder['shared_folder_uid']
                result.add_shared_folder(shared_folder_uid)
                try:
                    key_type = shared_folder['key_type']
                    del shared_folder['key_type']
                    shared_folder_key = utils.base64_url_decode(shared_folder['shared_folder_key'])
                    if key_type == 1:
                        shared_folder_key = crypto.decrypt_aes_v1(shared_folder_key, self.auth.data_key)
                    elif key_type == 2:
                        shared_folder_key = crypto.decrypt_rsa(shared_folder_key, self.auth.private_key)
                    else:
                        raise KeeperError('Shared Folder UID %s: wrong key type %s'.format(shared_folder_uid, key_type))
                    shared_folder_key = crypto.encrypt_aes_v1(shared_folder_key, self.storage.client_key)
                    shared_folder['shared_folder_key'] = utils.base64_url_encode(shared_folder_key)

                    if 'records' in shared_folder:
                        for record_uid in shared_folder['records']:
                            result.add_record(record_uid)

                    if not shared_folder.get('full_sync'):
                        existing_shared_folder = self.storage.shared_folders.get(shared_folder_uid)
                        if existing_shared_folder:
                            uids = set()
                            records = existing_shared_folder['records'] if 'records' in existing_shared_folder else []
                            if 'records_removed' in shared_folder:
                                uids.clear()
                                uids.union(shared_folder['records_removed'])
                                del shared_folder['records_removed']
                                records = [x for x in records if x['record_uid'] not in uids]
                            if records:
                                if 'records' in shared_folder:
                                    shared_folder['records'].append(records)
                                else:
                                    shared_folder['records'] = records

                            users = existing_shared_folder['users'] if 'users' in existing_shared_folder else []
                            if 'users_removed' in shared_folder:
                                uids.clear()
                                uids.union(shared_folder['users_removed'])
                                del shared_folder['users_removed']
                                users = [x for x in users if x['username'] not in uids]
                            if users:
                                if 'users' in shared_folder:
                                    shared_folder['users'].append(users)
                                else:
                                    shared_folder['users'] = users

                            teams = existing_shared_folder['teams'] if 'teams' in existing_shared_folder else []
                            if 'teams_removed' in shared_folder:
                                uids.clear()
                                uids.union(shared_folder['teams_removed'])
                                del shared_folder['teams_removed']
                                teams = [x for x in teams if x['team_uid'] not in uids]
                            if teams:
                                if 'teams' in shared_folder:
                                    shared_folder['teams'].append(teams)
                                else:
                                    shared_folder['teams'] = teams

                    if 'full_sync' in shared_folder:
                        del shared_folder['full_sync']

                    self.storage.shared_folders.put(shared_folder_uid, shared_folder)
                except Exception as e:
                    logging.error('Shared Folder %s key decrypt error: %s', shared_folder_uid, e)

        if 'user_folders' in response:
            result.should_check_folder_convert = False
            for uf in response['user_folders']:
                folder_uid = uf['folder_uid']
                if 'parent_uid' not in uf:
                    uf['parent_uid'] = PersonalFolderUid
                key_type = uf['key_type']
                del uf['key_type']
                key = utils.base64_url_decode(uf['user_folder_key'])
                del uf['user_folder_key']
                if key_type == 2:
                    key = crypto.decrypt_rsa(key, self.auth.private_key)
                else:
                    key = crypto.decrypt_aes_v1(key, self.auth.data_key)
                key = crypto.encrypt_aes_v1(key, self.storage.client_key)
                uf['folder_key'] = utils.base64_url_encode(key)
                uf['key_scope_uid'] = PersonalFolderUid
                self.storage.folders.put_folder(folder_uid, uf)

        if 'shared_folder_folders' in response:
            result.should_check_folder_convert = False
            for sff in response['shared_folder_folders']:
                folder_uid = sff['folder_uid']
                sff['folder_key'] = sff['shared_folder_folder_key']
                del sff['shared_folder_folder_key']
                if 'parent_uid' not in sff:
                    sff['parent_uid'] = sff['shared_folder_uid']
                sff['key_scope_uid'] = sff['shared_folder_uid']
                self.storage.folders.put_folder(folder_uid, sff)

        if 'user_folder_shared_folders' in response:
            result.should_check_folder_convert = False
            for ufsf in response['user_folder_shared_folders']:
                ufsf['type'] = 'shared_folder'
                if 'folder_uid' not in ufsf:
                    ufsf['folder_uid'] = PersonalFolderUid
                ufsf['parent_uid'] = ufsf['folder_uid']
                shared_folder_uid = ufsf['shared_folder_uid']
                ufsf['folder_uid'] = shared_folder_uid
                self.storage.folders.put_folder(shared_folder_uid, ufsf)

        if 'user_folder_records' in response:
            for ufr in response['user_folder_records']:
                folder_uid = ufr.get('folder_uid') or PersonalFolderUid
                record_uid = ufr['record_uid']
                self.storage.folders.put_record(record_uid, folder_uid)

        if 'shared_folder_folder_records' in response:
            for sffr in response['shared_folder_folder_records']:
                if 'folder_uid' not in sffr:
                    sffr['folder_uid'] = sffr['shared_folder_uid']
                folder_uid = sffr['folder_uid']
                record_uid = sffr['record_uid']
                self.storage.folders.put_record(record_uid, folder_uid)

        if record_key_update and self.should_convert_record_keys:
            rq = {
                "command": "record_update",
                "pt": self.auth.endpoint.device_name,
                "device_id": self.auth.endpoint.device_name,
                "client_time": utils.current_milli_time(),
                "update_records": record_key_update[:100]
            }
            rs = self.auth.execute_auth_command(rq, throw_on_error=False)
            if rs['result'] == 'success':
                if 'update_records' in rs:
                    failed = 0
                    total = len(rs['update_records'])
                    for rss in rs['update_records']:
                        if 'status_code' in rss:
                            if rss['status_code'] != 'success':
                                failed += 1
                    if failed > 0:
                        logging.warning('Failed to update %s of %s record keys', failed)
                    else:
                        logging.debug('Successfully updated %s record keys', failed, total)
            else:
                logging.warning('Convert record keys error (%s): %s', rs['result_code'], rs['message'])

        return result

    def incremental_rebuild(self, sync_down_result):
        # type: (SyncDownResult) -> None
        for team_uid in sync_down_result.teams:
            if team_uid in self.teams:
                team = self.teams[team_uid]
                del self.teams[team_uid]
                for shared_folder_uid in team.shared_folder_keys:
                    sync_down_result.shared_folders.add(shared_folder_uid)

        for shared_folder_uid in sync_down_result.shared_folders:
            if shared_folder_uid in self.shared_folders:
                shared_folder = self.shared_folders[shared_folder_uid]
                del self.shared_folders[shared_folder_uid]
                for record_uid in shared_folder.record_keys:
                    sync_down_result.records.add(record_uid)

        for record_uid in sync_down_result.records:
            if record_uid in self.records:
                del self.records[record_uid]

        for team_uid in sync_down_result.teams:
            t = self.storage.teams.get(team_uid)
            if not t:
                continue
            try:
                team_key = utils.base64_url_decode(t['team_key'])
                team_key = crypto.decrypt_aes_v1(team_key, self.storage.client_key)
                team = Team.parse(t, team_key)
                self.teams[team.team_uid] = team
            except Exception as e:
                logging.warning('Error loading Team UID %s: %s', team_uid, e)

        for shared_folder_uid in sync_down_result.shared_folders:
            sf = self.storage.shared_folders.get(shared_folder_uid)
            if not sf:
                continue
            try:
                shared_folder_key = None
                if 'shared_folder_key' in sf:
                    key = utils.base64_url_decode(sf['shared_folder_key'])
                    shared_folder_key = crypto.decrypt_aes_v1(key, self.storage.client_key)
                elif 'teams' in sf:
                    for sft in sf['teams']:
                        team_uid = sft['team_uid']
                        if team_uid in self.teams:
                            team = self.teams[team_uid]
                            if shared_folder_uid in team.shared_folder_keys:
                                shared_folder_key = team.shared_folder_keys[shared_folder_uid]
                                break
                if shared_folder_key:
                    shared_folder = SharedFolder.parse(sf, shared_folder_key)
                    self.shared_folders[shared_folder.shared_folder_uid] = shared_folder
                else:
                    self.storage.shared_folders.delete(shared_folder_uid)
            except Exception as e:
                logging.warning('Error loading Shared Folder UID %s: %s', shared_folder_uid, e)

        for record_uid in sync_down_result.records:
            r = self.storage.records.get(record_uid)
            if not r:
                continue
            try:
                meta_data = self.storage.metadata.get(record_uid)
                record_key = None
                if meta_data:
                    key = utils.base64_url_decode(r['record_key'])
                    record_key = crypto.decrypt_aes_v1(key, self.storage.client_key)
                else:
                    for shared_folder in self.shared_folders.values():
                        if record_uid in shared_folder.record_keys:
                            record_key = shared_folder.record_keys[record_uid]
                            break
                if record_key:
                    record = PasswordRecord.load(r, record_key)
                    if meta_data:
                        record.owner = meta_data['owner']
                        permission = RecordPermission()
                        permission.can_edit = meta_data['can_edit']
                        permission.can_share = meta_data['can_share']

                    for shared_folder in self.shared_folders.values():
                        if record_uid in shared_folder.record_permissions:
                            record.permissions.append(shared_folder.record_permissions[record_uid])

                    self.records[record_uid] = record
                else:
                    self.storage.records.delete(record_uid)
            except Exception as e:
                logging.warning('Error loading Record UID %s: %s', record_uid, e)

