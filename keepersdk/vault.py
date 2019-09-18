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

from typing import Optional, NoReturn

import collections
import json
import io
import requests
import tempfile

from . import crypto, utils
from .auth import Auth
from .storage import KeeperStorage, InMemoryVaultStorage
from .sync_down import VaultSyncDown
from .vault_types import PasswordRecord, AttachmentFile, Folder, PersonalFolderUid
from .errors import KeeperApiError

RecordAccessPath = collections.namedtuple('RecordAccessPath', 'record_uid, shared_folder_uid, team_uid')


class Vault(VaultSyncDown):
    def __init__(self, auth, storage=None):     # type: (Auth, Optional[KeeperStorage]) -> None
        super().__init__(auth, storage or InMemoryVaultStorage(auth.client_key))
        if self.auth.is_authenticated:
            self.sync_down()

    def sync_down(self):
        sync_down_result = self.sync_down_command()
        if sync_down_result.is_full_sync or len(self.records) == 0:
            self.full_rebuild()
        else:
            self.incremental_rebuild(sync_down_result)
        self.build_folders()

    def resolve_record_access_path(self, record, access_write=False, access_share=False):
        # type: (PasswordRecord, bool, bool) -> Optional[RecordAccessPath]
        for permission in record.permissions:
            if access_write and not permission.can_edit:
                continue
            if access_share and not permission.can_share:
                continue
            if permission.shared_folder_uid:
                if permission.shared_folder_uid not in self.shared_folders:
                    continue
                shared_folder = self.shared_folders[permission.shared_folder_uid]
                if not shared_folder.permissions:
                    continue
                for sf_permission in shared_folder.permissions:
                    if sf_permission.team_uid:
                        if sf_permission.team_uid in self.teams:
                            team = self.teams[sf_permission.team_uid]
                            if access_write and team.restrict_edit:
                                continue
                            if access_share and team.restrict_share:
                                continue
                            return RecordAccessPath(record_uid=record.record_uid,
                                                    shared_folder_uid=shared_folder.shared_folder_uid,
                                                    team_uid=team.team_uid)
                    else:
                        return RecordAccessPath(record_uid=record.record_uid,
                                                shared_folder_uid=shared_folder.shared_folder_uid,
                                                team_uid=None)
            else:
                return RecordAccessPath(record_uid=record.record_uid,
                                        shared_folder_uid=None,
                                        team_uid=None)
        return None

    def download_attachment(self, record, attachment_id, output_stream):
        # type: (PasswordRecord, str, io.RawIOBase) -> Optional[AttachmentFile]
        attachment = None           # type: Optional[AttachmentFile]
        for atta in record.attachments:
            if attachment_id == atta.id:
                attachment = atta
                break
            if atta.title:
                if atta.title.lower() == attachment_id.lower():
                    attachment = atta
                    break
            if atta.name:
                if atta.name.lower() == attachment_id.lower():
                    attachment = atta
                    break
        if attachment and output_stream:
            rq = {
                'command': 'request_download',
                'file_ids': [attachment.id],
                'record_uid': record.record_uid
            }
            ap = self.resolve_record_access_path(record)
            if ap:
                if ap.shared_folder_uid:
                    rq['shared_folder_uid'] = ap.shared_folder_uid
                    if ap.team_uid:
                        rq['team_uid'] = ap.team_uid
            rs = self.auth.execute_auth_command(rq)
            dl = rs['downloads'][0]
            if 'url' in dl:
                key = utils.base64_url_decode(attachment.key)
                with requests.get(dl['url'], stream=True) as rq_http:
                    iv = rq_http.raw.read(16)
                    decryptor = crypto.aes_v1_stream_decryptor(iv, key)
                    finished = False
                    while not finished:
                        to_decrypt = rq_http.raw.read(10240)
                        finished = len(to_decrypt) < 10240
                        if len(to_decrypt) > 0:
                            decrypted = decryptor.update(to_decrypt)
                            if decrypted:
                                output_stream.write(decrypted)
                    decrypted = decryptor.finish()
                    if decrypted:
                        output_stream.write(decrypted)

        return attachment

    def upload_attachment(self, input_stream):
        # type: (io.RawIOBase) -> Optional[AttachmentFile]
        rq = {
            'command': 'request_upload',
            'file_count': 1,
            'thumbnail_count': 0
        }
        rs = self.auth.execute_auth_command(rq)
        file_uploads = rs['file_uploads'][0]
        attachment = AttachmentFile()
        attachment.id = file_uploads['file_id']
        attachment.key = utils.generate_aes_key()
        with tempfile.TemporaryFile(mode='w+b') as dst:
            finished = False
            iv = crypto.get_random_bytes(16)
            dst.write(iv)
            file_size = 0
            encryptor = crypto.aes_v1_stream_encryptor(iv, attachment.key)
            while not finished:
                to_encrypt = input_stream.read(10240)
                finished = len(to_encrypt) < 10240
                if to_encrypt:
                    file_size += len(to_encrypt)
                    encrypted = encryptor.update(to_encrypt)
                    if encrypted:
                        dst.write(encrypted)
            encrypted = encryptor.finish(to_encrypt)
            if encrypted:
                dst.write(encrypted)

            attachment.size = file_size
            dst.seek(0)
            files = {
                file_uploads['file_parameter']: (file_uploads['file_id'], dst, 'application/octet-stream')
            }
            response = requests.post(file_uploads['url'], files=files, data=file_uploads['parameters'])
            if response.status_code == file_uploads['success_status_code']:
                return attachment

    def add_record(self, record, folder_uid=None):
        # type: (PasswordRecord, Optional[str]) -> NoReturn
        folder = self.get_folder(folder_uid)
        record_uid = utils.generate_uid()
        record_key = utils.generate_aes_key()
        encrypted_record_key = crypto.encrypt_aes_v1(record_key, self.auth.data_key)
        rq = {
            "command": "record_add",
            "record_uid": record_uid,
            "record_type": "password",
            "record_key": utils.base64_url_encode(encrypted_record_key),
            "how_long_ago": 0
        }
        if folder:
            rq['folder_type'] = folder.folder_type
            rq['folder_uid'] = folder.folder_uid
            if folder.shared_folder_uid:
                shared_folder = self.get_shared_folder(folder.shared_folder_uid)
                if shared_folder:
                    encrypted_record_key = crypto.encrypt_aes_v1(record.record_key, shared_folder.shared_folder_key)
                    rq['folder_key'] = utils.base64_url_encode(encrypted_record_key)
        else:
            rq['folder_type'] = 'user_folder'

        datas = PasswordRecord.dump(record)
        if 'data' in datas:
            data_data = json.dumps(datas['data']).encode('utf-8')
            rq['data'] = utils.base64_url_encode(crypto.encrypt_aes_v1(data_data, record_key))
        if 'extra' in datas:
            extra_data = json.dumps(datas['extra']).encode('utf-8')
            rq['data'] = utils.base64_url_encode(crypto.encrypt_aes_v1(extra_data, record_key))
            if 'udata' in datas:
                udata_data = json.dumps(datas['udata']).encode('utf-8')
                rq['udata'] = utils.base64_url_encode(udata_data)

        rs = self.auth.execute_auth_command(rq)
        record.record_uid = record_uid
        record.record_key = record_key
        record.revision = rs['revision']
        record.data = datas['data'] if 'data' in datas else None
        record.extra = datas['extra'] if 'extra' in datas else None
        record.udata = datas['udata'] if 'udata' in datas else None
        self.records[record.record_uid] = record
        if not folder:
            folder = self.root_folder
        folder.records.add(record.record_uid)

    def update_record(self, record, skip_data=False, skip_extra=False):
        # type: (PasswordRecord, bool, bool) -> NoReturn

        record_object = {
            "record_uid": record.record_uid,
            "version": 2,
            "client_modified_time": utils.current_milli_time(),
            "revision": record.revision
        }

        datas = PasswordRecord.dump(record)
        if 'data' in datas and not skip_data:
            data_data = json.dumps(datas['data']).encode('utf-8')
            record_object['data'] = utils.base64_url_encode(crypto.encrypt_aes_v1(data_data, record.record_key))
        if 'extra' in datas and not skip_extra:
            extra_data = json.dumps(datas['extra']).encode('utf-8')
            record_object['data'] = utils.base64_url_encode(crypto.encrypt_aes_v1(extra_data, record.record_key))
            if 'udata' in datas:
                udata_data = json.dumps(datas['udata']).encode('utf-8')
                record_object['udata'] = utils.base64_url_encode(udata_data)

        access_path = self.resolve_record_access_path(record, access_write=True)
        if access_path.shared_folder_uid:
            record_object['shared_folder_uid'] = access_path.shared_folder_uid
        if access_path.team_uid:
            record_object['team_uid'] = access_path.team_uid

        rq = {
            "command": "record_update",
            "device_id": self.auth.endpoint.device_name,
            "update_records": [record_object]
        }
        rs = self.auth.execute_auth_command(rq)
        if 'update_records' in rs:
            status = rs['update_records'][0]
            if status['status'] == 'success':
                record.revision = rs['revision']
            else:
                raise KeeperApiError(status['status_code'], status['message'])

    def delete_record(self, record_uid, folder=None):
        # type: (str, Optional[Folder]) -> NoReturn
        if not folder:
            if self.auth.ui:
                if not self.auth.ui.confirmation('Delete a record?'):
                    return
            rq = {
                "command": "record_update",
                "device_id": self.auth.endpoint.device_name,
                "delete_records": [record_uid]
            }
            self.auth.execute_auth_command(rq)
        else:
            record_object = {
                'object_uid': record_uid,
                'object_type': 'record',
                'delete_resolution': 'unlink'
            }
            if folder.folder_uid == PersonalFolderUid:
                record_object['from_type'] = 'user_folder'
            else:
                record_object['from_uid'] = folder.folder_uid
                record_object['from_type'] = folder.folder_type
            rq = {
                "command": "pre_delete",
                "objects": [record_object]
            }
            rs = self.auth.execute_auth_command(rq)
            if 'pre_delete_response' in rs:
                lines = rs['pre_delete_response']['would_delete']['deletion_summary']
                if self.auth.ui:
                    if not self.auth.ui.confirmation('\n'.join(lines)):
                        return
                rq = {
                    "commmand": "delete",
                    "pre_delete_token": rs['pre_delete_response']['pre_delete_token']
                }
                self.auth.execute_auth_command(rq)

        if record_uid in self.records:
            del self.records[record_uid]

        folders = [folder] if folder else [x for x in self.folders.values() if record_uid in x.records]
        for folder in folders:
            if record_uid in folder.records:
                folder.records.remove(record_uid)
            if folder.shared_folder_uid:
                if folder.shared_folder_uid in self.shared_folders:
                    pass
