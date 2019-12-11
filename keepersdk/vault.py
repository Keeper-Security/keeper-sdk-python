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

import json
import logging
import requests
import tempfile

from . import crypto, utils
from .storage import InMemoryVaultStorage
from .sync_down import sync_down_command
from .vault_data import VaultData
from .vault_types import PasswordRecord, AttachmentFile
from .errors import KeeperApiError


class RecordAccessPath:
    def __init__(self, record_uid):
        self.record_uid = record_uid
        self.shared_folder_uid = None
        self.team_uid = None


class Vault(VaultData):
    def __init__(self, auth, storage=None):
        super().__init__(auth.auth_context.client_key, storage or InMemoryVaultStorage())
        self.auth = auth
        if self.auth.is_authenticated:
            self.sync_down()

    def sync_down(self):
        rebuild_task = sync_down_command(self.auth, self.storage)
        self.rebuild_data(rebuild_task)

    def resolve_record_access_path(self, path, for_edit=False, for_share=False):
        if not path.record_uid:
            return None
        for rp in self.storage.record_keys.get_links_for_subject(path.record_uid):
            if for_edit and not rp.can_edit:
                continue
            if for_share and not rp.can_share:
                continue
            if not rp.shared_folder_uid:
                return rp

            for sfp in self.storage.shared_folder_keys.get_links_for_subject(rp.shared_folder_uid):
                if not sfp.team_uid:
                    path.shared_folder_uid = sfp.shared_folder_uid
                    return rp
                if not for_edit and not for_share:
                    path.shared_folder_uid = sfp.shared_folder_uid
                    path.team_uid = sfp.team_uid
                    return rp
                team = self.get_team(sfp.team_uid)
                if team:
                    if for_edit and team.restrict_edit:
                        continue
                    if for_share and team.restrict_share:
                        continue
                    path.shared_folder_uid = sfp.shared_folder_uid
                    path.team_uid = sfp.team_uid
                    return rp

    def download_attachment(self, record, attachment_id, output_stream):
        attachment = None
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
            path = RecordAccessPath(record_uid=record.record_uid)
            if self.resolve_record_access_path(path):
                if path.shared_folder_uid:
                    rq['shared_folder_uid'] = path.shared_folder_uid
                    if path.team_uid:
                        rq['team_uid'] = path.team_uid
            rs = self.auth.execute_auth_command(rq)
            dl = rs['downloads'][0]
            if 'url' in dl:
                key = attachment.key
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
            encrypted = encryptor.finish()
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
        folder = self.get_folder(folder_uid)

        record_key = utils.generate_aes_key()
        encrypted_record_key = crypto.encrypt_aes_v1(record_key, self.auth.auth_context.data_key)
        rq = {
            "command": "record_add",
            "record_uid": utils.generate_uid(),
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
                    encrypted_record_key = crypto.encrypt_aes_v1(record_key, shared_folder.shared_folder_key)
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

        self.auth.execute_auth_command(rq)

    def put_record(self, record, skip_data=False, skip_extra=False):
        record_object = {
            'record_uid': record.record_uid,
            'version': 2,
            'client_modified_time': utils.current_milli_time(),
        }

        existing_record = self.storage.records.get(record.record_uid) if record.record_uid else None
        existing_extra = None
        existing_udata = None
        if existing_record:
            record_object['revision'] = existing_record.revision
            path = RecordAccessPath(record_uid=record.record_uid)
            r_key = self.resolve_record_access_path(path, for_edit=True)
            if r_key:
                if r_key.key_type in {0, 2}:
                    enc_key = crypto.encrypt_aes_v1(record.record_key, self.auth.auth_context.data_key)
                    record_object['record_key'] = utils.base64_url_encode(enc_key)

                if path.shared_folder_uid:
                    record_object['shared_folder_uid'] = path.shared_folder_uid
                if path.team_uid:
                    record_object['team_uid'] = path.team_uid
            if existing_record.extra:
                try:
                    enc_extra = utils.base64_url_decode(existing_record.extra)
                    dec_extra = crypto.decrypt_aes_v1(enc_extra, record.record_key)
                    existing_extra = json.loads(dec_extra.decode('utf-8'))
                except Exception as e:
                    logging.debug('Record (%s) extra decrypt error: %s', existing_record.record_uid, e)
            if existing_record.udata:
                existing_udata = json.loads(existing_record.udata)

        datas = PasswordRecord.dump(record, extra=existing_extra, udata=existing_udata)
        if 'data' in datas and not skip_data:
            data_data = json.dumps(datas['data']).encode('utf-8')
            record_object['data'] = utils.base64_url_encode(crypto.encrypt_aes_v1(data_data, record.record_key))
        if 'extra' in datas and not skip_extra:
            extra_data = json.dumps(datas['extra']).encode('utf-8')
            record_object['data'] = utils.base64_url_encode(crypto.encrypt_aes_v1(extra_data, record.record_key))
            if 'udata' in datas:
                udata_data = json.dumps(datas['udata']).encode('utf-8')
                record_object['udata'] = utils.base64_url_encode(udata_data)

        rq = {
            "command": "record_update",
            "device_id": self.auth.endpoint.device_name,
            "client_time": utils.current_milli_time()
        }
        if existing_record:
            rq['update_records'] = [record_object]
        else:
            rq['add_records'] = [record_object]

        rs = self.auth.execute_auth_command(rq)
        status = rs['update_records' if existing_record else 'add_records'][0]
        if status['status'] != 'success':
            raise KeeperApiError(status['status_code'], status['message'])

    def delete_record(self, record_uid, folder=None):
        if not folder:
            if self.auth.auth_ui:
                if not self.auth.auth_ui.confirmation('Delete a record?'):
                    return
            rq = {
                "command": "record_update",
                "device_id": self.auth.endpoint.device_name,
                "delete_records": [record_uid]
            }
            rs = self.auth.execute_auth_command(rq)
            status = rs['delete_records'][0]
            if status['status'] != 'success':
                raise KeeperApiError(status['status_code'], status['message'])
        else:
            record_object = {
                'object_uid': record_uid,
                'object_type': 'record',
                'delete_resolution': 'unlink'
            }
            if folder.folder_uid == self.storage.personal_scope_uid:
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
                if self.auth.auth_ui:
                    if not self.auth.auth_ui.confirmation('\n'.join(lines)):
                        return
                rq = {
                    "commmand": "delete",
                    "pre_delete_token": rs['pre_delete_response']['pre_delete_token']
                }
                self.auth.execute_auth_command(rq)
