import abc
import contextlib
import io
import json
import mimetypes
import os
from typing import BinaryIO, Iterator, Optional, List, Union, Dict, Sequence

import requests

from . import vault_online
from .record_facades import FileRefRecordFacade
from .vault_extensions import resolve_record_access_path
from .vault_record import FileRecord, PasswordRecord, TypedRecord, AttachmentFile, AttachmentFileThumb
from .. import utils, crypto
from ..proto import record_pb2


class AttachmentDownloadRequest:
    def __init__(self) -> None:
        self.file_id = ''
        self.url = ''
        self.encryption_key = b''
        self.title = ''
        self.is_gcm_encrypted = False
        self.success_status_code = 200

    def download_to_stream(self, output_stream: BinaryIO) -> int:
        bytes_read = 0
        buffer = bytearray(10240)
        with self.get_decrypted_stream() as plain, memoryview(buffer) as mv:
            while True:
                n = plain.readinto(mv)
                if n is None or n == 0:
                    break
                bytes_read += n
                with mv[:n] as smv:
                    output_stream.write(smv)
            output_stream.flush()
            return bytes_read

    @contextlib.contextmanager
    def get_decrypted_stream(self) -> Iterator[io.RawIOBase]:
        with requests.get(self.url, stream=True) as rq_http:
            if self.success_status_code != rq_http.status_code:
                utils.get_logger().warning('HTTP status code: %d', rq_http.status_code)
            crypter = crypto.StreamCrypter()
            crypter.is_gcm = self.is_gcm_encrypted
            crypter.key = self.encryption_key
            with crypter.set_stream(rq_http.raw, for_encrypt=False) as attachment:
                yield attachment


    def download_to_file(self, file_name: str) -> None:
        utils.get_logger().info('Downloading \'%s\'', os.path.abspath(file_name))
        with open(file_name, 'wb') as file_stream:
            self.download_to_stream(file_stream)


def prepare_attachment_download(vault: vault_online.VaultOnline,
                                record_uid: str,
                                attachment_name: Optional[str]=None) -> Iterator[AttachmentDownloadRequest]:
    record = vault.vault_data.load_record(record_uid)
    if not record:
        utils.get_logger().warning('Record UID \"%s\" not found.', record_uid)
        return

    if isinstance(record, (TypedRecord, FileRecord)):
        rq_v3 = record_pb2.FilesGetRequest()
        rq_v3.for_thumbnails = False
        if isinstance(record, FileRecord):
            rq_v3.record_uids.append(utils.base64_url_decode(record.record_uid))
        elif isinstance(record, TypedRecord):
            facade = FileRefRecordFacade()
            facade.record = record
            if isinstance(facade.file_ref, list):
                for file_uid in facade.file_ref:
                    file_record = vault.vault_data.load_record(file_uid)
                    if isinstance(file_record, FileRecord):
                        if attachment_name:
                            name_l = attachment_name.lower()
                            if attachment_name != file_uid and file_record.title.lower() != name_l and \
                                    file_record.file_name.lower() != name_l:
                                continue
                        rq_v3.record_uids.append(utils.base64_url_decode(file_uid))

        if len(rq_v3.record_uids) > 0:
            rs_v3 = vault.keeper_auth.execute_auth_rest(
                'vault/files_download', rq_v3, response_type=record_pb2.FilesGetResponse)
            assert rs_v3 is not None
            for file_status in rs_v3.files:
                file_uid = utils.base64_url_encode(file_status.record_uid)
                if file_status.status == record_pb2.FG_SUCCESS:
                    file_record = vault.vault_data.load_record(file_uid)
                    if isinstance(file_record, FileRecord):
                        adr = AttachmentDownloadRequest()
                        adr.file_id = file_uid
                        adr.url = file_status.url
                        adr.success_status_code = file_status.success_status_code
                        encryption_key = vault.vault_data.get_record_key(file_uid)
                        assert encryption_key is not None
                        adr.encryption_key = encryption_key
                        adr.title = file_record.title if file_record.title else file_record.file_name
                        adr.is_gcm_encrypted = file_status.fileKeyType == record_pb2.ENCRYPTED_BY_DATA_KEY_GCM
                        yield adr
                else:
                    utils.get_logger().warning('Error requesting download URL for file \"%s\"', file_uid)

    elif isinstance(record, PasswordRecord):
        attachments: List[AttachmentFile] = []
        for atta in (record.attachments or []):
            if attachment_name:
                if attachment_name != atta.id and attachment_name.lower() != atta.title.lower() and \
                        attachment_name.lower() != atta.name.lower():
                    continue
            attachments.append(atta)
        if len(attachments) > 0:
            rq_v2 = {
                'command': 'request_download',
                'file_ids': [x.id for x in attachments],
                'record_uid': record_uid,
            }
            resolve_record_access_path(vault.vault_data.storage, rq_v2)
            rs_v2 = vault.keeper_auth.execute_auth_command(rq_v2)
            if rs_v2['result'] == 'success':
                for attachment, dl in zip(attachments, rs_v2['downloads']):
                    if 'url' in dl:
                        adr = AttachmentDownloadRequest()
                        adr.file_id = attachment.id
                        adr.title = attachment.title if attachment.title else attachment.name
                        adr.url = dl['url']
                        adr.encryption_key = utils.base64_url_decode(attachment.key)
                        adr.is_gcm_encrypted = False
                        yield adr


class UploadTask(abc.ABC):
    def __init__(self) -> None:
        self.mime_type = ''
        self.size = 0
        self.name = ''
        self.title = ''
        self.thumbnail: Optional[bytes] = None

    def prepare(self) -> None:
        pass

    @abc.abstractmethod
    def open(self) -> BinaryIO:
        pass


class BytesUploadTask(UploadTask):
    def __init__(self, data):
        super().__init__()
        self.data = data if isinstance(data, bytes) else b''
        self.size = len(self.data)

    @contextlib.contextmanager
    def open(self):
        yield io.BytesIO(self.data)


class FileUploadTask(UploadTask):
    def __init__(self, file_path: str) -> None:
        super().__init__()
        self.file_path = file_path
        self.name = os.path.basename(self.file_path)

    def prepare(self):
        self.file_path = os.path.expanduser(self.file_path)
        if not os.path.isfile(self.file_path):
            raise ValueError(f'File {self.file_path} does not exist')
        self.size = os.path.getsize(self.file_path)
        if not self.mime_type:
            mt = mimetypes.guess_type(self.file_path)
            if isinstance(mt, tuple) and mt[0]:
                self.mime_type = mt[0]

    @contextlib.contextmanager
    def open(self):
        yield open(self.file_path, 'rb')


def upload_attachments(vault: vault_online.VaultOnline,
                       record: Union[PasswordRecord, TypedRecord],
                       attachments: Sequence[UploadTask]) -> None:
    cryptor = crypto.StreamCrypter()
    if isinstance(record, PasswordRecord):
        cryptor.is_gcm = False
        if not isinstance(record.attachments, list):
            record.attachments = []
        thumbs = [x for x in attachments if x.thumbnail is not None]
        rq = {
            'command': 'request_upload',
            'file_count': len(attachments),
            'thumbnail_count': len(thumbs),
        }
        rs = vault.keeper_auth.execute_auth_command(rq)
        file_uploads = rs['file_uploads']
        thumb_uploads = rs['thumbnail_uploads']
        thumb_pos = 0
        for i, task in enumerate(attachments):
            try:
                uo = file_uploads[i]
                attachment_id = uo['file_id']
                attachment_key = utils.generate_aes_key()
                cryptor.key = attachment_key
                atta = AttachmentFile()
                task.prepare()
                with task.open() as task_stream, cryptor.set_stream(task_stream, True) as crypto_stream:
                    files = {
                        uo['file_parameter']: (attachment_id, crypto_stream, 'application/octet-stream')
                    }
                    response = requests.post(uo['url'], files=files, data=uo['parameters'])
                    if response.status_code == uo['success_status_code']:
                        atta.id = attachment_id
                        atta.name = task.name or ''
                        atta.title = task.title or ''
                        atta.mime_type = task.mime_type or ''
                        atta.last_modified = utils.current_milli_time()
                        atta.key = utils.base64_url_encode(attachment_key)
                        atta.size = task.size
                        record.attachments.append(atta)
                    else:
                        utils.get_logger().warning(
                            'Uploading file %s: HTTP status code %d', task.name, response.status_code)
                        continue
                if isinstance(task.thumbnail, bytes) and thumb_pos < len(thumbs) and thumb_pos < len(thumb_uploads):
                    thumb_task = thumbs[thumb_pos]
                    tuo = thumb_uploads[thumb_pos]
                    thumb_pos += 1
                    atta.thumbnails = []
                    try:
                        with io.BytesIO(task.thumbnail) as thumb_stream, \
                                cryptor.set_stream(thumb_stream, True) as crypto_stream:
                            files = {
                                tuo['file_parameter']: (tuo['file_id'], crypto_stream, 'application/octet-stream')
                            }
                            response = requests.post(tuo['url'], files=files, data=tuo['parameters'])
                            if response.status_code == uo['success_status_code']:
                                thumb = AttachmentFileThumb()
                                thumb.id = tuo['file_id']
                                thumb.type = thumb_task.mime_type
                                thumb.size = len(task.thumbnail)
                                atta.thumbnails.append(thumb)
                            else:
                                utils.get_logger().warning(
                                    'Uploading thumbnail %s: HTTP status code %d', task.name, response.status_code)
                    except Exception as e2:
                        utils.get_logger().warning('Error uploading thumbnail: %s', e2)
            except Exception as e1:
                utils.get_logger().warning('Error uploading attachment: %s', e1)

    elif isinstance(record, TypedRecord):
        cryptor.is_gcm = True
        rq_files = record_pb2.FilesAddRequest()
        rq_files.client_time = utils.current_milli_time()
        file_keys: Dict[bytes, bytes] = {}
        file_tasks: Dict[bytes, UploadTask] = {}
        for task in attachments:
            task.prepare()
            file_uid = utils.base64_url_decode(utils.generate_uid())
            file_key = utils.generate_aes_key()
            file_keys[file_uid] = file_key
            file_tasks[file_uid] = task
            file = record_pb2.File()
            file.record_uid = file_uid
            file.record_key = crypto.encrypt_aes_v2(file_key, vault.keeper_auth.auth_context.data_key)
            file.fileSize = task.size + 100
            file_data = {
                'title': task.title or task.name,
                'name': task.name or '',
                'type': task.mime_type or '',
                'size': task.size
            }
            if isinstance(task.thumbnail, bytes):
                file_data['thumbnail_size'] = len(task.thumbnail)
                file.thumbSize = len(task.thumbnail) + 100
            file.data = crypto.encrypt_aes_v2(json.dumps(file_data).encode(), file_key)
            rq_files.files.append(file)

        rs_files = vault.keeper_auth.execute_auth_rest(
            'vault/files_add', rq_files, response_type=record_pb2.FilesAddResponse)
        assert rs_files is not None

        facade = FileRefRecordFacade()
        facade.record = record
        for uo in rs_files.files:
            file_uid = uo.record_uid
            task = file_tasks[file_uid]
            if uo.status != record_pb2.FA_SUCCESS:
                utils.get_logger().warning('Uploading file %s: Get upload URL error.', task.name)
                continue

            file_key = file_keys[file_uid]
            cryptor.key = file_key
            try:
                with task.open() as task_stream, cryptor.set_stream(task_stream, True) as crypto_stream:
                    file_ref = utils.base64_url_encode(file_uid)
                    files = {
                        'file': (file_ref, crypto_stream, 'application/octet-stream')
                    }
                    response = requests.post(uo.url, files=files, data=json.loads(uo.parameters))
                    if response.status_code == uo.success_status_code:
                        facade.file_ref.append(file_ref)
                        if record.linked_keys is None:
                            record.linked_keys = {}
                        record.linked_keys[file_ref] = file_key
                    else:
                        utils.get_logger().warning(
                            'Uploading file %s: HTTP status code %d', task.name, response.status_code)
                        continue
                if isinstance(task.thumbnail, bytes):
                    try:
                        with io.BytesIO(task.thumbnail) as thumb_stream, \
                                cryptor.set_stream(thumb_stream, True) as crypto_stream:
                            files = {
                                'thumb': crypto_stream
                            }
                            requests.post(uo.url, files=files, data=json.loads(uo.thumbnail_parameters))
                    except Exception as e2:
                        utils.get_logger().warning('Error uploading thumbnail: %s', e2)
            except Exception as e1:
                utils.get_logger().warning('Error uploading attachment: %s', e1)
    else:
        utils.get_logger().warning('Unsupported record type: %s', str(type(record)))
