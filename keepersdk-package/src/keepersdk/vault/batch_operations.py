import abc
import dataclasses
import enum
import hashlib
import json
import time
from typing import Optional, Union, List, Tuple, Dict, Iterable, Set, Any

import attrs

from . import vault_record, vault_online, typed_field_utils, vault_extensions, vault_utils
from .. import utils, crypto
from ..proto import record_pb2, folder_pb2


class RecordMatch(enum.Enum):
    Nothing = 0
    MainFields = 1
    AllFields = 2


@attrs.define(kw_only=True)
class SharedFolderOptions:
    can_edit: Optional[bool] = None
    can_share: Optional[bool] = None
    manage_users: Optional[bool] = None
    manage_records: Optional[bool] = None


@attrs.define(kw_only=True, frozen=True)
class FolderNode:
    folder_uid: str
    folder_type: str
    folder_name: str
    parent_uid: Optional[str]


class IBatchVaultOperation(abc.ABC):
    @property
    @abc.abstractmethod
    def record_match(self) -> RecordMatch:
        pass

    @abc.abstractmethod
    def get_record_by_uid(self, record_uid: str) -> Optional[Union[vault_record.TypedRecord, vault_record.PasswordRecord]]:
        pass

    @abc.abstractmethod
    def get_folder_by_uid(self, folder_uid: str) -> Optional[FolderNode]:
        pass

    @abc.abstractmethod
    def get_folder_by_path(self, folder_path: str) -> Optional[FolderNode]:
        pass

    @abc.abstractmethod
    def create_folder_path(self,
                           folder_path: List[str], *,
                           shared_folder_options: Optional[SharedFolderOptions]) -> Optional[FolderNode]:
        pass

    @abc.abstractmethod
    def add_folder(self, folder_name: str, *,
                   parent_uid: Optional[str] = None,
                   shared_folder_options: Optional[SharedFolderOptions]) -> Optional[FolderNode]:
        pass

    @abc.abstractmethod
    def add_record(self,
                   record: Union[vault_record.TypedRecord, vault_record.PasswordRecord],
                   folder: Optional[FolderNode]
                   ) -> Optional[Union[vault_record.TypedRecord, vault_record.PasswordRecord]]:
        pass

    @abc.abstractmethod
    def update_record(self, record: Union[vault_record.TypedRecord, vault_record.PasswordRecord]) -> bool:
        pass

    @abc.abstractmethod
    def apply_changes(self) -> None:
        pass

    @abc.abstractmethod
    def reset(self) -> None:
        pass


def tokenize_keeper_record(record: Union[vault_record.PasswordRecord, vault_record.TypedRecord], match: RecordMatch) -> Iterable[str]:
    fields: List[str] = []
    fields.append(f'$title:{record.title}')
    if isinstance(record, vault_record.PasswordRecord):
        if record.login:
            fields.append(f'$login={record.login}')
        if record.password:
            fields.append(f'$password={record.password}')
        if record.link:
            fields.append(f'$url={record.link}')
        if record.totp:
            fields.append(f'$oneTimeCode={record.totp}')
        if match == RecordMatch.AllFields:
            if record.notes:
                fields.append(f'$notes={record.notes}')
            if isinstance(record.custom, list) and len(record.custom) > 0:
                for x in record.custom:
                    if x.name and x.value:
                        fields.append(f'{x.name}={x.value}')
    elif isinstance(record, vault_record.TypedRecord):
        fields.append(f'$type={record.record_type}')
        for field in record.fields:
            if field.type.endswith('Ref'):
                continue
            field_name, field_value = typed_field_utils.TypedFieldMixin.export_typed_field(field)
            if field_value:
                fields.append(f'{field_name}={field_value}')
        if match == RecordMatch.AllFields:
            if record.notes:
                fields.append(f'$notes={record.notes}')
            for field in record.custom:
                field_name, field_value = typed_field_utils.TypedFieldMixin.export_typed_field(field)
                if field_value:
                    fields.append(f'{field_name}={field_value}')

    fields.sort(reverse=False)
    yield from fields


@dataclasses.dataclass
class _RecordLink:
    record: Union[vault_record.PasswordRecord, vault_record.TypedRecord]
    folder: Optional[FolderNode]


class BatchStatus(enum.Enum):
    Added = enum.auto()
    Updated = enum.auto()
    Skipped = enum.auto()
    Failed = enum.auto()


class IBatchLogger(abc.ABC):
    @abc.abstractmethod
    def folder_status(self, folder_uid: str, status: BatchStatus, message: str) -> None:
        pass
    @abc.abstractmethod
    def record_status(self, record_uid: str, status: BatchStatus, message: str) -> None:
        pass


class BatchLogger(IBatchLogger):
    def __init__(self) -> None:
        self.folder_added: Set[str] = set()
        self.record_added: Set[str] = set()
        self.record_updated: Set[str] = set()
        self.folder_failure: Dict[str, str] = dict()
        self.record_failure: Dict[str, str] = dict()

    def folder_status(self, folder_uid: str, status: BatchStatus, message: str) -> None:
        if status == BatchStatus.Skipped:
            self.folder_failure[folder_uid] = f'Folder \"{folder_uid}\" was skipped: {message}'
        elif status == BatchStatus.Added:
            self.folder_added.add(folder_uid)
        elif status == BatchStatus.Failed:
            self.record_failure[folder_uid] = f'Folder \"{folder_uid}\" was failed: {message}'
            self.folder_added.remove(folder_uid)

    def record_status(self, record_uid: str, status: BatchStatus, message: str) -> None:
        if status == BatchStatus.Skipped:
            self.record_failure[record_uid] = f'Record \"{record_uid}\" was skipped: {message}'
        elif status == BatchStatus.Added:
            self.record_added.add(record_uid)
        elif status == BatchStatus.Updated:
            self.record_updated.add(record_uid)
        elif status == BatchStatus.Failed:
            self.record_failure[record_uid] = f'Record \"{record_uid}\" was failed: {message}'
            if record_uid in self.record_added:
                self.record_added.remove(record_uid)
            elif record_uid in self.record_updated:
                self.record_updated.remove(record_uid)


class BatchVaultOperations(IBatchVaultOperation):
    def __init__(self,
                 vault: vault_online.VaultOnline,
                 record_match: RecordMatch,
                 logger: Optional[IBatchLogger] = None) -> None:
        self._record_match = record_match
        self._vault = vault
        self._folders_to_add: List[Tuple[FolderNode, Optional[SharedFolderOptions]]] = []

        self._records_to_add: List[_RecordLink] = []
        self._record_set: Set[str] = set()
        self._records_to_update: List[Union[vault_record.TypedRecord, vault_record.PasswordRecord]] = []
        self._record_full_hashes: Dict[bytes, Set[str]] = {}
        self._record_main_hashes: Dict[bytes, Set[str]] = {}

        self._folder_info_lookup: Dict[str, FolderNode] = {}
        self._folder_path_lookup: Dict[str, str] = {}

        self._batch_logger = logger or BatchLogger()
        self.reset()

    @property
    def record_match(self) -> RecordMatch:
        return self._record_match

    def _get_path_to_root(self, folder_uid: str) -> Iterable[str]:
        uid: Optional[str] = folder_uid
        while uid:
            folder = self._folder_info_lookup.get(uid)
            if folder is None:
                break
            yield folder.folder_name
            uid = folder.parent_uid

    def get_folder_path(self, folder_uid: str) -> str:
        path_to_root = list(self._get_path_to_root(folder_uid))
        path_to_root.reverse()
        return vault_utils.compose_folder_path(path_to_root)

    def reset(self, *, record_match: Optional[RecordMatch]=None) -> None:
        if record_match is not None:
            self._record_match = record_match
        self._folders_to_add.clear()
        self._records_to_add.clear()
        self._record_set.clear()
        self._records_to_update.clear()
        self._folder_info_lookup.clear()
        self._folder_path_lookup.clear()

        for folder in self._vault.vault_data.folders():
            f = FolderNode(folder_uid=folder.folder_uid, folder_type=folder.folder_type, folder_name=folder.name,
                           parent_uid=folder.parent_uid)
            self._folder_info_lookup[f.folder_uid] = f

        for folder_uid in list(self._folder_info_lookup.keys()):
            path = self.get_folder_path(folder_uid).casefold()
            self._folder_path_lookup[path] = folder_uid

        if self._record_match != RecordMatch.Nothing:
            for record_info in self._vault.vault_data.records():
                record = self._vault.vault_data.load_record(record_info.record_uid)
                if isinstance(record, (vault_record.PasswordRecord, vault_record.TypedRecord)):
                    hasher = hashlib.sha256()
                    for token in tokenize_keeper_record(record, RecordMatch.AllFields):
                        hasher.update(token.encode('utf-8', errors='ignore'))
                    full_hash = hasher.digest()
                    if full_hash not in self._record_full_hashes:
                        self._record_full_hashes[full_hash] = set()
                    self._record_full_hashes[full_hash].add(record.record_uid)

                    if self._record_match == RecordMatch.MainFields:
                        hasher = hashlib.sha256()
                        for token in tokenize_keeper_record(record, RecordMatch.MainFields):
                            hasher.update(token.encode('utf-8', errors='ignore'))
                        main_hash = hasher.digest()
                        if main_hash not in self._record_main_hashes:
                            self._record_main_hashes[main_hash] = set()
                        self._record_main_hashes[main_hash].add(record.record_uid)

    def get_record_by_uid(self, record_uid: str) -> Optional[Union[vault_record.TypedRecord, vault_record.PasswordRecord]]:
        record: Optional[Union[vault_record.TypedRecord, vault_record.PasswordRecord]] = None
        if record_uid in self._record_set:
            record = next((x.record for x in self._records_to_add if x.record.record_uid == record_uid), None)
            if record is None:
                record = next((x for x in self._records_to_update if x.record_uid == record_uid), None)
        return record

    def get_folder_by_uid(self, folder_uid: str) -> Optional[FolderNode]:
        return self._folder_info_lookup.get(folder_uid)

    def get_folder_by_path(self, folder_path: str) -> Optional[FolderNode]:
        folder_uid = self._folder_path_lookup.get(folder_path.casefold())
        if folder_uid:
            return self._folder_info_lookup[folder_uid]

    def create_folder_path(self,
                           folder_path: List[str], *,
                           shared_folder_options: Optional[SharedFolderOptions] = None) -> Optional[FolderNode]:
        if len(folder_path) == 0:
            return None

        last_folder: Optional[FolderNode] = None
        for i in range(len(folder_path)):
            path = vault_utils.compose_folder_path(folder_path[:i+1])
            f = self.get_folder_by_path(path)
            if f is None:
                f = self.add_folder(folder_path[i],
                                    parent_uid=last_folder.folder_uid if last_folder else None,
                                    shared_folder_options=shared_folder_options if (i == len(folder_path) - 1) else None)
            last_folder = f
        return last_folder

    def add_folder(self, folder_name: str, *, parent_uid: Optional[str] = None, shared_folder_options: Optional[SharedFolderOptions]) -> Optional[FolderNode]:
        parent_folder: Optional[FolderNode] = None
        if parent_uid:
            parent_folder = self.get_folder_by_uid(parent_uid)
            if parent_folder is None:
                self._batch_logger.folder_status(folder_name, BatchStatus.Failed,  f'Parent folder UID "{parent_uid}" not found')
                return None
        if parent_folder:
            if shared_folder_options is not None and parent_folder.folder_type != 'user_folder':
                self._batch_logger.folder_status(folder_name, BatchStatus.Failed, 'Cannot be added as a shared folder.')
                shared_folder_options = None

        if shared_folder_options is not None:
            folder_type = 'shared_folder'
        elif parent_folder:
            folder_type = 'user_folder' if parent_folder.folder_type == 'user_folder' else 'shared_folder_folder'
        else:
            folder_type = 'user_folder'

        folder_uid = utils.generate_uid()
        f = FolderNode(folder_uid=folder_uid, folder_name=folder_name, folder_type=folder_type, parent_uid=parent_uid)

        self._folders_to_add.append((f, shared_folder_options))
        self._batch_logger.folder_status(folder_uid, BatchStatus.Added,
                                         f'Folder name: \"{folder_name}\"; Folder type: \"{folder_type}\"')

        self._folder_info_lookup[f.folder_uid] = f
        path = self.get_folder_path(folder_uid).casefold()
        self._folder_path_lookup[path] = folder_uid
        return f

    def add_record(self,
                   record: Union[vault_record.TypedRecord, vault_record.PasswordRecord],
                   folder: Optional[FolderNode] = None,
                   ) -> Optional[Union[vault_record.TypedRecord, vault_record.PasswordRecord]]:
        if not isinstance(record, (vault_record.TypedRecord, vault_record.PasswordRecord)):
            self._batch_logger.record_status (record.title, BatchStatus.Failed, f'Record type is not supported')
            return None

        hasher = hashlib.sha256()
        for token in tokenize_keeper_record(record, RecordMatch.AllFields):
            hasher.update(token.encode('utf-8', errors='ignore'))
        full_hash = hasher.digest()
        if full_hash in self._record_full_hashes:
            self._batch_logger.record_status(record.title, BatchStatus.Skipped , f'A full record match already exists')
            record_uids: Optional[Set[str]] = self._record_full_hashes[full_hash]
            if record_uids and len(record_uids) > 0:
                record_uid = next(iter(record_uids))
                r = self._vault.vault_data.load_record(record_uid)
                if isinstance(r, (vault_record.TypedRecord, vault_record.PasswordRecord)):
                    return r
            else:
                record.record_uid = ''
            return None

        if record.record_uid:
            existing_record: Optional[vault_record.KeeperRecordInfo] = self._vault.vault_data.get_record(record.record_uid)
            if existing_record:
                if self.update_record(record):
                    return record
                else:
                    return None
            if record.record_uid in self._record_set:
                self._batch_logger.record_status(record.title, BatchStatus.Skipped,
                                                  f'Record UID \"{record.record_uid}\" already added')
                return None
            record.record_uid = ''

        main_hash: Optional[bytes] = None
        if self._record_match == RecordMatch.MainFields:
            hasher = hashlib.sha256()
            for token in tokenize_keeper_record(record, RecordMatch.MainFields):
                hasher.update(token.encode('utf-8', errors='ignore'))
            main_hash = hasher.digest()
            if main_hash in self._record_main_hashes:
                record_uids = self._record_main_hashes.get(main_hash)
                if isinstance(record_uids, set) and len(record_uids) > 0:
                    existing_record = None
                    for record_uid in record_uids:
                        record_info = self._vault.vault_data.get_record(record_uid)
                        if record_info and record.version() == record_info.version:
                            existing_record = record_info
                            break

                    if existing_record:
                        record.record_uid = existing_record.record_uid
                        if self.update_record(record):
                            return record
                        else:
                            record.record_uid = ''


        if isinstance(folder, FolderNode):
            f = self.get_folder_by_uid(folder.folder_uid)
            if f is None:
                self._batch_logger.record_status(record.title, BatchStatus.Failed, f'Folder "{folder.folder_name}" has not been created. Adding to root folder.')
                folder = None

        if not record.record_uid:
            record.record_uid = utils.generate_uid()

        record_link = _RecordLink(record=record, folder=folder)
        self._records_to_add.append(record_link)
        folder_name = folder.folder_name if folder else ''
        self._batch_logger.record_status(record.record_uid, BatchStatus.Added,f'Adding record "{record.title}" to folder "{folder_name}".')
        self._record_set.add(record.record_uid)
        if full_hash not in self._record_full_hashes:
            self._record_full_hashes[full_hash] = set()
        self._record_full_hashes[full_hash].add(record.record_uid)
        if main_hash:
            if main_hash not in self._record_main_hashes:
                self._record_main_hashes[main_hash] = set()
            self._record_main_hashes[main_hash].add(record.record_uid)

        return record

    def update_record(self, record: Union[vault_record.TypedRecord, vault_record.PasswordRecord]) -> bool:
        if not isinstance(record, (vault_record.TypedRecord, vault_record.PasswordRecord)):
            return False

        existing_record = self._vault.vault_data.get_record(record.record_uid)
        if not existing_record:
            self._batch_logger.record_status(record.record_uid, BatchStatus.Skipped, f'Update: Record UID {record.record_uid} does not exist')
            return False

        if existing_record.version != record.version():
            self._batch_logger.record_status(record.record_uid, BatchStatus.Skipped, f'Update: Record UID "{record.record_uid}" wrong record type')
            return False

        self._records_to_update.append(record)
        self._batch_logger.record_status(record.record_uid, BatchStatus.Updated,f'Updated record UID "{record.record_uid}"')
        return True

    def _get_shared_folder(self, folder_uid: Optional[str]) -> str:
        while folder_uid:
            fn = self.get_folder_by_uid(folder_uid)
            if fn is None:
                break
            folder_uid = fn.parent_uid
            if fn.folder_type == 'shared_folder_folder':
                continue
            elif fn.folder_type == 'shared_folder':
                return fn.folder_uid
        raise Exception(f'Cannot find shared folder for {folder_uid}')

    def apply_changes(self) -> None:
        loop_no = 0
        data_key = self._vault.keeper_auth.auth_context.data_key
        enterprise_key = self._vault.keeper_auth.auth_context.enterprise_ec_public_key
        shared_folder_keys: Dict[str, bytes] = {}

        def get_shared_folder_key(f_uid: str) -> bytes:
            key = shared_folder_keys.get(f_uid)
            if key is None:
                key = self._vault.vault_data.get_shared_folder_key(f_uid)
                if key is None:
                    raise Exception(f'Cannot find shared folder key for {f_uid}')
                shared_folder_keys[f_uid] = key
            return key

        shared_folder_uid: Optional[str] = None
        legacy_audit_data: Dict[str, record_pb2.RecordAddAuditData] = {}
        legacy_records_to_add = [x for x in self._records_to_add if isinstance(x.record, vault_record.PasswordRecord)]

        while len(legacy_records_to_add) > 0 or len(self._folders_to_add) > 0:
            if loop_no > 0:
                time.sleep(10)
            loop_no += 1
            left = 999
            rq = folder_pb2.ImportFolderRecordRequest()
            if len(self._folders_to_add) > 0:
                cnt = min(left, len(self._folders_to_add))
                f_chunk: List[Tuple[FolderNode, Optional[SharedFolderOptions]]] = self._folders_to_add[:cnt]
                self._folders_to_add = self._folders_to_add[cnt:]
                for folder, sf_options in f_chunk:
                    folder_key = utils.generate_aes_key()
                    frq = folder_pb2.FolderRequest()
                    frq.folderUid = utils.base64_url_decode(folder.folder_uid)
                    if folder.parent_uid:
                        frq.parentFolderUid = utils.base64_url_decode(folder.parent_uid)
                    if folder.folder_type == 'shared_folder':
                        frq.folderType = folder_pb2.shared_folder
                    elif folder.folder_type == 'shared_folder_folder':
                        frq.folderType = folder_pb2.shared_folder_folder
                    else:
                        frq.folderType = folder_pb2.user_folder
                    data = json.dumps({'name': folder.folder_name}).encode('utf-8')
                    frq.folderData = crypto.encrypt_aes_v1(data, folder_key)
                    if folder.folder_type == 'user_folder':
                        frq.encryptedFolderKey = crypto.encrypt_aes_v1(folder_key, data_key)
                    elif folder.folder_type == 'shared_folder':
                        shared_folder_keys[folder.folder_uid] = folder_key
                        frq.encryptedFolderKey = crypto.encrypt_aes_v1(folder_key, data_key)
                        frq.sharedFolderFields.encryptedFolderName = crypto.encrypt_aes_v1(folder.folder_name.encode('utf-8'), folder_key)
                        if sf_options is not None:
                            frq.sharedFolderFields.manageUsers = sf_options.manage_users is True
                            frq.sharedFolderFields.manageRecords = sf_options.manage_records is True
                            frq.sharedFolderFields.canShare = sf_options.can_share is True
                            frq.sharedFolderFields.canEdit = sf_options.can_edit is True
                    elif folder.folder_type == 'shared_folder_folder':
                        shared_folder_uid = self._get_shared_folder(folder.folder_uid)
                        if folder.parent_uid and folder.parent_uid == shared_folder_uid:
                            frq.parentFolderUid = b''
                        shared_folder_key = get_shared_folder_key(shared_folder_uid)
                        frq.encryptedFolderKey = crypto.encrypt_aes_v1(folder_key, shared_folder_key)
                        frq.sharedFolderFolderFields.sharedFolderUid = utils.base64_url_decode(shared_folder_uid)

                    rq.folderRequest.append(frq)
                left -= len(rq.folderRequest)

            if len(legacy_records_to_add) > 0 and left > 10:
                cnt = min(len(legacy_records_to_add), left)
                r_chunk: List[_RecordLink] = legacy_records_to_add[:cnt]
                legacy_records_to_add = legacy_records_to_add[cnt:]
                for record_link in r_chunk:
                    lr = record_link.record
                    folder_node = record_link.folder
                    record_key = utils.generate_aes_key()
                    rrq = folder_pb2.RecordRequest()
                    rrq.recordUid = utils.base64_url_decode(lr.record_uid)
                    rrq.encryptedRecordKey = crypto.encrypt_aes_v1(record_key, data_key)
                    if folder_node is not None:
                        if folder_node.folder_type == 'shared_folder':
                            rrq.folderType = folder_pb2.shared_folder
                        elif folder_node.folder_type == 'shared_folder_folder':
                            rrq.folderType = folder_pb2.shared_folder_folder
                        else:
                            rrq.folderType = folder_pb2.user_folder
                        rrq.folderUid = utils.base64_url_decode(folder_node.folder_uid)
                        if folder_node.folder_type == 'shared_folder':
                            shared_folder_uid = folder_node.folder_uid
                        elif folder_node.folder_type == 'shared_folder_folder':
                            shared_folder_uid = self._get_shared_folder(folder_node.folder_uid)
                        if shared_folder_uid:
                            shared_folder_key = get_shared_folder_key(shared_folder_uid)
                            rrq.encryptedRecordFolderKey = crypto.encrypt_aes_v1(record_key, shared_folder_key)
                    else:
                        rrq.folderType = folder_pb2.FolderType.user_folder
                    assert isinstance(lr, vault_record.PasswordRecord)
                    data_dict, extra_dict, _ = vault_extensions.extract_password_record(lr)
                    rrq.recordData = crypto.encrypt_aes_v1(json.dumps(data_dict).encode(), record_key)
                    rrq.extra = crypto.encrypt_aes_v1(json.dumps(extra_dict).encode(), record_key)
                    rq.recordRequest.append(rrq)

                    if enterprise_key:
                        ad = vault_extensions.extract_audit_data(lr)
                        if ad:
                            audit_data = json.dumps(ad).encode('utf-8')
                            rad_rq = record_pb2.RecordAddAuditData()
                            rad_rq.record_uid = utils.base64_url_decode(lr.record_uid)
                            rad_rq.data = crypto.encrypt_ec(audit_data, enterprise_key)
                            legacy_audit_data[lr.record_uid] = rad_rq

            rs = self._vault.keeper_auth.execute_auth_rest('folder/import_folders_and_records', rq,
                                                           response_type=folder_pb2.ImportFolderRecordResponse)
            assert rs is not None
            for frs in rs.folderResponse:
                folder_uid = utils.base64_url_encode(frs.folderUid)
                folder_node = self.get_folder_by_uid(folder_uid)
                if frs.status == 'SUCCESS':
                    pass
                else:
                    self._batch_logger.folder_status(folder_uid, BatchStatus.Failed, frs.status)

            for rrs in rs.recordResponse:
                record_uid = utils.base64_url_encode(rrs.recordUid)
                if rrs.status == 'SUCCESS':
                    if record_uid in legacy_audit_data:
                        legacy_audit_data[record_uid].revision = rrs.revision
                else:
                    self._batch_logger.record_status(record_uid, BatchStatus.Failed, rrs.status)
                    if record_uid in legacy_audit_data:
                        del legacy_audit_data[record_uid]

        loop_no = 0
        typed_records_to_add = [x for x in self._records_to_add if isinstance(x.record, vault_record.TypedRecord)]
        while len(typed_records_to_add) > 0:
            if loop_no > 0:
                time.sleep(10)
            loop_no += 1

            rt_chunk: List[_RecordLink] = typed_records_to_add[:999]
            typed_records_to_add = typed_records_to_add[999:]

            ra_rq = record_pb2.RecordsAddRequest()
            ra_rq.client_time = utils.current_milli_time()
            for record_link in rt_chunk:
                assert isinstance(record_link.record, vault_record.TypedRecord)
                tr: vault_record.TypedRecord = record_link.record
                folder_node = record_link.folder
                record_key = utils.generate_aes_key()
                tra_rq = record_pb2.RecordAdd()
                tra_rq.record_uid = utils.base64_url_decode(tr.record_uid)
                tra_rq.client_modified_time = utils.current_milli_time()
                tra_rq.record_key = crypto.encrypt_aes_v2(record_key, data_key)
                if folder_node:
                    if folder_node.folder_type == 'user_folder':
                        tra_rq.folder_type = record_pb2.RecordFolderType.user_folder
                    elif folder_node.folder_type == 'shared_folder':
                        tra_rq.folder_type = record_pb2.RecordFolderType.shared_folder
                        shared_folder_uid = folder_node.folder_uid
                    elif folder_node.folder_type == 'shared_folder_folder':
                        tra_rq.folder_type = record_pb2.RecordFolderType.shared_folder_folder
                        shared_folder_uid = self._get_shared_folder(folder_node.folder_uid)

                    tra_rq.folder_uid = utils.base64_url_decode(folder_node.folder_uid)
                    if shared_folder_uid:
                        shared_folder_key = get_shared_folder_key(shared_folder_uid)
                        tra_rq.folder_key = crypto.encrypt_aes_v2(record_key, shared_folder_key)
                if not tr.record_type:
                    tr.record_type = 'login'
                rt = self._vault.vault_data.get_record_type_by_name(tr.record_type)
                if rt:
                    vault_extensions.adjust_typed_record(tr, rt)
                data = vault_extensions.get_padded_json_bytes(vault_extensions.extract_typed_record_data(tr, rt))
                tra_rq.data = crypto.encrypt_aes_v2(data, record_key)
                if enterprise_key:
                    ad = vault_extensions.extract_audit_data(tr)
                    if ad:
                        audit_data = json.dumps(ad).encode('utf-8')
                        tra_rq.audit.version = 0
                        tra_rq.audit.data = crypto.encrypt_ec(audit_data, enterprise_key)
                ra_rq.records.append(tra_rq)
            ra_rs = self._vault.keeper_auth.execute_auth_rest(
                'vault/records_add', ra_rq, response_type=record_pb2.RecordsModifyResponse)
            assert ra_rs is not None
            for ars in ra_rs.records:
                if ars.status == record_pb2.RecordModifyResult.RS_SUCCESS:
                    pass
                else:
                    record_uid = utils.base64_url_encode(ars.record_uid)
                    self._batch_logger.record_status(record_uid, BatchStatus.Failed, ars.message)

        if len(self._records_to_update):
            to_update = {x.record_uid:x for x in self._records_to_update}
            self._records_to_update.clear()
            self._records_to_update.extend(to_update.values())
            del to_update
            results: List[record_pb2.RecordModifyStatus] = []
            password_changed: Set[str] = set()
            attachments_added: Dict[str, Set[str]] = {}
            attachments_removed: Dict[str, Set[str]] = {}
            v2_records: List[Dict[str, Any]] = []
            v3_records: List[record_pb2.RecordUpdate] = []
            for record in self._records_to_update:
                record_info = self._vault.vault_data.get_record(record.record_uid)
                rec_key = self._vault.vault_data.get_record_key(record.record_uid)
                existing_record = self._vault.vault_data.load_record(record.record_uid)
                if not record_info or not rec_key or not existing_record:
                    sts = record_pb2.RecordModifyStatus()
                    sts.status = record_pb2.RecordModifyResult.RS_ACCESS_DENIED
                    sts.message = f'Record "{record.record_uid}" not found'
                    results.append(sts)
                    continue

                record_key = rec_key
                if isinstance(record, vault_record.PasswordRecord) and isinstance(existing_record, vault_record.PasswordRecord):
                    status = vault_extensions.compare_records(record, existing_record)
                    if bool(status & vault_extensions.RecordChangeStatus.Password):
                        password_changed.add(record.record_uid)

                    record_object = {
                        'record_uid': record.record_uid,
                        'version': 2,
                        'revision': record_info.revision,
                        'client_modified_time': utils.current_milli_time(),
                    }
                    vault_extensions.resolve_record_access_path(self._vault.vault_data.storage, record_object, for_edit=True)
                    data_dict, extra_dict, file_ids = vault_extensions.extract_password_record(record)
                    data = crypto.encrypt_aes_v1(json.dumps(data_dict).encode(), record_key)
                    record_object['data'] = utils.base64_url_encode(data)
                    extra = crypto.encrypt_aes_v1(json.dumps(extra_dict).encode(), record_key)
                    record_object['extra'] = utils.base64_url_encode(extra)
                    if file_ids:
                        record_object['udata'] = {'file_ids': file_ids}
                    v2_records.append(record_object)
                    if enterprise_key:
                        if bool(status & (vault_extensions.RecordChangeStatus.Title |
                                          vault_extensions.RecordChangeStatus.URL |
                                          vault_extensions.RecordChangeStatus.RecordType)):
                            ad = vault_extensions.extract_audit_data(record)
                            if ad:
                                audit_data = json.dumps(ad).encode('utf-8')
                                rad_rq = record_pb2.RecordAddAuditData()
                                rad_rq.record_uid = utils.base64_url_decode(record.record_uid)
                                rad_rq.data = crypto.encrypt_ec(audit_data, enterprise_key)
                                legacy_audit_data[record.record_uid] = rad_rq

                elif isinstance(record, vault_record.TypedRecord) and isinstance(existing_record, vault_record.TypedRecord):
                    status = vault_extensions.compare_records(record, existing_record)
                    if bool(status & vault_extensions.RecordChangeStatus.Password):
                        password_changed.add(record.record_uid)

                    ur = record_pb2.RecordUpdate()
                    ur.record_uid = utils.base64_url_decode(record.record_uid)
                    ur.client_modified_time = utils.current_milli_time()
                    ur.revision = record_info.revision
                    rt = self._vault.vault_data.get_record_type_by_name(record.record_type)
                    data_dict = vault_extensions.extract_typed_record_data(record, rt)
                    json_data = vault_extensions.get_padded_json_bytes(data_dict)
                    ur.data = crypto.encrypt_aes_v2(json_data, record_key)

                    existing_refs = vault_extensions.extract_typed_record_refs(existing_record)
                    refs = vault_extensions.extract_typed_record_refs(record)
                    for ref_record_uid in refs.difference(existing_refs):
                        ref_record_key = None
                        if record.linked_keys and ref_record_uid in record.linked_keys:
                            ref_record_key = record.linked_keys[ref_record_uid]
                        if not ref_record_key:
                            ref_record_key = self._vault.vault_data.get_record_key(ref_record_uid)
                        if ref_record_key:
                            link = record_pb2.RecordLink()
                            link.record_uid = utils.base64_url_decode(ref_record_uid)
                            link.record_key = crypto.encrypt_aes_v2(ref_record_key, record_key)
                            ur.record_links_add.append(link)
                    for ref in existing_refs.difference(refs):
                        ur.record_links_remove.append(utils.base64_url_decode(ref))

                    if enterprise_key and bool(status & (vault_extensions.RecordChangeStatus.Title |
                                                         vault_extensions.RecordChangeStatus.URL |
                                                         vault_extensions.RecordChangeStatus.RecordType)):
                        ad = vault_extensions.extract_audit_data(record)
                        if ad:
                            audit_data = json.dumps(ad).encode('utf-8')
                            ur.audit.version = 0
                            ur.audit.data = crypto.encrypt_ec(audit_data, enterprise_key)
                    v3_records.append(ur)
                else:
                    sts = record_pb2.RecordModifyStatus()
                    sts.record_uid = utils.base64_url_decode(record.record_uid)
                    sts.status = record_pb2.RecordModifyResult.RS_OLD_RECORD_VERSION_TYPE
                    sts.message = f'Cannot change record type "{record.record_uid}"'
                    results.append(sts)

                prev_atta_ids = vault_extensions.extract_record_attachment_ids(existing_record)
                new_atta_ids = vault_extensions.extract_record_attachment_ids(record)
                if len(prev_atta_ids) > 0 or len(new_atta_ids) > 0:
                    attachments_added[record.record_uid] = new_atta_ids.difference(prev_atta_ids)
                    attachments_removed[record.record_uid] = prev_atta_ids.difference(new_atta_ids)

            while len(v2_records) > 0:
                lr_chunk = v2_records[:99]
                v2_records = v2_records[99:]
                upr_rq = {
                    'command': 'record_update',
                    'client_time': utils.current_milli_time(),
                    'update_records': lr_chunk,
                }
                upr_rs = self._vault.keeper_auth.execute_auth_command(upr_rq)
                revision = upr_rs.get('revision', 0)
                for urrs in upr_rs.get('update_records', []):
                    status = urrs.get('status')
                    record_uid = urrs.get('record_uid') or ''
                    if status == 'success':
                        if record_uid in legacy_audit_data:
                            legacy_audit_data[record_uid].revision = revision
                    else:
                        password_changed.remove(record_uid)
                        if record_uid in attachments_added:
                            del attachments_added[record_uid]
                        if record_uid in attachments_removed:
                            del attachments_removed[record_uid]
                        sts = record_pb2.RecordModifyStatus()
                        sts.record_uid = utils.base64_url_decode(record_uid)
                        sts.status = record_pb2.RecordModifyResult.RS_ACCESS_DENIED if status == 'access_denied' else record_pb2.RecordModifyResult.RS_OUT_OF_SYNC
                        results.append(sts)

            while len(v3_records) > 0:
                tr_chunk = v3_records[:900]
                v3_records = v3_records[900:]
                utr_rq = record_pb2.RecordsUpdateRequest()
                utr_rq.client_time = utils.current_milli_time()
                utr_rq.records.extend(tr_chunk)
                utr_rs = self._vault.keeper_auth.execute_auth_rest('vault/records_update', utr_rq, response_type=record_pb2.RecordsModifyResponse)
                assert utr_rs is not None
                for uts in utr_rs.records:
                    if uts.status == record_pb2.RecordModifyResult.RS_SUCCESS:
                        pass
                    else:
                        record_uid = utils.base64_url_encode(uts.record_uid)
                        password_changed.remove(record_uid)
                        if record_uid in attachments_added:
                            del attachments_added[record_uid]
                        if record_uid in attachments_removed:
                            del attachments_removed[record_uid]
                        results.append(uts)

            caep = self._vault.client_audit_event_plugin()
            if caep:
                for record_uid in password_changed:
                    caep.schedule_audit_event('record_password_change', record_uid=record_uid)
                for record_uid, attachment_ids in attachments_added.items():
                    for attachment_uid in attachment_ids:
                        caep.schedule_audit_event(
                            'file_attachment_uploaded', record_uid=record_uid, attachment_id=attachment_uid)
                for record_uid, attachment_ids in attachments_removed.items():
                    for attachment_uid in attachment_ids:
                        caep.schedule_audit_event(
                            'file_attachment_deleted', record_uid=record_uid, attachment_id=attachment_uid)

            if len(results) > 0:
                for rms in results:
                    record_uid = utils.base64_url_encode(rms.record_uid)
                    message = f'({rms.status}): {rms.message}'
                    self._batch_logger.record_status(record_uid, BatchStatus.Failed, message)

        if len(legacy_audit_data) > 0:
            audit_data_list = list(legacy_audit_data.values())
            legacy_audit_data.clear()
            loop_no = 0
            while len(audit_data_list) > 0:
                if loop_no > 0:
                    time.sleep(10)
                loop_no += 1
                ad_chunk: List[record_pb2.RecordAddAuditData] = audit_data_list[:999]
                audit_data_list = audit_data_list[999:]
                ad_rq = record_pb2.AddAuditDataRequest()
                ad_rq.records.extend(ad_chunk)
                self._vault.keeper_auth.execute_auth_rest('vault/record_add_audit_data', ad_rq)

        self._vault.run_pending_jobs()
