import abc
import enum
import hashlib
from typing import Optional, Union, List, Tuple, Dict, Iterable, Callable, Literal, Set

import attrs

from . import vault_record, vault_online, typed_field_utils

from .. import utils
class LogMessageSeverity(enum.Enum):
    Error = 1
    Warning = 2
    Information = 3

class RecordMatch(enum.Enum):
    Nothing = 0
    MainFields = 1
    AllFields = 2

@attrs.define(kw_only=True)
class BatchSummary:
    share_folder_count: int
    folder_count: int
    legacy_record_count: int
    typed_record_count: int
    updated_record_count: int


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
    def get_folder_by_uid(self, folder_uid: str) -> Optional[FolderNode]:
        pass

    @abc.abstractmethod
    def get_folder_by_path(self, folder_path: str) -> Optional[FolderNode]:
        pass

    @abc.abstractmethod
    def add_folder(self, folder_name: str, *, parent_uid: Optional[str] = None, shared_folder_options: Optional[SharedFolderOptions]) -> None:
        pass

    @abc.abstractmethod
    def add_record(self, record: Union[vault_record.TypedRecord, vault_record.PasswordRecord], folder: Optional[FolderNode]) -> bool:
        pass

    @abc.abstractmethod
    def update_record(self, record: Union[vault_record.TypedRecord, vault_record.PasswordRecord]) -> bool:
        pass

    @abc.abstractmethod
    def apply_changes(self) -> BatchSummary:
        pass

    @abc.abstractmethod
    def reset(self) -> None:
        pass


def create_folder_path(path: Iterable[str]) -> str:
    result = ''
    for name in path:
        if name:
            if '/' in name:
                name = name.replace('/', '//')
            if len(result) > 0:
                result += '/'
            result += name
    return result

def tokenize_keeper_record(record: Union[vault_record.PasswordRecord, vault_record.TypedRecord], match: RecordMatch) -> Iterable[str]:
    fields: List[str] = []
    fields.append(f'$title:{record.record_type}')
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


class BatchVaultOperations(IBatchVaultOperation):
    def __init__(self, vault: vault_online.VaultOnline, record_match: RecordMatch) -> None:
        self._record_match = record_match
        self._vault = vault
        self._folders_to_add: List[Tuple[FolderNode, Optional[SharedFolderOptions]]] = []
        self._legacy_records_to_add: List[Tuple[vault_record.PasswordRecord, FolderNode]] = []
        self._typed_records_to_add: List[Tuple[vault_record.TypedRecord, FolderNode]] = []
        self._record_set: Set[str] = set()
        self._records_to_update: List[Union[vault_record.TypedRecord, vault_record.PasswordRecord]] = []
        self._record_full_hashes: Dict[bytes, str] = {}
        self._record_main_hashes: Dict[bytes, str] = {}

        self._folder_info_lookup: Dict[str, FolderNode] = {}
        self._folder_path_lookup: Dict[str, str] = {}

        self.batch_logger: Optional[Callable[[LogMessageSeverity, str], None]] = None

        self.reset()


    @property
    def record_match(self) -> RecordMatch:
        return self._record_match

    def _get_path_to_root(self, folder_uid: str) -> Iterable[str]:
        uid = folder_uid
        while uid:
            folder = self._folder_info_lookup.get(uid)
            if folder is None:
                break
            yield folder.folder_name
            uid = folder.parent_uid

    def get_folder_path(self, folder_uid: str) -> str:
        path_to_root = list(self._get_path_to_root(folder_uid))
        path_to_root.reverse()
        return create_folder_path(path_to_root)

    def reset(self) -> None:
        self._folders_to_add.clear()
        self._legacy_records_to_add.clear()
        self._typed_records_to_add.clear()
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
            for record in self._vault.vault_data.records():
                if isinstance(record, (vault_record.PasswordRecord, vault_record.TypedField)):
                    hasher = hashlib.sha256()
                    for token in tokenize_keeper_record(record, RecordMatch.AllFields):
                        hasher.update(token.encode('utf-8', errors='ignore'))
                    self._record_full_hashes[hasher.digest()] = record.record_uid
                    if self._record_match == RecordMatch.MainFields:
                        hasher = hashlib.sha256()
                        for token in tokenize_keeper_record(record, RecordMatch.MainFields):
                            hasher.update(token.encode('utf-8', errors='ignore'))
                        self._record_main_hashes[hasher.digest()] = record.record_uid

    def get_folder_by_uid(self, folder_uid: str) -> Optional[FolderNode]:
        return self._folder_info_lookup[folder_uid]

    def get_folder_by_path(self, folder_path: str) -> Optional[FolderNode]:
        folder_uid = self._folder_path_lookup[folder_path.casefold()]
        if folder_uid:
            return self._folder_info_lookup[folder_uid]

    def add_folder(self, folder_name: str, *, parent_uid: Optional[str] = None, shared_folder_options: Optional[SharedFolderOptions]) -> bool:
        parent_folder: Optional[FolderNode] = None
        if parent_uid:
            parent_folder = self.get_folder_by_uid(parent_uid)
            if parent_folder is None:
                if self.batch_logger:
                    self.batch_logger(LogMessageSeverity.Error, f'Add Folder "{folder_name}": Cannot be added as a shared folder.')
                return False
        if parent_folder:
            if shared_folder_options is not None and parent_folder.folder_type != 'user_folder':
                if self.batch_logger:
                    self.batch_logger(LogMessageSeverity.Warning, f'Add Folder "{folder_name}": Parent folder UID "{parent_uid}" not found')
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
        self._folder_info_lookup[f.folder_uid] = f
        path = self.get_folder_path(folder_uid).casefold()
        self._folder_path_lookup[path] = folder_uid
        return True

    def add_record(self, record: Union[vault_record.TypedRecord, vault_record.PasswordRecord], folder: Optional[FolderNode]) -> bool:
        if not isinstance(record, (vault_record.TypedRecord, vault_record.PasswordRecord)):
            if self.batch_logger is not None:
                self.batch_logger(LogMessageSeverity.Error, 'Add record: record type is not supported')
            return False

        hasher = hashlib.sha256()
        for token in tokenize_keeper_record(record, RecordMatch.AllFields):
            hasher.update(token.encode('utf-8', errors='ignore'))
        full_hash = hasher.digest()
        if full_hash in self._record_full_hashes:
            self.batch_logger(LogMessageSeverity.Warning, f'Add Record \"{record.title}\": A full record match already exists. Skipped.')
            return False

        if record.record_uid:
            existing_record = self._vault.vault_data.get_record(record.record_uid)
            if existing_record:
                if self.batch_logger is not None:
                    self.batch_logger(LogMessageSeverity.Information, f'Add Record \"{record.title}\": Record UID \"{record.record_uid}\" exists: Updated.')
                return self.update_record(record)
            if record.record_uid in self._record_set:
                self.batch_logger(LogMessageSeverity.Warning,
                                  f'Add Record \"{record.title}\": Record UID \"{record.record_uid}\" already added. Skipped.')
                return False

        return True
