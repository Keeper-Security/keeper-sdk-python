import fnmatch
import re
from typing import Optional, Iterator, List

from keepersdk.vault import vault_record, vault_utils, vault_types
from . import folder_utils
from ..params import KeeperParams


def try_resolve_single_record(record_name: Optional[str], context: KeeperParams) -> Optional[vault_record.KeeperRecordInfo]:
    assert context.vault is not None
    if not record_name:
        return None

    record_info = context.vault.vault_data.get_record(record_name)
    if record_info:
        return record_info

    folder, name = folder_utils.try_resolve_path(context, record_name)
    if name:
        name = name.casefold()
        for record_uid in folder.records:
            record_info = context.vault.vault_data.get_record(record_uid)
            if record_info and record_info.title.casefold() == name:
                return record_info

def resolve_records(pattern: str, context: KeeperParams, *, recursive: bool=False) -> Iterator[str]:
    assert context.vault is not None
    record_info = context.vault.vault_data.get_record(pattern)
    if record_info:
        yield record_info.record_uid
        return

    folder = context.vault.vault_data.get_folder(pattern)
    if folder:
        pattern = ''
    else:
        folder, pattern = folder_utils.try_resolve_path(context, pattern)

    if pattern:
        regex = re.compile(fnmatch.translate(pattern), re.IGNORECASE).match
        for record_uid in folder.records:
            record_info = context.vault.vault_data.get_record(record_uid)
            if record_info and regex(record_info.title):
                yield record_uid
    else:
        folders: List[vault_types.Folder] = []
        def add_folder(f: vault_types.Folder) -> None:
            folders.append(f)
        if recursive:
            vault_utils.traverse_folder_tree(context.vault.vault_data, folder, add_folder)
        else:
            add_folder(folder)
        for folder in folders:
            yield from folder.records
