from typing import Callable, List, Set, Optional

from . import vault_data, vault_types, vault_record


def traverse_folder_tree(vault: vault_data.VaultData,
                         folder: vault_types.Folder,
                         callback: Callable[[vault_types.Folder], None]):
    if not callable(callback):
        return

    callback(folder)

    all_folders: Set[str] = set()
    subfolders: List[str] = list(folder.subfolders)

    pos = 0
    while pos < len(subfolders):
        f_uid = subfolders[pos]
        if f_uid in all_folders:
            continue
        all_folders.add(f_uid)
        pos += 1
        f = vault.get_folder(f_uid)
        if f:
            callback(f)
            subfolders.extend(f.subfolders)


def get_folders_for_record(vault: vault_data.VaultData, record_uid: str) -> List[vault_types.Folder]:
    result: List[vault_types.Folder] = []
    def record_exists(f: vault_types.Folder) -> None:
        if record_uid in f.records:
            result.append(f)
    traverse_folder_tree(vault, vault.root_folder, record_exists)
    return result


def extract_password(record: vault_record.KeeperRecord) -> Optional[str]:
    if isinstance(record, vault_record.PasswordRecord):
        return record.password
    if isinstance(record, vault_record.TypedRecord):
        password_field = record.get_typed_field('password')
        if password_field:
            return password_field.get_default_value(str)

def extract_url(record: vault_record.KeeperRecord) -> Optional[str]:
    if isinstance(record, vault_record.PasswordRecord):
        return record.link
    if isinstance(record, vault_record.TypedRecord):
        url_field = record.get_typed_field('url')
        if url_field:
            return url_field.get_default_value(str)

