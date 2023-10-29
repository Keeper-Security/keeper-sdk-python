from typing import Callable, List, Set

from . import vault_data, vault_types


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