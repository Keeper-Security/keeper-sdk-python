from typing import List, Tuple, Optional

from keepersdk.vault import vault_types, vault_data
from ..params import KeeperParams

def get_folder_path(vault: vault_data.VaultData, folder_uid: Optional[str], delimiter='/') -> str:
    uid = folder_uid
    names: List[str] = []
    while uid:
        f = vault.get_folder(uid)
        if not f:
            break
        names.append(f.name.replace(delimiter, 2*delimiter))
        uid = f.parent_uid
    names.reverse()
    return delimiter.join(names)


def path_split(vault: vault_data.VaultData,
               folder: vault_types.Folder,
               path_string: str) -> Tuple[vault_types.Folder, List[str]]:
    """Split a path into directories with two replaces and a split."""
    is_abs_path = path_string.startswith('/') and not path_string.startswith('//')
    if is_abs_path:
        folder = vault.root_folder
        path_string = path_string[1:]

    components = [s.replace('\0', '/') for s in path_string.replace('//', '\0').split('/')]
    return folder, components


def try_resolve_path(context: KeeperParams, path: str) -> Tuple[vault_types.Folder, str]:
    """
    Look up the final FolderNode and name of the final component(s).
    If a record, the final component is the record.
    If existent folder(s), the final component is ''.
    If a non-existent folder, the final component is the folders, joined with /, that do not (yet) exist..
    """
    assert context.vault is not None
    if not isinstance(path, str):
        path = ''

    folder: Optional[vault_types.Folder] = context.vault.vault_data.get_folder(path)
    if folder is not None:
        return folder, ''

    if path.startswith('/') and not path.startswith('//'):
        folder = context.vault.vault_data.root_folder
        path = path[1:]
    elif context.current_folder:
        folder = context.vault.vault_data.get_folder(context.current_folder)
    if folder is None:
        folder = context.vault.vault_data.root_folder

    components = [s.replace('\0', '/') for s in path.replace('//', '\0').split('/')]
    while len(components) > 0:
        component = components.pop(0).strip()
        if component == '..':
            parent_uid = folder.parent_uid
            if parent_uid:
                f = context.vault.vault_data.get_folder(parent_uid)
                if f:
                    folder = f
            else:
                folder = context.vault.vault_data.root_folder
        elif component in ('', '.'):
            pass
        else:
            if component in folder.subfolders:
                f = context.vault.vault_data.get_folder(component)
                if f:
                    folder = f
            else:
                folders = [f for f in (context.vault.vault_data.get_folder(x) for x in folder.subfolders) if f]
                f = next((x for x in folders if x.name.strip() == component), None)
                if not f:
                    f = next((x for x in folders if x.name.strip().casefold() == component.casefold()), None)
                if f:
                    folder = f
                else:
                    components.insert(0, component)
                    break
    path = '/'.join(component.replace('/', '//') for component in components)

    # Return a 2-tuple of BaseFolderNode, str
    # The first is the folder/s containing the second, or the folder of the last component if the second is ''.
    # The second is the final component of the path we're passed as an argument to this function. It could be a record, or
    # a not-yet-existent directory.
    return folder, path
