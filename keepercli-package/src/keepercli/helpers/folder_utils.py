from typing import Tuple, Optional

from keepersdk.vault import vault_types
from ..params import KeeperParams


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
