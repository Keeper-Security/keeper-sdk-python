from typing import Callable, List, Set, Optional, Tuple, Iterable

from . import vault_data, vault_types
from ..authentication import keeper_auth


def parse_folder_path(path_string: str, *, path_delimiter: str='/') -> List[str]:
    assert len(path_delimiter) == 1
    return [x.replace('\0', path_delimiter) for x in path_string.replace(2*path_delimiter, '\0').split(path_delimiter) if x]


def compose_folder_path(path: Iterable[str], *, path_delimiter: str='/') -> str:
    assert len(path_delimiter) == 1
    return path_delimiter.join((x.replace(path_delimiter, 2*path_delimiter) for x in path if x))


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


def load_available_teams(auth: keeper_auth.KeeperAuth) -> Iterable[vault_types.TeamInfo]:
    rq = { 'command': 'get_available_teams' }
    rs = auth.execute_auth_command(rq)
    if 'teams' in rs:
        for team in rs['teams']:
            yield vault_types.TeamInfo(team_uid=team['team_uid'], name=team['team_name'])
