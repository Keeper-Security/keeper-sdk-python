#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

from typing import Optional

from ..helpers import folder_utils
from ..params import KeeperParams


class FolderMixin:
    @staticmethod
    def resolve_folder(params: KeeperParams, folder_name: str) -> Optional[str]:
        if not folder_name:
            return None
        if folder_name in params.folder_cache:
            return folder_name
        rs = folder_utils.try_resolve_path(params, folder_name)
        if rs is not None:
            folder, record_name = rs
            if folder and not record_name:
                return folder.folder_uid or ''
        return None
