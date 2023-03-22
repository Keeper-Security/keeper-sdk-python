#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper SDK
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

from .vault_storage import IVaultStorage
from ..storage.in_memory import InMemoryLinkStorage, InMemoryEntityStorage


class InMemoryVaultStorage(IVaultStorage):
    def __init__(self):
        self._revision = 0
        self._personal_scope = 'PersonalScopeUid'

        self._records = InMemoryEntityStorage()
        self._record_types = InMemoryEntityStorage()
        self._shared_folders = InMemoryEntityStorage()
        self._teams = InMemoryEntityStorage()
        self._non_shared_data = InMemoryEntityStorage()

        self._record_keys = InMemoryLinkStorage()
        self._shared_folder_keys = InMemoryLinkStorage()
        self._shared_folder_permissions = InMemoryLinkStorage()

        self._folders = InMemoryEntityStorage()
        self._folder_records = InMemoryLinkStorage()

        self._breach_watch_records = InMemoryEntityStorage()

    def get_revision(self):
        return self._revision

    def set_revision(self, value):
        self._revision = value

    def get_personal_scope_uid(self):
        return self._personal_scope

    def get_records(self):
        return self._records

    def get_record_types(self):
        return self._record_types

    def get_shared_folders(self):
        return self._shared_folders

    def get_teams(self):
        return self._teams

    def get_non_shared_data(self):
        return self._non_shared_data

    def get_record_keys(self):
        return self._record_keys

    def get_shared_folder_keys(self):
        return self._shared_folder_keys

    def get_shared_folder_permissions(self):
        return self._shared_folder_permissions

    def get_folders(self):
        return self._folders

    def get_folder_records(self):
        return self._folder_records

    def get_breach_watch_records(self):
        return self._breach_watch_records

    def clear(self):
        self._revision = 0
        self._records.clear()
        self._record_types.clear()

        self._shared_folders.clear()
        self._teams.clear()
        self._non_shared_data.clear()

        self._record_keys.clear()
        self._shared_folder_keys.clear()
        self._shared_folder_permissions.clear()

        self._folders.clear()
        self._folder_records.clear()

        self._breach_watch_records.clear()
