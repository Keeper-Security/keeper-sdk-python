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
        self._continuation_token = b''
        self._personal_scope = 'PersonalScopeUid'

        self._records = InMemoryEntityStorage()
        self._record_types = InMemoryEntityStorage()
        self._shared_folders = InMemoryEntityStorage()
        self._teams = InMemoryEntityStorage()
        self._non_shared_data = InMemoryEntityStorage()

        self._record_keys = InMemoryLinkStorage()
        self._shared_folder_keys = InMemoryLinkStorage()
        self._shared_folder_permissions = InMemoryLinkStorage()
        self._user_emails = InMemoryLinkStorage()

        self._folders = InMemoryEntityStorage()
        self._folder_records = InMemoryLinkStorage()

        self._breach_watch_records = InMemoryEntityStorage()

    @property
    def continuation_token(self):
        return self._continuation_token

    @continuation_token.setter
    def continuation_token(self, value):
        self._continuation_token = value

    @property
    def personal_scope_uid(self):
        return self._personal_scope

    @property
    def records(self):
        return self._records

    @property
    def record_types(self):
        return self._record_types

    @property
    def shared_folders(self):
        return self._shared_folders

    @property
    def teams(self):
        return self._teams

    @property
    def non_shared_data(self):
        return self._non_shared_data

    @property
    def record_keys(self):
        return self._record_keys

    @property
    def shared_folder_keys(self):
        return self._shared_folder_keys

    @property
    def shared_folder_permissions(self):
        return self._shared_folder_permissions

    @property
    def user_emails(self):
        return self._user_emails

    @property
    def folders(self):
        return self._folders

    @property
    def folder_records(self):
        return self._folder_records

    @property
    def breach_watch_records(self):
        return self._breach_watch_records

    def clear(self):
        self._continuation_token = b''
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
