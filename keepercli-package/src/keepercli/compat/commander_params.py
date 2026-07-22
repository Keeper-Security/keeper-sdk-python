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

from __future__ import annotations

import json
from typing import Any, Dict, Optional, Set

from keepersdk import utils
from keepersdk.vault import vault_extensions, vault_record

from ..params import KeeperParams


class _RestContext:
    def __init__(self, params: KeeperParams):
        self._params = params

    @property
    def server_key_id(self) -> int:
        if self._params.auth:
            return self._params.auth.keeper_endpoint.server_key_id
        return 7

    @property
    def server_base(self) -> str:
        server = self._params.keeper_config.server or ''
        if server.startswith('http'):
            return server
        return f'https://{server}'


_compat_installed = False


def ensure_commander_compat() -> None:
    global _compat_installed
    if _compat_installed:
        return
    _compat_installed = True

    KeeperParams.tube_registry = None  # type: ignore[attr-defined]

    def _invalidate_caches(params: KeeperParams) -> None:
        params._commander_record_cache = None  # type: ignore[attr-defined]
        params._commander_subfolder_record_cache = None  # type: ignore[attr-defined]
        params._commander_subfolder_cache = None  # type: ignore[attr-defined]
        params._commander_folder_cache = None  # type: ignore[attr-defined]

    def _build_record_cache(params: KeeperParams) -> Dict[str, Dict[str, Any]]:
        cache: Dict[str, Dict[str, Any]] = {}
        if params.vault is None:
            return cache
        vd = params.vault.vault_data
        for info in vd.records():
            uid = info.record_uid
            record_key = vd.get_record_key(uid)
            storage_record = vd.storage.records.get_entity(uid)
            if not storage_record or not record_key:
                continue
            kr = vd.load_record(uid)
            data_unencrypted = '{}'
            extra_unencrypted = None
            if kr:
                if isinstance(kr, vault_record.PasswordRecord):
                    data, extra, _ = vault_extensions.extract_password_record(kr)
                    data_unencrypted = json.dumps(data)
                    if extra:
                        extra_unencrypted = json.dumps(extra)
                elif isinstance(kr, vault_record.TypedRecord):
                    rt = vd.get_record_type_by_name(kr.record_type)
                    data = vault_extensions.extract_typed_record_data(kr, rt)
                    data_unencrypted = json.dumps(data)
            cache[uid] = {
                'record_uid': uid,
                'version': info.version,
                'revision': info.revision,
                'record_key_unencrypted': record_key,
                'data_unencrypted': data_unencrypted,
                'extra_unencrypted': extra_unencrypted,
                'client_modified_time': getattr(
                    storage_record, 'modified_time', 0
                ),
                'shared': bool(getattr(storage_record, 'shared', False)),
            }

        # Include NSF / Keeper Drive records so pam launch can resolve NSF UIDs.
        nsf = getattr(params.vault, 'nsf_data', None)
        if nsf is not None:
            for entry in nsf.records():
                uid = entry.record_uid
                if not uid or uid in cache:
                    continue
                record_key = getattr(entry, 'record_key', None) or b''
                data_unencrypted = entry.decrypted_data or '{}'
                cache[uid] = {
                    'record_uid': uid,
                    'version': getattr(entry, 'version', 3) or 3,
                    'revision': getattr(entry, 'revision', 0) or 0,
                    'record_key_unencrypted': record_key,
                    'data_unencrypted': data_unencrypted,
                    'extra_unencrypted': None,
                    'client_modified_time': getattr(entry, 'client_modified_time', 0) or 0,
                    'shared': bool(getattr(entry, 'shared', False)),
                }
        return cache

    def _build_subfolder_record_cache(params: KeeperParams) -> Dict[str, Set[str]]:
        mapping: Dict[str, Set[str]] = {}
        if params.vault is None:
            return mapping
        vd = params.vault.vault_data

        def walk(folder):
            folder_uid = folder.folder_uid or ''
            mapping.setdefault(folder_uid, set()).update(folder.records)
            for sub_uid in folder.subfolders:
                sub = vd.get_folder(sub_uid)
                if sub:
                    walk(sub)

        walk(vd.root_folder)
        return mapping

    def _build_subfolder_cache(params: KeeperParams) -> Dict[str, Dict[str, Any]]:
        cache: Dict[str, Dict[str, Any]] = {}
        if params.vault is None:
            return cache
        for folder in params.vault.vault_data.folders():
            cache[folder.folder_uid] = {
                'data_unencrypted': json.dumps({'name': folder.name or ''}),
            }
        root = params.vault.vault_data.root_folder
        cache[root.folder_uid or ''] = {
            'data_unencrypted': json.dumps({'name': root.name or 'My Vault'}),
        }
        return cache

    def _build_folder_cache(params: KeeperParams) -> Dict[str, Any]:
        cache: Dict[str, Any] = {}
        if params.vault is None:
            return cache
        for folder in params.vault.vault_data.folders():
            cache[folder.folder_uid] = folder
        cache[params.vault.vault_data.root_folder.folder_uid or ''] = params.vault.vault_data.root_folder
        return cache

    @property
    def batch_mode(self: KeeperParams) -> bool:
        return bool(self.keeper_config.batch_mode)

    @property
    def session_token(self: KeeperParams) -> Optional[str]:
        if self.auth:
            return utils.base64_url_encode(self.auth.auth_context.session_token)
        return None

    @property
    def server(self: KeeperParams) -> str:
        return self.keeper_config.server or ''

    @property
    def ssl_verify(self: KeeperParams) -> bool:
        return bool(self.keeper_config.certificate_check)

    @property
    def rest_context(self: KeeperParams) -> _RestContext:
        return _RestContext(self)

    @property
    def record_cache(self: KeeperParams) -> Dict[str, Dict[str, Any]]:
        if getattr(self, '_commander_record_cache', None) is None:
            self._commander_record_cache = _build_record_cache(self)
        return self._commander_record_cache

    @property
    def subfolder_record_cache(self: KeeperParams) -> Dict[str, Set[str]]:
        if getattr(self, '_commander_subfolder_record_cache', None) is None:
            self._commander_subfolder_record_cache = _build_subfolder_record_cache(self)
        return self._commander_subfolder_record_cache

    @property
    def subfolder_cache(self: KeeperParams) -> Dict[str, Dict[str, Any]]:
        if getattr(self, '_commander_subfolder_cache', None) is None:
            self._commander_subfolder_cache = _build_subfolder_cache(self)
        return self._commander_subfolder_cache

    @property
    def folder_cache(self: KeeperParams) -> Dict[str, Any]:
        if getattr(self, '_commander_folder_cache', None) is None:
            self._commander_folder_cache = _build_folder_cache(self)
        return self._commander_folder_cache

    @property
    def root_folder(self: KeeperParams):
        if self.vault:
            return self.vault.vault_data.root_folder
        return None

    @property
    def enforcements(self: KeeperParams):
        return getattr(self, '_enforcements', None)

    @enforcements.setter
    def enforcements(self: KeeperParams, value):
        self._enforcements = value

    KeeperParams.batch_mode = batch_mode  # type: ignore[assignment]
    KeeperParams.session_token = session_token  # type: ignore[assignment]
    KeeperParams.server = server  # type: ignore[assignment]
    KeeperParams.ssl_verify = ssl_verify  # type: ignore[assignment]
    KeeperParams.rest_context = rest_context  # type: ignore[assignment]
    KeeperParams.record_cache = record_cache  # type: ignore[assignment]
    KeeperParams.subfolder_record_cache = subfolder_record_cache  # type: ignore[assignment]
    KeeperParams.subfolder_cache = subfolder_cache  # type: ignore[assignment]
    KeeperParams.folder_cache = folder_cache  # type: ignore[assignment]
    KeeperParams.root_folder = root_folder  # type: ignore[assignment]
    KeeperParams.enforcements = enforcements  # type: ignore[assignment]
    KeeperParams._invalidate_commander_caches = _invalidate_caches  # type: ignore[attr-defined]
