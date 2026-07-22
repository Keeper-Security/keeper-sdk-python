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

from typing import Optional, Union, Dict, Any

from keepersdk.vault import vault_record

PasswordRecord = vault_record.PasswordRecord


class TypedRecord(vault_record.TypedRecord):
    @property
    def version(self):
        return super().version()

    @property
    def record_key(self):
        return getattr(self, '_record_key', b'')

    @record_key.setter
    def record_key(self, value):
        self._record_key = value


FileRecord = vault_record.FileRecord


class ApplicationRecord(vault_record.KeeperRecord):
    """Minimal KSM application record placeholder for Commander parity."""

    def version(self) -> int:
        return 5

    def load_record_data(self, data: Dict[str, Any], extra=None) -> None:
        self.title = data.get('title', '')


def _load_nsf_typed_record(vault, record_uid: str) -> Optional[TypedRecord]:
    if not vault or not vault.nsf_data or not vault.nsf_data.get_record(record_uid):
        return None
    from keepersdk.vault import nsf_management
    try:
        meta = nsf_management.load_nsf_record_metadata(vault, record_uid)
    except nsf_management.NsfError:
        return None
    typed = TypedRecord()
    typed.record_uid = record_uid
    entry = vault.nsf_data.get_record(record_uid)
    if entry and getattr(entry, 'record_key', None):
        typed.record_key = entry.record_key
    typed.load_record_data({
        'type': meta.get('type') or '',
        'title': meta.get('title') or record_uid,
        'notes': meta.get('notes') or '',
        'fields': meta.get('fields') or [],
    })
    return typed


class KeeperRecord(vault_record.KeeperRecord):
    @staticmethod
    def load(params, rec: Union[str, Dict[str, Any]]) -> Optional[vault_record.KeeperRecord]:
        if isinstance(rec, dict):
            rec = rec.get('record_uid')
        if not isinstance(rec, str) or not rec:
            return None
        if params.vault is None:
            return None
        loaded = params.vault.vault_data.load_record(rec)
        if loaded:
            return loaded
        return _load_nsf_typed_record(params.vault, rec)

    @staticmethod
    def size_to_str(size):
        return vault_record.KeeperRecord.size_to_str(size) if hasattr(vault_record.KeeperRecord, 'size_to_str') else str(size)
