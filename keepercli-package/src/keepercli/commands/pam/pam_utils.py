"""Shared PAM CLI helpers for classic vault + NSF typed-record access."""

from typing import Iterator, Optional

from keepersdk.helpers.keeper_dag.constants import PAM_CONFIGURATIONS
from keepersdk.vault import (
    nsf_management,
    record_management,
    vault_extensions,
    vault_online,
    vault_record,
)

from .. import base
from ...helpers import record_utils
from ...params import KeeperParams


def resolve_nsf_record_uid(vault: vault_online.VaultOnline, identifier: str) -> Optional[str]:
    """Resolve an NSF record UID from a UID or exact title."""
    if not vault.nsf_data or not identifier:
        return None
    if vault.nsf_data.get_record(identifier):
        return identifier
    try:
        return nsf_management.resolve_nsf_record_uid(vault, identifier)
    except nsf_management.NsfError:
        return None


def load_nsf_typed_record(
        vault: vault_online.VaultOnline, record_uid: str) -> Optional[vault_record.TypedRecord]:
    """Load an NSF record as TypedRecord (with record_key when available)."""
    if not vault.nsf_data or not record_uid or not vault.nsf_data.get_record(record_uid):
        return None
    try:
        meta = nsf_management.load_nsf_record_metadata(vault, record_uid)
    except nsf_management.NsfError:
        return None
    typed = vault_record.TypedRecord()
    typed.record_uid = record_uid
    typed.load_record_data({
        'type': meta.get('type') or '',
        'title': meta.get('title') or record_uid,
        'notes': meta.get('notes') or '',
        'fields': meta.get('fields') or [],
        'custom': meta.get('custom') or [],
    })
    entry = vault.nsf_data.get_record(record_uid)
    if entry and entry.record_key:
        typed.record_key = entry.record_key
    return typed


def is_nsf_record(vault: vault_online.VaultOnline, record_uid: str) -> bool:
    return bool(record_uid and vault.nsf_data and vault.nsf_data.get_record(record_uid))


def attach_record_key(vault: vault_online.VaultOnline, record: vault_record.TypedRecord) -> None:
    """Ensure TypedRecord has record_key from classic or NSF storage when possible."""
    if getattr(record, 'record_key', None):
        return
    key = vault.vault_data.get_record_key(record.record_uid)
    if not key and vault.nsf_data:
        entry = vault.nsf_data.get_record(record.record_uid)
        if entry:
            key = entry.record_key
    if key:
        record.record_key = key


def load_typed_record(
        context: KeeperParams,
        identifier: str,
) -> Optional[vault_record.TypedRecord]:
    """Load a TypedRecord from classic vault or NSF by UID/path/title."""
    vault = context.vault
    if not vault or not identifier:
        return None
    loaded = vault.vault_data.load_record(identifier)
    if isinstance(loaded, vault_record.TypedRecord):
        return loaded
    record_info = record_utils.try_resolve_single_record(identifier, context)
    if record_info:
        loaded = vault.vault_data.load_record(record_info.record_uid)
        if isinstance(loaded, vault_record.TypedRecord):
            return loaded
    nsf_uid = resolve_nsf_record_uid(vault, identifier)
    if nsf_uid:
        return load_nsf_typed_record(vault, nsf_uid)
    return None


def load_pam_typed_record(
        vault: vault_online.VaultOnline, identifier: str) -> Optional[vault_record.TypedRecord]:
    """Load a TypedRecord from classic vault or NSF by UID/title (vault-only)."""
    if not identifier:
        return None
    loaded = vault.vault_data.load_record(identifier)
    if loaded and isinstance(loaded, vault_record.TypedRecord):
        attach_record_key(vault, loaded)
        return loaded
    nsf_uid = resolve_nsf_record_uid(vault, identifier)
    if nsf_uid:
        return load_nsf_typed_record(vault, nsf_uid)
    return None


def save_typed_record(vault: vault_online.VaultOnline, record: vault_record.TypedRecord) -> None:
    """Persist typed-record body changes via NSF or classic update."""
    if is_nsf_record(vault, record.record_uid):
        schema = vault.vault_data.get_record_type_by_name(record.record_type)
        record_data = vault_extensions.extract_typed_record_data(record, schema)
        try:
            nsf_management.update_nsf_record(
                vault,
                record.record_uid,
                title=record.title,
                record_type=record.record_type,
                record_data=record_data,
                request_sync=True,
            )
        except nsf_management.NsfError as err:
            raise base.CommandError(str(err)) from err
    else:
        record_management.update_record(vault, record)
    vault.sync_down()


def iter_nsf_pam_configurations(
        vault: vault_online.VaultOnline) -> Iterator[vault_record.TypedRecord]:
    """Yield NSF PAM configuration TypedRecords."""
    if not vault.nsf_data:
        return
    for entry in vault.nsf_data.records():
        typed = load_nsf_typed_record(vault, entry.record_uid)
        if typed and typed.record_type in PAM_CONFIGURATIONS:
            yield typed
