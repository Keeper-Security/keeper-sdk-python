"""One-time share operations for records."""

import dataclasses
import datetime
from typing import List, Optional, Union
from urllib.parse import urlunparse

from .. import crypto, utils
from ..proto.APIRequest_pb2 import AddExternalShareRequest, Device, RemoveAppClientsRequest
from . import ksm_management, vault_online


TIMESTAMP_MILLISECONDS_FACTOR = 1000
MAX_BATCH_SIZE = 1000
SIX_MONTHS_IN_SECONDS = 182 * 24 * 60 * 60
EXTERNAL_SHARE_ADD_URL = "vault/external_share_add"
REMOVE_EXTERNAL_SHARE_URL = "vault/external_share_remove"
KEEPER_SECRETS_MANAGER_CLIENT_ID = "KEEPER_SECRETS_MANAGER_CLIENT_ID"
TRUNCATE_SUFFIX = "..."


@dataclasses.dataclass
class OneTimeShare:
    """One-time share link for a record."""

    record_uid: str
    share_link_name: str
    share_link_id: str
    generated: Optional[datetime.datetime]
    expires: Optional[datetime.datetime]
    opened: Optional[datetime.datetime]
    accessed: Optional[datetime.datetime]
    status: str  # 'Expired' | 'Opened' | 'Generated'


def list_one_time_shares(
    vault: vault_online.VaultOnline,
    record_uid: Union[str, List[str]],
    include_expired: bool = False,
) -> List[OneTimeShare]:
    """
    List one-time shares for the given record UID(s).

    Args:
        vault: Initialized VaultOnline instance.
        record_uid: Single record UID (str) or list of record UIDs.
        include_expired: If True, include shares that have already expired.
            Default False returns only active or not-yet-opened shares.

    Returns:
        List of OneTimeShare instances.
    """
    if vault is None:
        raise ValueError("Vault is not initialized.")

    uids = [record_uid] if isinstance(record_uid, str) else list(record_uid)
    if not uids:
        return []

    if len(uids) > MAX_BATCH_SIZE:
        uids = uids[:MAX_BATCH_SIZE]

    app_infos = ksm_management.get_app_info(vault=vault, app_uid=uids)
    now = utils.current_milli_time()
    result: List[OneTimeShare] = []

    for app_info in app_infos:
        if not getattr(app_info, "isExternalShare", False):
            continue

        record_uid_str = utils.base64_url_encode(app_info.appRecordUid)

        for client in getattr(app_info, "clients", []):
            if not include_expired and now > getattr(client, "accessExpireOn", 0):
                continue

            _append_share_link(result, app_info, client, record_uid_str, now)

    return result


def _append_share_link(
    result: List[OneTimeShare],
    app_info,
    client,
    record_uid_str: str,
    now: int,
) -> None:
    """Build OneTimeShare from app_info/client and append to result."""
    created_ts = getattr(client, "createdOn", 0) or 0
    expires_ts = getattr(client, "accessExpireOn", 0) or 0
    first_access_ts = getattr(client, "firstAccess", 0) or 0
    last_access_ts = getattr(client, "lastAccess", 0) or 0

    if now > expires_ts:
        status = "Expired"
    elif first_access_ts > 0:
        status = "Opened"
    else:
        status = "Generated"

    result.append(
        OneTimeShare(
            record_uid=record_uid_str,
            share_link_name=getattr(client, "id", "") or "",
            share_link_id=utils.base64_url_encode(client.clientId),
            generated=_ms_to_datetime(created_ts),
            expires=_ms_to_datetime(expires_ts),
            opened=_ms_to_datetime(first_access_ts) if first_access_ts else None,
            accessed=_ms_to_datetime(last_access_ts) if last_access_ts else None,
            status=status,
        )
    )


def _ms_to_datetime(ms: int) -> Optional[datetime.datetime]:
    """Convert millisecond timestamp to datetime."""
    if not ms or ms <= 0:
        return None
    return datetime.datetime.fromtimestamp(ms / TIMESTAMP_MILLISECONDS_FACTOR)


def create_one_time_share(
    vault: vault_online.VaultOnline,
    record_uid: str,
    expiration_period: datetime.timedelta,
    name: Optional[str] = None,
    is_editable: bool = False,
    is_self_destruct: bool = False,
) -> str:
    """
    Create a one-time share URL for a record.

    Args:
        vault: Initialized VaultOnline instance.
        record_uid: Record UID to share.
        expiration_period: How long the share link is valid (e.g. timedelta(days=7)).
            Cannot exceed 6 months.
        name: Optional label for the share link.
        is_editable: If True, the recipient can edit the shared record.
        is_self_destruct: If True, the share is invalidated after first open.

    Returns:
        The one-time share URL (string). The recipient opens this URL to access the record.

    Raises:
        ValueError: If vault is not initialized, record is not found, or
            expiration_period exceeds 6 months.
    """
    if vault is None:
        raise ValueError("Vault is not initialized.")

    if expiration_period.total_seconds() > SIX_MONTHS_IN_SECONDS:
        raise ValueError(
            "Expiration period cannot be greater than 6 months."
        )

    record_key = vault.vault_data.get_record_key(record_uid=record_uid)
    if record_key is None:
        raise ValueError(f"Record not found: {record_uid}")

    client_key = utils.generate_aes_key()
    client_id = crypto.hmac_sha512(
        client_key, KEEPER_SECRETS_MANAGER_CLIENT_ID.encode()
    )

    request = AddExternalShareRequest()
    request.recordUid = utils.base64_url_decode(record_uid)
    request.encryptedRecordKey = crypto.encrypt_aes_v2(record_key, client_key)
    request.clientId = client_id
    request.accessExpireOn = utils.current_milli_time() + int(
        expiration_period.total_seconds() * 1000
    )
    if name:
        request.id = name
    request.isSelfDestruct = is_self_destruct
    request.isEditable = is_editable

    vault.keeper_auth.execute_auth_rest(
        rest_endpoint=EXTERNAL_SHARE_ADD_URL,
        request=request,
        response_type=Device,
    )

    server = vault.keeper_auth.keeper_endpoint.server
    url = urlunparse(
        (
            "https",
            server,
            "/vault/share",
            None,
            None,
            utils.base64_url_encode(client_key),
        )
    )
    return url


def remove_one_time_share(
    vault: vault_online.VaultOnline,
    record_uid: str,
    share_identifier: str,
) -> None:
    """
    Remove a one-time share for a record.

    Args:
        vault: Initialized VaultOnline instance.
        record_uid: Record UID that has the one-time share.
        share_identifier: One-time share name (client.id), full share link ID
            (base64-encoded client ID), or a unique prefix of the share link ID.

    Raises:
        ValueError: If vault is not initialized, no one-time shares exist for
            the record, no share matches the identifier, or multiple shares
            match a partial identifier.
    """
    if vault is None:
        raise ValueError("Vault is not initialized.")

    app_infos = ksm_management.get_app_info(vault=vault, app_uid=record_uid)
    if not app_infos:
        raise ValueError(
            f"There are no one-time shares for record {record_uid!r}."
        )

    client_id = _find_client_id(app_infos, share_identifier)
    if client_id is None:
        raise ValueError(
            f'No one-time share found matching {share_identifier!r} for record {record_uid!r}.'
        )

    request = RemoveAppClientsRequest()
    request.appRecordUid = utils.base64_url_decode(record_uid)
    request.clients.append(client_id)

    vault.keeper_auth.execute_auth_rest(
        request=request,
        rest_endpoint=REMOVE_EXTERNAL_SHARE_URL,
    )


def _find_client_id(app_infos, share_identifier: str) -> Optional[bytes]:
    """
    Resolve share name or ID to a single client ID (bytes).

    Matches by exact share name (client.id), exact base64 clientId, or
    unique prefix of base64 clientId.
    """
    cleaned = (
        share_identifier[: -len(TRUNCATE_SUFFIX)]
        if share_identifier.endswith(TRUNCATE_SUFFIX)
        else share_identifier
    )
    cleaned_lower = cleaned.lower()
    partial_matches: List[bytes] = []

    for app_info in app_infos:
        if not getattr(app_info, "isExternalShare", False):
            continue
        for client in getattr(app_info, "clients", []):
            if (getattr(client, "id", "") or "").lower() == cleaned_lower:
                return client.clientId
            encoded = utils.base64_url_encode(client.clientId)
            if encoded == cleaned:
                return client.clientId
            if encoded.startswith(cleaned):
                partial_matches.append(client.clientId)

    if not partial_matches:
        return None
    if len(partial_matches) == 1:
        return partial_matches[0]
    raise ValueError(
        f'Multiple one-time shares match {share_identifier!r}. Use a more specific identifier.'
    )

