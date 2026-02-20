"""External (one-time) shares report for Keeper SDK.

Generates a report of all one-time share links (external shares) in the vault.
Useful for auditing and listing share-create / share-list style links across all records.

Usage:
    from keepersdk.vault import external_shares_report

    result = external_shares_report.run_external_shares_report(
        vault, include_expired=False, share_type='all'
    )
    for row in result.rows:
        print(row)
"""

import dataclasses
import datetime
from typing import Any, List, Optional

from . import vault_online, vault_record
from . import ksm_management, share_management_utils
from .. import utils


# Record versions that can have external shares (standard password/typed records)
SUPPORTED_RECORD_VERSIONS = (2, 3)

# Max record UIDs per get_app_info request (align with ksm_management / share-list)
MAX_BATCH_SIZE = 990

# Share type filter: direct = record has direct (user) shares; shared-folder = in a shared folder; all = both
SHARE_TYPE_ALL = 'all'
SHARE_TYPE_DIRECT = 'direct'
SHARE_TYPE_SHARED_FOLDER = 'shared-folder'

REPORT_HEADERS = [
    'record_uid',
    'record_title',
    'share_name',
    'share_link_id',
    'created',
    'expires',
    'first_opened',
    'status',
]

REPORT_TITLE = 'External Shares Report (One-Time Share Links)'


@dataclasses.dataclass
class ExternalSharesReportResult:
    """Result of running an external shares report."""

    rows: List[List[Any]]
    headers: List[str]
    report_title: str


def _get_record_uids_for_report(vault: vault_online.VaultOnline) -> List[str]:
    """Collect record UIDs that may have external shares (version 2 or 3)."""
    uids: List[str] = []
    for record_info in vault.vault_data.records():
        if record_info.version not in SUPPORTED_RECORD_VERSIONS:
            continue
        uids.append(record_info.record_uid)
    return uids


def _record_title(vault: vault_online.VaultOnline, record_uid: str) -> str:
    """Return record title for a given UID."""
    rec = vault.vault_data.get_record(record_uid=record_uid)
    return rec.title if rec else ''


def _record_share_type_mask(vault: vault_online.VaultOnline, record_uids: List[str]) -> dict:
    """Return dict record_uid -> (has_direct_share, has_shared_folder)."""
    if not record_uids:
        return {}
    try:
        shares_list = share_management_utils.get_record_shares(
            vault, record_uids, is_share_admin=False
        )
    except Exception:
        return {uid: (True, True) for uid in record_uids}

    mask = {}
    if shares_list:
        for rec in shares_list:
            uid = rec.get('record_uid')
            if not uid:
                continue
            shares = rec.get('shares') or {}
            up = shares.get('user_permissions') or []
            sfp = shares.get('shared_folder_permissions') or []
            has_direct = len(up) > 0
            has_sf = len(sfp) > 0
            mask[uid] = (has_direct, has_sf)
    for uid in record_uids:
        if uid not in mask:
            mask[uid] = (False, False)
    return mask


def _build_report_rows(
    vault: vault_online.VaultOnline,
    include_expired: bool,
    share_type: str = SHARE_TYPE_ALL,
) -> List[List[Any]]:
    """Fetch app info for all records and build report rows for external shares only."""
    record_uids = _get_record_uids_for_report(vault)
    if not record_uids:
        return []

    rows: List[List[Any]] = []
    now = utils.current_milli_time()

    for i in range(0, len(record_uids), MAX_BATCH_SIZE):
        batch = record_uids[i : i + MAX_BATCH_SIZE]
        app_infos = ksm_management.get_app_info(vault=vault, app_uid=batch)

        for app_info in app_infos:
            if not getattr(app_info, 'isExternalShare', False):
                continue

            record_uid = utils.base64_url_encode(app_info.appRecordUid)
            record_title = _record_title(vault, record_uid)

            for client in getattr(app_info, 'clients', []):
                if not include_expired and client.accessExpireOn and now > client.accessExpireOn:
                    continue

                created_ts = client.createdOn or 0
                expires_ts = client.accessExpireOn or 0
                first_opened_ts = getattr(client, 'firstAccess', 0) or 0

                created_dt = (
                    datetime.datetime.fromtimestamp(created_ts / 1000)
                    if created_ts else None
                )
                expires_dt = (
                    datetime.datetime.fromtimestamp(expires_ts / 1000)
                    if expires_ts else None
                )
                first_opened_dt = (
                    datetime.datetime.fromtimestamp(first_opened_ts / 1000)
                    if first_opened_ts else None
                )

                if now > expires_ts:
                    status = 'Expired'
                elif first_opened_ts > 0:
                    status = 'Opened'
                else:
                    status = 'Active'

                share_name = client.id if client.id else ''
                share_link_id = utils.base64_url_encode(client.clientId)

                rows.append([
                    record_uid,
                    record_title,
                    share_name,
                    share_link_id,
                    created_dt,
                    expires_dt,
                    first_opened_dt,
                    status,
                ])

    if share_type != SHARE_TYPE_ALL and rows:
        unique_uids = list({row[0] for row in rows})
        mask = _record_share_type_mask(vault, unique_uids)
        filtered = []
        for row in rows:
            uid = row[0]
            has_direct, has_sf = mask.get(uid, (False, False))
            if share_type == SHARE_TYPE_DIRECT and not has_direct:
                continue
            if share_type == SHARE_TYPE_SHARED_FOLDER and not has_sf:
                continue
            filtered.append(row)
        rows = filtered

    return rows


def run_external_shares_report(
    vault: vault_online.VaultOnline,
    include_expired: bool = False,
    share_type: str = SHARE_TYPE_ALL,
) -> ExternalSharesReportResult:
    """Generate a report of all external (one-time) share links in the vault.

    Args:
        vault: The VaultOnline instance (must be synced).
        include_expired: If True, include expired share links in the report.
        share_type: Filter by share type: 'direct', 'shared-folder', or 'all'.

    Returns:
        ExternalSharesReportResult with rows, headers, and report_title.
    """
    rows = _build_report_rows(
        vault,
        include_expired=include_expired,
        share_type=share_type,
    )
    return ExternalSharesReportResult(
        rows=rows,
        headers=list(REPORT_HEADERS),
        report_title=REPORT_TITLE,
    )
