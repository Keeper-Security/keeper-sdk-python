#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper SDK for Python
# Copyright 2026 Keeper Security Inc.
# Contact: commander@keepersecurity.com
#

from __future__ import annotations

import os
import re
from datetime import datetime
from typing import Any, Iterable, List, Optional, Sequence, Tuple

from ... import crypto, utils
from ...authentication import keeper_auth
from ...errors import KeeperApiError, KeeperError
from ...proto import GraphSync_pb2, workflow_pb2
from ...vault import nsf_management, vault_online, vault_record

logger = utils.get_logger()

WORKFLOW_SETTINGS_ENFORCEMENT_KEY = 'allow_configure_workflow_settings'
WORKFLOW_RECORD_TYPES = {
    'pamCloudResource', 'pamMachine', 'pamDirectory', 'pamDatabase', 'pamRemoteBrowser',
}

_PROTO_DUMP_RE = re.compile(
    r'\s*(?:type|value|name|stage|conditions|flowUid|resource)\s*:\s*(?:"[^"]*"|\S+)\s*',
)
_RESPONSE_CODE_RE = re.compile(r'\s*[Rr]esponse\s+code:\s*\S+\s*$')


class WorkflowError(KeeperError):
    """Raised when a PAM workflow operation cannot proceed."""


def post_to_router(
        vault: vault_online.VaultOnline,
        path: str,
        request: Optional[Any] = None,
        response_type: Optional[type] = None):
    """POST a protobuf request to the PAM router. Empty payloads return None."""
    try:
        rs = vault.keeper_auth.execute_router(path, request, response_type=response_type)
    except KeeperApiError as e:
        logger.error('Router call %s failed: %s', path, sanitize_router_error(e))
        raise
    if response_type is None:
        return rs
    if rs is None or not rs.ByteSize():
        return None
    return rs


def sanitize_router_error(error: Exception) -> str:
    msg = str(error)
    msg = _RESPONSE_CODE_RE.sub('', msg)
    msg = _PROTO_DUMP_RE.sub('', msg)
    msg = re.sub(r'\s+', ' ', msg).strip()
    return msg or 'Unknown error'


def refresh_enforcements(vault: vault_online.VaultOnline) -> None:
    """Reload account summary so role enforcements take effect without re-login."""
    from google.protobuf.json_format import MessageToDict
    try:
        rs = keeper_auth.load_account_summary(vault.keeper_auth)
        enf = MessageToDict(rs.Enforcements)
        bools = {x['key']: x.get('value', False) for x in enf.get('booleans', []) if 'key' in x}
        vault.keeper_auth.auth_context.enforcements.update(bools)
        if WORKFLOW_SETTINGS_ENFORCEMENT_KEY not in bools:
            vault.keeper_auth.auth_context.enforcements[WORKFLOW_SETTINGS_ENFORCEMENT_KEY] = False
    except Exception as e:
        logger.error('Failed to refresh enforcements: %s', e, exc_info=True)


def can_configure_workflow_settings(
        vault: vault_online.VaultOnline, *, refresh: bool = False) -> bool:
    """True when the user currently has allow_configure_workflow_settings."""
    if refresh:
        refresh_enforcements(vault)
    return bool(vault.keeper_auth.auth_context.enforcements.get(WORKFLOW_SETTINGS_ENFORCEMENT_KEY))


def ensure_can_configure_workflow_settings(
        vault: vault_online.VaultOnline, *, refresh: bool = True, action: str = 'manage') -> None:
    if can_configure_workflow_settings(vault, refresh=refresh):
        return
    raise WorkflowError(
        f'You do not have permission to manage workflow settings. '
        f'The "{action}" command requires the "Can manage workflow settings" '
        f'enforcement policy. Contact your Keeper administrator to enable this '
        f'for your role.'
    )


def get_record_key(vault: vault_online.VaultOnline, record_uid: str) -> Optional[bytes]:
    key = vault.vault_data.get_record_key(record_uid)
    if key:
        return key
    if vault.nsf_data:
        entry = vault.nsf_data.get_record(record_uid)
        if entry:
            return entry.record_key
    return None


def is_record_owner(vault: vault_online.VaultOnline, record_uid: str) -> bool:
    info = vault.vault_data.get_record(record_uid)
    if info and (info.flags & vault_record.RecordFlags.IsOwner):
        return True
    if vault.nsf and vault.nsf_data and vault.nsf_data.get_record(record_uid):
        account_uid = utils.base64_url_encode(vault.keeper_auth.auth_context.account_uid)
        for ra in vault.nsf.record_accesses.get_links_by_subject(record_uid):
            if ra.owner and ra.access_type_uid == account_uid:
                return True
    return False


def is_on_approver_list(vault: vault_online.VaultOnline, config) -> bool:
    if not config or not config.approvers:
        return False
    current_user = (vault.keeper_auth.auth_context.username or '').lower()
    team_uids = {t.team_uid for t in vault.vault_data.teams()}
    for approver in config.approvers:
        if approver.user and approver.user.lower() == current_user:
            return True
        if approver.teamUid:
            team_uid_b64 = utils.base64_url_encode(approver.teamUid)
            if team_uid_b64 in team_uids:
                return True
    return False


def is_workflow_exempt(vault: vault_online.VaultOnline, record_uid: str, config=None) -> bool:
    """Exempt = record owner OR on approver list. Transport failures fail closed."""
    if is_record_owner(vault, record_uid):
        return True
    if config is None:
        try:
            ref = ProtobufRefBuilder.record_ref(utils.base64_url_decode(record_uid), '')
            config = post_to_router(
                vault, 'read_workflow_config', request=ref, response_type=workflow_pb2.WorkflowConfig)
        except Exception as e:
            logger.debug('is_workflow_exempt config read failed for %s: %s', record_uid, e)
            return False
    return is_on_approver_list(vault, config)


def _load_nsf_typed_record(
        vault: vault_online.VaultOnline, record_uid: str) -> Optional[vault_record.TypedRecord]:
    if not vault.nsf_data or not vault.nsf_data.get_record(record_uid):
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


def load_typed_record(
        vault: vault_online.VaultOnline, identifier: str) -> Optional[vault_record.TypedRecord]:
    """Load a TypedRecord from classic vault or NSF by UID or exact title."""
    if not identifier:
        return None
    loaded = vault.vault_data.load_record(identifier)
    if isinstance(loaded, vault_record.TypedRecord):
        key = vault.vault_data.get_record_key(identifier)
        if key:
            loaded.record_key = key
        return loaded

    identifier_cf = identifier.casefold()
    matches: List[vault_record.TypedRecord] = []
    for info in vault.vault_data.records():
        if info.title.casefold() == identifier_cf:
            rec = vault.vault_data.load_record(info.record_uid)
            if isinstance(rec, vault_record.TypedRecord):
                key = vault.vault_data.get_record_key(info.record_uid)
                if key:
                    rec.record_key = key
                matches.append(rec)
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise WorkflowError(f'Multiple records match title "{identifier}"')

    if vault.nsf_data:
        try:
            nsf_uid = nsf_management.resolve_nsf_record_uid(vault, identifier)
        except nsf_management.NsfError:
            nsf_uid = None
        if nsf_uid:
            return _load_nsf_typed_record(vault, nsf_uid)
    return None


class RecordResolver:
    @staticmethod
    def resolve(
            vault: vault_online.VaultOnline,
            record_input: Optional[str],
            allow_missing: bool = False) -> Tuple[Optional[str], Optional[vault_record.TypedRecord]]:
        if not record_input:
            if allow_missing:
                return None, None
            raise WorkflowError('Record is required')
        rec = load_typed_record(vault, record_input)
        if rec:
            return rec.record_uid, rec
        if allow_missing:
            return None, None
        raise WorkflowError(f'Record "{record_input}" not found')

    @staticmethod
    def validate_workflow_record_type(record: vault_record.KeeperRecord) -> None:
        if not isinstance(record, vault_record.TypedRecord):
            raise WorkflowError('Workflows are only supported on PAM records')
        record_type = record.record_type or 'unknown'
        if record_type not in WORKFLOW_RECORD_TYPES:
            supported = ', '.join(sorted(WORKFLOW_RECORD_TYPES))
            raise WorkflowError(
                f'Record "{record.title}" is of type "{record_type}" which does not support workflows. '
                f'Supported record types: {supported}'
            )

    @staticmethod
    def resolve_name(vault: vault_online.VaultOnline, resource_ref) -> str:
        if resource_ref.name:
            return resource_ref.name
        if resource_ref.value:
            rec_uid = utils.base64_url_encode(resource_ref.value)
            rec = load_typed_record(vault, rec_uid)
            if rec:
                return rec.title
            info = vault.vault_data.get_record(rec_uid)
            if info:
                return info.title
        return ''

    @staticmethod
    def format_label(vault: vault_online.VaultOnline, resource_ref) -> str:
        rec_uid = utils.base64_url_encode(resource_ref.value) if resource_ref.value else ''
        rec_name = RecordResolver.resolve_name(vault, resource_ref)
        if rec_name and rec_name != rec_uid:
            return f'{rec_name} ({rec_uid})'
        return rec_uid or 'Unknown'

    @staticmethod
    def resolve_user(vault: vault_online.VaultOnline, user_id: int) -> str:
        for u in vault.vault_data.user_emails():
            if u.account_uid and u.account_uid == str(user_id):
                return u.username or f'User ID {user_id}'
        return f'User ID {user_id}'

    @staticmethod
    def resolve_team_name(vault: vault_online.VaultOnline, team_uid: str) -> str:
        team = vault.vault_data.get_team(team_uid)
        return team.name if team else ''

    @staticmethod
    def validate_team(vault: vault_online.VaultOnline, team_input: str) -> str:
        if vault.vault_data.get_team(team_input):
            return team_input
        for team in vault.vault_data.teams():
            if team.name.casefold() == team_input.casefold():
                return team.team_uid
        raise WorkflowError(f'Team "{team_input}" not found. Use a valid team UID or team name.')


class ProtobufRefBuilder:
    @staticmethod
    def record_ref(record_uid_bytes: bytes, record_name: str = '') -> GraphSync_pb2.GraphSyncRef:
        ref = GraphSync_pb2.GraphSyncRef()
        ref.type = GraphSync_pb2.RFT_REC
        ref.value = record_uid_bytes
        if record_name:
            ref.name = record_name
        return ref

    @staticmethod
    def workflow_ref(flow_uid_bytes: bytes) -> GraphSync_pb2.GraphSyncRef:
        ref = GraphSync_pb2.GraphSyncRef()
        ref.type = GraphSync_pb2.RFT_WORKFLOW
        ref.value = flow_uid_bytes
        return ref


class WorkflowFormatter:
    STAGE_MAP = {
        workflow_pb2.WS_READY_TO_START: 'Ready to Start',
        workflow_pb2.WS_STARTED: 'Started',
        workflow_pb2.WS_NEEDS_ACTION: 'Needs Action',
        workflow_pb2.WS_WAITING: 'Waiting',
    }

    CONDITION_MAP = {
        workflow_pb2.AC_APPROVAL: 'Approval Required',
        workflow_pb2.AC_CHECKIN: 'Check-in Required',
        workflow_pb2.AC_MFA: 'MFA Required',
        workflow_pb2.AC_TIME: 'Time Restriction',
        workflow_pb2.AC_REASON: 'Reason Required',
        workflow_pb2.AC_TICKET: 'Ticket Required',
    }

    DURATION_MULTIPLIERS = {'d': 86_400_000, 'h': 3_600_000, 'm': 60_000}

    DAY_PARSE_MAP = {
        'mon': workflow_pb2.MONDAY, 'monday': workflow_pb2.MONDAY,
        'tue': workflow_pb2.TUESDAY, 'tuesday': workflow_pb2.TUESDAY,
        'wed': workflow_pb2.WEDNESDAY, 'wednesday': workflow_pb2.WEDNESDAY,
        'thu': workflow_pb2.THURSDAY, 'thursday': workflow_pb2.THURSDAY,
        'fri': workflow_pb2.FRIDAY, 'friday': workflow_pb2.FRIDAY,
        'sat': workflow_pb2.SATURDAY, 'saturday': workflow_pb2.SATURDAY,
        'sun': workflow_pb2.SUNDAY, 'sunday': workflow_pb2.SUNDAY,
    }

    DAY_NAME_MAP = {
        workflow_pb2.MONDAY: 'Monday',
        workflow_pb2.TUESDAY: 'Tuesday',
        workflow_pb2.WEDNESDAY: 'Wednesday',
        workflow_pb2.THURSDAY: 'Thursday',
        workflow_pb2.FRIDAY: 'Friday',
        workflow_pb2.SATURDAY: 'Saturday',
        workflow_pb2.SUNDAY: 'Sunday',
    }

    BLOCKING_CONDITIONS = {workflow_pb2.AC_TIME, workflow_pb2.AC_APPROVAL}

    @staticmethod
    def format_stage(stage: int, status=None) -> str:
        if stage == workflow_pb2.WS_READY_TO_START and status is not None:
            if status.conditions:
                has_blocking = any(c in WorkflowFormatter.BLOCKING_CONDITIONS for c in status.conditions)
                if has_blocking:
                    return 'Waiting'
                return 'Ready to Start'
            if status.approvedBy and not status.startedOn:
                return 'Ready to Start'
            if not status.startedOn and not status.approvedBy:
                return 'Needs Action'
        return WorkflowFormatter.STAGE_MAP.get(stage, f'Unknown ({stage})')

    @staticmethod
    def format_conditions(conditions: Sequence[int]) -> str:
        return ', '.join(
            WorkflowFormatter.CONDITION_MAP.get(c, f'Unknown ({c})')
            for c in conditions
        )

    @staticmethod
    def parse_duration(duration_str: str) -> int:
        duration_str = duration_str.lower().strip()
        try:
            for suffix, factor in WorkflowFormatter.DURATION_MULTIPLIERS.items():
                if duration_str.endswith(suffix):
                    value = int(duration_str[:-1])
                    if value <= 0:
                        raise ValueError
                    return value * factor
            value = int(duration_str)
            if value <= 0:
                raise ValueError
            return value * 60_000
        except ValueError:
            raise WorkflowError(
                f'Invalid duration format: {duration_str}. '
                'Use a positive value like "2h", "30m", or "1d"'
            )

    @staticmethod
    def format_duration(milliseconds: int) -> str:
        seconds = milliseconds // 1000
        minutes = seconds // 60
        hours = minutes // 60
        days = hours // 24
        if days > 0:
            return f"{days} day{'s' if days != 1 else ''}"
        if hours > 0:
            return f"{hours} hour{'s' if hours != 1 else ''}"
        if minutes > 0:
            return f"{minutes} minute{'s' if minutes != 1 else ''}"
        return f"{seconds} second{'s' if seconds != 1 else ''}"

    @staticmethod
    def build_temporal_filter(allowed_days_str, time_range_str):
        if not allowed_days_str and not time_range_str:
            return None
        temporal = workflow_pb2.TemporalAccessFilter()
        if allowed_days_str:
            for day_token in allowed_days_str.split(','):
                day_token = day_token.strip().lower()
                day_enum = WorkflowFormatter.DAY_PARSE_MAP.get(day_token)
                if day_enum is None:
                    valid = ', '.join(sorted({k for k in WorkflowFormatter.DAY_PARSE_MAP if len(k) == 3}))
                    raise WorkflowError(f'Invalid day: "{day_token}". Valid: {valid}')
                temporal.allowedDays.append(day_enum)
        if time_range_str:
            if '-' not in time_range_str:
                raise WorkflowError('Time range must be in HH:MM-HH:MM format (e.g., "09:00-17:00")')
            start_str, end_str = time_range_str.split('-', 1)
            start_hhmm = WorkflowFormatter._parse_time_to_hhmm(start_str.strip())
            end_hhmm = WorkflowFormatter._parse_time_to_hhmm(end_str.strip())
            time_range = workflow_pb2.TimeOfDayRange()
            time_range.startTime = start_hhmm
            time_range.endTime = end_hhmm
            temporal.timeRanges.append(time_range)
        temporal.timeZone = WorkflowFormatter._get_local_iana_timezone()
        return temporal

    @staticmethod
    def _get_local_iana_timezone() -> str:
        tz = os.environ.get('TZ')
        if tz and '/' in tz:
            return tz
        try:
            from tzlocal import get_localzone_name
            zone = get_localzone_name()
            if zone:
                return zone
        except Exception as e:
            logger.debug('tzlocal lookup failed: %s', e)
        now = datetime.now().astimezone()
        key = getattr(now.tzinfo, 'key', None)
        if isinstance(key, str) and '/' in key:
            return key
        raise WorkflowError(
            'Could not detect local IANA timezone. '
            'Set the TZ environment variable (e.g., TZ=Asia/Kolkata).'
        )

    @staticmethod
    def _parse_time_to_hhmm(time_str: str) -> int:
        try:
            parts = time_str.split(':')
            h = int(parts[0])
            m = int(parts[1]) if len(parts) > 1 else 0
            if not (0 <= h <= 23 and 0 <= m <= 59):
                raise ValueError
            return h * 100 + m
        except (ValueError, IndexError):
            raise WorkflowError(f'Invalid time format: "{time_str}". Use HH:MM (e.g., "09:00")')

    @staticmethod
    def format_temporal_filter(at) -> Optional[dict]:
        if not at:
            return None
        result = {}
        if at.allowedDays:
            result['allowed_days'] = [WorkflowFormatter.DAY_NAME_MAP.get(d, str(d)) for d in at.allowedDays]
        if at.timeRanges:
            ranges = []
            for tr in at.timeRanges:
                sh, sm = divmod(tr.startTime, 100)
                eh, em = divmod(tr.endTime, 100)
                ranges.append(f'{sh:02d}:{sm:02d}-{eh:02d}:{em:02d}')
            result['time_ranges'] = ranges
        if at.timeZone:
            result['timezone'] = at.timeZone
        return result or None


def submit_access_request(
        vault: vault_online.VaultOnline,
        record_uid: str,
        record_name: str = '',
        reason: str = '',
        ticket: str = '') -> None:
    """Send a workflow access request. Reason/ticket are encrypted with the record key."""
    record_uid_bytes = utils.base64_url_decode(record_uid)
    record_key = None
    if reason or ticket:
        record_key = get_record_key(vault, record_uid)
        if not record_key:
            raise WorkflowError(
                'Record key not available — cannot encrypt reason/ticket. '
                'You do not have sufficient access to this record to send encrypted parameters.'
            )
    access_request = workflow_pb2.WorkflowAccessRequest()
    access_request.resource.CopyFrom(ProtobufRefBuilder.record_ref(record_uid_bytes, record_name))
    if reason:
        reason_bytes = reason.encode('utf-8') if isinstance(reason, str) else reason
        access_request.reason = crypto.encrypt_aes_v2(reason_bytes, record_key)
    if ticket:
        ticket_bytes = ticket.encode('utf-8') if isinstance(ticket, str) else ticket
        access_request.ticket = crypto.encrypt_aes_v2(ticket_bytes, record_key)
    post_to_router(vault, 'request_workflow_access', request=access_request)


def start_workflow_for_record(
        vault: vault_online.VaultOnline, record_uid: str, record_name: str = '') -> None:
    record_uid_bytes = utils.base64_url_decode(record_uid)
    state = workflow_pb2.WorkflowState()
    state.resource.CopyFrom(ProtobufRefBuilder.record_ref(record_uid_bytes, record_name))
    post_to_router(vault, 'start_workflow', request=state)


def add_approvers_to_workflow(
        vault: vault_online.VaultOnline,
        record_uid: str,
        record_name: str,
        users: Optional[Iterable[str]] = None,
        teams: Optional[Iterable[str]] = None,
        is_escalation: bool = False,
        escalation_after_ms: int = 0) -> None:
    record_uid_bytes = utils.base64_url_decode(record_uid)
    config = workflow_pb2.WorkflowConfig()
    config.parameters.resource.CopyFrom(ProtobufRefBuilder.record_ref(record_uid_bytes, record_name))
    for user_email in (users or []):
        approver = workflow_pb2.WorkflowApprover()
        approver.user = user_email
        approver.escalation = is_escalation
        if escalation_after_ms:
            approver.escalationAfterMs = escalation_after_ms
        config.approvers.append(approver)
    for team_input in (teams or []):
        resolved_team_uid = RecordResolver.validate_team(vault, team_input)
        approver = workflow_pb2.WorkflowApprover()
        approver.teamUid = utils.base64_url_decode(resolved_team_uid)
        approver.escalation = is_escalation
        if escalation_after_ms:
            approver.escalationAfterMs = escalation_after_ms
        config.approvers.append(approver)
    post_to_router(vault, 'add_workflow_approvers', request=config)


def workflow_state_to_dict(vault: vault_online.VaultOnline, wf) -> dict:
    st = wf.status
    return {
        'flow_uid': utils.base64_url_encode(wf.flowUid) if wf.flowUid else None,
        'record_uid': utils.base64_url_encode(wf.resource.value) if wf.resource.value else '',
        'record_name': RecordResolver.resolve_name(vault, wf.resource),
        'stage': WorkflowFormatter.format_stage(st.stage, st) if st else None,
        'conditions': (
            [WorkflowFormatter.format_conditions([c]) for c in st.conditions] if st and st.conditions else []
        ),
        'escalated': bool(st.escalated) if st else False,
        'checked_out_by': (st.checkedOutBy or None) if st else None,
        'can_force_checkin': bool(st.canForceCheckIn) if st else False,
        'started_on': (st.startedOn or None) if st else None,
        'expires_on': (st.expiresOn or None) if st else None,
        'approved_by': [
            {
                'user': a.user if a.user else RecordResolver.resolve_user(vault, a.userId),
                'approved_on': a.approvedOn or None,
            }
            for a in (st.approvedBy if st else [])
        ],
    }


def decrypt_workflow_param(
        vault: vault_online.VaultOnline, record_uid: str, encrypted_bytes) -> Optional[str]:
    if not encrypted_bytes:
        return None
    record_key = get_record_key(vault, record_uid)
    if not record_key:
        return 'No permission to view. Only users with record access can view this information.'
    try:
        return crypto.decrypt_aes_v2(encrypted_bytes, record_key).decode('utf-8')
    except Exception:
        logger.debug('Failed to decrypt workflow parameter for record %s', record_uid, exc_info=True)
        return 'Unable to decrypt'


def extract_workflow_param(wf, key: str):
    for p in wf.workflowParameters:
        if p.key == key:
            return p.data
    return None
