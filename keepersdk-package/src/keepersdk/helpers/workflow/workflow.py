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

from typing import Iterable, List, Optional

from ... import crypto, utils
from ...enterprise import enterprise_types
from ...proto import GraphSync_pb2, workflow_pb2
from ...vault import vault_online, vault_record

from .helpers import (
    ROUTER_TRANSPORT_ERRORS,
    ProtobufRefBuilder,
    RecordResolver,
    WorkflowError,
    WorkflowFormatter,
    add_approvers_to_workflow,
    decrypt_workflow_param,
    ensure_can_configure_workflow_settings,
    extract_workflow_param,
    is_workflow_exempt,
    logger,
    post_to_router,
    sanitize_router_error,
    submit_access_request,
    workflow_state_to_dict,
)


def create_workflow(
        vault: vault_online.VaultOnline,
        record: str,
        *,
        approvals_needed: int = 1,
        checkout: bool = False,
        start_on_approval: bool = False,
        require_reason: bool = False,
        require_ticket: bool = False,
        require_mfa: bool = False,
        duration: str = '1d',
        allowed_days: Optional[str] = None,
        time_range: Optional[str] = None,
        approvers: Optional[Iterable[str]] = None) -> dict:
    """Create workflow configuration for a PAM record (`pam workflow create`)."""
    ensure_can_configure_workflow_settings(vault, refresh=True, action='create')
    record_uid, rec = RecordResolver.resolve(vault, record)
    RecordResolver.validate_workflow_record_type(rec)
    record_uid_bytes = utils.base64_url_decode(record_uid)

    try:
        existing = post_to_router(
            vault, 'read_workflow_config',
            request=ProtobufRefBuilder.record_ref(record_uid_bytes, rec.title),
            response_type=workflow_pb2.WorkflowConfig,
        )
    except Exception as e:
        logger.debug('Pre-check read_workflow_config failed: %s', e)
        existing = None
    if existing:
        raise WorkflowError(
            f'Workflow already configured for "{rec.title}" ({record_uid}). '
            'Use update_workflow to modify it, read_workflow to inspect it, '
            'or delete_workflow then create_workflow to recreate it.'
        )

    if approvals_needed < 0:
        raise WorkflowError('Approvals needed must be 0 or greater')

    approver_list = list(dict.fromkeys(
        a.strip() for a in (approvers or []) if a and a.strip()
    ))
    if approvals_needed > 0 and not approver_list:
        raise WorkflowError(
            'At least one approver is required when approvals_needed > 0. '
            'Pass approvers, or use approvals_needed=0 for a workflow that does not need approval.'
        )
    if approver_list and approvals_needed == 0:
        logger.warning(
            'approvers supplied but approvals_needed is 0 — approvers will '
            'be recorded but no approval will ever be required.'
        )

    parameters = workflow_pb2.WorkflowParameters()
    parameters.resource.CopyFrom(ProtobufRefBuilder.record_ref(record_uid_bytes, rec.title))
    parameters.approvalsNeeded = approvals_needed
    parameters.checkoutNeeded = checkout
    parameters.startAccessOnApproval = start_on_approval
    parameters.requireReason = require_reason
    parameters.requireTicket = require_ticket
    parameters.requireMFA = require_mfa
    parameters.accessLength = WorkflowFormatter.parse_duration(duration)
    temporal_filter = WorkflowFormatter.build_temporal_filter(allowed_days, time_range)
    if temporal_filter:
        parameters.allowedTimes.CopyFrom(temporal_filter)

    try:
        post_to_router(vault, 'create_workflow_config', request=parameters)
        approvers_added: List[str] = []
        if approver_list:
            try:
                add_approvers_to_workflow(vault, record_uid, rec.title, users=approver_list)
                approvers_added = list(approver_list)
            except Exception as e:
                logger.warning(
                    'Workflow created, but failed to add approvers: %s. '
                    'Call add_workflow_approvers for record %s.',
                    sanitize_router_error(e), record_uid,
                )

        result = {
            'status': 'success',
            'record_uid': record_uid,
            'record_name': rec.title,
            'workflow_config': {
                'approvals_needed': parameters.approvalsNeeded,
                'checkout_needed': parameters.checkoutNeeded,
                'require_reason': parameters.requireReason,
                'require_ticket': parameters.requireTicket,
                'require_mfa': parameters.requireMFA,
                'access_duration': WorkflowFormatter.format_duration(parameters.accessLength),
            },
            'approvers': approvers_added,
        }
        logger.info('Workflow created for %s (%s)', rec.title, record_uid)
        return result
    except WorkflowError:
        raise
    except ROUTER_TRANSPORT_ERRORS as e:
        raise WorkflowError(f'Failed to create workflow: {sanitize_router_error(e)}') from e


def read_workflow(
        vault: vault_online.VaultOnline,
        record: str,
        enterprise_data: Optional[enterprise_types.IEnterpriseData] = None) -> dict:
    """Read workflow configuration (`pam workflow read`)."""
    record_uid, rec = RecordResolver.resolve(vault, record)
    record_uid_bytes = utils.base64_url_decode(record_uid)
    ref = ProtobufRefBuilder.record_ref(record_uid_bytes, rec.title)
    try:
        response = post_to_router(
            vault, 'read_workflow_config', request=ref, response_type=workflow_pb2.WorkflowConfig)
        if not response:
            logger.warning('No workflow configured for record %s (%s)', rec.title, record_uid)
            return {
                'status': 'no_workflow',
                'message': 'No workflow configured',
                'record_uid': record_uid,
                'record_name': rec.title,
            }
        p = response.parameters
        result = {
            'status': 'success',
            'record_uid': record_uid,
            'record_name': RecordResolver.resolve_name(vault, p.resource) or rec.title,
            'created_on': response.createdOn or None,
            'parameters': {
                'approvals_needed': p.approvalsNeeded,
                'checkout_needed': p.checkoutNeeded,
                'start_access_on_approval': p.startAccessOnApproval,
                'require_reason': p.requireReason,
                'require_ticket': p.requireTicket,
                'require_mfa': p.requireMFA,
                'access_duration': WorkflowFormatter.format_duration(p.accessLength),
                'allowed_times': WorkflowFormatter.format_temporal_filter(p.allowedTimes),
            },
            'approvers': [],
        }
        for approver in response.approvers:
            approver_info = {'escalation': approver.escalation}
            if approver.escalationAfterMs:
                approver_info['escalation_after'] = WorkflowFormatter.format_duration(approver.escalationAfterMs)
            if approver.HasField('user'):
                approver_info['type'] = 'user'
                approver_info['email'] = approver.user
            elif approver.HasField('userId'):
                approver_info['type'] = 'user_id'
                approver_info['user_id'] = approver.userId
                approver_info['email'] = RecordResolver.resolve_user(vault, approver.userId, enterprise_data)
            elif approver.HasField('teamUid'):
                team_uid = utils.base64_url_encode(approver.teamUid)
                approver_info['type'] = 'team'
                approver_info['team_uid'] = team_uid
                approver_info['team_name'] = RecordResolver.resolve_team_name(vault, team_uid, enterprise_data)
            result['approvers'].append(approver_info)
        if not result['approvers']:
            logger.warning('No approvers configured for record %s', record_uid)
        logger.info('Read workflow configuration for %s (%s)', rec.title, record_uid)
        return result
    except WorkflowError:
        raise
    except ROUTER_TRANSPORT_ERRORS as e:
        raise WorkflowError(f'Failed to read workflow: {sanitize_router_error(e)}') from e


def update_workflow(
        vault: vault_online.VaultOnline,
        record: str,
        *,
        approvals_needed: Optional[int] = None,
        checkout: Optional[bool] = None,
        start_on_approval: Optional[bool] = None,
        require_reason: Optional[bool] = None,
        require_ticket: Optional[bool] = None,
        require_mfa: Optional[bool] = None,
        duration: Optional[str] = None,
        allowed_days: Optional[str] = None,
        time_range: Optional[str] = None) -> dict:
    """Update existing workflow configuration (`pam workflow update`). Unspecified fields are kept."""
    ensure_can_configure_workflow_settings(vault, refresh=True, action='update')
    record_uid, rec = RecordResolver.resolve(vault, record)
    record_uid_bytes = utils.base64_url_decode(record_uid)
    try:
        ref = ProtobufRefBuilder.record_ref(record_uid_bytes, rec.title)
        current_config = post_to_router(
            vault, 'read_workflow_config', request=ref, response_type=workflow_pb2.WorkflowConfig)
        if not current_config:
            raise WorkflowError('No workflow found for record. Create one first with create_workflow.')

        parameters = workflow_pb2.WorkflowParameters()
        parameters.CopyFrom(current_config.parameters)
        updates = {
            'approvalsNeeded': approvals_needed,
            'checkoutNeeded': checkout,
            'startAccessOnApproval': start_on_approval,
            'requireReason': require_reason,
            'requireTicket': require_ticket,
            'requireMFA': require_mfa,
        }
        if approvals_needed is not None and approvals_needed < 0:
            raise WorkflowError('Approvals needed must be 0 or greater')

        updates_provided = False
        for proto_field, value in updates.items():
            if value is not None:
                setattr(parameters, proto_field, value)
                updates_provided = True
        if duration is not None:
            parameters.accessLength = WorkflowFormatter.parse_duration(duration)
            updates_provided = True
        temporal_filter = WorkflowFormatter.build_temporal_filter(allowed_days, time_range)
        if temporal_filter:
            parameters.allowedTimes.CopyFrom(temporal_filter)
            updates_provided = True
        if not updates_provided:
            raise WorkflowError(
                'No updates provided. Specify at least one option to update '
                '(e.g., approvals_needed, duration).'
            )
        post_to_router(vault, 'update_workflow_config', request=parameters)
        logger.info('Workflow updated for %s (%s)', rec.title, record_uid)
        return {'status': 'success', 'record_uid': record_uid, 'record_name': rec.title}
    except WorkflowError:
        raise
    except ROUTER_TRANSPORT_ERRORS as e:
        raise WorkflowError(f'Failed to update workflow: {sanitize_router_error(e)}') from e


def delete_workflow(vault: vault_online.VaultOnline, record: str) -> dict:
    """Delete workflow configuration from a record (`pam workflow delete`)."""
    ensure_can_configure_workflow_settings(vault, refresh=True, action='delete')
    record_uid, rec = RecordResolver.resolve(vault, record)
    record_uid_bytes = utils.base64_url_decode(record_uid)
    ref = ProtobufRefBuilder.record_ref(record_uid_bytes, rec.title)
    try:
        existing = post_to_router(
            vault, 'read_workflow_config', request=ref, response_type=workflow_pb2.WorkflowConfig)
    except Exception as e:
        logger.debug('Pre-check read_workflow_config failed: %s', e)
        existing = None
    if not existing:
        raise WorkflowError(
            f'No workflow configured for "{rec.title}" ({record_uid}). Nothing to delete.'
        )
    try:
        post_to_router(vault, 'delete_workflow_config', request=ref)
        logger.info('Workflow deleted for %s (%s)', rec.title, record_uid)
        return {'status': 'success', 'record_uid': record_uid, 'record_name': rec.title}
    except WorkflowError:
        raise
    except ROUTER_TRANSPORT_ERRORS as e:
        raise WorkflowError(f'Failed to delete workflow: {sanitize_router_error(e)}') from e


def add_workflow_approvers(
        vault: vault_online.VaultOnline,
        record: str,
        *,
        users: Optional[Iterable[str]] = None,
        teams: Optional[Iterable[str]] = None,
        escalation: bool = False,
        escalation_after: Optional[str] = None,
        enterprise_data: Optional[enterprise_types.IEnterpriseData] = None) -> dict:
    """Add approvers to a workflow (`pam workflow add-approver`)."""
    ensure_can_configure_workflow_settings(vault, refresh=True, action='add-approver')
    user_list = list(dict.fromkeys(u.strip() for u in (users or []) if u and u.strip()))
    team_list = list(dict.fromkeys(t.strip() for t in (teams or []) if t and t.strip()))
    if not user_list and not team_list:
        raise WorkflowError('Must specify at least one user or team')
    if escalation_after and not escalation:
        raise WorkflowError('escalation_after requires escalation=True')
    escalation_after_ms = WorkflowFormatter.parse_duration(escalation_after) if escalation_after else 0
    record_uid, rec = RecordResolver.resolve(vault, record)
    try:
        add_approvers_to_workflow(
            vault, record_uid, rec.title,
            users=user_list, teams=team_list,
            is_escalation=escalation, escalation_after_ms=escalation_after_ms,
            enterprise_data=enterprise_data,
        )
        total = len(user_list) + len(team_list)
        result = {
            'status': 'success',
            'record_uid': record_uid,
            'record_name': rec.title,
            'approvers_added': total,
            'escalation': escalation,
            'users': user_list,
            'teams': team_list,
        }
        if escalation_after_ms:
            result['escalation_after'] = WorkflowFormatter.format_duration(escalation_after_ms)
        logger.info('Added %s approver(s) to %s (%s)', total, rec.title, record_uid)
        return result
    except WorkflowError:
        raise
    except ROUTER_TRANSPORT_ERRORS as e:
        raise WorkflowError(f'Failed to add approvers: {sanitize_router_error(e)}') from e


def remove_workflow_approvers(
        vault: vault_online.VaultOnline,
        record: str,
        *,
        users: Optional[Iterable[str]] = None,
        teams: Optional[Iterable[str]] = None,
        enterprise_data: Optional[enterprise_types.IEnterpriseData] = None) -> dict:
    """Remove approvers from a workflow (`pam workflow remove-approver`)."""
    ensure_can_configure_workflow_settings(vault, refresh=True, action='remove-approver')
    user_list = list(dict.fromkeys(u.strip() for u in (users or []) if u and u.strip()))
    team_list = list(dict.fromkeys(t.strip() for t in (teams or []) if t and t.strip()))
    if not user_list and not team_list:
        raise WorkflowError('Must specify at least one user or team')
    record_uid, rec = RecordResolver.resolve(vault, record)
    record_uid_bytes = utils.base64_url_decode(record_uid)
    config = workflow_pb2.WorkflowConfig()
    config.parameters.resource.CopyFrom(ProtobufRefBuilder.record_ref(record_uid_bytes, rec.title))
    for user_email in user_list:
        approver = workflow_pb2.WorkflowApprover()
        approver.user = user_email
        config.approvers.append(approver)
    for team_input in team_list:
        resolved_team_uid = RecordResolver.validate_team(vault, team_input, enterprise_data)
        approver = workflow_pb2.WorkflowApprover()
        approver.teamUid = utils.base64_url_decode(resolved_team_uid)
        config.approvers.append(approver)
    try:
        post_to_router(vault, 'delete_workflow_approvers', request=config)
        total = len(user_list) + len(team_list)
        logger.info('Removed %s approver(s) from %s (%s)', total, rec.title, record_uid)
        return {
            'status': 'success',
            'record_uid': record_uid,
            'record_name': rec.title,
            'approvers_removed': total,
        }
    except WorkflowError:
        raise
    except ROUTER_TRANSPORT_ERRORS as e:
        raise WorkflowError(f'Failed to remove approvers: {sanitize_router_error(e)}') from e


def get_pending_approvals(
        vault: vault_online.VaultOnline,
        enterprise_data: Optional[enterprise_types.IEnterpriseData] = None) -> dict:
    """Get pending approval requests (`pam workflow pending`)."""
    try:
        response = post_to_router(
            vault, 'get_approval_requests', response_type=workflow_pb2.ApprovalRequests)
        if not response or not response.workflows:
            logger.info('No approval requests')
            return {'status': 'success', 'requests': []}

        seen_flows = set()
        unique = []
        for wf in response.workflows:
            fuid = bytes(wf.flowUid)
            if fuid not in seen_flows:
                seen_flows.add(fuid)
                unique.append(wf)

        current_user = vault.keeper_auth.auth_context.username
        pending = [wf for wf in unique if not _already_approved_by_me(vault, wf, current_user)]
        if not pending:
            logger.info('No pending approval requests')
            return {'status': 'success', 'requests': []}

        requests = []
        for wf in pending:
            rec_uid = utils.base64_url_encode(wf.resource.value) if wf.resource.value else ''
            requested_by = wf.user or RecordResolver.resolve_user(vault, wf.userId, enterprise_data)
            requests.append({
                'flow_uid': utils.base64_url_encode(wf.flowUid),
                'requested_by': requested_by,
                'record_uid': rec_uid,
                'record_name': RecordResolver.resolve_name(vault, wf.resource),
                'started_on': wf.startedOn or None,
                'expires_on': wf.expiresOn or None,
                'escalated': wf.escalated,
                'duration': (
                    WorkflowFormatter.format_duration(wf.expiresOn - wf.startedOn)
                    if wf.expiresOn and wf.startedOn else None
                ),
                'reason': decrypt_workflow_param(vault, rec_uid, extract_workflow_param(wf, 'reason')),
                'ticket': decrypt_workflow_param(vault, rec_uid, extract_workflow_param(wf, 'ticket')),
            })
        logger.info('Found %s pending approval request(s)', len(requests))
        return {'status': 'success', 'requests': requests}
    except WorkflowError:
        raise
    except ROUTER_TRANSPORT_ERRORS as e:
        raise WorkflowError(f'Failed to get approval requests: {sanitize_router_error(e)}') from e


def _already_approved_by_me(vault: vault_online.VaultOnline, wf, current_user: str) -> bool:
    try:
        st = workflow_pb2.WorkflowState()
        st.flowUid = wf.flowUid
        ws = post_to_router(
            vault, 'get_workflow_state', request=st, response_type=workflow_pb2.WorkflowState)
        if ws and ws.status and ws.status.approvedBy:
            for a in ws.status.approvedBy:
                if a.user == current_user:
                    return True
    except Exception:
        logger.debug('Failed to check approval status for flow', exc_info=True)
    return False


def approve_workflow(vault: vault_online.VaultOnline, flow_uid: str) -> dict:
    """Approve a workflow access request (`pam workflow approve`)."""
    try:
        flow_uid_bytes = utils.base64_url_decode(flow_uid)
    except (ValueError, TypeError) as e:
        raise WorkflowError(f'Invalid flow UID: "{flow_uid}"') from e
    approval = workflow_pb2.WorkflowApprovalOrDenial()
    approval.flowUid = flow_uid_bytes
    approval.deny = False
    try:
        post_to_router(vault, 'approve_or_deny_workflow_access', request=approval)
        logger.info('Access request approved for flow %s', flow_uid)
        return {'status': 'success', 'flow_uid': flow_uid, 'action': 'approved'}
    except WorkflowError:
        raise
    except ROUTER_TRANSPORT_ERRORS as e:
        raise WorkflowError(f'Failed to approve request: {sanitize_router_error(e)}') from e


def deny_workflow(
        vault: vault_online.VaultOnline,
        flow_uid: str,
        *,
        reason: Optional[str] = None,
        enterprise_data: Optional[enterprise_types.IEnterpriseData] = None) -> dict:
    """Deny a workflow access request (`pam workflow deny`)."""
    reason = reason or ''
    try:
        flow_uid_bytes = utils.base64_url_decode(flow_uid)
    except (ValueError, TypeError) as e:
        raise WorkflowError(f'Invalid flow UID: "{flow_uid}"') from e
    denial = workflow_pb2.WorkflowApprovalOrDenial()
    denial.flowUid = flow_uid_bytes
    denial.deny = True
    if reason:
        encrypted = _encrypt_denial_reason(vault, flow_uid_bytes, reason.encode('utf-8'), enterprise_data)
        if encrypted:
            denial.denialReason = encrypted
        else:
            logger.warning(
                'Could not encrypt denial reason for the requester — reason will not be attached. '
                'The denial itself will still be sent.'
            )
            reason = ''
    try:
        post_to_router(vault, 'approve_or_deny_workflow_access', request=denial)
        result = {'status': 'success', 'flow_uid': flow_uid, 'action': 'denied'}
        if reason:
            result['reason'] = reason
        logger.info('Access request denied for flow %s', flow_uid)
        return result
    except WorkflowError:
        raise
    except ROUTER_TRANSPORT_ERRORS as e:
        raise WorkflowError(f'Failed to deny request: {sanitize_router_error(e)}') from e


def _encrypt_denial_reason(
        vault: vault_online.VaultOnline,
        flow_uid_bytes: bytes,
        reason_bytes: bytes,
        enterprise_data: Optional[enterprise_types.IEnterpriseData] = None):
    try:
        response = post_to_router(
            vault, 'get_approval_requests', response_type=workflow_pb2.ApprovalRequests)
        if not response or not response.workflows:
            return None
        requester_email = None
        for wf in response.workflows:
            if wf.flowUid == flow_uid_bytes:
                requester_email = wf.user or RecordResolver.resolve_user(vault, wf.userId, enterprise_data)
                break
        if not requester_email or requester_email.startswith('User ID '):
            logger.debug('Could not resolve requester email for flow UID')
            return None
        vault.keeper_auth.load_user_public_keys([requester_email])
        public_keys = vault.keeper_auth.get_user_keys(requester_email)
        if not public_keys:
            logger.debug('Public key not available for %s', requester_email)
            return None
        if public_keys.ec:
            return crypto.encrypt_ec(reason_bytes, crypto.load_ec_public_key(public_keys.ec))
        if public_keys.rsa:
            return crypto.encrypt_rsa(reason_bytes, crypto.load_rsa_public_key(public_keys.rsa))
    except Exception:
        logger.debug('Failed to encrypt denial reason with requester public key', exc_info=True)
    return None


def request_workflow_access(
        vault: vault_online.VaultOnline,
        record: str,
        *,
        reason: str = '',
        ticket: str = '',
        escalate: bool = False,
        cancel: bool = False) -> dict:
    """Request, escalate, or cancel access (`pam workflow request`)."""
    if cancel and escalate:
        raise WorkflowError('cancel and escalate cannot be used together')
    if cancel and (reason or ticket):
        raise WorkflowError('cancel cannot be used with reason or ticket')
    if cancel:
        return _cancel_access_request(vault, record)
    if escalate:
        return _escalate_access_request(vault, record)
    return _submit_access_request(vault, record, reason=reason, ticket=ticket)


def _submit_access_request(
        vault: vault_online.VaultOnline, record: str, *, reason: str, ticket: str) -> dict:
    record_uid, rec = RecordResolver.resolve(vault, record)
    RecordResolver.validate_workflow_record_type(rec)
    if is_workflow_exempt(vault, record_uid):
        logger.warning(
            'You are exempt from workflow restrictions on this record. '
            'As a record owner or approver, you can access this resource directly.'
        )
        return {'status': 'exempt', 'message': 'Workflow not required', 'record_uid': record_uid}
    try:
        submit_access_request(vault, record_uid, rec.title, reason=reason, ticket=ticket)
        result = {
            'status': 'success',
            'record_uid': record_uid,
            'record_name': rec.title,
            'message': 'Access request sent to approvers',
        }
        if reason:
            result['reason'] = reason
        if ticket:
            result['ticket'] = ticket
        logger.info('Access request sent for %s (%s)', rec.title, record_uid)
        return result
    except WorkflowError:
        raise
    except ROUTER_TRANSPORT_ERRORS as e:
        raise WorkflowError(f'Failed to request access: {sanitize_router_error(e)}') from e


def _escalate_access_request(vault: vault_online.VaultOnline, record: str) -> dict:
    record_uid, rec = RecordResolver.resolve(vault, record)
    if is_workflow_exempt(vault, record_uid):
        logger.warning(
            'You are exempt from workflow restrictions on this record. '
            'As a record owner or approver, you can access this resource directly.'
        )
        return {'status': 'exempt', 'message': 'Workflow not required', 'record_uid': record_uid}
    record_uid_bytes = utils.base64_url_decode(record_uid)
    state = workflow_pb2.WorkflowState()
    state.resource.CopyFrom(ProtobufRefBuilder.record_ref(record_uid_bytes, rec.title))
    try:
        post_to_router(vault, 'request_escalation', request=state)
        logger.info('Request escalated for %s (%s)', rec.title, record_uid)
        return {
            'status': 'success',
            'record_uid': record_uid,
            'record_name': rec.title,
            'action': 'escalated',
        }
    except WorkflowError:
        raise
    except ROUTER_TRANSPORT_ERRORS as e:
        raise WorkflowError(f'Failed to escalate request: {sanitize_router_error(e)}') from e


def _cancel_access_request(vault: vault_online.VaultOnline, record: str) -> dict:
    record_uid, rec = RecordResolver.resolve(vault, record)
    record_uid_bytes = utils.base64_url_decode(record_uid)
    try:
        state_query = workflow_pb2.WorkflowState()
        state_query.resource.CopyFrom(
            ProtobufRefBuilder.record_ref(record_uid_bytes, rec.title if rec else '')
        )
        workflow_state = post_to_router(
            vault, 'get_workflow_state',
            request=state_query, response_type=workflow_pb2.WorkflowState,
        )
        if not workflow_state or not workflow_state.flowUid:
            raise WorkflowError('No active workflow request found for this record.')
        flow_ref = ProtobufRefBuilder.workflow_ref(workflow_state.flowUid)
        post_to_router(vault, 'end_workflow', request=flow_ref)
        flow_uid_str = utils.base64_url_encode(workflow_state.flowUid)
        logger.info('Workflow request cancelled for %s (%s)', rec.title, record_uid)
        return {
            'status': 'success',
            'record_uid': record_uid,
            'record_name': rec.title,
            'flow_uid': flow_uid_str,
            'action': 'cancelled',
        }
    except WorkflowError:
        raise
    except ROUTER_TRANSPORT_ERRORS as e:
        raise WorkflowError(f'Failed to cancel request: {sanitize_router_error(e)}') from e


def start_workflow(vault: vault_online.VaultOnline, uid: str) -> dict:
    """Start a workflow / check-out (`pam workflow start`). Accepts record UID/name or flow UID."""
    record_uid, rec = RecordResolver.resolve(vault, uid, allow_missing=True)
    state = workflow_pb2.WorkflowState()
    if record_uid:
        record_uid_bytes = utils.base64_url_decode(record_uid)
        state.resource.CopyFrom(ProtobufRefBuilder.record_ref(record_uid_bytes, rec.title))
    else:
        try:
            uid_bytes = utils.base64_url_decode(uid)
        except (ValueError, TypeError) as e:
            raise WorkflowError(f'"{uid}" is not a valid record UID/name or flow UID') from e
        state.flowUid = uid_bytes
        state.resource.CopyFrom(ProtobufRefBuilder.workflow_ref(uid_bytes))
    try:
        post_to_router(vault, 'start_workflow', request=state)
        result = {'status': 'success', 'action': 'checked_out'}
        if rec:
            result['record_uid'] = record_uid
            result['record_name'] = rec.title
            logger.info('Workflow started (checked out) for %s (%s)', rec.title, record_uid)
        else:
            result['flow_uid'] = uid
            logger.info('Workflow started (checked out) for flow %s', uid)
        return result
    except WorkflowError:
        raise
    except ROUTER_TRANSPORT_ERRORS as e:
        raise WorkflowError(f'Failed to start workflow: {sanitize_router_error(e)}') from e


def end_workflow(vault: vault_online.VaultOnline, uid: str, *, force: bool = False) -> dict:
    """End a workflow / check-in (`pam workflow end`). force=True allows approver force check-in."""
    if force:
        return _force_checkin(vault, uid)
    record_uid, rec = RecordResolver.resolve(vault, uid, allow_missing=True)
    if record_uid:
        return _end_by_record(vault, record_uid, rec)
    return _end_by_flow_uid(vault, uid)


def _force_checkin(vault: vault_online.VaultOnline, uid: str) -> dict:
    if not uid or not uid.strip():
        raise WorkflowError('Record UID, record name, or Flow UID is required')
    record_uid, rec = RecordResolver.resolve(vault, uid, allow_missing=True)
    if record_uid:
        ref = GraphSync_pb2.GraphSyncRef()
        ref.type = GraphSync_pb2.RFT_REC
        ref.value = utils.base64_url_decode(record_uid)
        if rec:
            ref.name = rec.title
    else:
        try:
            uid_bytes = utils.base64_url_decode(uid)
        except (ValueError, TypeError) as e:
            raise WorkflowError(f'"{uid}" is not a valid record UID/name or flow UID') from e
        ref = GraphSync_pb2.GraphSyncRef()
        ref.type = GraphSync_pb2.RFT_WORKFLOW
        ref.value = uid_bytes
    try:
        post_to_router(vault, 'force_checkin', request=ref)
        result = {'status': 'success', 'action': 'force_checkin'}
        if record_uid:
            result['record_uid'] = record_uid
            result['record_name'] = rec.title if rec else ''
            logger.info('Record force checked in: %s (%s)', rec.title if rec else '', record_uid)
        else:
            result['flow_uid'] = uid
            logger.info('Record force checked in for flow %s', uid)
        return result
    except WorkflowError:
        raise
    except ROUTER_TRANSPORT_ERRORS as e:
        raise WorkflowError(f'Failed to force check-in: {sanitize_router_error(e)}') from e


def _end_by_record(
        vault: vault_online.VaultOnline,
        record_uid: str,
        rec: Optional[vault_record.TypedRecord]) -> dict:
    try:
        state_query = workflow_pb2.WorkflowState()
        state_query.resource.CopyFrom(
            ProtobufRefBuilder.record_ref(
                utils.base64_url_decode(record_uid), rec.title if rec else '')
        )
        workflow_state = post_to_router(
            vault, 'get_workflow_state',
            request=state_query, response_type=workflow_pb2.WorkflowState,
        )
        if not workflow_state or not workflow_state.flowUid:
            raise WorkflowError(
                'No active workflow found for this record. '
                'The workflow may have already ended or never started.'
            )
        flow_ref = ProtobufRefBuilder.workflow_ref(workflow_state.flowUid)
        post_to_router(vault, 'end_workflow', request=flow_ref)
        flow_uid_str = utils.base64_url_encode(workflow_state.flowUid)
        logger.info(
            'Workflow ended (checked in) for %s (%s). Credentials may have been rotated.',
            rec.title if rec else record_uid, record_uid,
        )
        return {
            'status': 'success',
            'flow_uid': flow_uid_str,
            'record_uid': record_uid,
            'record_name': rec.title if rec else '',
            'action': 'ended',
        }
    except WorkflowError:
        raise
    except ROUTER_TRANSPORT_ERRORS as e:
        raise WorkflowError(f'Failed to end workflow: {sanitize_router_error(e)}') from e


def _end_by_flow_uid(vault: vault_online.VaultOnline, uid: str) -> dict:
    try:
        uid_bytes = utils.base64_url_decode(uid)
        ref = ProtobufRefBuilder.workflow_ref(uid_bytes)
        post_to_router(vault, 'end_workflow', request=ref)
        logger.info('Workflow ended (checked in) for flow %s. Credentials may have been rotated.', uid)
        return {'status': 'success', 'flow_uid': uid, 'action': 'ended'}
    except WorkflowError:
        raise
    except (ValueError, TypeError) as e:
        raise WorkflowError(f'"{uid}" is not a valid flow UID') from e
    except ROUTER_TRANSPORT_ERRORS as e:
        raise WorkflowError(f'Failed to end workflow: {sanitize_router_error(e)}') from e


def get_workflow_state(
        vault: vault_online.VaultOnline,
        record: str,
        enterprise_data: Optional[enterprise_types.IEnterpriseData] = None) -> dict:
    """Get workflow state for a record (`pam workflow state`)."""
    record_uid, rec = RecordResolver.resolve(vault, record)
    if is_workflow_exempt(vault, record_uid):
        logger.warning(
            'You are exempt from workflow restrictions on this record. '
            'As a record owner or approver, you can access this resource directly.'
        )
        return {'status': 'exempt', 'message': 'Workflow not required', 'record_uid': record_uid}

    state = workflow_pb2.WorkflowState()
    record_uid_bytes = utils.base64_url_decode(record_uid)
    state.resource.CopyFrom(ProtobufRefBuilder.record_ref(record_uid_bytes, rec.title))
    try:
        response = post_to_router(
            vault, 'get_workflow_state', request=state, response_type=workflow_pb2.WorkflowState)
        if response is None:
            logger.warning('No workflow found for record %s (%s)', rec.title, record_uid)
            return {'status': 'no_workflow', 'message': 'No workflow found', 'record_uid': record_uid}
        result = workflow_state_to_dict(vault, response, enterprise_data)
        result['status'] = 'success'
        logger.info('Workflow state for %s (%s): %s', rec.title, record_uid, result.get('stage'))
        return result
    except WorkflowError:
        raise
    except ROUTER_TRANSPORT_ERRORS as e:
        raise WorkflowError(f'Failed to get workflow state: {sanitize_router_error(e)}') from e


def get_user_access_state(
        vault: vault_online.VaultOnline,
        enterprise_data: Optional[enterprise_types.IEnterpriseData] = None) -> dict:
    """Get all workflow states for the current user (`pam workflow my-access`)."""
    try:
        response = post_to_router(
            vault, 'get_user_access_state', response_type=workflow_pb2.UserAccessState)
        if not response or not response.workflows:
            logger.info('No active workflows')
            return {'status': 'success', 'workflows': []}
        workflows = [workflow_state_to_dict(vault, wf, enterprise_data) for wf in response.workflows]
        logger.info('Found %s active workflow(s) for current user', len(workflows))
        return {'status': 'success', 'workflows': workflows}
    except WorkflowError:
        raise
    except ROUTER_TRANSPORT_ERRORS as e:
        raise WorkflowError(f'Failed to get user access state: {sanitize_router_error(e)}') from e
