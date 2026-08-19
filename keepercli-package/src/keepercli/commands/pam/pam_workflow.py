import argparse
import json
import shlex
from datetime import datetime
from typing import Optional

from keepersdk.helpers.workflow import (
    WorkflowError,
    add_workflow_approvers,
    approve_workflow,
    can_configure_workflow_settings,
    create_workflow,
    delete_workflow,
    deny_workflow,
    end_workflow,
    get_pending_approvals,
    get_user_access_state,
    get_workflow_state,
    read_workflow,
    remove_workflow_approvers,
    request_workflow_access,
    start_workflow,
    update_workflow,
)

from .. import base
from ... import api
from ...helpers import report_utils
from ...params import KeeperParams


logger = api.get_logger()

_ADMIN_VERBS = frozenset({'create', 'update', 'delete', 'add-approver', 'remove-approver'})


def _require_vault(context: KeeperParams):
    base.require_login(context)
    if context.vault is None:
        raise base.CommandError('Vault is not initialized, login to initialize the vault.')


def _run_sdk(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except WorkflowError as e:
        raise base.CommandError(e.message) from e


def _is_json(kwargs) -> bool:
    return kwargs.get('format') == 'json'


def _emit_json(payload: dict):
    return json.dumps(payload, indent=2)


def _fmt_ts(ts_ms) -> str:
    if not ts_ms:
        return ''
    return datetime.fromtimestamp(ts_ms / 1000).strftime('%Y-%m-%d %H:%M:%S')


def _fix_dash_uid_args(parser: argparse.ArgumentParser, args: str) -> str:
    """Insert '--' before a base64url UID starting with '-' so argparse treats it as positional."""
    if not args:
        return args
    try:
        tokens = shlex.split(args)
    except ValueError:
        return args
    if '--' in tokens:
        return args

    known_opts = set()
    consumes_value = set()
    for action in parser._actions:
        for opt in action.option_strings:
            known_opts.add(opt)
            if action.nargs != 0:
                consumes_value.add(opt)

    result = []
    skip_next = False
    for token in tokens:
        if skip_next:
            result.append(token)
            skip_next = False
            continue
        opt_name = token.split('=', 1)[0] if token.startswith('--') and '=' in token else token
        if opt_name in known_opts:
            result.append(token)
            if opt_name in consumes_value and token == opt_name:
                skip_next = True
            continue
        if token.startswith('-'):
            result.append('--')
        result.append(token)

    if len(result) != len(tokens):
        return ' '.join(shlex.quote(t) for t in result)
    return args


class DashUidArgsMixin:
    """Mixin for commands whose positional flow-UID arg may start with '-' (base64url)."""

    def execute_args(self, context, args, **kwargs):
        args = _fix_dash_uid_args(self.get_parser(), args)
        return super().execute_args(context, args, **kwargs)


class _WorkflowCommand(base.ArgparseCommand):
    def execute(self, context: KeeperParams, **kwargs):
        _require_vault(context)
        return self.execute_workflow(context, **kwargs)

    def execute_workflow(self, context: KeeperParams, **kwargs):
        raise NotImplementedError


class PAMWorkflowCommand(base.GroupCommand):
    def __init__(self):
        super().__init__('PAM Workflow')
        self._current_context: Optional[KeeperParams] = None
        self.register_command(WorkflowCreateCommand(), 'create', 'c')
        self.register_command(WorkflowReadCommand(), 'read', 'r')
        self.register_command(WorkflowUpdateCommand(), 'update', 'u')
        self.register_command(WorkflowDeleteCommand(), 'delete', 'd')
        self.register_command(WorkflowAddApproversCommand(), 'add-approver', 'aa')
        self.register_command(WorkflowDeleteApproversCommand(), 'remove-approver', 'ra')
        self.register_command(WorkflowGetApprovalRequestsCommand(), 'pending', 'p')
        self.register_command(WorkflowApproveCommand(), 'approve', 'a')
        self.register_command(WorkflowDenyCommand(), 'deny', 'dn')
        self.register_command(WorkflowRequestAccessCommand(), 'request', 'rq')
        self.register_command(WorkflowStartCommand(), 'start', 's')
        self.register_command(WorkflowEndCommand(), 'end', 'e')
        self.register_command(WorkflowGetStateCommand(), 'state', 'st')
        self.register_command(WorkflowGetUserAccessStateCommand(), 'my-access', 'ma')
        self.default_verb = 'state'

    def execute_args(self, context: KeeperParams, args, **kwargs):
        self._current_context = context
        _require_vault(context)

        pos = args.find(' ') if args else -1
        verb = (args[:pos].strip() if pos > 0 else args.strip()).lower() if args else ''
        if verb.startswith('-'):
            verb = ''
        resolved_verb = self.aliases.get(verb, verb)

        if resolved_verb in _ADMIN_VERBS and not can_configure_workflow_settings(context.vault, refresh=True):
            raise base.CommandError(
                f'You do not have permission to manage workflow settings. '
                f'The "{resolved_verb}" command requires the "Can manage workflow settings" '
                f'enforcement policy. Contact your Keeper administrator to enable this for your role.'
            )
        return super().execute_args(context, args, **kwargs)

    def print_help(self, **kwargs):
        context = self._current_context
        is_admin = bool(context and context.vault and can_configure_workflow_settings(context.vault))
        print(f'{kwargs.get("command")} command [--options]')
        table = []
        headers = ['Command', 'Description']
        for verb, command in self.commands.items():
            if verb in _ADMIN_VERBS and not is_admin:
                continue
            table.append([verb, command.description()])
        print('')
        report_utils.dump_report_data(table, headers=headers)
        print('')


class WorkflowCreateCommand(_WorkflowCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='pam workflow create',
            description='Create workflow configuration for a PAM record',
            allow_abbrev=False,
            parents=[base.json_output_parser],
        )
        self.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('record', help='Record UID or name to configure workflow for')
        parser.add_argument('-n', '--approvals-needed', type=int, default=1,
                            help='Number of approvals required (default: 1)')
        parser.add_argument('-co', '--checkout', action='store_true',
                            help='Enable single-user check-in/check-out mode')
        parser.add_argument('-sa', '--start-on-approval', action='store_true',
                            help='Start access timer when approved (vs when checked out)')
        parser.add_argument('-rr', '--require-reason', action='store_true',
                            help='Require user to provide reason for access')
        parser.add_argument('-rt', '--require-ticket', action='store_true',
                            help='Require user to provide ticket number')
        parser.add_argument('-rm', '--require-mfa', action='store_true',
                            help='Require MFA verification for access')
        parser.add_argument('-d', '--duration', type=str, default='1d',
                            help='Access duration (e.g., "2h", "30m", "1d"). Default: 1d')
        parser.add_argument('--allowed-days', type=str,
                            help='Comma-separated allowed days (e.g., "mon,tue,wed,thu,fri")')
        parser.add_argument('--time-range', type=str,
                            help='Allowed time range in HH:MM-HH:MM format (e.g., "09:00-17:00")')
        parser.add_argument('-u', '--approver', action='append',
                            help='User email to add as an approver. Pass multiple times to '
                                 'add several. Required when --approvals-needed > 0. '
                                 'Duplicates are removed automatically.')

    def execute_workflow(self, context: KeeperParams, **kwargs):
        result = _run_sdk(
            create_workflow,
            context.vault,
            kwargs.get('record'),
            approvals_needed=kwargs.get('approvals_needed', 1),
            checkout=bool(kwargs.get('checkout')),
            start_on_approval=bool(kwargs.get('start_on_approval')),
            require_reason=bool(kwargs.get('require_reason')),
            require_ticket=bool(kwargs.get('require_ticket')),
            require_mfa=bool(kwargs.get('require_mfa')),
            duration=kwargs.get('duration') or '1d',
            allowed_days=kwargs.get('allowed_days'),
            time_range=kwargs.get('time_range'),
            approvers=kwargs.get('approver'),
        )
        if _is_json(kwargs):
            return _emit_json(result)
        cfg = result.get('workflow_config') or {}
        logger.info('Workflow created successfully')
        logger.info('Record: %s (%s)', result.get('record_name'), result.get('record_uid'))
        logger.info('Approvals needed: %s', cfg.get('approvals_needed'))
        logger.info('Check-in/out: %s', 'Yes' if cfg.get('checkout_needed') else 'No')
        logger.info('Duration: %s', cfg.get('access_duration'))
        if cfg.get('require_reason'):
            logger.info('Requires reason: Yes')
        if cfg.get('require_ticket'):
            logger.info('Requires ticket: Yes')
        if cfg.get('require_mfa'):
            logger.info('Requires MFA: Yes')
        approvers = result.get('approvers') or []
        if approvers:
            logger.info('Approvers: %s', ', '.join(approvers))
        elif cfg.get('approvals_needed'):
            logger.warning(
                'Note: Add approvers with: pam workflow add-approver %s --user <email>',
                result.get('record_uid'),
            )


class WorkflowReadCommand(_WorkflowCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='pam workflow read',
            description='Read and display workflow configuration',
            parents=[base.json_output_parser],
        )
        self.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('record', help='Record UID or name')

    def execute_workflow(self, context: KeeperParams, **kwargs):
        result = _run_sdk(read_workflow, context.vault, kwargs.get('record'))
        if _is_json(kwargs):
            return _emit_json(result)
        if result.get('status') == 'no_workflow':
            logger.warning('No workflow configured for this record')
            logger.info('Record: %s (%s)', result.get('record_name'), result.get('record_uid'))
            logger.info('To create a workflow, run:')
            logger.info('  pam workflow create %s', result.get('record_uid'))
            return
        self._print_table(result)

    @staticmethod
    def _print_table(result: dict):
        logger.info('Workflow Configuration')
        logger.info('Record: %s', result.get('record_name'))
        logger.info('Record UID: %s', result.get('record_uid'))
        if result.get('created_on'):
            logger.info('Created: %s', _fmt_ts(result['created_on']))
        p = result.get('parameters') or {}
        logger.info('Access Parameters:')
        logger.info('  Approvals needed: %s', p.get('approvals_needed'))
        logger.info('  Check-in/out required: %s', 'Yes' if p.get('checkout_needed') else 'No')
        logger.info('  Access duration: %s', p.get('access_duration'))
        logger.info('  Timer starts: %s', 'On approval' if p.get('start_access_on_approval') else 'On check-out')
        logger.info('Requirements:')
        logger.info('  Reason required: %s', 'Yes' if p.get('require_reason') else 'No')
        logger.info('  Ticket required: %s', 'Yes' if p.get('require_ticket') else 'No')
        logger.info('  MFA required: %s', 'Yes' if p.get('require_mfa') else 'No')
        allowed = p.get('allowed_times') or {}
        if allowed:
            logger.info('Allowed Times:')
            if allowed.get('allowed_days'):
                logger.info('  Days: %s', ', '.join(allowed['allowed_days']))
            if allowed.get('time_ranges'):
                for tr in allowed['time_ranges']:
                    logger.info('  Time: %s', tr.replace('-', ' - '))
            if allowed.get('timezone'):
                logger.info('  Timezone: %s', allowed['timezone'])
        approvers = result.get('approvers') or []
        if approvers:
            logger.info('Approvers (%s):', len(approvers))
            for idx, approver in enumerate(approvers, 1):
                esc_label = ''
                if approver.get('escalation'):
                    esc_label = ' (Escalation'
                    if approver.get('escalation_after'):
                        esc_label += f' after {approver["escalation_after"]}'
                    esc_label += ')'
                if approver.get('type') == 'user':
                    logger.info('  %s. User: %s%s', idx, approver.get('email'), esc_label)
                elif approver.get('type') == 'user_id':
                    logger.info('  %s. User: %s%s', idx, approver.get('email') or approver.get('user_id'), esc_label)
                elif approver.get('type') == 'team':
                    team_uid = approver.get('team_uid')
                    team_name = approver.get('team_name')
                    team_display = f'{team_name} ({team_uid})' if team_name else team_uid
                    logger.info('  %s. Team: %s%s', idx, team_display, esc_label)
        else:
            logger.warning('No approvers configured')
            logger.info('Add approvers with: pam workflow add-approver %s --user <email>', result.get('record_uid'))


class WorkflowUpdateCommand(_WorkflowCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='pam workflow update',
            description='Update existing workflow configuration. '
                        'Only specified fields are changed; unspecified fields retain their current values.',
            parents=[base.json_output_parser],
        )
        self.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('record', help='Record UID or name with workflow to update')
        parser.add_argument('-n', '--approvals-needed', type=int, help='Number of approvals required')
        parser.add_argument('-co', '--checkout', type=lambda x: x.lower() == 'true',
                            help='Enable/disable check-in/check-out (true/false)')
        parser.add_argument('-sa', '--start-on-approval', type=lambda x: x.lower() == 'true',
                            help='Start timer on approval vs check-out (true/false)')
        parser.add_argument('-rr', '--require-reason', type=lambda x: x.lower() == 'true',
                            help='Require reason (true/false)')
        parser.add_argument('-rt', '--require-ticket', type=lambda x: x.lower() == 'true',
                            help='Require ticket (true/false)')
        parser.add_argument('-rm', '--require-mfa', type=lambda x: x.lower() == 'true',
                            help='Require MFA (true/false)')
        parser.add_argument('-d', '--duration', type=str, help='Access duration (e.g., "2h", "30m", "1d")')
        parser.add_argument('--allowed-days', type=str,
                            help='Comma-separated allowed days (e.g., "mon,tue,wed,thu,fri")')
        parser.add_argument('--time-range', type=str,
                            help='Allowed time range in HH:MM-HH:MM format (e.g., "09:00-17:00")')

    def execute_workflow(self, context: KeeperParams, **kwargs):
        result = _run_sdk(
            update_workflow,
            context.vault,
            kwargs.get('record'),
            approvals_needed=kwargs.get('approvals_needed'),
            checkout=kwargs.get('checkout'),
            start_on_approval=kwargs.get('start_on_approval'),
            require_reason=kwargs.get('require_reason'),
            require_ticket=kwargs.get('require_ticket'),
            require_mfa=kwargs.get('require_mfa'),
            duration=kwargs.get('duration'),
            allowed_days=kwargs.get('allowed_days'),
            time_range=kwargs.get('time_range'),
        )
        if _is_json(kwargs):
            return _emit_json(result)
        logger.info('Workflow updated successfully')
        logger.info('Record: %s (%s)', result.get('record_name'), result.get('record_uid'))


class WorkflowDeleteCommand(_WorkflowCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='pam workflow delete',
            description='Delete workflow configuration from a record',
            parents=[base.json_output_parser],
        )
        self.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('record', help='Record UID or name to remove workflow from')

    def execute_workflow(self, context: KeeperParams, **kwargs):
        result = _run_sdk(delete_workflow, context.vault, kwargs.get('record'))
        if _is_json(kwargs):
            return _emit_json(result)
        logger.info('Workflow deleted successfully')
        logger.info('Record: %s (%s)', result.get('record_name'), result.get('record_uid'))


class WorkflowAddApproversCommand(_WorkflowCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='pam workflow add-approver',
            description='Add approvers to a workflow',
            parents=[base.json_output_parser],
        )
        self.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('record', help='Record UID or name')
        parser.add_argument('-u', '--user', action='append',
                            help='User email to add as approver (can specify multiple times)')
        parser.add_argument('-t', '--team', action='append',
                            help='Team name or UID to add as approver (can specify multiple times)')
        parser.add_argument('-e', '--escalation', action='store_true', help='Mark as escalation approver')
        parser.add_argument('-ea', '--escalation-after', type=str,
                            help='Time before escalating to this approver (e.g., "30m", "1h", "2h"). '
                                 'Only meaningful with --escalation')

    def execute_workflow(self, context: KeeperParams, **kwargs):
        result = _run_sdk(
            add_workflow_approvers,
            context.vault,
            kwargs.get('record'),
            users=kwargs.get('user'),
            teams=kwargs.get('team'),
            escalation=bool(kwargs.get('escalation')),
            escalation_after=kwargs.get('escalation_after'),
        )
        if _is_json(kwargs):
            return _emit_json(result)
        logger.info('Approvers added successfully')
        logger.info('Record: %s (%s)', result.get('record_name'), result.get('record_uid'))
        logger.info('Added %s approver(s)', result.get('approvers_added'))
        if result.get('escalation'):
            esc_info = f' (after {result["escalation_after"]})' if result.get('escalation_after') else ''
            logger.info('Type: Escalation approver%s', esc_info)


class WorkflowDeleteApproversCommand(_WorkflowCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='pam workflow remove-approver',
            description='Remove approvers from a workflow',
            parents=[base.json_output_parser],
        )
        self.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('record', help='Record UID or name')
        parser.add_argument('-u', '--user', action='append', help='User email to remove as approver')
        parser.add_argument('-t', '--team', action='append', help='Team name or UID to remove as approver')

    def execute_workflow(self, context: KeeperParams, **kwargs):
        result = _run_sdk(
            remove_workflow_approvers,
            context.vault,
            kwargs.get('record'),
            users=kwargs.get('user'),
            teams=kwargs.get('team'),
        )
        if _is_json(kwargs):
            return _emit_json(result)
        logger.info('Approvers removed successfully')
        logger.info('Record: %s (%s)', result.get('record_name'), result.get('record_uid'))
        logger.info('Removed %s approver(s)', result.get('approvers_removed'))


class WorkflowGetApprovalRequestsCommand(_WorkflowCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='pam workflow pending',
            description='Get pending approval requests',
            parents=[base.json_output_parser],
        )
        super().__init__(parser)

    def execute_workflow(self, context: KeeperParams, **kwargs):
        result = _run_sdk(get_pending_approvals, context.vault)
        requests = result.get('requests') or []
        if _is_json(kwargs):
            return _emit_json(result)
        if not requests:
            logger.warning('No pending approval requests')
            return
        rows = []
        for req in requests:
            rows.append([
                req.get('record_name') or '',
                req.get('record_uid') or '',
                req.get('flow_uid') or '',
                req.get('requested_by') or '',
                req.get('reason') or '',
                req.get('ticket') or '',
                _fmt_ts(req.get('started_on')),
                _fmt_ts(req.get('expires_on')),
                req.get('duration') or '',
            ])
        headers = ['Record Name', 'Record UID', 'Flow UID', 'Requested By', 'Reason',
                   'Ticket', 'Started', 'Expires', 'Duration']
        report_utils.dump_report_data(rows, headers=headers)


class WorkflowApproveCommand(DashUidArgsMixin, _WorkflowCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='pam workflow approve',
            description='Approve a workflow access request',
            parents=[base.json_output_parser],
        )
        self.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('flow_uid', help='Flow UID of the workflow to approve')

    def execute_workflow(self, context: KeeperParams, **kwargs):
        result = _run_sdk(approve_workflow, context.vault, kwargs.get('flow_uid'))
        if _is_json(kwargs):
            return _emit_json(result)
        logger.info('Access request approved')
        logger.info('Flow UID: %s', result.get('flow_uid'))


class WorkflowDenyCommand(DashUidArgsMixin, _WorkflowCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='pam workflow deny',
            description='Deny a workflow access request',
            parents=[base.json_output_parser],
        )
        self.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('flow_uid', help='Flow UID of the workflow to deny')
        parser.add_argument('-r', '--reason', help='Reason for denial')

    def execute_workflow(self, context: KeeperParams, **kwargs):
        result = _run_sdk(deny_workflow, context.vault, kwargs.get('flow_uid'), reason=kwargs.get('reason'))
        if _is_json(kwargs):
            return _emit_json(result)
        logger.info('Access request denied')
        logger.info('Flow UID: %s', result.get('flow_uid'))
        if result.get('reason'):
            logger.info('Reason: %s', result['reason'])


class WorkflowRequestAccessCommand(_WorkflowCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='pam workflow request',
            description='Request access to a PAM resource, escalate, or cancel a pending request',
            parents=[base.json_output_parser],
        )
        self.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('record', help='Record UID or name')
        parser.add_argument('-r', '--reason', help='Reason for access request')
        parser.add_argument('-t', '--ticket', help='External ticket/reference number')
        parser.add_argument('-e', '--escalate', action='store_true',
                            help='Escalate a pending request to escalation approvers')
        parser.add_argument('-c', '--cancel', action='store_true',
                            help='Cancel a pending or active workflow request')

    def execute_workflow(self, context: KeeperParams, **kwargs):
        result = _run_sdk(
            request_workflow_access,
            context.vault,
            kwargs.get('record'),
            reason=kwargs.get('reason') or '',
            ticket=kwargs.get('ticket') or '',
            escalate=bool(kwargs.get('escalate')),
            cancel=bool(kwargs.get('cancel')),
        )
        if _is_json(kwargs):
            return _emit_json(result)
        if result.get('status') == 'exempt':
            logger.warning('You are exempt from workflow restrictions on this record.')
            logger.info('As a record owner or approver, you can access this resource directly.')
            return
        action = result.get('action')
        if action == 'escalated':
            logger.info('Request escalated')
            logger.info('Record: %s (%s)', result.get('record_name'), result.get('record_uid'))
            logger.info('Escalation approvers have been notified.')
        elif action == 'cancelled':
            logger.info('Workflow request cancelled')
            logger.info('Record: %s (%s)', result.get('record_name'), result.get('record_uid'))
            logger.info('Flow UID: %s', result.get('flow_uid'))
        else:
            logger.info('Access request sent')
            logger.info('Record: %s (%s)', result.get('record_name'), result.get('record_uid'))
            if result.get('reason'):
                logger.info('Reason: %s', result['reason'])
            if result.get('ticket'):
                logger.info('Ticket: %s', result['ticket'])
            logger.info('Approvers have been notified.')


class WorkflowStartCommand(DashUidArgsMixin, _WorkflowCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='pam workflow start',
            description='Start a workflow (check-out). Can use either record UID/name or flow UID.',
            parents=[base.json_output_parser],
        )
        self.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('uid', help='Record UID, record name, or Flow UID')

    def execute_workflow(self, context: KeeperParams, **kwargs):
        result = _run_sdk(start_workflow, context.vault, kwargs.get('uid'))
        if _is_json(kwargs):
            return _emit_json(result)
        logger.info('Workflow started (checked out)')
        if result.get('record_uid'):
            logger.info('Record: %s (%s)', result.get('record_name'), result.get('record_uid'))
        else:
            logger.info('Flow UID: %s', result.get('flow_uid'))


class WorkflowEndCommand(DashUidArgsMixin, _WorkflowCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='pam workflow end',
            description='End a workflow (check-in).',
            parents=[base.json_output_parser],
        )
        self.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('uid', help='Record UID, record name, or Flow UID')
        parser.add_argument('-f', '--force', action='store_true',
                            help="force check-in: approvers can terminate another user's active session "
                                 'when single-user checkout is enabled.')

    def execute_workflow(self, context: KeeperParams, **kwargs):
        result = _run_sdk(end_workflow, context.vault, kwargs.get('uid'), force=bool(kwargs.get('force')))
        if _is_json(kwargs):
            return _emit_json(result)
        if result.get('action') == 'force_checkin':
            logger.info('Record force checked in')
        else:
            logger.info('Workflow ended (checked in)')
        if result.get('record_uid'):
            logger.info('Record: %s (%s)', result.get('record_name'), result.get('record_uid'))
        if result.get('flow_uid'):
            logger.info('Flow UID: %s', result.get('flow_uid'))
        if result.get('action') == 'ended':
            logger.info('Credentials may have been rotated.')


class WorkflowGetStateCommand(_WorkflowCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='pam workflow state',
            description='Get workflow state for a record',
            parents=[base.json_output_parser],
        )
        self.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('record', help='Record UID or name')

    def execute_workflow(self, context: KeeperParams, **kwargs):
        result = _run_sdk(get_workflow_state, context.vault, kwargs.get('record'))
        if _is_json(kwargs):
            return _emit_json(result)
        if result.get('status') == 'exempt':
            logger.warning('You are exempt from workflow restrictions on this record.')
            logger.info('As a record owner or approver, you can access this resource directly.')
            return
        if result.get('status') == 'no_workflow':
            logger.warning('No workflow found for this record')
            return
        logger.info('Workflow State')
        record_label = result.get('record_name') or ''
        rec_uid = result.get('record_uid') or ''
        if record_label and rec_uid:
            logger.info('Record: %s (%s)', record_label, rec_uid)
        elif rec_uid:
            logger.info('Record: %s', rec_uid)
        if result.get('flow_uid'):
            logger.info('Flow UID: %s', result['flow_uid'])
        if result.get('stage'):
            logger.info('Stage: %s', result['stage'])
        conditions = result.get('conditions') or []
        if conditions:
            logger.info('Conditions: %s', ', '.join(conditions))
        if result.get('checked_out_by'):
            logger.info('Checked out by: %s', result['checked_out_by'])
        if result.get('can_force_checkin'):
            logger.info('Force check-in: Available')
        if result.get('escalated'):
            logger.info('Escalated: Yes')
        if result.get('started_on'):
            logger.info('Started: %s', _fmt_ts(result['started_on']))
        if result.get('expires_on'):
            logger.info('Expires: %s', _fmt_ts(result['expires_on']))
        approved_by = result.get('approved_by') or []
        if approved_by:
            logger.info('Approved by:')
            for a in approved_by:
                suffix = f" at {_fmt_ts(a.get('approved_on'))}" if a.get('approved_on') else ''
                logger.info('  - %s%s', a.get('user'), suffix)


class WorkflowGetUserAccessStateCommand(_WorkflowCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='pam workflow my-access',
            description='Get all workflow states for current user',
            parents=[base.json_output_parser],
        )
        super().__init__(parser)

    def execute_workflow(self, context: KeeperParams, **kwargs):
        result = _run_sdk(get_user_access_state, context.vault)
        workflows = result.get('workflows') or []
        if _is_json(kwargs):
            return _emit_json(result)
        if not workflows:
            logger.warning('No active workflows')
            return
        rows = []
        for wf in workflows:
            approved_by = ''
            if wf.get('approved_by'):
                approved_by = '\n'.join(a.get('user') or '' for a in wf['approved_by'])
            rows.append([
                wf.get('stage') or '',
                wf.get('record_name') or '',
                wf.get('record_uid') or '',
                wf.get('flow_uid') or '',
                wf.get('checked_out_by') or '',
                approved_by,
                _fmt_ts(wf.get('started_on')),
                _fmt_ts(wf.get('expires_on')),
            ])
        headers = ['Stage', 'Record Name', 'Record UID', 'Flow UID', 'Checked Out By',
                   'Approved By', 'Started', 'Expires']
        report_utils.dump_report_data(rows, headers=headers)
