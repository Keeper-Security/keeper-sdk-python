"""Action report command for Keeper CLI."""

import argparse
import os
from typing import Any, List, Optional

from keepersdk.authentication import keeper_auth
from keepersdk.enterprise import action_report, account_transfer, batch_management, enterprise_management, enterprise_types

from . import base
from .. import api, prompt_utils
from ..helpers import report_utils
from ..params import KeeperParams


class ActionReportCommand(base.ArgparseCommand, enterprise_management.IEnterpriseManagementLogger):
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='action-report',
            description='Run an action report based on user activity.',
            parents=[base.report_output_parser]
        )
        ActionReportCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
        self.logger = api.get_logger()
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            '--target', '-t',
            dest='target_user_status',
            action='store',
            choices=['no-logon', 'no-update', 'locked', 'invited', 'no-recovery'],
            default='no-logon',
            help='User status to report on. Default: no-logon'
        )
        parser.add_argument(
            '--days-since', '-d',
            dest='days_since',
            type=int,
            action='store',
            help='Number of days since event of interest (e.g., login, record add/update, lock). '
                 'Default: 30 (or 90 for locked users)'
        )
        parser.add_argument(
            '--columns',
            dest='columns',
            action='store',
            type=str,
            help='Comma-separated list of columns to show on report. '
                 'Supported: name, status, transfer_status, node, team_count, teams, role_count, roles, alias, 2fa_enabled'
        )
        parser.add_argument(
            '--apply-action', '-a',
            dest='apply_action',
            action='store',
            choices=['lock', 'delete', 'transfer', 'none'],
            default='none',
            help='Admin action to apply to each user in the report. Default: none'
        )
        parser.add_argument(
            '--target-user',
            dest='target_user',
            action='store',
            help='Username/email of account to transfer users to when --apply-action=transfer is specified'
        )
        parser.add_argument(
            '--dry-run', '-n',
            dest='dry_run',
            action='store_true',
            default=False,
            help='Enable dry-run mode (preview actions without executing)'
        )
        parser.add_argument(
            '--force', '-f',
            dest='force',
            action='store_true',
            help='Skip confirmation prompt when applying irreversible admin actions (e.g., delete, transfer)'
        )
        parser.add_argument(
            '--node',
            dest='node',
            action='store',
            help='Filter users by node (node name or ID)'
        )
    
    def warning(self, message: str) -> None:
        self.logger.warning(message)
    
    def execute(self, context: KeeperParams, **kwargs) -> Any:
        base.require_login(context)
        base.require_enterprise_admin(context)
        
        target_status = kwargs.get('target_user_status', 'no-logon')
        days_since = kwargs.get('days_since')
        node_name = kwargs.get('node')
        apply_action = kwargs.get('apply_action', 'none')
        target_user = kwargs.get('target_user')
        dry_run = kwargs.get('dry_run', False)
        force = kwargs.get('force', False)
        output_format = kwargs.get('format', 'table')
        output_file = kwargs.get('output')
        
        if node_name is not None and (not isinstance(node_name, str) or not node_name.strip()):
            self.logger.warning('Please provide node name or node ID. The --node parameter cannot be empty.')
            return
        
        allowed_actions = action_report.ActionReportGenerator.get_allowed_actions(target_status)
        if apply_action not in allowed_actions:
            self.logger.warning(
                f'Action \'{apply_action}\' not allowed on \'{target_status}\' users: '
                f'value must be one of {allowed_actions}'
            )
            return
        
        if apply_action == 'transfer' and not target_user:
            self.logger.warning('--target-user is required when --apply-action=transfer is specified')
            return
        
        if days_since is None:
            days_since = 90 if target_status == 'locked' else 30
        
        config = action_report.ActionReportConfig(
            target_user_status=target_status,
            days_since=days_since,
            node_name=node_name,
            apply_action=apply_action,
            target_user=target_user,
            dry_run=dry_run,
            force=force
        )

        generator = action_report.ActionReportGenerator(
            context.enterprise_data, context.auth, config=config
        )
        
        report_entries = generator.generate_report()
        action_result = self._apply_admin_action(context, report_entries, config)
        rows, headers = self._generate_output(report_entries, output_format, kwargs.get('columns'))
        
        status_display = target_status[0].upper() + target_status[1:] if target_status else target_status
        title = f'Admin Action Taken:\n{action_result.to_text()}\n'
        title += '\nNote: the following reflects data prior to any administrative action being applied'
        title += f'\n{len(report_entries)} User(s) With "{status_display}" Status Older Than {days_since} Day(s)'
        if node_name:
            title += f' in Node "{node_name}"'
        title += ': '
        
        result = report_utils.dump_report_data(
            rows, headers, fmt=output_format, filename=output_file, title=title
        )
        
        if output_file:
            _, ext = os.path.splitext(output_file)
            if not ext:
                output_file += '.json' if output_format == 'json' else '.csv'
            self.logger.info(f'Report saved to: {os.path.abspath(output_file)}')
        
        if apply_action != 'none' and not dry_run and action_result.affected_count > 0:
            context.enterprise_loader.load()
        
        return result
    
    def _generate_output(
        self,
        entries: List[action_report.ActionReportEntry],
        output_format: str,
        columns_filter: Optional[str]
    ) -> tuple:
        all_columns = {
            'user_id': lambda e: e.enterprise_user_id,
            'email': lambda e: e.email,
            'name': lambda e: e.full_name,
            'status': lambda e: e.status,
            'transfer_status': lambda e: e.transfer_status,
            'node': lambda e: e.node_path,
            'roles': lambda e: e.roles or [],
            'role_count': lambda e: len(e.roles) if e.roles else 0,
            'teams': lambda e: e.teams or [],
            'team_count': lambda e: len(e.teams) if e.teams else 0,
            '2fa_enabled': lambda e: e.tfa_enabled,
        }
        
        if columns_filter:
            requested_cols = [c.strip().lower() for c in columns_filter.split(',')]
            columns = ['user_id']
            for col in requested_cols:
                if col in all_columns and col not in columns:
                    columns.append(col)
        else:
            columns = ['user_id', 'email', 'name', 'status', 'transfer_status', 'node']
        
        rows = [[all_columns[col](entry) for col in columns] for entry in entries]
        headers = columns if output_format == 'json' else [report_utils.field_to_title(h) for h in columns]
        return rows, headers
    
    def _apply_admin_action(
        self,
        context: KeeperParams,
        entries: List[action_report.ActionReportEntry],
        config: action_report.ActionReportConfig
    ) -> action_report.ActionResult:
        action = config.apply_action
        
        if action == 'none' or not entries:
            return action_report.ActionResult(action='NONE (No action specified)', status='n/a', affected_count=0)
        
        if config.dry_run:
            return action_report.ActionResult(action=action, status='dry run', affected_count=0)
        
        if action in ('delete', 'transfer') and not config.force:
            emails = [e.email for e in entries]
            alert = prompt_utils.get_formatted_text('\nALERT!\n', prompt_utils.COLORS.FAIL)
            prompt_utils.output_text(
                alert,
                f'\nYou are about to {action} the following accounts:\n' +
                '\n'.join(f'{idx + 1}) {email}' for idx, email in enumerate(emails)) +
                '\n\nThis action cannot be undone.\n'
            )
            answer = prompt_utils.user_choice('Do you wish to proceed?', 'yn', 'n')
            if answer.lower() != 'y':
                return action_report.ActionResult(
                    action=action,
                    status='Cancelled by user',
                    affected_count=0
                )
        
        try:
            if action == 'lock':
                return self._lock_users(context.enterprise_loader, entries)
            elif action == 'delete':
                return self._delete_users(context.enterprise_loader, entries)
            elif action == 'transfer':
                return self._transfer_users(context, entries, config.target_user)
            return action_report.ActionResult(action=action, status='unknown', affected_count=0)
        except Exception as e:
            self.logger.warning(f'Action failed: {e}')
            return action_report.ActionResult(
                action=action, status='fail', affected_count=0, server_message=str(e)
            )
    
    def _lock_users(
        self, loader: enterprise_types.IEnterpriseLoader, entries: List[action_report.ActionReportEntry]
    ) -> action_report.ActionResult:
        batch = batch_management.BatchManagement(loader=loader, logger=self)
        user_ids = [e.enterprise_user_id for e in entries]
        batch.user_actions(to_lock=user_ids)
        
        try:
            batch.apply()
            return action_report.ActionResult(
                action='lock',
                status='success',
                affected_count=len(entries)
            )
        except Exception as e:
            return action_report.ActionResult(
                action='lock',
                status='fail',
                affected_count=0,
                server_message=str(e)
            )
    
    def _delete_users(
        self, loader: enterprise_types.IEnterpriseLoader, entries: List[action_report.ActionReportEntry]
    ) -> action_report.ActionResult:
        batch = batch_management.BatchManagement(loader=loader, logger=self)
        users_to_delete = [
            enterprise_management.UserEdit(enterprise_user_id=e.enterprise_user_id)
            for e in entries
        ]
        batch.modify_users(to_remove=users_to_delete)
        
        try:
            batch.apply()
            return action_report.ActionResult(
                action='delete',
                status='success',
                affected_count=len(entries)
            )
        except Exception as e:
            return action_report.ActionResult(
                action='delete',
                status='fail',
                affected_count=0,
                server_message=str(e)
            )
    
    def _transfer_users(
        self, context: KeeperParams, entries: List[action_report.ActionReportEntry], target_user: Optional[str]
    ) -> action_report.ActionResult:
        if not target_user:
            return action_report.ActionResult(
                action='transfer',
                status='fail',
                affected_count=0,
                server_message='No transfer target specified'
            )
        
        target = target_user.lower().strip()
        
        target_user_obj = next(
            (u for u in context.enterprise_data.users.get_all_entities()
             if u.username.lower() == target and u.status == 'active' and u.lock == 0),
            None
        )
        if not target_user_obj:
            return action_report.ActionResult(
                action='transfer', status='fail', affected_count=0,
                server_message=f'Invalid transfer target: {target}'
            )
        
        if target in {e.email.lower() for e in entries}:
            return action_report.ActionResult(
                action='transfer', status='fail', affected_count=0,
                server_message='Cannot transfer user to themselves'
            )
        
        target_keys = self._load_user_public_keys(context.auth, target)
        if not target_keys:
            return action_report.ActionResult(
                action='transfer', status='fail', affected_count=0,
                server_message=f'Failed to get user {target} public key'
            )
        
        transfer_manager = account_transfer.AccountTransferManager(
            loader=context.enterprise_loader, auth=context.auth
        )
        
        affected = 0
        errors = []
        
        for entry in entries:
            try:
                result = transfer_manager.transfer_account(entry.email, target, target_keys)
                if result.success:
                    affected += 1
                else:
                    errors.append(f'{entry.email}: {result.error_message}')
            except Exception as e:
                errors.append(f'{entry.email}: {e}')
        
        status = 'success' if affected == len(entries) else 'incomplete' if affected > 0 else 'fail'
        server_message = '\n'.join(errors) if errors else 'n/a'
        
        return action_report.ActionResult(
            action='transfer_and_delete_user',
            status=status,
            affected_count=affected,
            server_message=server_message
        )
    
    def _load_user_public_keys(self, auth: keeper_auth.KeeperAuth, username: str) -> Optional[keeper_auth.UserKeys]:
        try:
            rq = {
                'command': 'public_keys',
                'key_owners': [username]
            }
            rs = auth.execute_auth_command(rq)
            
            if 'public_keys' in rs and rs['public_keys']:
                pk = rs['public_keys'][0]
                return keeper_auth.UserKeys(
                    rsa=pk.get('public_key'),
                    ec=pk.get('public_ecc_key'),
                    aes=None
                )
        except Exception as e:
            self.logger.debug(f'Failed to load public keys for {username}: {e}')
        
        return None
