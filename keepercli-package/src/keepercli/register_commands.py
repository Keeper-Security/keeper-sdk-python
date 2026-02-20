from typing import Optional

from .commands import base


def register_commands(commands: base.CliCommands, scopes: Optional[base.CommandScope] = None):
    from .commands import cli_commands
    commands.register_command('help', cli_commands.HelpCommand(commands), base.CommandScope.Common)
    commands.register_command('history', cli_commands.HistoryCommand(), base.CommandScope.Common, 'h')
    commands.register_command('clear', cli_commands.ClearCommand(), base.CommandScope.Common, 'c')
    commands.register_command('debug', cli_commands.DebugCommand(), base.CommandScope.Common)
    commands.register_command('version', cli_commands.VersionCommand(), base.CommandScope.Common, 'v')

    if not scopes or bool(scopes & base.CommandScope.Account):
        from .commands import account_commands
        from .biometric import BiometricCommand
        from .commands import account_commands, two_fa
        commands.register_command('server',
                                  base.GetterSetterCommand('server', 'Sets or displays current Keeper region'),
                                  base.CommandScope.Account)
        commands.register_command('login', account_commands.LoginCommand(), base.CommandScope.Account)
        commands.register_command('biometric', BiometricCommand(), base.CommandScope.Account)
        commands.register_command('logout', account_commands.LogoutCommand(), base.CommandScope.Account)
        commands.register_command('this-device', account_commands.ThisDeviceCommand(), base.CommandScope.Account)
        commands.register_command('whoami', account_commands.WhoamiCommand(), base.CommandScope.Account)
        commands.register_command('reset-password', account_commands.ResetPasswordCommand(), base.CommandScope.Account)
        commands.register_command('2fa', two_fa.TwoFaCommand(), base.CommandScope.Account)


    if not scopes or bool(scopes & base.CommandScope.Vault):
        from .commands import (vault_folder, vault, vault_record, record_edit, importer_commands, breachwatch,
                               record_type, secrets_manager, shares, password_report, trash, record_file_report,
                               record_handling_commands, register, password_generate, verify_records,
                               shared_records_report, share_report)
        
        commands.register_command('sync-down', vault.SyncDownCommand(), base.CommandScope.Vault, 'd')
        commands.register_command('cd', vault_folder.FolderCdCommand(), base.CommandScope.Vault)
        commands.register_command('ls', vault_folder.FolderListCommand(), base.CommandScope.Vault)
        commands.register_command('tree', vault_folder.FolderTreeCommand(), base.CommandScope.Vault)
        commands.register_command('mkdir', vault_folder.FolderMakeCommand(), base.CommandScope.Vault)
        commands.register_command('rmdir', vault_folder.FolderRemoveCommand(), base.CommandScope.Vault)
        commands.register_command('rndir', vault_folder.FolderRenameCommand(), base.CommandScope.Vault)
        commands.register_command('mv', vault_folder.FolderMoveCommand(), base.CommandScope.Vault)
        commands.register_command('transform-folder', vault_folder.FolderTransformCommand(), base.CommandScope.Vault)
        commands.register_command('list', vault_record.RecordListCommand(), base.CommandScope.Vault, 'l')
        commands.register_command('list-sf', vault_record.SharedFolderListCommand(), base.CommandScope.Vault, 'lsf')
        commands.register_command('list-team', vault_record.TeamListCommand(), base.CommandScope.Vault, 'lt')
        commands.register_command('shortcut', vault_record.ShortcutCommand(), base.CommandScope.Vault)
        commands.register_command('search', record_edit.RecordSearchCommand(), base.CommandScope.Vault, 's')
        commands.register_command('record-history', record_handling_commands.RecordHistoryCommand(), base.CommandScope.Vault, 'rh')
        commands.register_command('clipboard-copy', record_handling_commands.ClipboardCommand(), base.CommandScope.Vault, 'cc')
        commands.register_command('find-duplicate', record_handling_commands.FindDuplicateCommand(), base.CommandScope.Vault)
        commands.register_command('find-password', record_handling_commands.ClipboardCommand(), base.CommandScope.Vault)
        commands.register_command('find-ownerless', register.FindOwnerlessCommand(), base.CommandScope.Vault)
        commands.register_command('record-add', record_edit.RecordAddCommand(), base.CommandScope.Vault, 'ra')
        commands.register_command('record-update', record_edit.RecordUpdateCommand(), base.CommandScope.Vault, 'ru')
        commands.register_command('rm', record_edit.RecordDeleteCommand(), base.CommandScope.Vault)
        commands.register_command('get', record_edit.RecordGetCommand(), base.CommandScope.Vault)
        commands.register_command('delete-attachment', record_edit.RecordDeleteAttachmentCommand(), base.CommandScope.Vault)
        commands.register_command('download-attachment', record_edit.RecordDownloadAttachmentCommand(), base.CommandScope.Vault, 'da')
        commands.register_command('upload-attachment', record_edit.RecordUploadAttachmentCommand(), base.CommandScope.Vault, 'ua')
        commands.register_command('file-report', record_file_report.RecordFileReportCommand(), base.CommandScope.Vault)
        commands.register_command('import', importer_commands.ImportCommand(), base.CommandScope.Vault)
        commands.register_command('export', importer_commands.ExportCommand(), base.CommandScope.Vault)
        commands.register_command('generate', password_generate.PasswordGenerateCommand(), base.CommandScope.Vault, 'gen')
        commands.register_command('breachwatch', breachwatch.BreachWatchCommand(), base.CommandScope.Vault, 'bw')
        commands.register_command('password-report', password_report.PasswordReportCommand(), base.CommandScope.Vault)
        commands.register_command('record-type-add', record_type.RecordTypeAddCommand(), base.CommandScope.Vault)
        commands.register_command('record-type-edit', record_type.RecordTypeEditCommand(), base.CommandScope.Vault)
        commands.register_command('record-type-delete', record_type.RecordTypeDeleteCommand(), base.CommandScope.Vault)
        commands.register_command('record-type-info', record_type.RecordTypeInfoCommand(), base.CommandScope.Vault, 'rti')
        commands.register_command('load-record-types', record_type.LoadRecordTypesCommand(), base.CommandScope.Vault)
        commands.register_command('download-record-types', record_type.DownloadRecordTypesCommand(), base.CommandScope.Vault)
        commands.register_command('secrets-manager-app', secrets_manager.SecretsManagerAppCommand(), base.CommandScope.Vault)
        commands.register_command('secrets-manager-client', secrets_manager.SecretsManagerClientCommand(), base.CommandScope.Vault)
        commands.register_command('secrets-manager-share', secrets_manager.SecretsManagerShareCommand(), base.CommandScope.Vault)
        commands.register_command('share-record', shares.ShareRecordCommand(), base.CommandScope.Vault, 'sr')
        commands.register_command('share-folder', shares.ShareFolderCommand(), base.CommandScope.Vault, 'sf')
        commands.register_command('share-list', shares.OneTimeShareListCommand(), base.CommandScope.Vault)
        commands.register_command('share-create', shares.OneTimeShareCreateCommand(), base.CommandScope.Vault)
        commands.register_command('share-remove', shares.OneTimeShareRemoveCommand(), base.CommandScope.Vault)
        commands.register_command('record-permission', record_handling_commands.RecordPermissionCommand(), base.CommandScope.Vault)
        commands.register_command('trash', trash.TrashCommand(), base.CommandScope.Vault)
        commands.register_command('verify-shared-folders', verify_records.VerifySharedFoldersCommand(), base.CommandScope.Vault)
        commands.register_command('verify-records', verify_records.VerifyRecordsCommand(), base.CommandScope.Vault)
        commands.register_command('shared-records-report', shared_records_report.SharedRecordsReportCommand(), base.CommandScope.Vault) 
        commands.register_command('share-report', share_report.ShareReportCommand(), base.CommandScope.Vault) 


    if not scopes or bool(scopes & base.CommandScope.Enterprise):
        from .commands import (enterprise_info, enterprise_node, enterprise_role, enterprise_team, enterprise_user, enterprise_create_user,
                               importer_commands, audit_report, audit_alert, audit_log, transfer_account, pedm_admin, msp, user_report,
                               aging_report, action_report, security_audit_report, enterprise_push, compliance)
        from .commands.pam import keeper_pam

        commands.register_command('create-user', enterprise_create_user.CreateEnterpriseUserCommand(), base.CommandScope.Enterprise, 'ecu')
        commands.register_command('enterprise-down', enterprise_info.EnterpriseDownCommand(), base.CommandScope.Enterprise, 'ed')
        commands.register_command('enterprise-info', enterprise_info.EnterpriseInfoCommand(), base.CommandScope.Enterprise, 'ei')
        commands.register_command('enterprise-node', enterprise_node.EnterpriseNodeCommand(), base.CommandScope.Enterprise, 'en')
        commands.register_command('enterprise-role', enterprise_role.EnterpriseRoleCommand(), base.CommandScope.Enterprise, 'er')
        commands.register_command('enterprise-team', enterprise_team.EnterpriseTeamCommand(), base.CommandScope.Enterprise, 'et')
        commands.register_command('enterprise-user', enterprise_user.EnterpriseUserCommand(), base.CommandScope.Enterprise, 'eu')
        commands.register_command('transfer-user', transfer_account.EnterpriseTransferAccountCommand(), base.CommandScope.Enterprise)
        commands.register_command('audit-report', audit_report.EnterpriseAuditReport(), base.CommandScope.Enterprise)
        commands.register_command('audit-alert', audit_alert.AuditAlerts(), base.CommandScope.Enterprise)
        commands.register_command('audit-log', audit_log.AuditLogCommand(), base.CommandScope.Enterprise, 'al')
        commands.register_command('download-membership', importer_commands.DownloadMembershipCommand(), base.CommandScope.Enterprise)
        commands.register_command('apply-membership', importer_commands.ApplyMembershipCommand(), base.CommandScope.Enterprise)
        commands.register_command('device-approve', enterprise_user.EnterpriseDeviceApprovalCommand(), base.CommandScope.Enterprise)
        commands.register_command('pedm', pedm_admin.PedmCommand(), base.CommandScope.Enterprise)
        commands.register_command('switch-to-mc', msp.SwitchToManagedCompanyCommand(), base.CommandScope.Enterprise)
        commands.register_command('team-approve', enterprise_team.TeamApproveCommand(), base.CommandScope.Enterprise)
        commands.register_command('user-report', user_report.UserReportCommand(), base.CommandScope.Enterprise, 'ur')
        commands.register_command('security-audit-report', security_audit_report.SecurityAuditReportCommand(), base.CommandScope.Enterprise, 'sar')
        commands.register_command('aging-report', aging_report.AgingReportCommand(), base.CommandScope.Enterprise, 'ar')
        commands.register_command('action-report', action_report.ActionReportCommand(), base.CommandScope.Enterprise, 'acr')
        commands.register_command('compliance', compliance.ComplianceCommand(), base.CommandScope.Enterprise, 'cr')
        commands.register_command('pam', keeper_pam.PAMControllerCommand(), base.CommandScope.Enterprise)
        commands.register_command('enterprise-push', enterprise_push.EnterprisePushCommand(), base.CommandScope.Enterprise, 'ep')
