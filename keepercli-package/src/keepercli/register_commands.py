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
        commands.register_command('server',
                                  base.GetterSetterCommand('server', 'Sets or displays current Keeper region'),
                                  base.CommandScope.Account)
        commands.register_command('login', account_commands.LoginCommand(), base.CommandScope.Account)
        commands.register_command('logout', account_commands.LogoutCommand(), base.CommandScope.Account)
        commands.register_command('this-device', account_commands.ThisDeviceCommand(), base.CommandScope.Account)
        commands.register_command('whoami', account_commands.WhoamiCommand(), base.CommandScope.Account)


    if not scopes or bool(scopes & base.CommandScope.Vault):
        from .commands import vault_folder, vault, vault_record, record_edit
        commands.register_command('sync-down', vault.SyncDownCommand(), base.CommandScope.Vault, 'd')
        commands.register_command('cd', vault_folder.FolderCdCommand(), base.CommandScope.Vault)
        commands.register_command('ls', vault_folder.FolderListCommand(), base.CommandScope.Vault)
        commands.register_command('tree', vault_folder.FolderTreeCommand(), base.CommandScope.Vault)
        commands.register_command('mkdir', vault_folder.FolderMakeCommand(), base.CommandScope.Vault)
        commands.register_command('rmdir', vault_folder.FolderRemoveCommand(), base.CommandScope.Vault)
        commands.register_command('rndir', vault_folder.FolderRenameCommand(), base.CommandScope.Vault)
        commands.register_command('mv', vault_folder.FolderMoveCommand(), base.CommandScope.Vault)
        commands.register_command('list', vault_record.RecordListCommand(), base.CommandScope.Vault, 'l')
        commands.register_command('shortcut', vault_record.ShortcutCommand(), base.CommandScope.Vault)
        commands.register_command('record-add', record_edit.RecordAddCommand(), base.CommandScope.Vault, 'ra')
        commands.register_command('record-update', record_edit.RecordUpdateCommand(), base.CommandScope.Vault, 'ru')
        commands.register_command('delete-attachment', record_edit.RecordUpdateCommand(), base.CommandScope.Vault)
        commands.register_command('download-attachment', record_edit.RecordDownloadAttachmentCommand(), base.CommandScope.Vault, 'da')
        commands.register_command('upload-attachment', record_edit.RecordUploadAttachmentCommand(), base.CommandScope.Vault, 'ua')
