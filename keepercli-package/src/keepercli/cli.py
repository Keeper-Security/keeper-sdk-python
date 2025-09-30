import logging
import sys
from typing import Optional, Any, Iterable, List

from prompt_toolkit import PromptSession
from prompt_toolkit.history import History

from . import prompt_utils, api, autocomplete
from .commands import command_completer, base, command_history
from .helpers import report_utils
from .params import KeeperParams, KeeperConfig
from keepersdk import constants
from keepersdk.vault import vault_utils

if sys.platform == 'win32':
    from colorama import just_fix_windows_console
    just_fix_windows_console()


class KeeperHistory(History):
    def __init__(self):
        super().__init__()

    def load_history_strings(self) -> Iterable[str]:
        yield from command_history[::-1]

    def store_string(self, string: str) -> None:
        last_command = command_history[-1] if len(command_history) > 0 else ''
        if last_command != string:
            command_history.append(string)


def do_command(command_line: str, context: KeeperParams, commands: base.CliCommands) -> Any:
    cmd, sep, args = command_line.partition(' ')
    orig_cmd = cmd
    if cmd in commands.aliases:
        ali = commands.aliases[cmd]
        if isinstance(ali, (tuple, list)):
            cmd = ali[0]
            args = ' '.join(ali[1:]) + ' ' + args
        else:
            cmd = ali
    if cmd in commands.commands:
        command, _ = commands.commands[cmd]
        return command.execute_args(context, args.strip(), command=orig_cmd)
    else:
        display_command_help(commands)
    return None


def loop(keeper_config: KeeperConfig, commands: base.CliCommands):
    prompt_session: Optional[PromptSession] = None
    command_queue: List[str] = []
    context_stack: List[KeeperParams] = []
    context = KeeperParams(keeper_config)

    def get_prompt() -> str:
        if keeper_config.batch_mode:
            return ''
        if context.auth is None:
            return 'Not logged in'

        if context.vault is not None:
            vault_data = context.vault.vault_data
            folder_path = vault_data.root_folder.name
            path = vault_utils.get_folder_path(vault_data, folder_uid=context.current_folder)
            if path:
                folder_path += '/' + path

            if len(folder_path) > 40:
                folder_path = '...' + folder_path[-37:]
            return folder_path
        if context.enterprise_data is not None:
            return context.enterprise_data.enterprise_info.enterprise_name

        return context.auth.auth_context.username

    logger = api.get_logger()

    if not keeper_config.batch_mode:
        if sys.stdin.isatty() and sys.stdout.isatty():
            from prompt_toolkit.enums import EditingMode
            from prompt_toolkit.shortcuts import CompleteStyle
            completer = command_completer.CommandCompleter(commands, autocomplete.standard_completer(context))
            prompt_session = PromptSession(
                multiline=False, editing_mode=EditingMode.EMACS, complete_style=CompleteStyle.MULTI_COLUMN,
                complete_while_typing=False, completer=completer, auto_suggest=None, key_bindings=prompt_utils.kb,
                enable_history_search=False, history=KeeperHistory())

        if keeper_config.username:
            options = '--resume-session'
            if keeper_config.password:
                options += ' --pass="{0}"'.format(keeper_config.password.replace('"', '\\"'))
            cmd = 'login ' + options + ' ' + keeper_config.username
            command_queue.append(cmd)
        else:
            if keeper_config.server:
                api.get_logger().info('Current Keeper region: %s', keeper_config.server)
            else:
                api.get_logger().info('Use "server" command to change Keeper region > "server US"')
                for region in constants.KEEPER_PUBLIC_HOSTS:
                    api.get_logger().info('\t%s: %s', region, constants.KEEPER_PUBLIC_HOSTS[region])
            api.get_logger().info('To login type: login <email>')
    else:
        logger.setLevel(logging.DEBUG if keeper_config.debug else logging.WARNING)

    while True:
        if context.auth:
            context.auth.on_idle()

        if len(command_queue) > 0:
            command = command_queue.pop(0)
        else:
            prompt = get_prompt()
            if prompt:
                prompt += '> '
            try:
                if prompt_session:
                    command = prompt_session.prompt(prompt)
                else:
                    command = input(prompt)
            except EOFError:
                return 0
            except KeyboardInterrupt:
                prompt_utils.output_text('')
                continue
        command = command.strip()
        if not command:
            continue

        if command.lower() in ('q', 'quit'):
            if len(context_stack) > 0:
                context_to_release = context
                context = context_stack.pop()
                logger.info('Returning to previous context...')
                context_to_release.clear_session()
                continue
            else:
                break

        suppress_errno = False
        if command.startswith("@"):
            suppress_errno = True
            command = command[1:]
        if keeper_config.batch_mode:
            logger.info('> %s', command)
        error_no = 1
        try:
            if context.vault and context.vault.sync_requested:
                context.vault.sync_down()
            result = do_command(command, context, commands)
            error_no = 0
            if isinstance(result, KeeperParams):
                context_stack.append(context)
                context = result
            elif isinstance(result, str):
                prompt_utils.output_text(result)
        except base.CommandError as ce:
            logger.warning(ce.message)
        except EOFError:
            break
        except KeyboardInterrupt:
            pass
        except Exception as e:
            logger.debug(e, exc_info=True)
            logger.error('An unexpected error occurred: %s. Type "debug" to toggle verbose error output', e)

        if keeper_config.batch_mode and error_no != 0 and not suppress_errno:
            break


def display_command_help(commands: base.CliCommands):
    alias_lookup = {x[1]: x[0] for x in commands.aliases.items()}
    all_scopes = {x[1]: x[1].name for x in commands.commands.values()}
    scopes = sorted(all_scopes.keys())
    headers = ['', 'Command', 'Alias', '', 'Description']
    table = []
    for scope in scopes:
        scope_commands = [key for key, value in commands.commands.items() if value[1] == scope]
        idx = 0
        for cmd in sorted(scope_commands):
            c = commands.commands[cmd][0]
            table.append([all_scopes[scope] if idx == 0 else '', cmd, alias_lookup.get(cmd) or '', '...', c.description()])
            idx += 1

    prompt_utils.output_text('\nCommands:')
    report_utils.dump_report_data(table, headers, no_header=True)
    prompt_utils.output_text('', 'Type \'help command\' to display help on command')
