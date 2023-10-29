import logging
import sys
from typing import Optional, Any, Iterable

from prompt_toolkit import PromptSession
from prompt_toolkit.history import History

from . import prompt_utils, constants, api, login, autocomplete
from .commands import command_completer, base, command_history
from .helpers import folder_utils, report_utils
from .params import KeeperParams

if sys.platform == 'win32':
    from colorama import just_fix_windows_console
    just_fix_windows_console()


class KeeperHistory(History):
    def __init__(self):
        super().__init__()

    def load_history_strings(self) -> Iterable[str]:
        yield from command_history[::-1]

    def store_string(self, string: str) -> None:
        pass


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
        last_command = command_history[-1] if len(command_history) > 0 else ''
        if last_command != command_line:
            command_history.append(command_line)
        command, _ = commands.commands[cmd]
        return command.execute_args(context, args, command=orig_cmd)
    else:
        display_command_help(commands)


def loop(context: KeeperParams, commands: base.CliCommands):
    prompt_session: Optional[PromptSession] = None

    def get_prompt() -> str:
        if context.batch_mode:
            return ''
        if context.auth is None:
            return 'Not logged in'
        if context.vault is None:
            return context.auth.auth_context.username

        folder_path = context.vault.root_folder.name
        path = folder_utils.get_folder_path(context.vault, folder_uid=context.current_folder)
        if path:
             folder_path += '/' + path

        if len(folder_path) > 40:
            folder_path = '...' + folder_path[-37:]
        return folder_path

    logger = api.get_logger()
    if not context.batch_mode:
        if context.username:
            login.LoginFlow.login(context)
            # TODO check enforcements
        else:
            if context.server:
                logger.info('Current Keeper region: %s', context.server)
            else:
                logging.info('Use "server" command to change Keeper region > "server US"')
                for region in constants.KEEPER_PUBLIC_HOSTS:
                    logging.info('\t%s: %s', region, constants.KEEPER_PUBLIC_HOSTS[region])
            logging.info('To login type: login <email>')
    else:
        logger.setLevel(logging.DEBUG if context.debug else logging.WARNING)

    if sys.stdin.isatty() and sys.stdout.isatty():
        from prompt_toolkit.enums import EditingMode
        from prompt_toolkit.shortcuts import CompleteStyle
        completer = command_completer.CommandCompleter(commands, autocomplete.standard_completer(context))
        prompt_session = PromptSession(
            multiline=False, editing_mode=EditingMode.VI, complete_style=CompleteStyle.MULTI_COLUMN,
            complete_while_typing=False, completer=completer, auto_suggest=None, key_bindings=prompt_utils.kb,
            history=KeeperHistory())

    while True:
        if context.auth:
            context.auth.on_idle()

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
            break

        suppress_errno = False
        if command.startswith("@"):
            suppress_errno = True
            command = command[1:]
        if context.batch_mode:
            logger.info('> %s', command)
        error_no = 1
        try:
            if context.sync_data:
                if context.vault:
                    context.vault.sync_down()
                context.sync_data = False
            result = do_command(command, context, commands)
            error_no = 0
            if result:
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

        if context.batch_mode and error_no != 0 and not suppress_errno:
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
