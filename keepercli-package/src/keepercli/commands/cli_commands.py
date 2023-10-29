import argparse
import logging

from keepersdk import utils
from prompt_toolkit import shortcuts

from . import base, command_history
from ..params import KeeperParams
from .. import prompt_utils

class HelpCommand(base.ArgparseCommand):
    parser = argparse.ArgumentParser(prog='help', description='Displays help on a specific command')
    parser.add_argument('command', action='store', type=str, help='Commander\'s command')

    def __init__(self, commands: base.CliCommands):
        super().__init__(HelpCommand.parser)
        self.commands = commands

    def execute(self, context: KeeperParams, **kwargs):
        cmd = kwargs.get('command')
        if cmd:
            if cmd in self.commands.aliases:
                ali = self.commands.aliases[cmd]
                if type(ali) == tuple:
                    cmd = ali[0]
                else:
                    cmd = ali

            if cmd in self.commands.commands:
                command, _ = self.commands.commands[cmd]
                if isinstance(command, base.ArgparseCommand):
                    parser = command.get_parser()
                    parser.print_help()
                elif isinstance(command, base.GroupCommand):
                    command.print_help(command=cmd)
                else:
                    print(command.description())


class ClearCommand(base.ICliCommand):
    def execute_args(self, context: KeeperParams, args: str, **kwargs):
        shortcuts.clear()

    def description(self):
        return 'Clear the screen'

class DebugCommand(base.ICliCommand):
    def execute_args(self, context: KeeperParams, args: str, **kwargs):
        logger = utils.get_logger('keeper')
        is_debug = logger.getEffectiveLevel() <= logging.DEBUG
        logger.setLevel((logging.WARNING if context.batch_mode else logging.INFO) if is_debug else logging.DEBUG)
        is_debug = logger.getEffectiveLevel() <= logging.DEBUG
        prompt_utils.output_text('Debug ' + ('ON' if is_debug else 'OFF'))

    def description(self):
        return 'Toggle debug output'


class HistoryCommand(base.ICliCommand):
    def execute_args(self, context: KeeperParams, args: str, **kwargs):
        prompt_utils.output_text('Command history:')
        prompt_utils.output_text('----------------')
        for h in command_history[::-1]:
            prompt_utils.output_text(h)

    def description(self):
        return 'Show command history'