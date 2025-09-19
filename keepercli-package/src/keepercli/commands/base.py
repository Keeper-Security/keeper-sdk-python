import abc
import argparse
import enum
import re
import shlex
import sys
from typing import Optional, Any, Dict, Iterable, Tuple

from keepersdk import errors

from ..helpers import report_utils
from ..params import KeeperParams
from .. import api

json_output_parser = argparse.ArgumentParser(add_help=False)
json_output_parser.add_argument('--format', dest='format', action='store', choices=['table', 'json'],
                                default='table', help='format of output')
json_output_parser.add_argument('--output', dest='output', action='store',
                                help='path to resulting output file (ignored for "table" format)')


report_output_parser = argparse.ArgumentParser(add_help=False)
report_output_parser.add_argument('--format', dest='format', action='store', choices=['table', 'csv', 'json'],
                                  default='table', help='format of output')
report_output_parser.add_argument('--output', dest='output', action='store',
                                  help='path to resulting output file (ignored for "table" format)')


class CommandError(errors.KeeperError):
    def __init__(self, message):
        super().__init__(message)
        self.command = ''

    def __str__(self):
        if self.command:
            return f'{self.command}: {self.message}'
        else:
            return super().__str__()


class ICliCommand(abc.ABC):
    @abc.abstractmethod
    def execute_args(self, context: KeeperParams, args: str, **kwargs):
        pass

    @abc.abstractmethod
    def description(self):
        pass


class CommandScope(enum.IntFlag):
    Account = enum.auto()
    Vault = enum.auto()
    Enterprise = enum.auto()
    MSP = enum.auto()
    Distributor = enum.auto()
    Common = enum.auto()


class CommandCollection(abc.ABC):
    @abc.abstractmethod
    def get_command_by_alias(self, alias: str) -> Optional[str]:
        pass

    @abc.abstractmethod
    def get_command_by_name(self, command: str) -> Optional[ICliCommand]:
        pass

    @abc.abstractmethod
    def query_commands(self, prefix) -> Iterable[str]:
        pass


class CliCommands(CommandCollection):
    def __init__(self) -> None:
        self.commands: Dict[str, Tuple[ICliCommand, CommandScope]] = {}
        self.aliases: Dict[str, str] = {}

    def register_command(self, name: str, cmd: ICliCommand, scope: CommandScope, alias: Optional[str]=None) -> None:
        self.commands[name] = (cmd, scope)
        if alias:
            self.aliases[alias] = name

    def get_command_by_alias(self, alias: str) -> Optional[str]:
        return self.aliases.get(alias)

    def get_command_by_name(self, command: str) -> Optional[ICliCommand]:
        cmd = self.commands.get(command)
        if isinstance(cmd, tuple):
            return cmd[0]

    def query_commands(self, prefix) -> Iterable[str]:
        for key in self.commands.keys():
            if key.startswith(prefix):
                yield key


class GetterSetterCommand(ICliCommand):
    def __init__(self, attr_name, attr_description):
        self._description = f'Sets or displays {attr_description}'
        self._attr_name = attr_name
        self._attr_description = attr_description

    def description(self):
        return self._description

    def execute_args(self, context: KeeperParams, args: str, **kwargs):
        value = self.validate(args)
        if hasattr(context, self._attr_name):
            if args:
                setattr(context, self._attr_name, value)
            else:
                return getattr(context, self._attr_name)

    def validate(self, value: str) -> Any:
        return value


class ParseError(Exception):
    pass


class ArgparseCommand(ICliCommand, abc.ABC):
    def __init__(self, parser: argparse.ArgumentParser):
        super().__init__()
        if parser.exit != ArgparseCommand.suppress_exit:
            setattr(parser, 'exit', ArgparseCommand.suppress_exit)
        if parser.error != ArgparseCommand.raise_parse_exception:
            setattr(parser, 'error', ArgparseCommand.raise_parse_exception)
        self._parser = parser
        self.extra_parameters = ''

    @abc.abstractmethod
    def execute(self, context: KeeperParams, **kwargs):
        pass

    def execute_args(self, context: KeeperParams, args, **kwargs):
        d = {}
        d.update(kwargs)
        self.extra_parameters = ''
        parser = self.get_parser()
        try:
            opts, extra_args = parser.parse_known_args(shlex.split(args))
            if extra_args:
                self.extra_parameters = ' '.join(extra_args)
            d.update(opts.__dict__)
            return self.execute(context, **d)
        except ParseError as e:
            message = str(e)
            if message:
                api.get_logger().warning(message)

    @staticmethod
    def raise_parse_exception(m):
        raise ParseError(m)

    @staticmethod
    def suppress_exit(*args):
        raise ParseError()

    def get_parser(self):
        return self._parser

    def description(self):
        return self._parser.description


class GroupCommand(ICliCommand, CommandCollection):
    def __init__(self, description: str) -> None:
        super().__init__()
        self.aliases: Dict[str, str] = {}
        self.commands: Dict[str, ICliCommand] = {}
        self._description = description
        self.default_verb = ''

    def register_command(self, command: ICliCommand, name: str, alias: Optional[str] = None):
        self.commands[name] = command
        if alias:
            self.aliases[alias] = name

    def description(self):
        return self._description

    def execute_args(self, context: KeeperParams, args, **kwargs):
        verb = ''
        if not args.startswith('-'):
            pos = args.find(' ')
            if pos > 0:
                verb = args[:pos].strip()
                args = args[pos + 1:].strip()
            else:
                verb = args.strip()
                args = ''
        elif args == '-h':
            self.print_help(**kwargs)
            return

        if not verb and self.default_verb:
            verb = self.default_verb
            self.print_help(**kwargs)

        if verb in self.aliases:
            verb = self.aliases[verb]

        if not verb:
            self.print_help(**kwargs)
            return

        command = self.commands.get(verb)
        if not command:
            raise CommandError(f'subcommand \"{verb}\" is not found')

        kwargs['action'] = verb
        return command.execute_args(context, args, **kwargs)

    def print_help(self, **kwargs):
        print(f'{kwargs.get("command")} command [--options]')
        table = []
        headers = ['Command', 'Description']
        for verb, command in self.commands.items():
            row = [verb, command.description()]
            table.append(row)
        print('')
        report_utils.dump_report_data(table, headers=headers)
        print('')

    def get_command_by_alias(self, alias: str) -> Optional[str]:
        return self.aliases.get(alias)

    def get_command_by_name(self, command: str) -> Optional[ICliCommand]:
        return self.commands.get(command)

    def query_commands(self, prefix) -> Iterable[str]:
        for key in self.commands.keys():
            if key.startswith(prefix):
                yield key


parameter_pattern = re.compile(r'\${(\w+)}')


def expand_cmd_args(args, envvars, pattern=parameter_pattern):
    pos = 0
    while True:
        m = pattern.search(args, pos)
        if not m:
            break
        p = m.group(1)
        if p in envvars:
            pv = envvars[p]
            args = args[:m.start()] + pv + args[m.end():]
            pos = m.start() + len(pv)
        else:
            pos = m.end() + 1
    return args


def normalize_output_param(args: str) -> str:
    if sys.platform.startswith('win'):
        # Replace backslashes in output param only if in windows
        args_list = re.split(r'\s+--', args)
        for i, args_grp in enumerate(args_list):
            if re.match(r'(--)*output', args_grp):
                args_list[i] = re.sub(r'\\(\w+)', r'/\1', args_grp)
        args = ' --'.join(args_list)
    return args
