import argparse
import logging
import os
import platform
import sys

from prompt_toolkit import shortcuts

from keepersdk import constants
from . import base, command_history
from .. import api, prompt_utils, versioning, __version__
from ..helpers import report_utils
from ..params import KeeperParams


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
                if isinstance(ali, tuple):
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
        logger = logging.getLogger()
        is_debug = logger.getEffectiveLevel() <= logging.DEBUG
        logger.setLevel((logging.WARNING if context.keeper_config.batch_mode else logging.INFO) if is_debug else logging.DEBUG)
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


class VersionCommand(base.ArgparseCommand):
    version_parser = argparse.ArgumentParser(prog='version', description='Displays version of the installed Commander')
    version_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='verbose output')
    version_parser.add_argument('-p', '--packages', action='store_true', help='Show installed Python packages')

    def __init__(self):
        super().__init__(VersionCommand.version_parser)

    def execute(self, context, **kwargs):
        logger = api.get_logger()
        version_details = versioning.is_up_to_date_version()
        is_verbose = kwargs.get('verbose', False)
        show_packages = kwargs.get('packages', False)

        this_app_version = __version__

        if version_details.get('is_up_to_date') is None:
            this_app_version = f'{this_app_version} (Current version)'

        table = []
        table.append(['Commander Version', this_app_version])
        if is_verbose:
            if context.auth:
                table.append(['API Client Version', context.auth.keeper_endpoint.client_version])
            else:
                table.append(['API Client Version', constants.CLIENT_VERSION])
            table.append(['Python Version', sys.version.replace("\n", "")])
            if version_details.get('is_up_to_date') is None:
                logger.debug("It appears that Commander is up to date")
            elif not version_details.get('is_up_to_date'):
                latest_version = version_details.get('current_github_version')
                table.append(["Latest version", latest_version])

            p = platform.system()
            if p == 'Darwin':
                p = 'MacOS'
            table.append(['Operating System', f'{p} ({platform.release()})'])
            table.append(['Working directory', os.getcwd()])
            table.append(['Package directory', os.path.dirname(api.__file__)])
            table.append(['Config. File', context.keeper_config.config_filename])
            table.append(['Executable', sys.executable])

        if logger.isEnabledFor(logging.DEBUG) or show_packages:
            ver = sys.version_info
            if ver.major >= 3 and ver.minor >= 8:
                import importlib.metadata
                dist = importlib.metadata.packages_distributions()
                packages = {}
                for pack in dist.values():
                    if isinstance(pack, list) and len(pack) > 0:
                        name = pack[0]
                        if name in packages:
                            continue
                        try:
                            version = importlib.metadata.version(name)
                            packages[name] = version
                        except Exception as e:
                            logger.debug('Get package %s version error: %s', name, e)
                packs = [f'{x[0]}=={x[1]}' for x in packages.items()]
                packs.sort(key=lambda x: x.lower())
                table.append(['Packages', packs])
            else:
                table.append(['Packages', 'Not supported'])
        if versioning.is_binary_app():
            table.append(["Installation path", sys._MEIPASS])

        return report_utils.dump_report_data(table, ('key', 'value'), no_header=True)
