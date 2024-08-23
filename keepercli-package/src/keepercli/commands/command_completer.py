from typing import Iterable, Optional, Callable

from prompt_toolkit import completion

from . import base
from .. import autocomplete


class CommandCompleter(completion.Completer):
    def __init__(self,
                 command_collection: base.CommandCollection,
                 on_complete: Optional[Callable[[str, str], Iterable[str]]] = None) -> None:
        self.commands = command_collection
        self.on_complete = on_complete

    def get_completions(self, document, complete_event):
        if not document.is_cursor_at_the_end:
            return
        if not complete_event.completion_requested:
            return

        word_pos = autocomplete.split_text(document.text)
        tokens = [autocomplete.unescape_string(document.text[f:t+1]) for f, t in word_pos]

        cmd = ''
        if  len(tokens) > 0:
            cmd = autocomplete.unquote_string(tokens.pop(0))
            word_pos.pop(0)
            ac = self.commands.get_command_by_alias(cmd)
            if ac:
                cmd = ac

        command = self.commands.get_command_by_name(cmd)
        if command is None:
            if len(tokens) == 0 and document.char_before_cursor != ' ':
                cmds = [x for x in self.commands.query_commands(cmd)]
                cmds.sort()
                for c in cmds:
                    yield completion.Completion(c, start_position=-len(document.text))
            return

        # find last command
        while len(tokens) > 0 and isinstance(command, base.GroupCommand):
            cmd = autocomplete.unquote_string(tokens[0])
            c = command.commands.get(cmd)
            if c:
                command = c
                tokens.pop(0)
                word_pos.pop(0)
            else:
                break

        if len(tokens) == 0 and document.char_before_cursor != ' ':
            return

        if isinstance(command, base.GroupCommand):
            if (len(tokens) == 0 and document.char_before_cursor == ' ') or (len(tokens) == 1 and document.char_before_cursor != ' '):
                if len(tokens) == 1:
                    prefix = autocomplete.unquote_string(tokens.pop(0))
                    t_pos = word_pos.pop(0)[0]
                else:
                    prefix = ''
                    t_pos = len(document.text)
                cmds = [x for x in command.commands.keys() if x.startswith(prefix)]
                cmds.sort()
                for c in cmds:
                    yield completion.Completion(c, start_position=t_pos-len(document.text))
            return
        if isinstance(command, base.ArgparseCommand):
            parser = command.get_parser()
            if parser is None:
                return

            options = {}
            positional = None
            if hasattr(parser, '_actions') and isinstance(parser._actions, list):
                for arg in parser._actions:
                    if arg.dest == 'help':
                        continue
                    if isinstance(arg.option_strings, list) and len(arg.option_strings) > 0:
                        for opt in arg.option_strings:
                            options[opt] = arg
                    else:
                        if positional is None:
                            positional = arg

            expand_arg = None
            expand_prefix = None
            start_pos = 0
            if len(tokens) > 0:
                prefix = autocomplete.unquote_string(tokens[-1])
                t_pos = word_pos[-1]
                start_pos = t_pos[0]-len(document.text)
                if document.char_before_cursor != ' ':
                    if prefix.startswith('-'):
                        h, s, t = prefix.partition('=')
                        if s:
                            if h in options:
                                arg = options[h]
                                if arg.nargs is None:
                                    expand_arg = arg
                                    expand_prefix = t
                        else:
                            for opt in options.keys():
                                if opt.startswith(prefix):
                                    yield completion.Completion(opt, start_position=start_pos)
                            return
                    elif len(tokens) > 1:
                        if tokens[-2] in options:
                            arg = options[tokens[-2]]
                            if arg.nargs is None:
                                expand_arg = arg
                                expand_prefix = prefix
                else:
                    if prefix.startswith('-') and prefix in options:
                        expand_arg = options[prefix]
                        expand_prefix = ''

            if expand_arg is None and positional:
                expand_arg = positional
                if document.char_before_cursor == ' ':
                    expand_prefix = ''
                else:
                    expand_prefix = tokens[-1] if len(tokens) > 0 else ''

            if expand_arg is None:
                return
            if isinstance(expand_arg.choices, list) and len(expand_arg.choices) > 0:
                for c in expand_arg.choices:
                    if c.startswith(expand_prefix):
                        yield completion.Completion(c, start_position=-len(expand_prefix))
            elif expand_arg.metavar is not None:
                if self.on_complete:
                    for exp in self.on_complete(expand_arg.metavar, expand_prefix):
                        yield completion.Completion(exp, start_position=start_pos)


    @staticmethod
    def fix_input(txt):
        is_escape = False
        is_quote = False
        is_double_quote = False
        for c in txt:
            if c == '\\':
                is_escape = not is_escape
            elif not is_escape:
                if c == '\'':
                    if is_double_quote:
                        return None
                    is_quote = not is_quote
                elif c == '"':
                    if is_quote:
                        return None
                    is_double_quote = not is_double_quote

        if is_quote:
            txt = txt + '\''

        if is_double_quote:
            txt = txt + '"'

        return txt
