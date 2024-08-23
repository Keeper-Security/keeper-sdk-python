import enum
import getpass
import sys

from typing import Optional, List, Set

import prompt_toolkit.formatted_text
from prompt_toolkit import PromptSession, key_binding, filters
from prompt_toolkit.enums import EditingMode
from prompt_toolkit.output.base import Output
from prompt_toolkit.shortcuts import CompleteStyle, print_formatted_text
from prompt_toolkit.auto_suggest import AutoSuggest, Suggestion
from prompt_toolkit.buffer import Buffer
from prompt_toolkit.document import Document
from prompt_toolkit.styles import Style


prompt_session: Optional[PromptSession] = None
_reading_stdin = False


kb = key_binding.KeyBindings()
@kb.add('enter', filter=filters.completion_is_selected)
def _(event):
    event.current_buffer.complete_state = None
    b = event.app.current_buffer
    b.complete_state = None

_output: Output

if sys.stdin.isatty() and sys.stdout.isatty():
    from prompt_toolkit.input.defaults import create_input
    from prompt_toolkit.output.defaults import create_output

    _output = create_output(always_prefer_tty=True)
    prompt_session = PromptSession(multiline=False, complete_while_typing=False,
                                   editing_mode=EditingMode.VI,
                                   complete_style=CompleteStyle.MULTI_COLUMN,
                                   input=create_input(always_prefer_tty=True),
                                   output=_output)
else:
    from prompt_toolkit.output.plain_text import PlainTextOutput
    _output = PlainTextOutput(sys.stdout)


class CommandSuggest(AutoSuggest):
    def __init__(self, commands: List[str]):
        self.commands = commands

    def get_suggestion(self, buffer: Buffer, document: Document) -> Optional[Suggestion]:
        text = document.text.rsplit("\n", 1)[-1].strip()
        if not text:
            return None
        matches = [x for x in self.commands if x.startswith(text)]
        if len(matches) == 1:
            return Suggestion(matches[0][len(text):])
        elif len(matches) > 1:
            i = len(text)
            maxi = min((len(x) for x in matches))
            s: Set[str] = set()
            while i < maxi:
                s.clear()
                s.update((x[i] for x in matches))
                if len(s) > 1:
                    break
                i += 1
            if i > len(text):
                return Suggestion(matches[0][len(text):i])


def cancel_input():
    if prompt_session:
        if prompt_session.app and prompt_session.app.is_running:
            prompt_session.app.exit()
    else:
        global _reading_stdin
        if _reading_stdin:
            print('\nPress <Enter> to continue')


_STYLE = Style([
    ('h3', 'fg:ansigreen bold'),
    ('b', 'bold'),
])

class COLORS(str, enum.Enum):
    WARNING = 'fg:ansiyellow'
    FAIL = 'fg:ansired'

_WARNING = Style([('', 'fg:ansiyellow')])


def output_text(*lines, color: Optional[str]=None):
    style = _STYLE
    if color == 'WARNING':
        style = _WARNING
    print_formatted_text(*lines, sep='\n', style=style, output=_output)

def get_formatted_text(text: str, color: Optional[COLORS]=None) -> prompt_toolkit.formatted_text.FormattedText:
    return prompt_toolkit.formatted_text.FormattedText([(color.value if color else '', text)])

def input_text(prompt, auto_suggest=None):  # type: (str, Optional[AutoSuggest]) -> str
    if prompt_session:
        prompt_session.auto_suggest = auto_suggest
        return prompt_session.prompt(prompt, is_password=False)
    else:
        global _reading_stdin
        _reading_stdin = True
        try:
            text = input(prompt)
            return text
        finally:
            _reading_stdin = False


def input_password(prompt):   # type: (str) -> str
    if prompt_session:
        prompt_session.auto_suggest = None
        return prompt_session.prompt(prompt, is_password=True)
    else:
        global _reading_stdin
        _reading_stdin = True
        try:
            text = getpass.getpass(prompt)
            return text
        finally:
            _reading_stdin = False


def user_choice(question, choice, default='', show_choice=True, multi_choice=False):
    choices = [ch.lower() if ch.upper() == default.upper() else ch.lower() for ch in choice]

    result = ''
    while True:
        pr = question
        if show_choice:
            pr = pr + ' [' + '/'.join(choices) + ']'

        pr = pr + ': '
        result = input_text(pr)

        if len(result) == 0:
            return default

        if multi_choice:
            s1 = set([x.lower() for x in choices])
            s2 = set([x.lower() for x in result])
            if s2 < s1:
                return ''.join(s2)
            pass
        elif any(map(lambda x: x.upper() == result.upper(), choices)):
            return result
