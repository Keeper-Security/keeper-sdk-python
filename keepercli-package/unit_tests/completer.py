import unittest
from typing import Iterable

from prompt_toolkit import completion, document

from keepercli import register_commands, autocomplete
from keepercli.commands import command_completer, base


class MyTestCase(unittest.TestCase):
    def test_completion(self):
        cmds = base.CliCommands()
        register_commands.register_commands(cmds)

        history = []
        def fff(meta: str, prefix: str) -> Iterable[str]:
            history.append((meta, prefix))
            return []

        completer = command_completer.CommandCompleter(cmds, fff)

        doc = document.Document('login sko')
        ce = completion.CompleteEvent(completion_requested=True)
        for x in completer.get_completions(doc, ce):
            history.append((x.text, ''))

    def test_parse(self):
        text = 'cmd\tdfg\ e\\wr  "rty pow'
        word_pos = autocomplete.split_text(text)
        self.assertEqual(len(word_pos), 3)
        words = [text[f:t+1] for f, t in word_pos]
        self.assertListEqual(words, ['cmd', 'dfg\ e\\wr', '"rty pow'])

if __name__ == '__main__':
    unittest.main()
