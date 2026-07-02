from unittest import TestCase, mock

from keepersdk import generator


class TestKeeperPassphraseGenerator(TestCase):

    def test_default_generates_five_hyphen_separated_words(self):
        gen = generator.KeeperPassphraseGenerator()
        with mock.patch('secrets.choice', side_effect=['alpha', 'bravo', 'charlie', 'delta', 'echo']):
            with mock.patch('secrets.randbelow', return_value=3):
                result = gen.generate()
        self.assertEqual(result, 'Alpha3-Bravo-Charlie-Delta-Echo')

    def test_does_not_shuffle_words_like_diceware(self):
        gen = generator.KeeperPassphraseGenerator(
            word_count=5, separator=' ', capitalize=False, append_number=False)
        with mock.patch('secrets.choice', side_effect=['one', 'two', 'three', 'four', 'five']):
            result = gen.generate()
        self.assertEqual(result, 'one two three four five')

    def test_capitalize_applies_to_every_word_number_to_first_word_only(self):
        gen = generator.KeeperPassphraseGenerator(
            word_count=5, separator='-', capitalize=True, append_number=True)
        with mock.patch('secrets.choice', side_effect=['alpha', 'bravo', 'charlie', 'delta', 'echo']):
            with mock.patch('secrets.randbelow', return_value=7):
                result = gen.generate()
        self.assertEqual(result, 'Alpha7-Bravo-Charlie-Delta-Echo')

    def test_create_from_policy_honors_passphrase_fields(self):
        gen = generator.KeeperPassphraseGenerator.create_from_policy({
            'passphrase-length': 5,
            'passphrase-separator': '-',
            'passphrase-capitalize': True,
            'passphrase-number': True,
        })
        with mock.patch('secrets.choice', side_effect=['alpha', 'bravo', 'charlie', 'delta', 'echo']):
            with mock.patch('secrets.randbelow', return_value=4):
                result = gen.generate()
        self.assertEqual(result, 'Alpha4-Bravo-Charlie-Delta-Echo')

    def test_parse_passphrase_gen_parameters(self):
        opts, error = generator.parse_passphrase_gen_parameters(
            ['passphrase', '7', '_', 'true', 'false'])
        self.assertIsNone(error)
        self.assertEqual(opts.word_count, 7)
        self.assertEqual(opts.separator, '_')
        self.assertTrue(opts.capitalize)
        self.assertFalse(opts.append_number)

    def test_parse_passphrase_rejects_invalid_separator(self):
        _, error = generator.parse_passphrase_gen_parameters(
            ['passphrase', '7', '@', 'true', 'true'])
        self.assertIn('Invalid passphrase separator', error)

    def test_parse_passphrase_rejects_invalid_boolean(self):
        _, error = generator.parse_passphrase_gen_parameters(
            ['passphrase', '7', '_', 'tr', 'true'])
        self.assertIn('capitalize', error)

    def test_parse_passphrase_rejects_trailing_comma(self):
        _, error = generator.parse_passphrase_gen_parameters(
            ['passphrase', '9', '_', 'true', ''])
        self.assertIn('missing value after comma', error)

    def test_parse_passphrase_rejects_extra_parameters(self):
        _, error = generator.parse_passphrase_gen_parameters(
            ['passphrase', '7', '_', 'true', 'true', 'test'])
        self.assertIn('Unexpected', error)

    def test_parse_passphrase_rejects_out_of_range_word_count(self):
        _, error = generator.parse_passphrase_gen_parameters(['passphrase', '12'])
        self.assertIn('between 5 and 9', error)

    def test_create_with_options_overrides_policy(self):
        policy = {
            'passphrase-length': 5,
            'passphrase-separator': '-',
            'passphrase-capitalize': False,
            'passphrase-number': False,
        }
        gen = generator.KeeperPassphraseGenerator.create_with_options(
            policy, word_count=3, separator='_', capitalize=True, append_number=True)
        self.assertEqual(gen.word_count, 5)
        self.assertEqual(gen.separator, '_')
        self.assertTrue(gen.capitalize)
        self.assertTrue(gen.append_number)

    def test_commander_defaults_override_policy_capitalize_and_number(self):
        gen = generator.KeeperPassphraseGenerator.create_with_options({
            'passphrase-capitalize': False,
            'passphrase-number': False,
        })
        self.assertTrue(gen.capitalize)
        self.assertTrue(gen.append_number)

    def test_policy_separator_uses_vault_order_not_raw_first_char(self):
        gen = generator.KeeperPassphraseGenerator.create_with_options({
            'passphrase-separator': '!._?-',
        })
        self.assertEqual(gen.separator, '-')

    def test_invalid_separator_override_is_rejected_by_parser(self):
        _, error = generator.parse_passphrase_gen_parameters(
            ['passphrase', '7', '~', 'true', 'true'])
        self.assertIn('Invalid passphrase separator', error)

    def test_word_count_clamped_to_vault_range(self):
        self.assertEqual(generator.clamp_passphrase_word_count(2), 5)
        self.assertEqual(generator.clamp_passphrase_word_count(9), 9)
        self.assertEqual(generator.clamp_passphrase_word_count(12), 9)

    def test_word_count_clamp_logs_warning(self):
        with mock.patch('keepersdk.generator.logging.warning') as mock_warning:
            generator.clamp_passphrase_word_count(12)
        mock_warning.assert_called_once()
        args, _ = mock_warning.call_args
        self.assertIn('between', args[0])
        self.assertEqual(args[1:], (5, 9, 9))

    def test_loads_bundled_diceware_wordlist(self):
        words = generator._load_wordlist()
        self.assertEqual(len(words), 7776)
        self.assertEqual(words[0], 'abacus')

    def test_resolve_gen_password_algorithm_rejects_typos(self):
        algorithm, error = generator.resolve_gen_password_algorithm(['passphra'])
        self.assertIsNone(algorithm)
        self.assertIn('passphrase', error)

    def test_resolve_gen_password_algorithm_accepts_numeric_length(self):
        algorithm, error = generator.resolve_gen_password_algorithm(['16'])
        self.assertEqual(algorithm, 'rand')
        self.assertIsNone(error)
