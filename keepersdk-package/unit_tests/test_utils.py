import base64
import unittest
from typing import Type, Any, Tuple, Dict

from keepersdk import utils, crypto
import attrs

from keepersdk.enterprise import types1, private_data

class UtilsTestCase(unittest.TestCase):
    def test_is_email(self):
        self.assertTrue(utils.is_email('username@company.cc'))
        self.assertTrue(utils.is_email('username@sub-domain.company.cc'))
        self.assertTrue(utils.is_email('username@group.sub-domain.company.cc'))
        self.assertFalse(utils.is_email('username-company.cc'))
        self.assertFalse(utils.is_email('username@company'))
        self.assertFalse(utils.is_email('@company.cc'))
        self.assertFalse(utils.is_email('company'))
        self.assertFalse(utils.is_email('username@cc'))

    def test_password_score(self):
        self.assertLessEqual(utils.password_score(' '), 10)
        self.assertEqual(utils.password_score(utils.generate_uid()), 100)

    def test_dataclass(self):
        tree_key = utils.generate_aes_key()
        data = base64.b64decode("CIKAgIDQ/2IogYCAgND/YjJWVFgwRHlFQ1l2aUF6QVZLVUY2VXJQWGU4WllCVlJ4ODhyRVBqZkxGbWtwNXRZYkt1NnFYYjFMYTVnSkRvdktsOXZaWVVwaV9TN01BWGxmTng0em1QaEE=")
        ne = private_data._INodeEntity()
        kk = ne.store(data, tree_key)
        ee: types1.IEnterpriseEntity[types1.Node, int] = ne
        for n in ee.get_all_entities():
            print(n)

    def test_ore(self):
        a: Dict[Tuple[str, int], Any] = {}
        a[('eeee', 33)] = 'rrrrr'
        print(a)
