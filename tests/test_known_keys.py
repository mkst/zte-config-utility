import unittest

from zcu.known_keys import find_key, get_all_keys


class TestPublicMethods(unittest.TestCase):
    def test_find_key(self):
        res = find_key("zxhn h298a")
        self.assertEqual(b"m8@96&ZG3Nm7N&Iz", res)

    def test_find_key_not_present(self):
        res = find_key("foobar")
        self.assertEqual(None, res)

    def test_get_all_keys(self):
        res = get_all_keys()
        self.assertTrue(len(res) > 0)
