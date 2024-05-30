import unittest
from types import SimpleNamespace
from zcu.known_keys import find_key, get_all_keys, run_keygens, run_all_keygens, mac_to_str


class TestPublicMethods(unittest.TestCase):
    def test_find_key(self):
        res = find_key("zxhn h298a")
        self.assertEqual("m8@96&ZG3Nm7N&Iz", res)

    def test_find_key_not_present(self):
        res = find_key("foobar")
        self.assertEqual(None, res)

    def test_get_all_keys(self):
        res = get_all_keys()
        self.assertTrue(len(res) > 0)

    def test_run_serial_keygen(self):
        params = SimpleNamespace(signature = "ZXHN H298A V1.0", serial = " HELLO")
        res = run_keygens(params)[0]
        self.assertEqual(res[0], "8cc72b05705d5c46 HELLO")
        self.assertEqual(res[1], "667b02a85c61c786 HELLO")

    def test_run_serial_keygen_custom(self):
        params = SimpleNamespace(signature = "ZXHN H298A V1.0", key_prefix = "HI", iv_prefix = "HELLO", serial = " THERE")
        res = run_keygens(params)[0]
        self.assertEqual(res[0], "HI THERE")
        self.assertEqual(res[1], "HELLO THERE")

    def test_run_signature_keygen_h168n(self):
        params = SimpleNamespace(signature = "ZXHN H168N V3.5")
        res = run_keygens(params)[0]
        self.assertEqual(res[0], "ZXHNH168NV3.5Key02721401")
        self.assertEqual(res[1], "ZXHNH168NV3.5Iv02721401")

    def test_run_signature_keygen_h268q(self):
        params = SimpleNamespace(signature = "ZXHN H268Q V7.0")
        res = run_keygens(params)[0]
        self.assertEqual(res[0], "ZXHNH268QV7.0Key02710010")
        self.assertEqual(res[1], "ZXHNH268QV7.0Iv02710010")

    def test_run_all_keygens(self):
        params = SimpleNamespace(signature = "ZXHN H268Q V7.X", serial = "Test")
        res = run_all_keygens(params)
        goodRes = ("ZXHNH268QV7.XKey02710010", "ZXHNH268QV7.XIv02710010", "signature: 'ZXHN H268Q V7.X'")
        self.assertIn(goodRes, res)

    def test_mac_to_str(self):
        macStr = '00:1234:56Aa:bB'
        self.assertEqual(mac_to_str(macStr), "00:12:34:56:aa:bb")

if __name__ == "__main__":
    unittest.main()
