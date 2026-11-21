import unittest
from hashlib import sha256
from types import SimpleNamespace
from zcu.known_keys import (
    find_key,
    get_all_keys,
    run_keygens,
    run_all_keygens,
    run_any_keygen,
    mac_to_str,
    tagparams_keygen,
)


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
        params = SimpleNamespace(signature="ZXHN H298A V1.0", serial=" HELLO")
        res = run_keygens(params)[0]
        self.assertEqual(res[0], "8cc72b05705d5c46 HELLO")
        self.assertEqual(res[1], "667b02a85c61c786 HELLO")

    def test_run_serial_keygen_custom(self):
        params = SimpleNamespace(
            signature="ZXHN H298A V1.0",
            key_prefix="HI",
            iv_prefix="HELLO",
            serial=" THERE",
        )
        res = run_keygens(params)[0]
        self.assertEqual(res[0], "HI THERE")
        self.assertEqual(res[1], "HELLO THERE")

    def test_run_signature_keygen_h168n(self):
        params = SimpleNamespace(signature="ZXHN H168N V3.5")
        res = run_keygens(params)[0]
        self.assertEqual(res[0], "ZXHNH168NV3.5Key02721401")
        self.assertEqual(res[1], "ZXHNH168NV3.5Iv02721401")

    def test_run_signature_keygen_h268q(self):
        params = SimpleNamespace(signature="ZXHN H268Q V7.0")
        res = run_keygens(params)[0]
        self.assertEqual(res[0], "ZXHNH268QV7.0Key02710010")
        self.assertEqual(res[1], "ZXHNH268QV7.0Iv02710010")

    def test_run_signature_keygen_h1600(self):
        params = SimpleNamespace(signature="ZTE H1600")
        res = run_keygens(params)[0]
        self.assertEqual(res[0], "ZTEH1600Key02670001")
        self.assertEqual(res[1], "ZTEH1600Iv02670001")

    def test_run_signature_keygen_h196a(self):
        params = SimpleNamespace(signature="H196A V9")
        res = run_keygens(params)[0]
        self.assertEqual(res[0], "H196AV9Key02660001")
        self.assertEqual(res[1], "H196AV9Iv02660001")

    def test_run_tagparams_keygen_h288a(self):
        params = SimpleNamespace(
            signature="H288A",
            serial="A1B2C3D4",
            mac="00:11:22:33:44:55",
            longPass="deadbeefdeadbeef",
        )
        res = run_any_keygen(params, "tagparams")
        self.assertEqual(res[0], "deadbeefdeadbeefA1B2C3D4Mcd5c46e")
        self.assertEqual(
            res[1], "G21b667b00:11:22:33:44:55deadbeefdeadbeef"
        )

    def test_run_tagparams_keygen_hv3601p(self):
        params = SimpleNamespace(
            signature="",
            serial="ZTEYH9KQ5900772",
            mac="c8:98:28:40:58:95",
            longPass="D6%6%&f9Nxe7^bcRD6dGu^EFHuc$4Tyt",
        )
        key, iv, source = tagparams_keygen(params)
        self.assertEqual(
            key, "D6%6%&f9Nxe7^bcRD6dGu^EFHuc$4TytZTEYH9KQ5900772Mcd5c46e"
        )
        self.assertEqual(sha256(key.encode()).hexdigest(), "6f1210f853bd4c617d8d9c2ef8c510a366eb27dbe404d2c4f19af80fd63c2b3e")
        self.assertTrue(source.startswith("tagparams:"))

    def test_run_all_keygens(self):
        params = SimpleNamespace(signature="ZXHN H268Q V7.X", serial="Test")
        res = run_all_keygens(params)
        goodRes = (
            "ZXHNH268QV7.XKey02710010",
            "ZXHNH268QV7.XIv02710010",
            "signature: 'ZXHN H268Q V7.X'",
        )
        self.assertIn(goodRes, res)

    def test_mac_to_str(self):
        macStr = "00:1234:56Aa:bB"
        self.assertEqual(mac_to_str(macStr), "00:12:34:56:aa:bb")


if __name__ == "__main__":
    unittest.main()
