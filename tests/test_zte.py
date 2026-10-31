import struct
import unittest
from io import BytesIO

import zcu


class TestHeaderMethods(unittest.TestCase):

    ZXHN_H298N_config = "resources/ZXHN_H298N.bin"
    ZXHN_H298N_signature = b"ZXHN H298N"

    ZXHN_H108N_V25_config = "resources/ZXHN_H108N_V2.5.bin"
    ZXHN_H108N_V25_signature = b"ZXHN H108N V2.5"

    ZXHN_H168N_V35_config = "resources/ZXHN_H168N_V3.5.bin"
    ZXHN_H168N_V35_signature = b"ZXHN H168N V3.5"

    F600W_config = "resources/F600W.bin"
    F600W_signature = b"F600W"

    XML_config = "resources/db_default_auto_cfg.bin"
    XML_signature = b""

    # read_header tests
    def test_zxhn_h298n_read_header(self):
        with open(self.ZXHN_H298N_config, "rb") as infile:
            header_length = zcu.zte.read_header(infile)
            self.assertEqual(128, header_length)

    def test_zxhn_h108n_v25_read_header(self):
        with open(self.ZXHN_H108N_V25_config, "rb") as infile:
            header_length = zcu.zte.read_header(infile)
            self.assertEqual(128, header_length)

    def test_zxhn_h168n_v35_read_header(self):
        with open(self.ZXHN_H168N_V35_config, "rb") as infile:
            header_length = zcu.zte.read_header(infile)
            self.assertEqual(0, header_length)

    def test_f600w_read_header(self):
        with open(self.F600W_config, "rb") as infile:
            header_length = zcu.zte.read_header(infile)
            self.assertEqual(0, header_length)

    def test_xml_read_header(self):
        with open(self.XML_config, "rb") as infile:
            header_length = zcu.zte.read_header(infile)
            self.assertEqual(0, header_length)

    # read_signature tests
    def test_zxhn_h298n_read_signature(self):
        with open(self.ZXHN_H298N_config, "rb") as infile:
            infile.seek(128)
            signature = zcu.zte.read_signature(infile)
            self.assertEqual(self.ZXHN_H298N_signature, signature)

    def test_zxhn_h108n_v25_read_signature(self):
        with open(self.ZXHN_H108N_V25_config, "rb") as infile:
            infile.seek(128)
            signature = zcu.zte.read_signature(infile)
            self.assertEqual(self.ZXHN_H108N_V25_signature, signature)

    def test_zxhn_h168n_v35_read_signature(self):
        with open(self.ZXHN_H168N_V35_config, "rb") as infile:
            signature = zcu.zte.read_signature(infile)
            self.assertEqual(self.ZXHN_H168N_V35_signature, signature)

    def test_f600w_read_signature(self):
        with open(self.F600W_config, "rb") as infile:
            signature = zcu.zte.read_signature(infile)
            self.assertEqual(self.F600W_signature, signature)

    def test_xml_read_signature(self):
        with open(self.XML_config, "rb") as infile:
            signature = zcu.zte.read_signature(infile)
            self.assertEqual(self.XML_signature, signature)

    # read_payload_type tests
    def test_zxhn_h298n_read_payload_type(self):
        with open(self.ZXHN_H298N_config, "rb") as infile:
            infile.seek(150)
            payload_type = zcu.zte.read_payload_type(infile)
            self.assertEqual(2, payload_type)

    def test_zxhn_h108n_v25_read_payload_type(self):
        with open(self.ZXHN_H108N_V25_config, "rb") as infile:
            infile.seek(155)
            payload_type = zcu.zte.read_payload_type(infile)
            self.assertEqual(2, payload_type)

    def test_zxhn_h168n_v35_read_payload_type(self):
        with open(self.ZXHN_H168N_V35_config, "rb") as infile:
            infile.seek(27)
            payload_type = zcu.zte.read_payload_type(infile)
            self.assertEqual(4, payload_type)

    def test_f600w_read_payload_type(self):
        with open(self.F600W_config, "rb") as infile:
            infile.seek(17)
            payload_type = zcu.zte.read_payload_type(infile)
            self.assertEqual(0, payload_type)

    def test_xml_read_payload_type(self):
        with open(self.XML_config, "rb") as infile:
            infile.seek(0)
            payload_type = zcu.zte.read_payload_type(infile)
            self.assertEqual(0, payload_type)

    # add_header tests
    def test_add_header_type_0(self):
        payload = BytesIO()
        payload.write(b"abcdefhi")
        payload.seek(0)
        data = zcu.zte.add_header(payload, b"TEST", 0)

        signature_header = struct.unpack(">3I", data.read(12))
        self.assertEqual(0x04030201, signature_header[0])
        self.assertEqual(0, signature_header[1])
        self.assertEqual(4, signature_header[2])
        signature = struct.unpack(">4s", data.read(4))
        self.assertEqual(b"TEST", signature[0])
        # payload
        self.assertEqual(b"abcdefhi", data.read())

    def test_add_header_type_2(self):
        payload = BytesIO()
        payload.write(b"abcdefhi")
        payload.seek(0)
        data = zcu.zte.add_header(payload, b"TEST", 65536, include_header=True)

        magic = struct.unpack(">4I", data.read(16))
        self.assertEqual(0x99999999, magic[0])
        self.assertEqual(0x44444444, magic[1])
        self.assertEqual(0x55555555, magic[2])
        self.assertEqual(0xAAAAAAAA, magic[3])

        header = struct.unpack(">28I", data.read(112))
        self.assertEqual(65536, header[12])  # version
        self.assertEqual(128, header[13])  # header size (?)
        self.assertEqual(24, header[14])  # payload + signature size

        signature_header = struct.unpack(">3I", data.read(12))
        self.assertEqual(0x04030201, signature_header[0])
        self.assertEqual(0, signature_header[1])
        self.assertEqual(4, signature_header[2])
        signature = struct.unpack(">4s", data.read(4))
        self.assertEqual(b"TEST", signature[0])
        # payload
        self.assertEqual(b"abcdefhi", data.read())


if __name__ == "__main__":
    unittest.main()
