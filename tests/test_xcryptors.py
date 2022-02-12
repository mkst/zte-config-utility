import struct
import unittest

from zcu.xcryptors import Xcryptor, T4Xcryptor, DigiXcryptor


class TestXcryptor(unittest.TestCase):

    ZXHN_H298N_config = "resources/ZXHN_H298N.bin"
    ZXHN_H298N_zlib = "resources/ZXHN_H298N.zlib"
    ZXHN_H298N_key = b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0Wj"

    ZXHN_H108N_V25_config = "resources/ZXHN_H108N_V2.5.bin"
    ZXHN_H108N_V25_zlib = "resources/ZXHN_H108N_V2.5.zlib"
    ZXHN_H108N_V25_key = b"GrWM2Hz&LTvz&f^5"

    ZXHN_H168N_V31_config = "resources/ZXHN_H168N_V3.1.bin"
    ZXHN_H168N_V31_zlib = "resources/ZXHN_H168N_V3.1.zlib"
    ZXHN_H168N_V31_key = b"GrWM3Hz&LTvz&f^9"

    ZXHN_H168N_V35_config = "resources/ZXHN_H168N_V3.5.bin"
    ZXHN_H168N_V35_zlib = "resources/ZXHN_H168N_V3.5.zlib"
    ZXHN_H168N_V35_key = "ZXHNH168NV3.5"

    def test_zxhn_h298n_decryption(self):
        with open(self.ZXHN_H298N_config, "rb") as infile:
            infile.seek(210)
            xcryptor = Xcryptor(self.ZXHN_H298N_key)
            res = xcryptor.decrypt(infile)
            self.assertEqual(18432, len(res.read()))

    def test_zxhn_h298n_decryption_change_key(self):
        with open(self.ZXHN_H298N_config, "rb") as infile:
            infile.seek(210)
            xcryptor = Xcryptor(b"abcdefghijklmnop")
            xcryptor.set_key(self.ZXHN_H298N_key)
            res = xcryptor.decrypt(infile)
            self.assertEqual(18432, len(res.read()))

    def test_zxhn_h108n_v25_decryption(self):
        with open(self.ZXHN_H108N_V25_config, "rb") as infile:
            infile.seek(215)
            xcryptor = Xcryptor(self.ZXHN_H108N_V25_key)
            res = xcryptor.decrypt(infile)
            self.assertEqual(6528, len(res.read()))

    def test_zxhn_h168n_v31_decryption(self):
        with open(self.ZXHN_H168N_V31_config, "rb") as infile:
            infile.seek(215)
            xcryptor = Xcryptor(self.ZXHN_H168N_V31_key)
            res = xcryptor.decrypt(infile)
            self.assertEqual(8672, len(res.read()))

    def test_zxhn_h168n_v35_decryption(self):
        with open(self.ZXHN_H168N_V35_config, "rb") as infile:
            infile.seek(87)
            xcryptor = T4Xcryptor(self.ZXHN_H168N_V35_key)
            res = xcryptor.decrypt(infile)
            self.assertEqual(10768, len(res.read()))

    def test_zxhn_h298n_encryption(self):
        with open(self.ZXHN_H298N_zlib, "rb") as infile:
            xcryptor = Xcryptor(self.ZXHN_H298N_key, chunk_size=65536)

            data = xcryptor.encrypt(infile)
            header = struct.unpack(">15I", data.read(60))
            self.assertEqual(0x01020304, header[0])    # magic
            self.assertEqual(2, header[1])             # aes
            self.assertEqual(0, header[2])             # unencrypted size (n/a)
            self.assertEqual(18504, header[3])         # payload + header size
            self.assertEqual(65536, header[4])         # block size
            self.assertEqual(0, header[5])             # data crc (n/a)
            self.assertEqual(0, header[6])             # header crc
            self.assertEqual(18444, len(data.read()))  # payload without header

    def test_zxhn_h108n_v25_encryption(self):
        with open(self.ZXHN_H108N_V25_zlib, "rb") as infile:
            xcryptor = Xcryptor(self.ZXHN_H108N_V25_key, chunk_size=65536)
            data = xcryptor.encrypt(infile)
            header = struct.unpack(">15I", data.read(60))
            self.assertEqual(0x01020304, header[0])   # magic
            self.assertEqual(2, header[1])            # aes
            self.assertEqual(0, header[2])            # unencrypted size (n/a)
            self.assertEqual(6600, header[3])         # payload + header size
            self.assertEqual(65536, header[4])        # block size
            self.assertEqual(0, header[5])            # data crc (n/a)
            self.assertEqual(0, header[6])            # header crc
            self.assertEqual(6540, len(data.read()))  # payload without header

    def test_zxhn_h168n_v31_encryption(self):
        with open(self.ZXHN_H168N_V31_zlib, "rb") as infile:
            xcryptor = Xcryptor(self.ZXHN_H168N_V31_key, chunk_size=65536, include_unencrypted_length=True)
            data = xcryptor.encrypt(infile)
            header = struct.unpack(">15I", data.read(60))
            self.assertEqual(0x01020304, header[0])   # magic
            self.assertEqual(2, header[1])            # aes
            self.assertEqual(8672, header[2])         # unencrypted size
            self.assertEqual(8744, header[3])         # payload + header size
            self.assertEqual(65536, header[4])        # block size
            self.assertEqual(0, header[5])            # data crc (n/a)
            self.assertEqual(0, header[6])            # header crc
            self.assertEqual(8684, len(data.read()))  # payload without header

    def test_zxhn_h168n_v35_encryption(self):
        with open(self.ZXHN_H168N_V35_zlib, "rb") as infile:
            xcryptor = T4Xcryptor(self.ZXHN_H108N_V25_key, chunk_size=65536)
            data = xcryptor.encrypt(infile)
            header = struct.unpack(">15I", data.read(60))
            self.assertEqual(0x01020304, header[0])   # magic
            self.assertEqual(4, header[1])            # aes
            self.assertEqual(0, header[2])            # unencrypted size
            self.assertEqual(0, header[3])            # payload + header size
            self.assertEqual(0, header[4])            # block size
            self.assertEqual(0, header[5])            # data crc (n/a)
            self.assertEqual(0, header[6])            # header crc
            self.assertEqual(10780, len(data.read())) # payload without header

if __name__ == "__main__":
    unittest.main()
