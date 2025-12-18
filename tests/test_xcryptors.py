import struct
import unittest

from zcu.xcryptors import CBCXcryptor, Xcryptor


class TestXcryptor(unittest.TestCase):

    ZXHN_H298N_config = "resources/ZXHN_H298N.bin"
    ZXHN_H298N_zlib = "resources/ZXHN_H298N.zlib"
    ZXHN_H298N_key = "Wj"

    ZXHN_H108N_V25_config = "resources/ZXHN_H108N_V2.5.bin"
    ZXHN_H108N_V25_zlib = "resources/ZXHN_H108N_V2.5.zlib"
    ZXHN_H108N_V25_key = "GrWM2Hz&LTvz&f^5"

    ZXHN_H168N_V31_config = "resources/ZXHN_H168N_V3.1.bin"
    ZXHN_H168N_V31_zlib = "resources/ZXHN_H168N_V3.1.zlib"
    ZXHN_H168N_V31_key = "GrWM3Hz&LTvz&f^9"

    ZXHN_H168N_V35_config = "resources/ZXHN_H168N_V3.5.bin"
    ZXHN_H168N_V35_zlib = "resources/ZXHN_H168N_V3.5.zlib"
    ZXHN_H168N_V35_sig = "ZXHNH168NV3.5"
    ZXHN_H168N_V35_key = ZXHN_H168N_V35_sig + "Key02721401"
    ZXHN_H168N_V35_iv = ZXHN_H168N_V35_sig + "Iv02721401"

    ZXHN_H298Q_C7_db_type3 = "resources/ZXHN_H298Q_C7_db_type3.bin"
    ZXHN_H298Q_C7_db_type0 = "resources/ZXHN_H298Q_C7_db_type0.bin"
    ZXHN_H298Q_C7_db_key = "H298Q"

    def test_zxhn_h298n_decryption(self):
        with open(self.ZXHN_H298N_config, "rb") as inFile:
            inFile.seek(210)
            xcryptor = Xcryptor(self.ZXHN_H298N_key)
            res = xcryptor.decrypt(inFile)
            with open(self.ZXHN_H298N_zlib, "rb") as goodFile:
                goodBytes = goodFile.read()
            self.assertEqual(res.read(), goodBytes)

    def test_zxhn_h298n_decryption_change_key(self):
        with open(self.ZXHN_H298N_config, "rb") as inFile:
            inFile.seek(210)
            xcryptor = Xcryptor()
            xcryptor.set_key(self.ZXHN_H298N_key)
            res = xcryptor.decrypt(inFile)
            with open(self.ZXHN_H298N_zlib, "rb") as goodFile:
                goodBytes = goodFile.read()
            self.assertEqual(res.read(), goodBytes)

    def test_zxhn_h108n_v25_decryption(self):
        with open(self.ZXHN_H108N_V25_config, "rb") as inFile:
            inFile.seek(215)
            xcryptor = Xcryptor(self.ZXHN_H108N_V25_key)
            res = xcryptor.decrypt(inFile)
            resBytes = res.read()
            self.assertEqual(6528, len(resBytes))
            with open(self.ZXHN_H108N_V25_zlib, "rb") as goodFile:
                goodBytes = goodFile.read()
            self.assertEqual(resBytes, goodBytes)

    def test_zxhn_h168n_v31_decryption(self):
        with open(self.ZXHN_H168N_V31_config, "rb") as inFile:
            inFile.seek(215)
            xcryptor = Xcryptor(self.ZXHN_H168N_V31_key)
            res = xcryptor.decrypt(inFile)
            resBytes = res.read()
            self.assertEqual(8672, len(resBytes))
            with open(self.ZXHN_H168N_V31_zlib, "rb") as goodFile:
                goodBytes = goodFile.read()
            self.assertEqual(resBytes, goodBytes)

    def test_zxhn_h168n_v35_decryption(self):
        with open(self.ZXHN_H168N_V35_config, "rb") as inFile:
            inFile.seek(87)
            xcryptor = CBCXcryptor()
            xcryptor.set_key(self.ZXHN_H168N_V35_key, self.ZXHN_H168N_V35_iv)
            res = xcryptor.decrypt(inFile)
            with open(self.ZXHN_H168N_V35_zlib, "rb") as goodFile:
                goodBytes = goodFile.read()
            self.assertEqual(res.read(), goodBytes)

    def test_zxhn_h298q_db_decryption(self):
        with open(self.ZXHN_H298Q_C7_db_type3, "rb") as inFile:
            inFile.seek(60)
            xcryptor = CBCXcryptor(self.ZXHN_H298Q_C7_db_key)
            res = xcryptor.decrypt(inFile)
            with open(self.ZXHN_H298Q_C7_db_type0, "rb") as goodFile:
                goodBytes = goodFile.read()
            self.assertEqual(res.read(), goodBytes)

    def test_zxhn_h298n_encryption(self):
        with open(self.ZXHN_H298N_zlib, "rb") as inFile:
            xcryptor = Xcryptor(self.ZXHN_H298N_key, chunk_size=65536)
            data = xcryptor.encrypt(inFile)
            header = struct.unpack(">15I", data.read(60))
            payloadData = data.read()
            self.assertEqual(0x01020304, header[0])  # magic
            self.assertEqual(2, header[1])  # aes128ecb
            self.assertEqual(0, header[2])  # unencrypted size (n/a)
            self.assertEqual(18504, header[3])  # payload + header size
            self.assertEqual(65536, header[4])  # block size
            self.assertEqual(0, header[5])  # data crc (n/a)
            self.assertEqual(0, header[6])  # header crc
            self.assertEqual(18444, len(payloadData))  # payload without header
            with open(self.ZXHN_H298N_config, "rb") as goodFile:
                goodFile.seek(210)
                goodData = goodFile.read()
            self.assertEqual(payloadData, goodData)

    def test_zxhn_h108n_v25_encryption(self):
        with open(self.ZXHN_H108N_V25_zlib, "rb") as inFile:
            xcryptor = Xcryptor(self.ZXHN_H108N_V25_key, chunk_size=65536)
            data = xcryptor.encrypt(inFile)
            header = struct.unpack(">15I", data.read(60))
            payloadData = data.read()
            self.assertEqual(0x01020304, header[0])  # magic
            self.assertEqual(2, header[1])  # aes128ecb
            self.assertEqual(0, header[2])  # unencrypted size (n/a)
            self.assertEqual(6600, header[3])  # payload + header size
            self.assertEqual(65536, header[4])  # block size
            self.assertEqual(0, header[5])  # data crc (n/a)
            self.assertEqual(0, header[6])  # header crc
            self.assertEqual(6540, len(payloadData))  # payload without header
            with open(self.ZXHN_H108N_V25_config, "rb") as goodFile:
                goodFile.seek(215)
                goodData = goodFile.read()
            self.assertEqual(payloadData, goodData)

    def test_zxhn_h168n_v31_encryption(self):
        with open(self.ZXHN_H168N_V31_zlib, "rb") as inFile:
            xcryptor = Xcryptor(
                self.ZXHN_H168N_V31_key,
                chunk_size=65536,
                include_unencrypted_length=True,
            )
            data = xcryptor.encrypt(inFile)
            header = struct.unpack(">15I", data.read(60))
            payloadData = data.read()
            self.assertEqual(0x01020304, header[0])  # magic
            self.assertEqual(2, header[1])  # aes128ecb
            self.assertEqual(8672, header[2])  # unencrypted size
            self.assertEqual(8744, header[3])  # payload + header size
            self.assertEqual(65536, header[4])  # block size
            self.assertEqual(0, header[5])  # data crc (n/a)
            self.assertEqual(0, header[6])  # header crc
            self.assertEqual(8684, len(payloadData))  # payload without header
            with open(self.ZXHN_H168N_V31_config, "rb") as goodFile:
                goodFile.seek(215)
                goodData = goodFile.read()
            self.assertEqual(payloadData, goodData)

    def test_zxhn_h168n_v35_encryption(self):
        with open(self.ZXHN_H168N_V35_zlib, "rb") as inFile:
            xcryptor = CBCXcryptor(chunk_size=65536)
            xcryptor.set_key(self.ZXHN_H168N_V35_key, self.ZXHN_H168N_V35_iv)
            data = xcryptor.encrypt(inFile)
            header = struct.unpack(">15I", data.read(60))
            payloadData = data.read()
            self.assertEqual(0x01020304, header[0])  # magic
            self.assertEqual(4, header[1])  # aes256cbc(Key!=IV)
            self.assertEqual(0, header[2])  # unencrypted size
            self.assertEqual(0, header[3])  # payload + header size
            self.assertEqual(0, header[4])  # block size
            self.assertEqual(0, header[5])  # data crc (n/a)
            self.assertEqual(0, header[6])  # header crc
            self.assertEqual(10780, len(payloadData))  # payload without header
            with open(self.ZXHN_H168N_V35_config, "rb") as goodFile:
                goodFile.seek(87)
                goodData = goodFile.read()
            self.assertEqual(payloadData, goodData)

    def test_zxhn_h298q_db_encryption(self):
        with open(self.ZXHN_H298Q_C7_db_type0, "rb") as inFile:
            xcryptor = CBCXcryptor(self.ZXHN_H298Q_C7_db_key)
            data = xcryptor.encrypt(inFile)
            header = struct.unpack(">15I", data.read(60))
            payloadData = data.read()
            self.assertEqual(0x01020304, header[0])  # magic
            self.assertEqual(3, header[1])  # aes256cbc(Key==IV)
            self.assertEqual(0, header[2])  # unencrypted size
            self.assertEqual(0, header[3])  # payload + header size
            self.assertEqual(0, header[4])  # block size
            self.assertEqual(0, header[5])  # data crc (n/a)
            self.assertEqual(0, header[6])  # header crc
            self.assertEqual(7052, len(payloadData))  # payload without header
            with open(self.ZXHN_H298Q_C7_db_type3, "rb") as goodFile:
                goodFile.seek(60)
                goodData = goodFile.read()
            self.assertEqual(payloadData, goodData)


if __name__ == "__main__":
    unittest.main()
