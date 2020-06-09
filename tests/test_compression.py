import struct
import unittest

import zcu


class TestCompressionMethods(unittest.TestCase):

    ZXHN_H298N_xml = 'resources/ZXHN_H298N.xml'
    ZXHN_H298N_zlib = 'resources/ZXHN_H298N.zlib'

    ZXHN_H108N_V25_xml = 'resources/ZXHN_H108N_V2.5.xml'
    ZXHN_H108N_V25_zlib = 'resources/ZXHN_H108N_V2.5.zlib'

    F600W_xml = 'resources/F600W.xml'
    F600W_zlib = 'resources/F600W.zlib'

    def test_zxhn_h298n_compress_helper(self):
        with open(self.ZXHN_H298N_xml, 'rb') as infile:
            data, stats = zcu.compression.compress_helper(infile, 65536)
            header = struct.unpack('>3I', data.read(12))

            self.assertEqual(18370 - 12, len(data.read()))
            self.assertEqual(65536, header[0])  # decompressed_size
            self.assertEqual(6966, header[1])   # compressed_size
            self.assertEqual(7038, header[2])   # cumulative_length 60 + 12 byte headers

            self.assertEqual(2395375672, stats['crc'])
            self.assertEqual(279475, stats['uncompressed_size'])
            self.assertEqual(16194, stats['compressed_size'])

    def test_zxhn_h108n_v25_compress_helper(self):
        with open(self.ZXHN_H108N_V25_xml, 'rb') as infile:
            data, stats = zcu.compression.compress_helper(infile, 65536)
            header = struct.unpack('>3I', data.read(12))

            self.assertEqual(6460 - 12, len(data.read()))  # exclude first header
            self.assertEqual(65536, header[0])  # decompressed_size
            self.assertEqual(5915, header[1])   # compressed_size
            self.assertEqual(5987, header[2])   # cumulative_length 60 + 12 byte headers

            self.assertEqual(2150787823, stats['crc'])
            self.assertEqual(67332, stats['uncompressed_size'])
            self.assertEqual(5987, stats['compressed_size'])

    def test_f600w_compress_helper(self):
        with open(self.F600W_xml, 'rb') as infile:
            data, stats = zcu.compression.compress_helper(infile, 65536)
            header = struct.unpack('>3I', data.read(12))

            self.assertEqual(16542 - 12, len(data.read()))  # exclude first header
            self.assertEqual(65536, header[0])  # decompressed_size
            self.assertEqual(5930, header[1])   # compressed_size
            self.assertEqual(6002, header[2])   # cumulative_length 60 + 12 byte headers

            self.assertEqual(132239431, stats['crc'])
            self.assertEqual(152177, stats['uncompressed_size'])
            self.assertEqual(13983, stats['compressed_size'])

    def test_zxhn_h298n_compress(self):
        with open(self.ZXHN_H298N_xml, 'rb') as infile:
            data = zcu.compression.compress(infile, 65536)
            header = struct.unpack('>15I', data.read(60))
            self.assertEqual(0x01020304, header[0])  # magic
            self.assertEqual(0, header[1])           # zlib
            self.assertEqual(279475, header[2])      # uncompressed size
            self.assertEqual(16194, header[3])       # cumulative compressed
            self.assertEqual(65536, header[4])       # block size
            self.assertEqual(2395375672, header[5])  # data crc
            self.assertEqual(3315187213, header[6])  # header crc
            self.assertEqual(18370, len(data.read()))

    def test_zxhn_h108n_v25_compress(self):
        with open(self.ZXHN_H108N_V25_xml, 'rb') as infile:
            data = zcu.compression.compress(infile, 65536)
            header = struct.unpack('>15I', data.read(60))
            self.assertEqual(0x01020304, header[0])
            self.assertEqual(0, header[1])
            self.assertEqual(67332, header[2])
            self.assertEqual(5987, header[3])
            self.assertEqual(65536, header[4])
            self.assertEqual(2150787823, header[5])
            self.assertEqual(2609256942, header[6])
            self.assertEqual(6460, len(data.read()))

    def test_f600w_compress(self):
        with open(self.F600W_xml, 'rb') as infile:
            data = zcu.compression.compress(infile, 65536)
            header = struct.unpack('>15I', data.read(60))
            self.assertEqual(0x01020304, header[0])
            self.assertEqual(0, header[1])
            self.assertEqual(152177, header[2])
            self.assertEqual(13983, header[3])
            self.assertEqual(65536, header[4])
            self.assertEqual(132239431, header[5])
            self.assertEqual(1739794835, header[6])
            self.assertEqual(16542, len(data.read()))

    def test_zxhn_h298n_decompress(self):
        with open(self.ZXHN_H298N_zlib, 'rb') as infile:
            infile.seek(60)
            data, crc = zcu.compression.decompress(infile)
            xml = data.read(4)
            self.assertEqual(b'<DB>', xml)
            self.assertEqual(2395375672, crc)

    def test_zxhn_h108n_v25_decompress(self):
        with open(self.ZXHN_H108N_V25_zlib, 'rb') as infile:
            infile.seek(60)
            data, crc = zcu.compression.decompress(infile)
            xml = data.read(4)
            self.assertEqual(b'<DB>', xml)
            self.assertEqual(2150787823, crc)

    def test_f600w_decompress(self):
        with open(self.F600W_zlib, 'rb') as infile:
            infile.seek(60)
            data, crc = zcu.compression.decompress(infile)
            xml = data.read(4)
            self.assertEqual(b'<DB>', xml)
            self.assertEqual(132239431, crc)

if __name__ == '__main__':
    unittest.main()
