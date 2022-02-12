import struct
from io import BytesIO
from hashlib import sha256

from Cryptodome.Cipher import AES

from zcu.constants import PAYLOAD_MAGIC


class Xcryptor():
    """Standard Type 2 encryption"""
    aes_cipher = None
    force_same_data_length = True

    default_key_prefix = None
    default_iv_prefix = None

    def __init__(self, aes_key, chunk_size=65536, include_unencrypted_length=False,
                 key_prefix=None, iv_prefix=None):
        self.chunk_size = chunk_size
        self.include_unencrypted_length = include_unencrypted_length
        # currently unsupported / unused in Xcryptor
        self.key_prefix = key_prefix if key_prefix else self.default_key_prefix
        self.iv_prefix = iv_prefix if iv_prefix else self.default_iv_prefix

        self.set_key(aes_key)

    def set_key(self, aes_key):
        self.aes_cipher = AES.new(aes_key, AES.MODE_ECB)

    def set_iv_prefix(self, iv_prefix):
        raise Exception("Base Xcryptor does not support 'iv_prefix'")

    def set_key_prefix(self, key_prefix):
        raise Exception("Base Xcryptor does not support 'key_prefix'")

    def read_chunks(self, infile):
        """decrypt a block
        A 'block' consists of a 12 byte (3x4-byte INT) header and an AES payload
        HEADER
            [XXXX] Decrypted length
            [XXXX] Encrypted length
            [XXXX] 0
        PAYLOAD
            [....] ZLIB chunk
        """
        encrypted_data = BytesIO()

        while True:
            chunk_size, _, more_chunks = struct.unpack(">3I", infile.read(12))
            encrypted_data.write(infile.read(chunk_size))
            if more_chunks == 0:  # "continue" flag not set
                break
        encrypted_data.seek(0)
        return encrypted_data

    def decrypt(self, infile):
        data = self.read_chunks(infile)
        res = BytesIO()
        res.write(self.aes_cipher.decrypt(data.read()))
        res.seek(0)
        return res

    def create_header(self):
        header = struct.pack(
            ">6I",
            PAYLOAD_MAGIC,
            2,  # aes in ECB mode
            self.unencrypted_data_length if self.include_unencrypted_length else 0,
            self.encrypted_data_length + 60 + 12,
            self.chunk_size,
            0)
        return header

    def encrypt(self, infile):
        """encrypt and add header

        A 'block' consists of a 60 byte (15x4-byte INT) header followed by
        a single PAYLOAD section.

        HEADER
            [XXXX] Magic number '0x01020304'
            [XXXX] Payload type, 2 = AES 4 = digi
            [XXXX] Unencrypted length
            [XXXX] 'block' size (including header)
            [XXXX] Chunk size
            [XXXX....] 40 bytes of padding
        PAYLOAD
            HEADER
                12 byte header
            AES
                'chunk size' payload
        """

        data = infile.read()

        unencrypted_data_length = len(data)
        self.unencrypted_data_length = unencrypted_data_length

        # pad to 16 byte alignment
        if unencrypted_data_length % 16 > 0:
            data = data + (16 - unencrypted_data_length % 16)*b"\0"

        encrypted_data = self.aes_cipher.encrypt(data)
        encrypted_data_length = len(encrypted_data)
        self.encrypted_data_length = encrypted_data_length

        header = self.create_header()

        result = BytesIO()
        result.write(header)
        # 36 bytes of padding
        result.write(struct.pack(">9I", *(9 * [0])))
        # mini header for aes payload
        aes_header = struct.pack(
            ">3I",
            *(encrypted_data_length if self.force_same_data_length else unencrypted_data_length,
              encrypted_data_length,
              0)
        )
        result.write(aes_header)
        result.write(encrypted_data)
        result.seek(0)
        return result


class T4Xcryptor(Xcryptor):
    # type 4 encryption, using signature for key/iv
    default_key_prefix = "Key02721401"
    default_iv_prefix = "Iv02721401"

    force_same_data_length = False

    def set_key_prefix(self, key_prefix):
        self.key_prefix = key_prefix

    def set_iv_prefix(self, iv_prefix):
        self.iv_prefix = iv_prefix

    def set_key(self, aes_key):
        if isinstance(aes_key, bytes):
            aes_key_str = aes_key.decode("utf8")
        else:
            aes_key_str = aes_key
        plain_key = self.key_prefix + aes_key_str
        plain_iv = self.iv_prefix + aes_key_str
        key = sha256(plain_key.encode("utf8")).digest()
        iv = sha256(plain_iv.encode("utf8")).digest()

        self.aes_cipher = AES.new(key, AES.MODE_CBC, iv[:16])

    def read_chunks(self, infile):
        encrypted_data = BytesIO()
        while True:
            _, chunk_size, more_data = struct.unpack(">3I", infile.read(12))
            encrypted_data.write(infile.read(chunk_size))
            if more_data == 0:
                break
        encrypted_data.seek(0)
        return encrypted_data

    def create_header(self):
        header = struct.pack(
            ">6I",
            PAYLOAD_MAGIC,
            4,  # aes in CBC mode
            self.encrypted_data_length if self.include_unencrypted_length else 0,
            0,
            0,
            0)
        return header


class DigiXcryptor(T4Xcryptor):
    """Type 4 Encryption, using serial for key/iv (digimobil)"""
    default_key_prefix = "8cc72b05705d5c46"
    default_iv_prefix = "667b02a85c61c786"
