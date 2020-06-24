"""Encryption and decryption helper functions"""

import struct
from io import BytesIO
from Cryptodome.Cipher import AES

from . import constants


def aes_decrypt(cipher, aes_key):
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
        aes_chunk = struct.unpack('>3I', cipher.read(12))
        encrypted_data.write(cipher.read(aes_chunk[0]))
        if aes_chunk[2] == 0:
            break
    encrypted_data.seek(0)
    aes_cipher = AES.new(aes_key, AES.MODE_ECB)
    decrypted_data = BytesIO()
    decrypted_data.write(aes_cipher.decrypt(encrypted_data.read()))

    decrypted_data.seek(0)
    return decrypted_data


def aes_encrypt(infile, aes_key, chunk_size, include_unencrypted_length=False):
    """encrypt and add header

    A 'block' consists of a 60 byte (15x4-byte INT) header followed by
    a single PAYLOAD section.

    HEADER
        [XXXX] Magic number '0x04030201'
        [XXXX] Payload type, 2 = AES
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
    # pad to 16 byte alignment
    if len(data) % 16 > 0:
        data = data + (16 - len(data) % 16)*b'\0'

    encrypted_data = AES.new(aes_key, AES.MODE_ECB).encrypt(data)
    encrypted_data_length = len(encrypted_data)

    header = struct.pack('>6I',
                         constants.PAYLOAD_MAGIC,
                         2,  # aes
                         encrypted_data_length if include_unencrypted_length else 0,
                         encrypted_data_length + 60 + 12,
                         chunk_size,
                         0)
    result = BytesIO()
    result.write(header)
    result.write(struct.pack('>9I', *(0, 0, 0, 0, 0, 0, 0, 0, 0)))
    # mini header for aes payload
    result.write(struct.pack('>3I', *(encrypted_data_length,
                                      encrypted_data_length,
                                      0)))
    result.write(encrypted_data)
    result.seek(0)

    return result
