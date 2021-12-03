"""Encryption and decryption helper functions"""

import struct
from io import BytesIO
from Cryptodome.Cipher import AES
from hashlib import sha256

from . import constants


def digi_key(input, is_t4_sign):
    if is_t4_sign:
        plain_key = input + constants.T4_SIGN_BASE_KEY
        plain_iv = input + constants.T4_SIGN_BASE_IV
    else:
        plain_key = constants.DIGIMOBIL_BASE_KEY + input
        plain_iv = constants.DIGIMOBIL_BASE_IV + input
    key = sha256(plain_key.encode('utf-8')).digest()
    iv = sha256(plain_iv.encode('utf-8')).digest()
    return (key, iv)

def aes_decrypt(cipher, aes_key, is_digi=False, is_t4_sign=False):
    """decrypt a block
    A 'block' consists of a 12 byte (3x4-byte INT) header and an AES payload
    HEADER
        [XXXX] Decrypted length
        [XXXX] Encrypted length
        [XXXX] 0
    PAYLOAD
        [....] ZLIB chunk
    """
    is_t4 = is_digi or is_t4_sign
    encrypted_data = BytesIO()
    while True:
        aes_chunk = struct.unpack('>3I', cipher.read(12))
        # aes_chunk[0] -> length not padded
        # aes_chunk[1] -> padded length
        chunk_size = aes_chunk[1] if is_t4 else aes_chunk[0]
        encrypted_data.write(cipher.read(chunk_size))
        if aes_chunk[2] == 0:
            break
    encrypted_data.seek(0)
    if is_t4:
        (key, iv) = digi_key(aes_key, is_t4_sign)
        aes_cipher = AES.new(key, AES.MODE_CBC, iv[:16])
    else:
        aes_cipher = AES.new(aes_key, AES.MODE_ECB)
    decrypted_data = BytesIO()
    decrypted_data.write(aes_cipher.decrypt(encrypted_data.read()))

    decrypted_data.seek(0)
    return decrypted_data


def aes_encrypt(infile, aes_key, chunk_size, include_unencrypted_length=False, is_digi=False, is_t4_sign=False):
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
    is_t4 = is_digi or is_t4_sign
    data = infile.read()
    # pad to 16 byte alignment
    if len(data) % 16 > 0:
        data = data + (16 - len(data) % 16)*b'\0'

    if is_t4:
        (key, iv) = digi_key(aes_key, is_t4_sign)
        encrypted_data = AES.new(key, AES.MODE_CBC, iv[:16]).encrypt(data)
    else:
        encrypted_data = AES.new(aes_key, AES.MODE_ECB).encrypt(data)
    encrypted_data_length = len(encrypted_data)

    header = struct.pack('>6I',
                         constants.PAYLOAD_MAGIC,
                         4 if is_t4 else 2,  # aes
                         encrypted_data_length if include_unencrypted_length else 0,
                         0 if is_t4 else encrypted_data_length + 60 + 12,
                         0 if is_t4 else chunk_size,
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
