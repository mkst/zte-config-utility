
import struct
import hashlib

# 32-bit right rotation
def rotr32(a, c):
    return ((a >> c) | (a << (32 - c))) & 0xFFFFFFFF

ROUND_CONSTANTS = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

def _sha256_raw_digest(message):
    """Processes an already padded SHA-256 message"""

    # Initialize hash value
    digest = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ]

    # Process message in 64 byte chunks
    for chunk in range(0, len(message), 64):
        chunk = message[chunk : chunk + 64]

        # Unpack chunk into 32-bit words in big endian
        w = list(struct.unpack('>' + 'I' * 16, chunk))

        # Extend chunk into the remaining 48 words of the message schedule array
        for i in range(16, 64):
            s0 = rotr32(w[-15], 7) ^ rotr32(w[-15], 18) ^ (w[-15] >> 3)
            s1 = rotr32(w[-2], 17) ^ rotr32(w[-2], 19) ^ (w[-2] >> 10)
            w.append((w[-16] + s0 + w[-7] + s1) & 0xFFFFFFFF)

        # Initialize working variables to current hash value
        a, b, c, d, e, f, g, h = digest

        # Main compression loop
        for r_w, r_k in zip(w, ROUND_CONSTANTS):
            S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)
            ch = (e & f) ^ ((e ^ 0xFFFFFFFF) & g)
            temp1 = (h + S1 + ch + r_k + r_w)
            S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj)

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        # Add the result to the current digest
        digest = [(x + y) & 0xFFFFFFFF for x, y in zip(digest, (a, b, c, d, e, f, g, h))]

    # Pack the words in big-endian, and return as the digest
    return struct.pack('>' + 'I' * 8, *digest)

def buggy_sha256(message):
    """
    This function implements the buggy SHA-256 function available at
    https://github.com/ilvn/SHA256/blob/d8d69dbfeeb68f31e74f8e24971332e996eed76b/mark2/sha256.c,
    in that specific commit.

    This function is what the ZTE Z3600P router is using in the libsha256.so library, for
    derivating the configuration encryption key and IV.
    """

    # Process depending on the length of last chunk 64-byte chunk in the message
    last_chunk_len = len(message) % 64

    # If 0 to 55, all is ok, so process as regular SHA2
    if last_chunk_len <= 55:
        return hashlib.sha256(message).digest()

    # Pack message length in bits
    packed_len = struct.pack('>Q', 8 * len(message))

    # If 56 bytes:
    #  - No extra padding block is added, despite being necessary.
    #  - The total message length overwrites the 0x80 end-of-message marker.
    if last_chunk_len == 56:
        return _sha256_raw_digest(message + packed_len)

    # If 57-63:
    #  - End of message bit present
    #  - Zeros added as padding within current block as expected
    #  - Padding in padding block, instead of being zeros, uses bytes from last block due to memory
    #    not being cleared.
    message += b'\x80' + b'\x00' * (64 - last_chunk_len - 1)
    message += message[-64 : -8] + packed_len
    return _sha256_raw_digest(message)

if __name__ == '__main__':
    buggy_vectors = [
        ('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', b''),
        ('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', b'abc'),
        ('595615dbe4f0f407ae397d08b4c2cb870cb9b0e11937416f950c5160acf9c005', b'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabc'),
        ('f20ff09b1fa20a39ccb8d76c02f21456ac8b559d9d9cc1c56b9d8b7cbdfce24c', b'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd'),
        ('999da187e473b98511f18db3e0c06c3b15981113a06d79f6a3bf1692f3006ddc', b'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcde'),
        ('2734836623ac4b137d13d30f987708c1eff4c411b9f7965ab255c0117f630472', b'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk'),
    ]
    for correct, inp in buggy_vectors:
        assert(buggy_sha256(inp).hex() == correct)
