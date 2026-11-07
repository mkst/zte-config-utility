"""Compression and decompression helper functions"""

import struct
import zlib
from io import BytesIO
from typing import BinaryIO, Optional

from . import constants


def decompress(infile: BinaryIO) -> tuple[BytesIO, int]:
    """decompress a block, return data and crc
    A 'block' consists of a 12 byte (3x4-byte INT) header and a ZLIB payload
    HEADER
        [XXXX] Decompressed length of block (bytes)
        [XXXX] Compressed length of block (bytes)
        [XXXX] 0 if last block else cumulative compressed blocks length
    PAYLOAD
        [....] ZLIB chunk
    """
    decompressed_data = BytesIO()
    crc = 0
    while True:
        aes_header = struct.unpack(">3I", infile.read(12))
        decompressed_length = aes_header[0]
        compressed_length = aes_header[1]
        compressed_chunk = infile.read(compressed_length)
        crc = zlib.crc32(compressed_chunk, crc)
        decompressed_chunk = zlib.decompress(compressed_chunk)
        assert decompressed_length == len(
            decompressed_chunk
        ), "header decompressed length mismatch %i vs %i" % (
            decompressed_length,
            len(decompressed_chunk),
        )
        decompressed_data.write(decompressed_chunk)
        if aes_header[2] == 0:
            break
    decompressed_data.seek(0)
    return (decompressed_data, crc)


def compress_helper(
    infile: BinaryIO, chunk_size: int, incorrect_compressed_size: bool = False
) -> tuple[BytesIO, dict]:
    """compression helper, consumes chunk_size segments of infile"""
    # cumulative compressed length includes 60-byte payload header
    # it is the cumulative amount of bytes compressed EXCLUDING the last block
    cumulative_compressed_length = 15 * 4
    total_uncompressed_length = 0
    crc = 0

    compressed_data = BytesIO()
    while True:
        data = infile.read(chunk_size)
        uncompressed_length = len(data)
        if uncompressed_length == 0:
            break

        total_uncompressed_length += uncompressed_length

        compressed_chunk = zlib.compress(data, zlib.Z_BEST_COMPRESSION)
        crc = zlib.crc32(compressed_chunk, crc) & 0xFFFFFFFF

        if uncompressed_length < chunk_size:
            more_chunks = 0
        else:
            # increment cumulative length if not last block
            cumulative_compressed_length += len(compressed_chunk) + 3 * 4
            more_chunks = cumulative_compressed_length

        chunk_header = struct.pack(
            ">3I", uncompressed_length, len(compressed_chunk), more_chunks
        )

        compressed_data.write(chunk_header)
        compressed_data.write(compressed_chunk)

    compressed_data.seek(0)

    if incorrect_compressed_size:
        # some versions incorrectly add the final chunk size twice
        cumulative_compressed_length += len(compressed_chunk) + 3 * 4

    stats = {
        "crc": crc,
        "uncompressed_size": total_uncompressed_length,
        "compressed_size": cumulative_compressed_length,
    }

    return (compressed_data, stats)


def compress(
    infile: BinaryIO, chunk_size: int, incorrect_compressed_size: bool = False
) -> BytesIO:
    """compress and add header

    A 'block' consists of a 60 byte (15x4-byte INT) header followed by
    >=1 PAYLOAD section(s).

    HEADER
        [XXXX] Magic number '0x04030201'
        [XXXX] Payload type, 0 = ZLIB
        [XXXX] Total decompressed length
        [XXXX] Cumulative compressed size* (*not always)
        [XXXX] Decompressed chunk size
        [XXXX] CRC of compressed data
        [XXXX] CRC of first 24 bytes of the header
        [XXXX....] 32 bytes of padding
    PAYLOAD
        HEADER
            12 byte header
        ZLIB
            variable byte payload
    """
    compressed_data, stats = compress_helper(
        infile, chunk_size, incorrect_compressed_size=incorrect_compressed_size
    )

    header = struct.pack(
        ">6I",
        constants.PAYLOAD_MAGIC,
        0,  # no encryption, only zlib compression
        stats["uncompressed_size"],
        stats["compressed_size"],
        chunk_size,
        stats["crc"],
    )
    payload = BytesIO()
    payload.write(header)
    payload.write(struct.pack(">I", zlib.crc32(header) & 0xFFFFFFFF))
    payload.write(struct.pack(">8I", *(0, 0, 0, 0, 0, 0, 0, 0)))
    payload.write(compressed_data.read())
    payload.seek(0)

    return payload


def repair_payload_header(data: bytes) -> Optional[bytes]:
    """Rebuild the 60 byte header of a type-0 (zlib) payload.

    Some type 3/4 payloads are encrypted with a CBC IV that differs from the
    IV derived from the device parameters.  In that case only the first 16
    bytes of the decrypted payload are corrupted: that is the beginning of the
    60 byte header, which contains the magic number.  Every following cipher
    block and the whole chunk chain are still correct, so the header can be
    rebuilt and validated from the chunk chain.

    Returns the repaired payload, or ``None`` if it cannot be validated.
    """
    if len(data) < 60 + 12:
        return None

    if data[:4] == struct.pack(">I", constants.PAYLOAD_MAGIC):
        return data

    offset = 60
    chunk_size = 0
    total_decompressed = 0
    compressed_crc = 0
    cumulative_compressed = 60
    chunks = 0

    while True:
        if offset + 12 > len(data):
            return None
        dec_size, comp_size, more = struct.unpack(">3I", data[offset:offset + 12])
        chunk = data[offset + 12:offset + 12 + comp_size]
        if len(chunk) != comp_size or dec_size == 0:
            return None
        compressed_crc = zlib.crc32(chunk, compressed_crc) & 0xFFFFFFFF
        total_decompressed += dec_size
        chunk_size = max(chunk_size, dec_size)
        chunks += 1
        if more == 0:
            break
        cumulative_compressed += comp_size + 12
        offset = cumulative_compressed
        if chunks > 0x100000:
            return None

    if len(data) < 24:
        return None
    stored_compressed_crc = struct.unpack(">I", data[0x14:0x18])[0]
    stored_header_crc = struct.unpack(">I", data[0x18:0x1C])[0]
    if compressed_crc != stored_compressed_crc:
        return None

    header = struct.pack(
        ">6I",
        constants.PAYLOAD_MAGIC,
        0,  # zlib only
        total_decompressed,
        cumulative_compressed,
        chunk_size,
        compressed_crc,
    )
    if zlib.crc32(header) & 0xFFFFFFFF != stored_header_crc:
        return None

    return header + data[24:]
