"""Various helper functions to read/write zte configuration"""

import struct
from io import BytesIO
from os import stat
from typing import BinaryIO, Optional

from . import constants


def read_header(infile: BinaryIO, little_endian: bool = False) -> int:
    """expects to be at position 0 of the file, returns size of header"""
    fmt = ">4I"
    header_magic = struct.unpack(fmt, infile.read(struct.calcsize(fmt)))
    if header_magic == constants.ZTE_MAGIC:
        # 128 byte header
        fmt = f'{"<" if little_endian else ">"}28I'
        header = struct.unpack(fmt, infile.read(struct.calcsize(fmt)))
        if header[2] == 0x4000000:
            print("WARNING: Incorrect endianess specified!")
            infile.seek(0)
            return read_header(infile, not little_endian)

        assert (
            header[2] == 4
        ), f"Expected header[2] to be 0x4, was actually 0x{header[2]:X}"
        header_length = header[13]
        signed_config_size = header[14]
        file_size = stat(infile.name).st_size
        assert (
            header_length + signed_config_size == file_size
        ), "file size does not match header"
    else:
        # no extra header so return to start of the file
        infile.seek(0)
    return infile.tell()


def read_signature(infile: BinaryIO) -> bytes:
    """expects to be at the start of the signature magic, returns signature"""
    fmt = ">3I"
    signature_header = struct.unpack(fmt, infile.read(struct.calcsize(fmt)))
    signature = b""
    if signature_header[0] == constants.SIGNATURE_MAGIC:
        # _ = signature_header[1] # 0 ?
        signature_length = signature_header[2]
        signature = infile.read(signature_length)
    else:
        # no signature so return to start of the file
        infile.seek(0)
    return signature


def read_payload(infile: BinaryIO, raise_on_error: bool = True) -> Optional[tuple]:
    """expects to be at the start of the payload magic"""
    fmt = ">15I"
    payload_header = struct.unpack(fmt, infile.read(struct.calcsize(fmt)))
    if payload_header[0] != constants.PAYLOAD_MAGIC:
        if raise_on_error:
            raise ValueError("Payload header does not start with the payload magic.")
        else:
            return None
    return payload_header


def read_payload_type(infile: BinaryIO, raise_on_error: bool = True) -> Optional[int]:
    """expects to be at the start of the payload magic"""
    payload_header = read_payload(infile, raise_on_error)
    return payload_header[1] if payload_header is not None else None


# TODO: split out 'add_signature' functionality
def add_header(
    payload: BinaryIO,
    signature: bytes,
    version: int,
    include_header: bool = False,
    little_endian: bool = False,
) -> BytesIO:
    """creates a 'full' payload of (header), signature and payload"""
    full_payload = BytesIO()
    signature_length = len(signature)

    payload_data = payload.read()

    if include_header:
        full_payload_length = len(payload_data)
        if signature_length > 0:
            full_payload_length += 12 + signature_length
        full_payload.write(struct.pack(">4I", *constants.ZTE_MAGIC))
        header = [
            0,
            0,
            4,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            64,  # 0x40
            version,
            128,  # 0x80
            full_payload_length,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ]
        fmt = f'{"<" if little_endian else ">"}28I'
        full_payload.write(struct.pack(fmt, *header))

    if signature_length > 0:
        signature_header = [
            constants.SIGNATURE_MAGIC,
            0,
            signature_length,
        ]
        full_payload.write(struct.pack(">3I", *signature_header))
        full_payload.write(signature)

    full_payload.write(payload_data)
    full_payload.seek(0)

    return full_payload
