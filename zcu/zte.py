"""Various helper functions to read/write zte configuration"""

from io import BytesIO
from os import stat
import struct

from . import constants


def read_header(infile):
    """expects to be at position 0 of the file, returns size of header"""
    header_magic = struct.unpack('>4I', infile.read(16))
    if header_magic == constants.ZTE_MAGIC:
        # 128 byte header
        header = struct.unpack('>28I', infile.read(112))
        assert header[2] == 4
        header_length = header[13]
        signed_config_size = header[14]
        file_size = stat(infile.name).st_size
        assert header_length + signed_config_size == file_size
    else:
        # no extra header so return to start of the file
        infile.seek(0)
    return infile.tell()


def read_signature(infile):
    """expects to be at the start of the signature magic, returns
    (signature, bytes read)"""
    signature_header = struct.unpack('>3I', infile.read(12))
    signature = b''
    if signature_header[0] == constants.SIGNATURE_MAGIC:
        # _ = signature_header[1] # 0 ?
        signature_length = signature_header[2]
        signature = infile.read(signature_length)
    else:
        # no signature so return to start of the file
        infile.seek(0)
    return signature


def read_payload(infile, raise_on_error=True):
    """expects to be at the start of the payload magic"""
    payload_header = struct.unpack('>15I', infile.read(60))
    if payload_header[0] != constants.PAYLOAD_MAGIC:
        if raise_on_error:
            raise ValueError("Payload header does not start with the payload magic.")
        else:
            return None
    return payload_header


def read_payload_type(infile, raise_on_error=True):
    """expects to be at the start of the payload magic"""
    payload_header = read_payload(infile, raise_on_error)
    return payload_header[1] if payload_header is not None else None


def add_header(payload, signature, payload_type, version):
    """creates a 'full' payload of (header), signature and payload"""
    full_payload = BytesIO()
    signature_length = len(signature)

    payload_data = payload.read()
    # check if model is F609
    if signature != b'F609':
        if payload_type == 2:
            full_payload_length = len(payload_data)
            if signature_length > 0:
                full_payload_length += 12 + signature_length
            full_payload.write(struct.pack('>4I', *constants.ZTE_MAGIC))
            full_payload.write(struct.pack('>28I', *(0, 0, 4, 0,
                                                     0, 0, 0, 0,
                                                     0, 0, 0, 64,
                                                     version, 128,
                                                     full_payload_length, 0,
                                                     0, 0, 0, 0,
                                                     0, 0, 0, 0,
                                                     0, 0, 0, 0)))
    if signature_length > 0:
        full_payload.write(struct.pack('>3I', *(constants.SIGNATURE_MAGIC,
                                                0,
                                                signature_length)))
        full_payload.write(signature)

    # add payload
    full_payload.write(payload_data)
    full_payload.seek(0)

    return full_payload
