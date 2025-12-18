"""Encode config.xml into config.bin"""

import argparse
import pathlib
from types import SimpleNamespace

import zcu
from zcu.known_keys import run_any_keygen
from zcu.xcryptors import CBCXcryptor, Xcryptor


def main():
    """the main function"""
    parser = argparse.ArgumentParser(
        description="Encode config.bin for ZTE Routers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "infile",
        type=pathlib.Path,
        help="Raw configuration file e.g. config.xml",
    )
    parser.add_argument(
        "outfile", type=pathlib.Path, nargs="?", help="Output file, e.g. config.bin"
    )
    parser.add_argument(
        "--key", type=lambda x: x.encode(), default=b"", help="Key for AES encryption"
    )
    parser.add_argument(
        "--iv",
        type=lambda x: x.encode(),
        default=b"",
        help="IV for key derivation, switches encryption mode to AES256CBC",
    )
    parser.add_argument(
        "--model",
        type=str,
        default="",
        help="Generate Key/IV from model name, implies payload-type 3",
    )
    parser.add_argument(
        "--serial",
        type=str,
        default="",
        help="Generate Key/IV from serial number(DIGImobil routers), implies payload-type 4",
    )
    parser.add_argument(
        "--signature",
        type=str,
        default="",
        help='Signature string of device for signing, e.g "ZXHN H298N"',
    )
    parser.add_argument(
        "--use-signature-encryption",
        action="store_true",
        help='Generate Key/IV from signature, implies payload-type 4. Use this if you used --signature when decoding, or the output of the decoding script said "Using signature: <something>".',
    )
    parser.add_argument(
        "--chunk-size", type=int, default=65536, help="ZLIB chunk sizes (default 65536)"
    )
    parser.add_argument(
        "--payload-type",
        type=int,
        default=None,
        choices=[0, 2, 3, 4, 5, 6],
        help="Payload type (0=plain, 2=aes128ecb key encryption, 3=aes256cbc model encryption, 4=aes256cbc signature/serial encryption)",
    )
    parser.add_argument(
        "--version",
        type=int,
        default=2,
        choices=[1, 2],
        help="Payload version (1=unknown, 2=unknown)",
    )
    parser.add_argument(
        "--include-header", action="store_true", help="Include header? (default No)"
    )
    parser.add_argument(
        "--little-endian-header",
        action="store_true",
        help="Is header little endian? (default No)",
    )
    parser.add_argument(
        "--include-unencrypted-length",
        action="store_true",
        help="Include unencrypted length in header (default No)",
    )
    parser.add_argument(
        "--key-prefix",
        type=str,
        default="",
        help="Override Key prefix for Serial based key generation",
    )
    parser.add_argument(
        "--iv-prefix",
        type=str,
        default="",
        help="Override IV prefix for Serial based key generation",
    )
    parser.add_argument(
        "--key-suffix",
        type=str,
        default="",
        help="Override Key suffix for Signature based key generation",
    )
    parser.add_argument(
        "--iv-suffix",
        type=str,
        default="",
        help="Override IV suffix for Signature based key generation",
    )
    parser.add_argument(
        "--force-no-key",
        action="store_true",
        help="Don't try to infer AES key from signature",
    )
    parser.add_argument(
        "--incorrect-compressed-size",
        action="store_true",
        help="Whether the 'compressed size' header incorrectly includes the final chunk size twice",
    )

    args = parser.parse_args()

    infile_path: pathlib.Path = args.infile
    outfile_path: pathlib.Path = args.outfile
    if outfile_path is None or not outfile_path.exists():
        outfile_path = infile_path.with_suffix(".xml")

    infile = open(infile_path, "rb")
    outfile = open(outfile_path, "wb")

    key = args.key
    iv = args.iv

    payload_type = 0

    if args.model:
        payload_type = 3
        key = args.model
        iv = None
    elif args.serial:
        payload_type = 4
        params = SimpleNamespace(signature=args.signature, serial=args.serial)
        print(f"Using serial: '{params.serial}'")
        if args.key_prefix:
            params.key_prefix = args.key_prefix if (args.key_prefix != "NONE") else ""
            print(f"Using key prefix: '{params.key_prefix}'")
        if args.iv_prefix:
            params.iv_prefix = args.iv_prefix if (args.iv_prefix != "NONE") else ""
            print(f"Using iv prefix: '{params.iv_prefix}'")
        key, iv = run_any_keygen(params, "serial")[:2]
    elif args.use_signature_encryption:
        payload_type = 4
        if not args.signature:
            print("Warning: Using signature encryption but --signature not provided!")

        params = SimpleNamespace(signature=args.signature)
        print(f"Using signature: '{params.signature}'")
        if args.key_suffix:
            params.key_suffix = args.key_suffix if (args.key_suffix != "NONE") else ""
            print(f"Using key suffix: '{params.key_suffix}'")
        if args.iv_suffix:
            params.iv_suffix = args.iv_suffix if (args.iv_suffix != "NONE") else ""
            print(f"Using iv suffix: '{params.iv_suffix}'")
        key, iv = run_any_keygen(params, "signature")[:2]
    elif args.iv:
        payload_type = 4
    elif args.key:
        payload_type = 2

    signature = args.signature
    if not key and signature:
        if not args.force_no_key:
            possible_key = zcu.known_keys.find_key(signature)
            if possible_key is not None:
                key = possible_key
                payload_type = 2
            if key:
                print(f"Using key '{key}' for signature '{signature}'")

    incorrect_compressed_size = args.incorrect_compressed_size

    data = zcu.compression.compress(
        infile, args.chunk_size, incorrect_compressed_size=incorrect_compressed_size
    )

    if args.payload_type is not None:
        if args.payload_type != payload_type:
            print(f"Overriding Payload Type: {args.payload_type}")
        payload_type = args.payload_type

    if all(b == 0 for b in signature) and payload_type in (2, 4):
        print("Warning: No/empty signature provided!")

    if all(b == 0 for b in key) and (payload_type != 0 or signature):
        if not args.force_no_key:
            print("Warning: No key provided!")

    if payload_type == 2:
        encryptor = Xcryptor(
            key,
            chunk_size=args.chunk_size,
            include_unencrypted_length=args.include_unencrypted_length,
        )
        data = encryptor.encrypt(data)
    elif payload_type in (3, 4, 5, 6):
        encryptor = CBCXcryptor(
            chunk_size=args.chunk_size,
            include_unencrypted_length=args.include_unencrypted_length,
            payload_type=payload_type,
        )
        encryptor.set_key(aes_key=key, aes_iv=iv)
        data = encryptor.encrypt(data)

    version = (
        (args.version >> 16) if args.little_endian_header else (args.version << 16)
    )
    encoded = zcu.zte.add_header(
        data,
        signature.encode("utf8"),
        version,
        include_header=args.include_header,
        little_endian=args.little_endian_header,
    )
    outfile.write(encoded.read())
    print("Done!")


if __name__ == "__main__":
    main()
