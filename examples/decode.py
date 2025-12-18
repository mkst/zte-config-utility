"""Decode config.bin into config.xml"""

import argparse
import pathlib
import sys
from types import SimpleNamespace

import zcu
from zcu.known_keys import TYPE_3_KNOWN_KEY_IVS
from zcu.xcryptors import CBCXcryptor, Xcryptor


def error(msg):
    print(msg, file=sys.stderr)


def decode_payload_type_0(infile):
    print("Decoding type 0 payload...")

    # no decryption required
    return (infile, None)


def decode_payload_type_2(infile, args, params):
    print("Decoding type 2 payload...")

    keys = set()

    if hasattr(params, "key"):
        keys.add(params.key)
    elif hasattr(params, "signature"):
        key_for_signature = zcu.known_keys.find_key(params.signature)
        if key_for_signature is not None:
            keys.add(key_for_signature)

    if args.try_all_known_keys:
        for key in zcu.known_keys.get_all_keys():
            keys.add(key)

    if len(keys) == 0:
        error(
            "No --key specified or found via signature, try again with --try-all-known-keys or specifying the --key."
        )
        return None

    decryptor = Xcryptor()

    start_pos = infile.tell()
    for key in keys:
        infile.seek(start_pos)

        if len(keys) > 1:
            print(f"Trying key: '{key}'")

        decryptor.set_key(key)
        decrypted = decryptor.decrypt(infile)
        if zcu.zte.read_payload_type(decrypted, raise_on_error=False) is not None:
            return (decrypted, key)

    error(f"Failed to decrypt payload. Tried {len(keys)} key(s)!")
    return None


def decode_payload_type_3(infile, args, params):
    print("Decoding type 3 payload...")

    models = []
    if hasattr(params, "model"):
        models.append(params.model)

    if args.try_all_known_keys:
        models.extend(zcu.known_keys.get_all_models())

    key_ivs = [(m, m, f"Model {m}") for m in models]
    if args.try_all_known_keys:
        key_ivs.extend(TYPE_3_KNOWN_KEY_IVS)

    if len(key_ivs) == 0:
        error(
            "Failed to decrypt payload. No keys found! Try specifying --model and/or --try-all-known-keys and try again."
        )
        return None

    decryptor = CBCXcryptor()

    start_pos = infile.tell()
    for key, iv, name in key_ivs:
        infile.seek(start_pos)

        if len(models) > 1:
            print(f"Trying key: {name}")

        decryptor.set_key(key, iv)
        decrypted = decryptor.decrypt(infile)
        if zcu.zte.read_payload_type(decrypted, raise_on_error=False) is not None:
            return (decrypted, key)

    error(f"Failed to decrypt payload. Tried {len(models)} model name(s)!")
    return None


def decode_payload_type_4(infile, args, params):
    print("Decoding type 4 payload...")

    if args.try_all_known_keys:
        key_ivs = zcu.known_keys.run_all_keygens(params)
    else:
        key_ivs = zcu.known_keys.run_keygens(params)

    if len(key_ivs) == 0:
        msg = "No keygens matched the supplied/detected signature and parameters! Try adding --try-all-known-keys"
        if not hasattr(params, "serial"):
            msg += " or --serial YOUR_SERIAL_NUMBER"
        msg += " and try again."
        error(msg)
        return None

    decryptor = CBCXcryptor()

    start_pos = infile.tell()
    for key, iv, source in key_ivs:
        infile.seek(start_pos)

        print(f"Trying key: '{key}' iv: '{iv}' generated from {source}")

        decryptor.set_key(key, iv)
        decrypted = decryptor.decrypt(infile)
        if zcu.zte.read_payload_type(decrypted, raise_on_error=False) is not None:
            return (decrypted, key)

    error(f"Failed to decrypt payload. Tried {len(key_ivs)} generated key(s)!")
    return None


def decode_payload(infile, args, params, payload_type):
    if payload_type == 0:
        res = decode_payload_type_0(infile)
    elif payload_type == 2:
        res = decode_payload_type_2(infile, args, params)
    elif payload_type == 3:
        res = decode_payload_type_3(infile, args, params)
    elif payload_type == 4:
        res = decode_payload_type_4(infile, args, params)
    else:
        error(f"No support for payload type {payload_type}!")
        return 1

    return res


def main():
    parser = argparse.ArgumentParser(
        description="Decode config.bin from ZTE Routers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "infile",
        type=pathlib.Path,
        help="Encoded configuration file e.g. config.bin",
    )
    parser.add_argument(
        "outfile",
        type=pathlib.Path,
        nargs="?",
        help="Output file e.g. config.xml",
    )
    parser.add_argument(
        "--little-endian",
        action="store_true",
        help="Whether payload is little-endian (defaults to big-endian)",
    )
    parser.add_argument(
        "--key",
        type=lambda x: x.encode(),
        default=b"",
        help="Key for AES decryption",
    )
    parser.add_argument(
        "--model", type=str, default="", help="Device model for Type-3 key derivation"
    )
    parser.add_argument(
        "--serial",
        type=str,
        default="",
        help="Serial number for Type-4 key generation (digimobil routers/tagparams based)",
    )
    parser.add_argument(
        "--mac",
        type=str,
        default="",
        help="MAC address for TagParams-based key generation",
    )
    parser.add_argument(
        "--longpass",
        type=str,
        default="",
        help="Long password from TagParams (entry 4100) for key generation",
    )
    parser.add_argument(
        "--signature",
        type=str,
        default="",
        help="Supply/override signature for Type-4 key generation",
    )
    parser.add_argument(
        "--try-all-known-keys",
        action="store_true",
        help="Try decrypting with all known keys and generators (default False)",
    )
    parser.add_argument(
        "--key-prefix",
        type=str,
        default="",
        help="Override Key prefix for Serial/TagParams based key generation",
    )
    parser.add_argument(
        "--iv-prefix",
        type=str,
        default="",
        help="Override IV prefix for Serial/TagParams based key generation",
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
    args = parser.parse_args()

    infile_path: pathlib.Path = args.infile
    outfile_path: pathlib.Path = args.outfile
    if outfile_path is None or not outfile_path.exists():
        outfile_path = infile_path.with_suffix(".xml")

    infile = open(infile_path, "rb")
    outfile = open(outfile_path, "wb")

    zcu.zte.read_header(infile, little_endian=args.little_endian)

    signature = zcu.zte.read_signature(infile).decode()
    if signature:
        print(f"Detected signature: {signature}")

    payload_type = zcu.zte.read_payload_type(infile)
    print(f"Detected payload type {payload_type}")

    params = SimpleNamespace()
    if args.signature:
        params.signature = args.signature
    else:
        params.signature = signature

    if args.key:
        params.key = args.key
    if args.model:
        params.model = args.model
    if args.serial:
        params.serial = args.serial if (args.serial != "NONE") else ""
    if args.mac:
        params.mac = args.mac if (args.mac != "NONE") else ""
    if args.longpass:
        params.longPass = args.longpass if (args.longpass != "NONE") else ""
    if args.key_prefix:
        params.key_prefix = args.key_prefix if (args.key_prefix != "NONE") else ""
    if args.key_suffix:
        params.key_suffix = args.key_suffix if (args.key_suffix != "NONE") else ""
    if args.iv_prefix:
        params.iv_prefix = args.iv_prefix if (args.iv_prefix != "NONE") else ""
    if args.iv_suffix:
        params.iv_suffix = args.iv_suffix if (args.iv_suffix != "NONE") else ""

    res = decode_payload(infile, args, params, payload_type)
    if res is None:
        return 1

    decrypted, key = res

    decompressed, _ = zcu.compression.decompress(decrypted)
    outfile.write(decompressed.read())

    if key is not None:
        print(f"Successfully decoded using key: '{key}'")
    else:
        print("Successfully decoded")

    return 0


if __name__ == "__main__":
    main()
