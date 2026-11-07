"""Decode config.bin into config.xml"""

import argparse
import pathlib
import sys
import zlib
from io import BytesIO
from types import SimpleNamespace

import zcu
from zcu.known_keys import TYPE_3_KNOWN_KEY_IVS
from zcu.xcryptors import CBCXcryptor, Xcryptor


def error(msg):
    print(msg, file=sys.stderr)


def repair_payload_after_bad_iv(decrypted):
    """Rebuild a payload header damaged by an unknown CBC IV.

    Returns a stream positioned at the first chunk header (offset 60) or
    ``None`` when the payload cannot be validated.
    """
    decrypted.seek(0)
    data = decrypted.read()
    repaired = zcu.compression.repair_payload_header(data)
    if repaired is None or repaired == data:
        return None

    stream = BytesIO(repaired)
    stream.seek(60)
    return stream


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

    decryptor = CBCXcryptor()

    if getattr(args, "raw_key", None) is not None:
        if getattr(args, "raw_iv", None) is None:
            error("--key-hex requires --iv-hex when decoding type 4 payloads.")
            return None

        print("Using raw AES key/IV from --key-hex/--iv-hex")

        try:
            decryptor.set_raw_key(args.raw_key, args.raw_iv)
        except ValueError as exc:
            error(str(exc))
            return None

        decrypted = decryptor.decrypt(infile)
        if zcu.zte.read_payload_type(decrypted, raise_on_error=False) is not None:
            return (decrypted, None)

        repaired = repair_payload_after_bad_iv(decrypted)
        if repaired is not None:
            return (repaired, None)

        error("Raw key/IV did not produce a valid payload.")
        return None

    if args.try_all_known_keys:
        key_ivs = zcu.known_keys.run_all_keygens(params)
    else:
        key_ivs = zcu.known_keys.run_keygens(params)

    # Explicit TagParams values are enough to run the tagparams generator even
    # when the signature is unknown/empty (e.g. a bare payload without header).
    if all(hasattr(params, attr) for attr in ("mac", "serial", "longPass")):
        generated = zcu.known_keys.tagparams_keygen(params)
        if generated and generated not in key_ivs:
            key_ivs.append(generated)

    if len(key_ivs) == 0:
        msg = "No keygens matched the supplied/detected signature and parameters! Try adding --try-all-known-keys"
        if not hasattr(params, "serial"):
            msg += " or --serial YOUR_SERIAL_NUMBER"
        msg += " and try again."
        error(msg)
        return None

    start_pos = infile.tell()
    for key, iv, source in key_ivs:
        infile.seek(start_pos)

        print(f"Trying key: '{key}' iv: '{iv}' generated from {source}")

        decryptor.set_key(key, iv)
        decrypted = decryptor.decrypt(infile)
        if zcu.zte.read_payload_type(decrypted, raise_on_error=False) is not None:
            return (decrypted, key)

        repaired = repair_payload_after_bad_iv(decrypted)
        if repaired is not None:
            print(
                "  note: the payload header was corrupted by an unknown CBC IV; "
                "rebuilt it from the chunk chain"
            )
            return (repaired, key)

    error(f"Failed to decrypt payload. Tried {len(key_ivs)} generated key(s)!")
    return None


def decode_payload_type_6(infile, args, params):
    print("Decoding type 6 payload...")

    if not args.key or not args.iv:
        error("Payload type 6 requires both --key and --iv.")
        return None

    decryptor = CBCXcryptor(payload_type=6)
    decryptor.set_key(args.key, args.iv)

    try:
        decrypted = decryptor.decrypt(infile)
        if decrypted is None:
            error("Failed to decrypt type 6 payload.")
            return None

        decrypted.seek(0)
        inner_type = zcu.zte.read_payload_type(
            decrypted, raise_on_error=False
        )

        if inner_type is None:
            error("Invalid inner payload header.")
            return None

    except (ValueError, EOFError) as exc:
        error(f"Failed to decrypt type 6 payload: {exc}")
        return None

    return decrypted, args.key


def decode_payload(infile, args, params, payload_type):
    if payload_type == 0:
        res = decode_payload_type_0(infile)
    elif payload_type == 2:
        res = decode_payload_type_2(infile, args, params)
    elif payload_type == 3:
        res = decode_payload_type_3(infile, args, params)
    elif payload_type == 4:
        res = decode_payload_type_4(infile, args, params)
    elif payload_type == 6:
        res = decode_payload_type_6(infile, args, params)
    else:
        error(f"No support for payload type {payload_type}!")
        return None

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
        "--iv",
        type=lambda x: x.encode(),
        default=b"",
        help="IV for AES-CBC decryption (SHA256-derived)",
    )
    parser.add_argument(
        "--offset",
        type=lambda x: int(x, 0),
        default=0,
        help="Offset of the payload inside a larger dump (e.g. an mtd partition)",
    )
    parser.add_argument(
        "--key-hex",
        type=str,
        default="",
        help="Raw AES key as hex for type 4 payloads (skips key derivation)",
    )
    parser.add_argument(
        "--iv-hex",
        type=str,
        default="",
        help="Raw 16-byte AES IV as hex for type 4 payloads (skips IV derivation)",
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

    try:
        args.raw_key = bytes.fromhex(args.key_hex) if args.key_hex else None
        args.raw_iv = bytes.fromhex(args.iv_hex) if args.iv_hex else None
    except ValueError:
        error("--key-hex/--iv-hex must be valid hexadecimal strings")
        return 1

    infile_path: pathlib.Path = args.infile
    outfile_path: pathlib.Path = args.outfile
    if outfile_path is None:
        outfile_path = infile_path.with_suffix(".xml")

        if outfile_path.exists():
            overwrite = input(f"Output file {outfile_path} exists, overwrite? (y/N) ").lower()
            while overwrite not in {"y", "n", ""}:
                overwrite = input(f"Output file {outfile_path} exists, overwrite? (y/N) ").lower()

            if overwrite != "y":
                print("Not overwriting output, nothing to do!")
                return

    if args.offset:
        with open(infile_path, "rb") as raw:
            raw.seek(args.offset)
            infile = BytesIO(raw.read())
    else:
        infile = open(infile_path, "rb")

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

    try:
        decompressed, _ = zcu.compression.decompress(decrypted)
        xml_data = decompressed.read()
    except (ValueError, EOFError, zlib.error) as exc:
        error(f"Failed to decompress payload: {exc}")
        return 1

    with open(outfile_path, "wb") as outfile:
        outfile.write(xml_data)

    if key is not None:
        key_text = key.decode() if isinstance(key, bytes) else key
        print(f"Successfully decoded using key: '{key_text}'")
    else:
        print("Successfully decoded")

    return 0


if __name__ == "__main__":
    main()
