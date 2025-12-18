import argparse
import hashlib
import pathlib

import zcu
from zcu.known_keys import KNOWN_KEYS, KNOWN_SIGNATURES, mac_to_str
from zcu.xcryptors import CBCXcryptor, Xcryptor

KNOWN_KEY_SUFFIXES = [
    "Wj%2$CjM",  # F680
]

KNOWN_KEYPAIR_SUFFIXES = [
    ("", ""),  # e.g. type 3
    ("key", "IV"),
    ("Key02660004", "Iv02660004"),
    ("Key02710001", "Iv02710001"),
    ("Key02710010", "Iv02710010"),
    ("Key02721401", "Iv02721401"),
    ("8cc72b05705d5c46f412af8cbed55aa", "667b02a85c61c786def4521b060265e"),
]

KNOWN_KEYPAIR_PREFIXES = [
    ("", ""),
    ("8cc72b05705d5c46", "667b02a85c61c786"),
    ("8dc79b15726d5c46", "678b02a85c63c786"),
]

KNOWN_KEYPAIRS = [
    ("H267AV1_CZkey", "H267AV1_CZIV"),
    ("8cc72b05705d5c46f412af8cbed55aad", "667b02a85c61c786def4521b060265e8"),
    ("8dc79b15726d5c46d412af8cbed65aad", "678b02a85c63c786def4523b061265e8"),
    #  ZTE F670
    ("L04&Product@5A238dc79b15726d5c06", "ZTE%FN$GponNJ025678b02a85c63c706"),
    #  ZTE F6600P Payload 5
    ("f680v9.0", "ZTE%FN$GponNJ025"),
]

KNOWN_PASSWORD_KEYPAIR_SUFFIXES = [
    ("", ""),
    ("Mcd5c46e", "G21b667b"),
]

KNOWN_MAC_SERIAL_IVS = [
    "ZTE%FN$GponNJ025",
]


def md5_to_hex(x):
    md5 = hashlib.md5(x.encode("utf8")).hexdigest()
    return bytes(bytearray.fromhex(md5)).hex()[:16]


def hardcoded_keypairs(args):
    return [(k, None) for k in KNOWN_KEYS]


def signature_keypairs(args):
    keypairs = []

    if args.key and args.iv:
        keypairs += [(args.key, args.iv)]

    signatures = []
    if args.signature:
        signatures += [
            args.signature,
            args.signature.replace(" ", ""),
        ]
    signatures += KNOWN_SIGNATURES

    for signature in signatures:
        if args.key_suffix and args.iv_suffix:
            keypairs += [
                (f"{signature}{args.key_suffix}", f"{signature}{args.iv_suffix}")
            ]

        keypairs += [
            (f"{signature}{key}", f"{signature}{iv}")
            for (key, iv) in KNOWN_KEYPAIR_SUFFIXES
        ]

    keypairs += [(key, iv) for (key, iv) in KNOWN_KEYPAIRS]

    return keypairs


def serial_keypairs(args):
    keypairs = []
    if args.serial_number is None:
        print("To decode any 'serial' payloads, please specify Serial Number, e.g.")
        print("  --serial 'SERIALNUMBER'")
        return keypairs

    serial = args.serial_number

    keypair_prefixes = []
    if args.key_prefix and args.iv_prefix:
        keypair_prefixes += [
            (args.key_prefix, args.iv_prefix),
        ]
    keypair_prefixes += KNOWN_KEYPAIR_PREFIXES

    keypairs += [(f"{key}{serial}", f"{iv}{serial}") for (key, iv) in keypair_prefixes]

    return keypairs


def mac_keypairs(args):
    keypairs = []

    if args.mac_address is None:
        print("To decode any 'mac' payloads, please specify MAC Address, e.g.")
        print("  --mac 'AA:BB:CC:DD:EE:FF'")
        return keypairs

    mac = args.mac_address

    for suffix in KNOWN_KEY_SUFFIXES:
        # AES key: 'three lowest bytes of MAC address' + 'Wj%2$CjM'
        keypairs += [
            (md5_to_hex(mac_to_str(mac, separator="")[6:] + suffix), None),
        ]

    return keypairs


def mac_serial_keypairs(args):
    keypairs = []
    if args.mac_address is None or args.serial_number is None:
        print(
            "To decode any 'mac+serial' payloads, please specify MAC Address and Serial Number, e.g."
        )
        print("  --mac 'AA:BB:CC:DD:EE:FF' --serial 'SERIALNUMBER'")
        return keypairs

    serial = args.serial_number
    mac = args.mac_address

    for iv in KNOWN_MAC_SERIAL_IVS:
        keypairs += [
            # raw serial
            (serial + mac_to_str(mac, reverse=False, separator=""), iv),
            (serial + mac_to_str(mac, reverse=True, separator=""), iv),
            (serial + mac_to_str(mac, reverse=False, separator=":"), iv),
            (serial + mac_to_str(mac, reverse=True, separator=":"), iv),
            # skip first 4 chars, e.g. ZTEGXXXXXXXX
            (serial[4:] + mac_to_str(mac, reverse=False, separator=""), iv),
            (serial[4:] + mac_to_str(mac, reverse=True, separator=""), iv),
            (serial[4:] + mac_to_str(mac, reverse=False, separator=":"), iv),
            (serial[4:] + mac_to_str(mac, reverse=True, separator=":"), iv),
            # take last 8 chars, e.g. ____XXXXXXXX
            (serial[-8:] + mac_to_str(mac, reverse=False, separator=""), iv),
            (serial[-8:] + mac_to_str(mac, reverse=True, separator=""), iv),
            (serial[-8:] + mac_to_str(mac, reverse=False, separator=":"), iv),
            (serial[-8:] + mac_to_str(mac, reverse=True, separator=":"), iv),
            # take first 8 chars, e.g. ZTEGXXXX___
            (serial[:8] + mac_to_str(mac, reverse=False, separator=""), iv),
            (serial[:8] + mac_to_str(mac, reverse=True, separator=""), iv),
            (serial[:8] + mac_to_str(mac, reverse=False, separator=":"), iv),
            (serial[:8] + mac_to_str(mac, reverse=True, separator=":"), iv),
            # seen in f680 router
            (md5_to_hex(serial + mac_to_str(mac, reverse=True, separator="")), None),
        ]

        # # convert first 8 hex chars to ascii
        # if all([x in "0123456789abcdef" for x in serial[:8].lower()]):
        #     ascii_serial = bytearray.fromhex(serial[:8]).decode()
        #     keypairs += [
        #         (ascii_serial + mac_to_str(mac, reverse=False, separator=""), iv),
        #         (ascii_serial + mac_to_str(mac, reverse=True, separator=""), iv),
        #         (ascii_serial + mac_to_str(mac, reverse=False, separator=":"), iv),
        #         (ascii_serial + mac_to_str(mac, reverse=True, separator=":"), iv),
        #     ]

    return keypairs


def mac_serial_password_keypairs(args):
    # NOTE: "suffix" is a misnomer here:
    # key is PASSWORD|SERIAL|SUFFIX
    # iv is PREFIX|MAC|PASSWORD

    keypairs = []
    if args.mac_address is None or args.serial_number is None or args.password is None:
        print(
            "To decode any 'mac+serial+password' payloads, please specify MAC Address, Serial Number and Password parameters, e.g."
        )
        print(
            "  --mac 'AA:BB:CC:DD:EE:FF' --serial 'SERIALNUMBER' --password 'password'"
        )
        return keypairs

    mac = mac_to_str(args.mac_address, reverse=False, separator=":")
    serial = args.serial_number
    password = args.password

    if args.key_suffix and args.iv_suffix:
        keypairs += [
            (f"{password}{serial}{args.key_suffix}", f"{args.iv_suffix}{mac}{password}")
        ]

    keypairs += [
        (f"{password}{serial}{key}", f"{iv}{mac}{password}")
        for (key, iv) in KNOWN_PASSWORD_KEYPAIR_SUFFIXES
    ]

    return keypairs


def decrypt(infile, decryptor, keypair):
    start_pos = infile.tell()
    decryptor.set_key(*keypair)
    try:
        decrypted = decryptor.decrypt(infile)
    except ValueError:
        infile.seek(start_pos)
        return None
    infile.seek(start_pos)
    if decrypted is not None:
        if zcu.zte.read_payload_type(decrypted, raise_on_error=False) is not None:
            return decrypted
    return None


HANDLERS = [
    # key only
    lambda a: (hardcoded_keypairs(a), Xcryptor()),
    lambda a: (mac_keypairs(a), Xcryptor()),
    lambda a: (mac_serial_keypairs(a), Xcryptor()),
    # key + iv
    lambda a: (signature_keypairs(a), CBCXcryptor()),  # requires signature
    lambda a: (serial_keypairs(a), CBCXcryptor()),  # requires serial
    lambda a: (mac_serial_keypairs(a), CBCXcryptor()),  # requires mac, serial
    lambda a: (
        mac_serial_password_keypairs(a),
        CBCXcryptor(),
    ),  # requires mac, serial, password
]


def main():
    parser = argparse.ArgumentParser()

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
        type=str,
        help="Supply a Key to try",
    )
    parser.add_argument(
        "--iv",
        type=str,
        help="Supply a IV to try",
    )

    parser.add_argument(
        "--signature",
        type=str,
        help="Supply/override Signature for Type-4 key generation",
    )
    parser.add_argument(
        "--serial-number",
        type=str,
        help="Supply Serial Number of device",
    )
    parser.add_argument(
        "--mac-address",
        type=str,
        help="Supply MAC Address of device, e.g. AA:BB:CC:DD:EE:FF",
    )
    parser.add_argument(
        "--password",
        type=str,
        help="Supply Long password from TagParams (entry 4100) for key generation",
    )
    parser.add_argument(
        "--key-prefix",
        type=str,
        help="Supply Key Prefix",
    )
    parser.add_argument(
        "--key-suffix",
        type=str,
        help="Supply Key Suffix",
    )
    parser.add_argument(
        "--iv-prefix",
        type=str,
        help="Supply IV Prefix",
    )
    parser.add_argument(
        "--iv-suffix",
        type=str,
        help="Supply IV Suffix",
    )

    args = parser.parse_args()

    infile_path: pathlib.Path = args.infile
    outfile_path: pathlib.Path = args.outfile
    if outfile_path is None or not outfile_path.exists():
        outfile_path = infile_path.with_suffix(".xml")

    infile = open(infile_path, "rb")
    outfile = open(outfile_path, "wb")

    # check magic
    header = infile.read(4)
    if header == b"BAMC":
        print(f"ERROR: {infile.name} is base64 encoded, please decode and try again.")
        return 1

    infile.seek(0)
    zcu.zte.read_header(infile, little_endian=args.little_endian)

    signature = zcu.zte.read_signature(infile).decode()
    if args.signature is None:
        args.signature = signature

    payload_type = zcu.zte.read_payload_type(infile)
    if payload_type != 0:
        for handler in HANDLERS:
            success = False
            keypairs, decryptor = handler(args)
            for keypair in keypairs:
                # print(f"Trying (key, iv): {keypair}")
                decrypted = decrypt(infile, decryptor, keypair)
                if decrypted is not None:
                    success = True
                    break
            if success:
                break
        else:
            print("Unable to find valid key for payload.")
            return 1
    else:
        decompressed, _ = zcu.compression.decompress(infile)
        outfile.write(decompressed.read())
        print(f"Successfully decompressed {infile.name}")
        return 0

    decompressed, _ = zcu.compression.decompress(decrypted)
    outfile.write(decompressed.read())
    print(
        f"Successfully decrypted and decompressed {infile.name} using (key, iv): {keypair}"
    )
    return 0


if __name__ == "__main__":
    main()
