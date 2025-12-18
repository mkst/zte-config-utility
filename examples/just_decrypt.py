"""Decrypt config.bin into config.zlib"""

import argparse
import pathlib

import zcu
from zcu.xcryptors import Xcryptor


def main():
    """the main function"""
    parser = argparse.ArgumentParser(
        description="Decrypt config.bin from ZTE Routers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "infile",
        type=pathlib.Path,
        help="Encoded configuration file (config.bin)",
    )
    parser.add_argument("outfile", type=pathlib.Path, help="Output file (config.zlib)")
    parser.add_argument(
        "--key", type=lambda x: x.encode(), default=b"", help="Key for AES decryption"
    )
    args = parser.parse_args()

    key = args.key.ljust(16, b"\0")[:16]

    infile_path: pathlib.Path = args.infile
    outfile_path: pathlib.Path = args.outfile
    if outfile_path is None or not outfile_path.exists():
        outfile_path = infile_path.with_suffix(".xml")

    infile = open(infile_path, "rb")
    outfile = open(outfile_path, "wb")

    zcu.zte.read_header(infile)
    zcu.zte.read_signature(infile)
    zcu.zte.read_payload(infile)

    decryptor = Xcryptor(key)
    decrypted = decryptor.decrypt(infile)

    outfile.write(decrypted.read())


if __name__ == "__main__":
    main()
