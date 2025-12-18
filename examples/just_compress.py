"""Compress config.xml into config.zlib"""

import argparse
import pathlib

import zcu


def main():
    """the main function"""
    parser = argparse.ArgumentParser(
        description="Compress config.xml from ZTE Routers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "infile",
        type=pathlib.Path,
        help="Raw configuration file (config.xml)",
    )
    parser.add_argument(
        "outfile", type=pathlib.Path, nargs="?", help="Output file (config.zlib)"
    )
    args = parser.parse_args()

    infile_path: pathlib.Path = args.infile
    outfile_path: pathlib.Path = args.outfile
    if outfile_path is None or not outfile_path.exists():
        outfile_path = infile_path.with_suffix(".xml")

    infile = open(infile_path, "rb")
    outfile = open(outfile_path, "wb")

    compressed = zcu.compression.compress(infile, 65536)

    outfile.write(compressed.read())


if __name__ == "__main__":
    main()
