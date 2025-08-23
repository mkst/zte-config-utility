"""Compress config.xml into config.zlib"""

import argparse

import zcu


def main():
    """the main function"""
    parser = argparse.ArgumentParser(
        description="Compress config.xml from ZTE Routers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "infile",
        type=str,
        help="Raw configuration file (config.xml)",
    )
    parser.add_argument(
        "outfile", type=str, nargs="?", help="Output file (config.zlib)"
    )
    args = parser.parse_args()

    infile_name: str = args.infile
    outfile_name: str = args.outfile
    if outfile_name is None:
        outfile_name = infile_name.replace(".bin", ".xml")

    infile = open(infile_name, "rb")
    outfile = open(outfile_name, "wb")

    compressed = zcu.compression.compress(infile, 65536)

    outfile.write(compressed.read())


if __name__ == "__main__":
    main()
