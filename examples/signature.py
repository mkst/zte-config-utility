"""Extract signature text from config.bin"""

import argparse

import zcu


def main():
    """the main function"""
    parser = argparse.ArgumentParser(
        description="Extract signature from config.bin of ZTE Routers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "infile", type=argparse.FileType("rb"), help="Configuration file (config.bin)"
    )

    args = parser.parse_args()

    infile = args.infile

    header = infile.read(4)
    if header == b"BAMC":
        print(f"ERROR: {infile.name} is base64 encoded, please decode and try again.")
        return 1
    infile.seek(0)

    zcu.zte.read_header(infile)
    signature = zcu.zte.read_signature(infile)
    print(signature.decode("utf-8"))


if __name__ == "__main__":
    main()
