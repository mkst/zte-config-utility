"""Compress config.xml into config.zlib"""
import argparse

import zcu


def main():
    """the main function"""
    parser = argparse.ArgumentParser(description='Compress config.xml from ZTE Routers',
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('infile', type=argparse.FileType('rb'),
                        help='Raw configuration file (config.xml)')
    parser.add_argument('outfile', type=argparse.FileType('wb'),
                        help='Output file (config.zlib)')
    args = parser.parse_args()

    infile = args.infile
    outfile = args.outfile

    compressed = zcu.compression.compress(infile, 65536)

    outfile.write(compressed.read())


if __name__ == '__main__':
    main()
