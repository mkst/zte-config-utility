"""Extract signature text from config.bin"""
import argparse

import zcu


def main():
    """the main function"""
    parser = argparse.ArgumentParser(description='Extract signature from config.bin of ZTE Routers',
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('infile', type=argparse.FileType('rb'),
                        help='Configuration file (config.bin)')

    args = parser.parse_args()

    zcu.zte.read_header(args.infile)
    signature = zcu.zte.read_signature(args.infile)
    print(signature.decode('utf-8'))


if __name__ == '__main__':
    main()
