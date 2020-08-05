"""Decode config.bin into config.xml"""
import argparse

import zcu


def main():
    """the main function"""
    parser = argparse.ArgumentParser(description='Decode config.bin from ZTE Routers',
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('infile', type=argparse.FileType('rb'),
                        help='Encoded configuration file (config.bin)')
    parser.add_argument('outfile', type=argparse.FileType('wb'),
                        help='Output file (config.xml)')
    parser.add_argument('--key', type=lambda x: x.encode(), default=b'',
                        help="Key for AES decryption")
    parser.add_argument('--serial', type=str, default='',
                        help="Serial number for AES decryption (digimobil routers)")
    args = parser.parse_args()

    if args.serial:
        key = args.serial
        is_digi = True
    else:
        key = args.key.ljust(16, b'\0')[:16]
        is_digi = False

    infile = args.infile
    outfile = args.outfile

    zcu.zte.read_header(infile)
    zcu.zte.read_signature(infile)
    payload_type = zcu.zte.read_payload_type(infile)
    if payload_type in [2,4]:
        infile = zcu.encryption.aes_decrypt(infile, key, is_digi)
        payload_type = zcu.zte.read_payload_type(infile)
    res, _ = zcu.compression.decompress(infile)
    outfile.write(res.read())

if __name__ == '__main__':
    main()
