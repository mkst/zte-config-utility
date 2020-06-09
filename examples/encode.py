"""Encode config.xml into config.bin"""
import argparse

import zcu


def main():
    """the main function"""
    parser = argparse.ArgumentParser(description='Encode config.bin for ZTE Routers',
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('infile', type=argparse.FileType('rb'),
                        help='Raw configuration file (config.xml)')
    parser.add_argument('outfile', type=argparse.FileType('wb'),
                        help='Output file')
    parser.add_argument('--key', type=lambda x: x.encode(), default=b'',
                        help="Key for AES encryption")
    parser.add_argument('--signature', type=lambda x: x.encode(), default=b'',
                        help='Signature string of device, e.g "ZXHN H298N"')
    parser.add_argument('--chunk-size', type=int, default=65536,
                        help='ZLIB chunk sizes (default 65536)')
    parser.add_argument('--payload-type', type=int, default=2, choices=[0, 2],
                        help='payload type (0=compressed, 2=compressed+encrypted)')
    parser.add_argument('--version', type=int, default=2, choices=[1, 2],
                        help='payload version (1=unknown, 2=unknown)')

    args = parser.parse_args()

    infile = args.infile
    outfile = args.outfile
    key = args.key.ljust(16, b'\0')[:16]
    signature = args.signature
    chunk_size = args.chunk_size
    payload_type = args.payload_type
    version = args.version << 16

    payload_data = zcu.compression.compress(infile, chunk_size)

    if payload_type == 2:
        payload_data = zcu.encryption.aes_encrypt(payload_data, key, chunk_size)

    encoded = zcu.zte.add_header(payload_data, signature, payload_type, version)
    outfile.write(encoded.read())

if __name__ == '__main__':
    main()
