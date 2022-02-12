"""Encode config.xml into config.bin"""
import argparse

import zcu

from zcu.xcryptors import Xcryptor, T4Xcryptor, DigiXcryptor


def main():
    """the main function"""
    parser = argparse.ArgumentParser(description='Encode config.bin for ZTE Routers',
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('infile', type=argparse.FileType('rb'),
                        help='Raw configuration file e.g. config.xml')
    parser.add_argument('outfile', type=argparse.FileType('wb'),
                        help='Output file, e.g. config.bin')
    parser.add_argument('--key', type=lambda x: x.encode(), default=b'',
                        help="Key for AES encryption")
    parser.add_argument('--serial', type=str, default='',
                        help="Serial number for AES encryption (digimobil routers)")
    parser.add_argument('--signature', type=lambda x: x.encode(), default=b'',
                        help='Signature string of device, e.g "ZXHN H298N"')
    parser.add_argument('--signature-encryption', type=str, default='',
                        help='Signature string for encryption. Use this if you used --signature when decoding, or the output of the decoding script said "Using signature: <something>". It has to be the same as the one used when decoding.')
    parser.add_argument('--chunk-size', type=int, default=65536,
                        help='ZLIB chunk sizes (default 65536)')
    parser.add_argument('--payload-type', type=int, default=2, choices=[0, 2],
                        help='Payload type (0=compressed, 2=compressed+encrypted)')
    parser.add_argument('--version', type=int, default=2, choices=[1, 2],
                        help='payload version (1=unknown, 2=unknown)')
    parser.add_argument('--include-unencrypted-length', action='store_true',
                        help='Include unencrypted length in header (default No)')

    args = parser.parse_args()

    infile = args.infile
    outfile = args.outfile
    if args.serial:
        key = args.serial
        encryptor = DigiXcryptor(key, chunk_size=args.chunk_size, include_unencrypted_length=args.include_unencrypted_length)
        payload_type = 4
    elif args.signature_encryption:
        key = args.signature_encryption
        encryptor = T4Xcryptor(key, chunk_size=args.chunk_size, include_unencrypted_length=args.include_unencrypted_length)
        payload_type = 4
    else:
        key = args.key.ljust(16, b'\0')[:16]
        encryptor = Xcryptor(key, chunk_size=args.chunk_size, include_unencrypted_length=args.include_unencrypted_length)
        payload_type = args.payload_type

    signature = args.signature
    if all(b == 0 for b in signature):
        print("Warning: no signature provided!")

    data = zcu.compression.compress(infile, args.chunk_size)

    if payload_type in (2, 4):
        if all(b == 0 for b in key):
            print("Warning: no key provided!")
        data = encryptor.encrypt(data)

    version = args.version << 16
    encoded = zcu.zte.add_header(data, signature, payload_type, version)
    outfile.write(encoded.read())
    print("Done!")


if __name__ == '__main__':
    main()
