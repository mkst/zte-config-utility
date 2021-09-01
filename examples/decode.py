"""Decode config.bin into config.xml"""
import sys
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
    signature = zcu.zte.read_signature(infile).decode()
    print("Signature: " + signature)
    if all(b == 0 for b in key):
        key = zcu.known_keys.find_key(signature)
        if key:
            print("Using key: " + key.decode())
        else:
            error("No known key for this signature, please specify one.")
            return
    payload_type = zcu.zte.read_payload_type(infile)
    if payload_type in [2,4]:
        infile = zcu.encryption.aes_decrypt(infile, key, is_digi)
        if zcu.zte.read_payload_type(infile, False) == None:
            error("Malformed decrypted payload, probably used the wrong key!")
            return
    res, _ = zcu.compression.decompress(infile)
    outfile.write(res.read())
    print("Success!")

def error(err):
    print(err, file=sys.stderr)

if __name__ == '__main__':
    main()
