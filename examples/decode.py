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
    parser.add_argument('--signature', type=str, default='',
                        help="Custom signature for AES decryption (for certain type 4s, note: spaces won't be removed automatically on this one)")
    parser.add_argument('--try-all-known-keys', action='store_true',
                        help='Try decrypting with each known key, until one works (default No)')
    args = parser.parse_args()

    is_digi = False
    is_t4_sign = False
    if args.serial:
        key = args.serial
        is_digi = True
    elif args.signature:
        key = args.signature
        is_t4_sign = True
    else:
        key = args.key.ljust(16, b'\0')[:16]

    infile = args.infile
    outfile = args.outfile
    try_all_known_keys = args.try_all_known_keys

    zcu.zte.read_header(infile)
    signature = zcu.zte.read_signature(infile).decode()
    print("Signature: " + signature)
    payload_type = zcu.zte.read_payload_type(infile)
    start_pos = infile.tell()
    if payload_type in [2,4]:
        try:
            if try_all_known_keys:
                matched_key = None
                for loop_key in zcu.known_keys.get_all_keys():
                    infile.seek(start_pos)
                    infile_dec = zcu.encryption.aes_decrypt(infile, loop_key, is_digi)
                    if zcu.zte.read_payload_type(infile_dec, False) != None:
                        infile = infile_dec
                        matched_key = loop_key
                        break
                if matched_key == None:
                    error("No known key matched.")
                else:
                    print("Matched key: " + matched_key.decode())
            else:
                if all(b == 0 for b in key):
                    if payload_type == 2:
                        key = zcu.known_keys.find_key(signature)
                        if key:
                            print("Using key: " + key.decode())
                        else:
                            error("No known key for this signature, please specify one.")
                            return
                    else:
                        key = signature.replace(' ', '')
                        is_t4_sign = True
                        print("Using signature: " + key)
                infile_dec = zcu.encryption.aes_decrypt(infile, key, is_digi, is_t4_sign)
                if zcu.zte.read_payload_type(infile_dec, False) == None and payload_type == 4 and not is_t4_sign: # is type 4, but failed and we haven't tried using the signature derived key/iv
                    key = signature.replace(' ', '')
                    print("Failed! Trying again, with signature: " + key)
                    infile.seek(start_pos)
                    infile_dec = zcu.encryption.aes_decrypt(infile, key, is_digi, True)
                infile_dec.seek(0)
                if zcu.zte.read_payload_type(infile_dec, False) == None:
                    error("Malformed decrypted payload, probably used the wrong key!")
                    check_type(is_digi, is_t4_sign, payload_type)
                    return
                infile = infile_dec
        except ValueError as ex:
            error("Failed to decrypt payload.")
            if check_type(is_digi, is_t4_sign, payload_type):
                raise ValueError(ex)
            return
    res, _ = zcu.compression.decompress(infile)
    outfile.write(res.read())
    print("Success!")

def check_type(is_digi, is_t4_sign, payload_type):
    is_t4_method = is_digi or is_t4_sign
    if is_t4_method and payload_type == 2:
        error("Hint: payload type is 2, might need a key instead of a " + ('serial number.' if is_digi else 'signature.'))
    elif not is_t4_method and payload_type == 4:
        error("Hint: payload type is 4, might need a serial number instead of a key.")
    else:
        return True
    return False

def error(err):
    print(err, file=sys.stderr)

if __name__ == '__main__':
    main()
