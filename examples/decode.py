"""Decode config.bin into config.xml"""
import sys
import argparse

import zcu

from zcu.xcryptors import Xcryptor, T4Xcryptor, DigiXcryptor


def main():
    """the main function"""
    parser = argparse.ArgumentParser(description="Decode config.bin from ZTE Routers",
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("infile", type=argparse.FileType("rb"),
                        help="Encoded configuration file e.g. config.bin")
    parser.add_argument("outfile", type=argparse.FileType("wb"),
                        help="Output file e.g. config.xml")
    parser.add_argument("--key", type=lambda x: x.encode(), default=b"",
                        help="Key for AES decryption")
    parser.add_argument("--serial", type=str, default="",
                        help="Serial number for AES decryption (digimobil routers)")
    parser.add_argument("--signature", type=str, default="",
                        help="Custom signature for AES decryption (for certain type 4s, note: spaces will not be removed automatically)")
    parser.add_argument("--try-all-known-keys", action="store_true",
                        help="Try decrypting with all known keys (default No)")
    parser.add_argument("--key-prefix", type=str, default="",
                        help="Override key prefix for Type 4 devices")
    parser.add_argument("--iv-prefix", type=str, default="",
                        help="Override iv prefix for Type 4 devices")
    args = parser.parse_args()

    # TODO: can this be handled differently?
    signature_is_key = serial_is_key = False

    infile = args.infile
    outfile = args.outfile

    zcu.zte.read_header(infile)
    signature = zcu.zte.read_signature(infile).decode()
    print("Signature: %s" % signature)
    payload_type = zcu.zte.read_payload_type(infile)

    if args.serial:
        key = args.serial
        decryptor = DigiXcryptor(key)
        serial_is_key = True
    elif args.signature:
        key = args.signature
        decryptor = T4Xcryptor(key)
        signature_is_key = True
    else:
        key = args.key.ljust(16, b"\0")[:16]
        if payload_type == 2:
            decryptor = Xcryptor(key)
        elif payload_type == 4:
            decryptor = T4Xcryptor(key)
            if args.key_prefix:
                decryptor.set_key_prefix(args.key_prefix)
            if args.iv_prefix:
                decryptor.set_iv_prefix(args.iv_prefix)
        else:
            # no decryption required
            pass

    start_pos = infile.tell()
    if payload_type in (2, 4):
        try:
            if args.try_all_known_keys:
                matched_key = None
                for loop_key in zcu.known_keys.get_all_keys():
                    print("Trying key: %s" % loop_key)
                    # return to start of encrypted section
                    infile.seek(start_pos)
                    decryptor.set_key(loop_key)
                    decrypted = decryptor.decrypt(infile)
                    if zcu.zte.read_payload_type(decrypted, raise_on_error=False) is not None:
                        infile = decrypted
                        matched_key = loop_key
                        break
                if matched_key is None:
                    error("None of the known keys matched.")
                    return
                else:
                    print("Matched key: %s" % matched_key.decode())
            else:
                if all(b == 0 for b in key):
                    if payload_type == 2:
                        key = zcu.known_keys.find_key(signature)
                        if key:
                            print("Trying key: %s" % key.decode())
                            decryptor.set_key(key)
                        else:
                            error("No known keys for this signature, please specify one.")
                            return
                    else:
                        # remove all spaces
                        key = signature.replace(" ", "")
                        signature_is_key = True
                        decryptor = T4Xcryptor(key)
                        print("Using signature: %s" % key)
                infile_dec = decryptor.decrypt(infile)

                if zcu.zte.read_payload_type(infile_dec, raise_on_error=False) is None and payload_type == 4 and not signature_is_key:
                    # is type 4, but failed and we haven't tried using the signature derived key/iv
                    key = signature.replace(" ", "")
                    print("Failed! Trying again, with signature: %s" % key)
                    decryptor.set_key(key)
                    infile.seek(start_pos)
                    infile_dec = decryptor.decrypt(infile)

                # try again
                infile_dec.seek(0)
                if zcu.zte.read_payload_type(infile_dec, raise_on_error=False) is None:
                    error("Malformed decrypted payload, likely you used the wrong key!")
                    check_type(serial_is_key, signature_is_key, payload_type)
                    return
                infile = infile_dec
        except ValueError as ex:
            error("Failed to decrypt payload.")
            if check_type(serial_is_key, signature_is_key, payload_type):
                raise ValueError(ex)
            return
    else:
        # no encryption used
        pass

    res, _ = zcu.compression.decompress(infile)
    outfile.write(res.read())
    print("Successfully decoded!")


def check_type(serial_is_key, signature_is_key, payload_type):
    is_t4_method = serial_is_key or signature_is_key
    if is_t4_method and payload_type == 2:
        error("Hint: Payload type is 2, might need a key instead of a %s" % ("serial number." if serial_is_key else "signature."))
    elif not is_t4_method and payload_type == 4:
        error("Hint: Payload type is 4, might need a serial number instead of a key.")
    else:
        return True
    return False


def error(err):
    print(err, file=sys.stderr)


if __name__ == "__main__":
    main()
