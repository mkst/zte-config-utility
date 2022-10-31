"""Decode config.bin into config.xml"""
import sys
import argparse
from types import SimpleNamespace
import zcu

from zcu.xcryptors import Xcryptor, CBCXcryptor
from zcu.known_keys import serial_keygen, signature_keygen

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
    parser.add_argument('--model', type=str, default='',
                        help="Device model for Type-3 key derivation")
    parser.add_argument("--serial", type=str, default="",
                        help="Serial number for Type-4 key generation (digimobil routers/tagparams based)")
    parser.add_argument("--mac", type=str, default="",
                        help="MAC address for TagParams-based key generation")
    parser.add_argument("--longpass", type=str, default="",
                        help="Long password from TagParams (entry 4100) for key generation")
    parser.add_argument("--signature", type=str, default="",
                        help="Supply/override signature for Type-4 key generation")
    parser.add_argument("--try-all-known-keys", action="store_true",
                        help="Try decrypting with all known keys and generators (default No)")
    parser.add_argument("--key-prefix", type=str, default='',
                        help="Override Key prefix for Serial/TagParams based key generation")
    parser.add_argument("--iv-prefix", type=str, default='',
                        help="Override IV prefix for Serial/TagParams based key generation")
    parser.add_argument("--key-suffix", type=str, default='',
                        help="Override Key suffix for Signature based key generation")
    parser.add_argument("--iv-suffix", type=str, default='',
                        help="Override IV suffix for Signature based key generation")
    args = parser.parse_args()

    infile = args.infile
    outfile = args.outfile

    zcu.zte.read_header(infile)
    signature = zcu.zte.read_signature(infile).decode()
    if signature:
        print("Detected signature: %s" % signature)
    payload_type = zcu.zte.read_payload_type(infile)
    print("Detected payload type %d" % payload_type)
    start_pos = infile.tell()

    params = SimpleNamespace()
    if args.signature:
        params.signature = args.signature
    else:
        params.signature = signature
    
    if args.key:
        params.key = args.key
    if args.model:
        params.model = args.model
    if args.serial:
        params.serial = args.serial if (args.serial != 'NONE') else ''
    if args.mac:
        params.mac = args.mac if (args.mac != 'NONE') else ''
    if args.longpass:
        params.longPass = args.longpass if (args.longpass != 'NONE') else ''
    if args.key_prefix:
        params.key_prefix = args.key_prefix if (args.key_prefix != 'NONE') else ''
    if args.key_suffix:
        params.key_suffix = args.key_suffix if (args.key_suffix != 'NONE') else ''
    if args.iv_prefix:
        params.iv_prefix = args.iv_prefix if (args.iv_prefix != 'NONE') else ''
    if args.iv_suffix:
        params.iv_suffix = args.iv_suffix if (args.iv_suffix != 'NONE') else ''

    matched = None
    if payload_type == 3:
        models = []
        if hasattr(params, 'model'):
            models.append(params.model)

        if args.try_all_known_keys:
            models.extend(zcu.known_keys.get_all_models())

        if not len(models):
            error("No model argument specified for type 3 decryption and not trying all known keys!")
            return 1

        for model in models:
            if len(models) > 1:
                print("Trying model name: %s" % model)
            decryptor = CBCXcryptor(model)
            infile.seek(start_pos)
            decrypted = decryptor.decrypt(infile)
            if zcu.zte.read_payload_type(decrypted, raise_on_error=False) is not None:
                matched = "model: '%s'" % model
                infile = decrypted
                break

        if matched is None:
            error("Failed to decrypt type 3 payload, tried %d model name(s)!" % len(models))
            return 1
    elif payload_type == 4:
        generated = []
        if args.try_all_known_keys:
            generated = zcu.known_keys.run_all_keygens(params)
        else:
            res = zcu.known_keys.run_keygen(params)
            if res is not None:
                generated.append(res)

        if not len(generated):
            errStr = "No type 4 keygens matched the supplied/detected signature and parameters! Maybe adding --try-all-known-keys "
            if not hasattr(params,'serial'):
                errStr += "or --serial "
            errStr += "would work."
            error(errStr)
            return 1

        for genkey in generated:
            key, iv, source = genkey
            if len(generated) > 1:
                print("Trying key: '%s' iv: '%s' generated from %s" % (key, iv, source))

            decryptor = CBCXcryptor()
            decryptor.set_key(key, iv)
            infile.seek(start_pos)
            decrypted = decryptor.decrypt(infile)
            if zcu.zte.read_payload_type(decrypted, raise_on_error=False) is not None:
                matched = source
                infile = decrypted
                break

        if matched is None:
            error("Failed to decrypt type 4 payload, tried %d generated key(s)!" % len(generated))
            return 1
    elif payload_type == 2:
        keys = []
        if hasattr(params, 'key'):
            keys.append(params.key)
        elif hasattr(params, 'signature'):
            found_key = zcu.known_keys.find_key(params.signature)
            if (found_key is not None) and (found_key not in keys):
                keys.append(found_key)
        if args.try_all_known_keys:
            for key in zcu.known_keys.get_all_keys():
                if key not in keys:
                    keys.append(key)

        if not len(keys):
            error("No --key specified or found via signature, and not trying all known keys!")
            return 1

        for key in keys:
            if len(keys) > 1:
                print("Trying key: %s" % key)

            decryptor = Xcryptor(key)
            infile.seek(start_pos)
            decrypted = decryptor.decrypt(infile)
            if zcu.zte.read_payload_type(decrypted, raise_on_error=False) is not None:
                matched = "key: '%s'" % key
                infile = decrypted
                break

        if matched is None:
            error("Failed to decrypt type 2 payload, tried %d key(s)!" % len(keys))
            return 1
    elif payload_type == 0:
        # no decryption required
        pass
    else:
        error("Unknown payload type %d encountered!" % payload_type)
        return 1

    res, _ = zcu.compression.decompress(infile)
    outfile.write(res.read())

    if matched is not None:
        print("Successfully decoded using %s!" % matched)
    else:
        print("Successfully decoded!")

    return 0


def error(err):
    print(err, file=sys.stderr)


if __name__ == "__main__":
    main()
