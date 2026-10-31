#!/usr/bin/env python3
"""
ZTE F6600 Configuration Utility
Tool for decrypting ZTE F6600 config.bin backups to XML and re-encrypting them back.
"""

import sys
import os
import argparse
import struct
import zlib
from io import BytesIO
from hashlib import sha256
from Cryptodome.Cipher import AES

# Key & IV strings for ZTE F6600
KEY_STR = "D0BBC6C68676592e09a0"
IV_STR = "ZTE%FN$GponNJ025"

# Protocol constants
ZTE_MAGIC = (0x99999999, 0x44444444, 0x55555555, 0xAAAAAAAA)
SIGNATURE_MAGIC = 0x04030201
PAYLOAD_MAGIC = 0x01020304
F6600_SIGNATURE = b"F6600"
CHUNK_SIZE = 65536


def get_cipher():
    key = sha256(KEY_STR.encode("utf-8")).digest()
    iv = sha256(IV_STR.encode("utf-8")).digest()[:16]
    return AES.new(key, AES.MODE_CBC, iv)


def decrypt_f6600(infile_path, outfile_path):
    if not os.path.exists(infile_path):
        print(f"Error: El archivo de entrada '{infile_path}' no existe.", file=sys.stderr)
        return 1

    with open(infile_path, "rb") as f:
        data = f.read()

    file_size = len(data)
    min_size = 128 + 12 + len(F6600_SIGNATURE) + 60 + 12
    if file_size < min_size:
        print(f"Error: El archivo '{infile_path}' es demasiado pequeño ({file_size} bytes).", file=sys.stderr)
        return 1

    # 1. Cabecera ZTE (128 bytes)
    magic = struct.unpack(">4I", data[:16])
    if magic != ZTE_MAGIC:
        print(f"[!] Advertencia: Magic ZTE no esperado en '{infile_path}'. Intentando continuar...")

    header = struct.unpack("<28I", data[16:128])
    signed_payload_size = header[14]
    header_length = header[13]

    if header_length + signed_payload_size != file_size:
        print(f"[!] Advertencia: El tamaño del archivo ({file_size}) difiere de la cabecera ({header_length + signed_payload_size}).")

    stream = BytesIO(data[128:])

    # 2. Firma ZTE (12 bytes cabecera + string)
    sig_hdr = struct.unpack(">3I", stream.read(12))
    if sig_hdr[0] != SIGNATURE_MAGIC:
        print("Error: Cabecera de firma inválida (SIGNATURE_MAGIC no coincide).", file=sys.stderr)
        return 1

    sig_len = sig_hdr[2]
    sig_text = stream.read(sig_len).decode("utf-8", errors="ignore")
    print(f"[*] Router / Firma detectada: {sig_text}")

    # 3. Payload Header exterior (60 bytes)
    payload_hdr = struct.unpack(">15I", stream.read(60))
    if payload_hdr[0] != PAYLOAD_MAGIC:
        print("Error: Cabecera de payload exterior inválida (PAYLOAD_MAGIC no coincide).", file=sys.stderr)
        return 1

    payload_type = payload_hdr[1]
    print(f"[*] Tipo de payload exterior: {payload_type}")
    if payload_type != 6:
        print(f"[!] Advertencia: Se esperaba tipo 6 para F6600, pero se leyó tipo {payload_type}.")

    # 4. Lectura de chunks cifrados (AES-256-CBC)
    encrypted_buf = BytesIO()
    total_dec_size = 0
    while True:
        hdr_bytes = stream.read(12)
        if len(hdr_bytes) < 12:
            break
        dec_size, chunk_size, more_data = struct.unpack(">3I", hdr_bytes)
        encrypted_buf.write(stream.read(chunk_size))
        total_dec_size += dec_size
        if more_data == 0:
            break

    # 5. Descifrado AES-256-CBC
    cipher = get_cipher()
    decrypted_raw = cipher.decrypt(encrypted_buf.getvalue())[:total_dec_size]
    dec_stream = BytesIO(decrypted_raw)

    # 6. Payload Header interior (60 bytes)
    inner_hdr = struct.unpack(">15I", dec_stream.read(60))
    if inner_hdr[0] != PAYLOAD_MAGIC:
        print("Error: El contenido descifrado no coincide con el magic esperado. Clave/IV incorrectos.", file=sys.stderr)
        return 1

    # 7. Descompresión ZLIB de los bloques de configuración
    decompressed_data = BytesIO()
    chunk_count = 0
    while True:
        chunk_hdr = dec_stream.read(12)
        if len(chunk_hdr) < 12:
            break
        dec_len, comp_len, more_chunks = struct.unpack(">3I", chunk_hdr)
        compressed_chunk = dec_stream.read(comp_len)
        try:
            decompressed_chunk = zlib.decompress(compressed_chunk)
        except Exception as e:
            print(f"Error al descomprimir chunk zlib #{chunk_count}: {e}", file=sys.stderr)
            return 1

        if len(decompressed_chunk) != dec_len:
            print(f"Error de integridad en chunk #{chunk_count}: longitud {len(decompressed_chunk)} != esperada {dec_len}", file=sys.stderr)
            return 1

        decompressed_data.write(decompressed_chunk)
        chunk_count += 1
        if more_chunks == 0:
            break

    # Guardar archivo de salida
    out_bytes = decompressed_data.getvalue()
    with open(outfile_path, "wb") as out:
        out.write(out_bytes)

    print(f"[✓] Archivo decriptado con éxito!")
    print(f"    Entrada: {infile_path} ({file_size:,} bytes)")
    print(f"    Salida:  {outfile_path} ({len(out_bytes):,} bytes)")
    return 0


def compress_xml(xml_bytes, chunk_size=CHUNK_SIZE):
    cumulative = 60
    total_uncompressed = 0
    crc = 0
    stream = BytesIO(xml_bytes)
    compressed_body = BytesIO()

    while True:
        data = stream.read(chunk_size)
        if not data:
            break
        uncompressed_len = len(data)
        total_uncompressed += uncompressed_len

        comp = zlib.compress(data, zlib.Z_BEST_COMPRESSION)
        crc = zlib.crc32(comp, crc) & 0xFFFFFFFF

        if uncompressed_len < chunk_size:
            more_chunks = 0
        else:
            cumulative += len(comp) + 12
            more_chunks = cumulative

        chunk_hdr = struct.pack(">3I", uncompressed_len, len(comp), more_chunks)
        compressed_body.write(chunk_hdr)
        compressed_body.write(comp)

    # Cabecera interior de 60 bytes
    hdr_fields = struct.pack(">6I", PAYLOAD_MAGIC, 0, total_uncompressed, cumulative, chunk_size, crc)
    hdr_crc = zlib.crc32(hdr_fields) & 0xFFFFFFFF

    inner = BytesIO()
    inner.write(hdr_fields)
    inner.write(struct.pack(">I", hdr_crc))
    inner.write(struct.pack(">8I", *(0, 0, 0, 0, 0, 0, 0, 0)))
    inner.write(compressed_body.getvalue())
    return inner.getvalue()


def encrypt_f6600(infile_path, outfile_path):
    if not os.path.exists(infile_path):
        print(f"Error: El archivo de entrada '{infile_path}' no existe.", file=sys.stderr)
        return 1

    with open(infile_path, "rb") as f:
        xml_data = f.read()

    print(f"[*] Comprimiendo XML ({len(xml_data):,} bytes)...")
    inner_payload = compress_xml(xml_data)
    unenc_len = len(inner_payload)

    # Padding AES (múltiplo de 16)
    pad_len = (16 - (unenc_len % 16)) % 16
    padded = inner_payload + b"\0" * pad_len
    enc_len = len(padded)

    print(f"[*] Cifrando payload con AES-256-CBC ({enc_len:,} bytes)...")
    cipher = get_cipher()
    ciphertext = cipher.encrypt(padded)

    # Payload Header exterior tipo 6 (60 bytes)
    outer_hdr = struct.pack(">15I", PAYLOAD_MAGIC, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    enc_chunk_hdr = struct.pack(">3I", unenc_len, enc_len, 0)
    outer_payload = outer_hdr + enc_chunk_hdr + ciphertext

    # Firma ZTE
    sig_hdr = struct.pack(">3I", SIGNATURE_MAGIC, 0, len(F6600_SIGNATURE))
    signed_payload = sig_hdr + F6600_SIGNATURE + outer_payload

    # Cabecera ZTE (128 bytes, little-endian para los 28 enteros)
    signed_payload_len = len(signed_payload)
    fields = [0] * 28
    fields[2] = 4
    fields[11] = 64
    fields[12] = 2  # Versión 2
    fields[13] = 128  # Tamaño cabecera
    fields[14] = signed_payload_len
    zte_hdr = struct.pack("<28I", *fields)
    zte_magic = struct.pack(">4I", *ZTE_MAGIC)

    full_binary = zte_magic + zte_hdr + signed_payload
    with open(outfile_path, "wb") as out:
        out.write(full_binary)

    print(f"[✓] Archivo encriptado con éxito listo para el router!")
    print(f"    Entrada: {infile_path} ({len(xml_data):,} bytes)")
    print(f"    Salida:  {outfile_path} ({len(full_binary):,} bytes)")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Utilidad para Decriptar y Encriptar backups de router ZTE F6600",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Comando a ejecutar")

    p_dec = subparsers.add_parser("decrypt", help="Decriptar config.bin a XML")
    p_dec.add_argument("infile", nargs="?", default="config.bin", help="Archivo .bin de entrada (default: config.bin)")
    p_dec.add_argument("outfile", nargs="?", default=None, help="Archivo .xml de salida")

    p_enc = subparsers.add_parser("encrypt", help="Encriptar XML a config.bin")
    p_enc.add_argument("infile", nargs="?", default="config.xml", help="Archivo .xml de entrada (default: config.xml)")
    p_enc.add_argument("outfile", nargs="?", default=None, help="Archivo .bin de salida")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    if args.command == "decrypt":
        infile = args.infile
        outfile = args.outfile
        if not outfile:
            if infile.endswith(".bin"):
                outfile = infile[:-4] + ".xml"
            else:
                outfile = infile + ".xml"
        return decrypt_f6600(infile, outfile)

    elif args.command == "encrypt":
        infile = args.infile
        outfile = args.outfile
        if not outfile:
            if infile.endswith(".xml"):
                outfile = infile[:-4] + "_enc.bin"
            else:
                outfile = infile + ".bin"
        return encrypt_f6600(infile, outfile)


if __name__ == "__main__":
    sys.exit(main() or 0)
