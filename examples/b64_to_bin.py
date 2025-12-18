import base64
import sys
from pathlib import Path


def main():
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} [infile] <outfile>")
        print(f"  e.g. python3 {sys.argv[0]} config.bin")
        return 1

    infile = Path(sys.argv[1])

    if len(sys.argv) > 2:
        outfile = Path(sys.argv[2])
    else:
        outfile = infile

    if not infile.is_file():
        print(f"{infile} not found")
        return 1

    with infile.open("rb") as f:
        data = f.read()

    if data[:4] != b"BAMC":
        print("This isn't a base64 encoded config.bin")
        return 1

    try:
        decoded = base64.b64decode(data)
    except Exception:
        print(f"Failed to base64 decode {infile}: e")
        return

    with outfile.open("wb") as f:
        f.write(decoded)

    print("Success!")


if __name__ == "__main__":
    main()
