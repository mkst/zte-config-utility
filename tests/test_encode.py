import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class TestEncode(unittest.TestCase):
    def test_little_endian_header_preserves_version(self):
        repository = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary_directory:
            infile = Path(temporary_directory) / "config.xml"
            outfile = Path(temporary_directory) / "config.bin"
            infile.write_text("<config />", encoding="utf-8")
            environment = os.environ.copy()
            environment["PYTHONPATH"] = os.pathsep.join(
                filter(None, [str(repository), environment.get("PYTHONPATH")])
            )

            subprocess.run(
                [
                    sys.executable,
                    "examples/encode.py",
                    str(infile),
                    str(outfile),
                    "--payload-type",
                    "0",
                    "--include-header",
                    "--little-endian-header",
                ],
                check=True,
                cwd=repository,
                env=environment,
            )

            with outfile.open("rb") as encoded:
                encoded.read(16)
                header = struct.unpack("<28I", encoded.read(112))

        self.assertEqual(2, header[12])
