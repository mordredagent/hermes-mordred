#!/usr/bin/env python3
"""Explicitly prepare hash-locked SQLCipher API headers; never compile SQLite.

The build hook only validates local inputs. This separate command is the explicit
network preparation step for CI/build operators, before a Windows editable or
wheel install. Only two verified API headers leave the source archive.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import tarfile
import urllib.request
from pathlib import Path

SOURCE_URL = (
    "https://files.pythonhosted.org/packages/61/ec/"
    "d79c2e5f5b9246471f217cdd5f703dc8d804bce557a047e1bfad4f33c376/sqlcipher3_wheels-0.5.7.tar.gz"
)
SOURCE_SHA256 = "5fd344abba62c487c4d857a6fb55cb8dff8a97d4c4fbb4f9394b473e8e315dee"
HEADER_SHA256 = {
    "sqlite3.h": "64d0df48780a6606fed83f4b7fb6a6d89254762a5437e7b68e5fdf0a71a9fa40",
    "sqlite3ext.h": "d085a90ec1497094ebd090811e9988e97b6a51604a6135fde6af00186168af8a",
}
_PREFIX = "sqlcipher3_wheels-0.5.7/src/sqlcipher/"


def _verify(name: str, data: bytes, digest: str) -> None:
    if hashlib.sha256(data).hexdigest() != digest:
        raise RuntimeError(f"SQLCipher build input digest mismatch: {name}")


def validate_headers(directory: Path) -> None:
    """Refuse missing/replaced caller inputs against the locked source recipe."""
    for name, digest in HEADER_SHA256.items():
        try:
            data = (directory / name).read_bytes()
        except OSError:
            raise RuntimeError(f"missing SQLCipher build input: {name}") from None
        _verify(name, data, digest)


def prepare_headers(directory: Path, source: bytes) -> None:
    """Verify source then extract only headers by exact archive member name."""
    _verify("sqlcipher3-wheels 0.5.7 source", source, SOURCE_SHA256)
    with tarfile.open(fileobj=io.BytesIO(source), mode="r:gz") as archive:
        header_file = archive.extractfile(_PREFIX + "sqlite3.h")
        amalgamation_file = archive.extractfile(_PREFIX + "sqlite3.c")
        if header_file is None or amalgamation_file is None:
            raise RuntimeError("locked SQLCipher source lacks API headers")
        header, amalgamation = header_file.read(), amalgamation_file.read()
    start = amalgamation.index(b"/************** Begin file sqlite3ext.h")
    start = amalgamation.index(b"\n", start) + 1
    end = amalgamation.index(b"/************** End of sqlite3ext.h", start)
    headers = {"sqlite3.h": header, "sqlite3ext.h": amalgamation[start:end]}
    for name, value in headers.items():
        _verify(name, value, HEADER_SHA256[name])
    directory.mkdir(parents=True, exist_ok=True)
    for name, value in headers.items():
        (directory / name).write_bytes(value)
    validate_headers(directory)
    (directory / "dbcrypt-headers.json").write_text(
        json.dumps({"source_url": SOURCE_URL, "source_sha256": SOURCE_SHA256, "headers": HEADER_SHA256}, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", required=True, type=Path)
    parser.add_argument("--source-archive", type=Path, help="use an already downloaded locked source; no network")
    args = parser.parse_args()
    if args.source_archive is not None:
        source = args.source_archive.read_bytes()
    else:
        with urllib.request.urlopen(SOURCE_URL, timeout=60) as response:
            source = response.read(32 * 1024 * 1024 + 1)
    prepare_headers(args.output_directory, source)


if __name__ == "__main__":
    main()
