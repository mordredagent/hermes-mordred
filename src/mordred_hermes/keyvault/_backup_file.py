"""A backup file that restores the keyvault on its own: no passphrase to type.

``setup --no-prompts`` (the one-step installer) never asks for a passphrase.
It generates one, uses it for the keyvault ceremony and the at-rest vault's
recovery, and saves it inside the backup file next to the ``export_backup``
blob that it protects. The file alone then restores the keyvault on another
device, so the file itself is the secret: whoever holds it holds the keyvault.

Layout (all lengths big-endian)::

    b"MRKF1\\n" | u16 passphrase length | passphrase (UTF-8) | export_backup blob

A file without the magic is a plain ``export_backup`` blob (``keyvault
export``, ``keyvault init --backup-file``): it needs the passphrase typed.
"""

from __future__ import annotations

import secrets
import struct
from typing import Final

MAGIC: Final = b"MRKF1\n"
_LENGTH: Final = struct.Struct(">H")
#: 32 random bytes, URL-safe base64 (43 characters): far beyond any guessing.
GENERATED_BYTES: Final = 32


class BackupFileCorrupt(ValueError):
    """The file starts like a self-contained backup but is not a valid one."""


def generate_passphrase() -> str:
    return secrets.token_urlsafe(GENERATED_BYTES)


def pack(passphrase: str, blob: bytes) -> bytes:
    """The self-contained backup file for ``blob`` and the ``passphrase`` protecting it."""
    encoded = passphrase.encode("utf-8")
    if not encoded or len(encoded) > 0xFFFF:
        raise ValueError("passphrase length out of range")
    return MAGIC + _LENGTH.pack(len(encoded)) + encoded + blob


def unpack(data: bytes) -> tuple[str | None, bytes]:
    """``(passphrase, blob)``; ``passphrase`` is ``None`` for a plain ``export_backup`` blob."""
    if not data.startswith(MAGIC):
        return None, data
    head = len(MAGIC)
    if len(data) < head + _LENGTH.size:
        raise BackupFileCorrupt("truncated")
    (length,) = _LENGTH.unpack_from(data, head)
    start = head + _LENGTH.size
    if length == 0 or len(data) <= start + length:
        raise BackupFileCorrupt("truncated")
    try:
        passphrase = data[start : start + length].decode("utf-8")
    except UnicodeDecodeError:
        raise BackupFileCorrupt("passphrase is not UTF-8") from None
    return passphrase, data[start + length :]
