"""Seed test files exactly as the checked private primitive would publish them.

A raw ``Path.write_bytes`` in a checked private directory gets the platform
default security: on Windows the creator token's default DACL (often with a
logon-session SID) or the parent's inherited ACEs, never the protected
owner/SYSTEM/Administrators descriptor that admission requires. Tests that
need a *private* file with arbitrary content (malformed headers, history,
copied manifests) create it through ``open_private_directory`` instead, so
the product's real classification is reached on every platform.
"""

from __future__ import annotations

import os
from pathlib import Path

from mordred_hermes._private_fs import open_private_directory


def write_private(path: Path, data: bytes) -> None:
    """Create or replace ``path`` (POSIX 0600 / Windows protected private DACL)."""
    existing = os.path.lexists(path)
    with open_private_directory(path.parent) as directory, directory.transaction() as txn:
        if existing:
            txn.replace_bytes(path.name, data)
        else:
            txn.create_bytes(path.name, data)
