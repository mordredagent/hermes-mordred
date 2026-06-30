"""Shared vault root + identity derivation.

A vault's device-key tag and Keychain anchor account are both derived from its
root path, so every entry point — the operator CLI (``wizard/vault_cli.py``) and
the runtime decrypt shim (``_runtime_env.py``) — opens the **same** vault for a
given root. This lives in ``keyvault`` (not ``wizard``) so the runtime shim,
which ships in this package, needs no upward dependency on ``wizard``.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from .._home import hermes_home as _hermes_home

# Default vault root, relative to the Hermes home: ``<home>/mordred/vault``.
_VAULT_SUBDIR = ("mordred", "vault")


def default_vault_root() -> Path:
    """The default vault root: ``<hermes home>/mordred/vault``."""
    return _hermes_home().joinpath(*_VAULT_SUBDIR)


def resolve_root(root: str | None) -> Path:
    """Resolve a vault root, defaulting to :func:`default_vault_root`.

    A user-supplied root is resolved to an absolute, normalized path so the same
    vault yields the same :func:`vault_identity` regardless of spelling (relative
    path, ``..``, cwd). ``default_vault_root`` is already absolute.
    """
    if root is not None:
        return Path(root).resolve()
    return default_vault_root()


def vault_identity(root: Path) -> str:
    """Stable id (device-key tag + Keychain anchor account) for a vault root.

    Derived from the root path so distinct vaults never collide in the shared
    Keychain anchor service. The same root string always maps to the same id.
    """
    digest = hashlib.sha256(str(root).encode("utf-8")).hexdigest()[:16]
    return f"mordred-hermes.vault.{digest}"
