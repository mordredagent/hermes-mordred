"""``hermes mordred keyvault {list,verify-digest}`` — backend-free keyvault inspection.

Phase 4 PR8. SPEC.md §4.2 / TODO.md §4.2 L429-430.

These two commands only *read* the on-disk keyvault layout
(``meta.json`` + ``digests/<key_id_hash>.commit``); they need neither a
Secure-Enclave ``NativeBackend`` nor the ``cryptography`` stack, so this
module imports on any platform. ``keyvault init`` / ``keyvault recover``
(and ``audit decrypt``) do need the production backend and land in a
later PR.

- ``list`` — print each key's cleartext id, on-disk hash and creation
  timestamp. The verification digest (key material) is never printed.
- ``verify-digest`` — print the full 32-byte verification digest of
  every key, hex-encoded, so the operator can cross-check it against the
  value recorded on a second device at generation time.

The wizard owns reads over ``~/.hermes/mordred/keyvault/``; ``keyvault``
itself remains the sole writer (PATHS.md).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .._home import hermes_home as _hermes_home
from ..keyvault import _storage

__all__ = ["cli_list", "cli_verify_digest", "list_keys", "verify_digest"]


def _resolve_root(home: Path | None) -> Path:
    """Resolve the keyvault root, defaulting the Hermes home via :func:`_hermes_home`.

    The home is resolved here (not deferred to ``resolve_keyvault_dir``'s
    own default) so tests can monkeypatch this module's :func:`_hermes_home`
    to point at a ``tmp_path``.
    """
    return _storage.resolve_keyvault_dir(home if home is not None else _hermes_home())


def list_keys(*, home: Path | None = None) -> int:
    """Print the keyvault's key ids. Returns 0 always (an empty vault is not an error)."""
    meta = _storage.load_meta(_resolve_root(home))
    keys = meta["keys"]
    if not keys:
        print("No keys in keyvault.")
        return 0
    print(f"{len(keys)} key(s) in keyvault:")
    for key_id_hash in sorted(keys):
        row = keys[key_id_hash]
        key_id = row.get("key_id", "<unknown>")
        created = row.get("created_at", "<unknown>")
        print(f"  {key_id}  (hash {key_id_hash}, created {created})")
    return 0


def verify_digest(*, home: Path | None = None) -> int:
    """Print every key's full verification digest for offline cross-checking.

    Returns 0 when every digest was read, 1 when the vault is empty or any
    ``digests/<hash>.commit`` file could not be read.
    """
    root = _resolve_root(home)
    meta = _storage.load_meta(root)
    keys = meta["keys"]
    if not keys:
        print("No keys to verify in keyvault.", file=sys.stderr)
        return 1

    rc = 0
    print("Verification digests (compare against the value recorded at generation time):")
    for key_id_hash in sorted(keys):
        key_id = keys[key_id_hash].get("key_id", "<unknown>")
        commit = root / "digests" / f"{key_id_hash}.commit"
        try:
            digest = _storage.safe_read(commit)
        except OSError as exc:
            print(f"  {key_id}  (hash {key_id_hash}): digest unavailable — {exc}", file=sys.stderr)
            rc = 1
            continue
        print(f"  {key_id}  (hash {key_id_hash}): {digest.hex()}")
    return rc


# -----------------------------------------------------------------------------
# CLI adapters wired in cli.py.
# -----------------------------------------------------------------------------


def cli_list(args: argparse.Namespace) -> int:
    """argparse handler for ``keyvault list`` (takes no options)."""
    del args
    return list_keys()


def cli_verify_digest(args: argparse.Namespace) -> int:
    """argparse handler for ``keyvault verify-digest`` (takes no options)."""
    del args
    return verify_digest()
