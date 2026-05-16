"""Backend-free probe: is the Mordred keyvault initialized?

Used by install-time enforcement of ``metadata.mordred.requires_keyvault``
(TODO.md §4.1). A keyvault is "initialized" once it holds at least one
key. The check reads ``meta.json`` only — no Secure-Enclave
``NativeBackend`` and no ``cryptography`` stack — so it runs on every
platform, exactly like ``wizard/keyvault_cli.py``'s read-only commands.

``keyvault._storage`` is imported lazily *inside* :func:`keyvault_initialized`
so the privacy_check plugin carries no module-level dependency on the
keyvault plugin: a skill that does not declare ``requires_keyvault`` never
triggers the import. The corrupt-keyvault failure is re-raised as the
probe-owned :class:`KeyvaultProbeError` for the same reason — install-time
callers in the privacy_check / wizard layer can handle it without a
module-level import of the keyvault plugin's internal exception types.

This module reads files but does not write.
"""

from __future__ import annotations

from pathlib import Path

__all__ = ["KeyvaultProbeError", "keyvault_initialized"]


class KeyvaultProbeError(RuntimeError):
    """The keyvault could not be probed — its ``meta.json`` is corrupt.

    Wraps ``keyvault._storage.KeyvaultCorruptError`` (chained via
    ``__cause__``) so install-time callers can report a corrupt keyvault
    gracefully — a clean message and exit code — instead of crashing with
    a keyvault-internal traceback.
    """


def keyvault_initialized(home: Path | None = None) -> bool:
    """Return True when the Mordred keyvault holds at least one key.

    ``home`` selects the Hermes home directory (tests pass a ``tmp_path``);
    ``None`` resolves the production ``~/.hermes``. A missing ``meta.json``
    and an empty ``keys`` object both count as "not initialized".

    Raises :class:`KeyvaultProbeError` when ``meta.json`` exists but is
    structurally invalid — a corrupt keyvault is an exceptional state the
    operator must repair, and failing loud is safer than silently treating
    it as uninitialized.
    """
    from ..keyvault import _storage

    root = _storage.resolve_keyvault_dir(home)
    try:
        meta = _storage.load_meta(root)
    except _storage.KeyvaultCorruptError as exc:
        raise KeyvaultProbeError(f"keyvault meta.json is corrupt: {exc}") from exc
    return bool(meta["keys"])
