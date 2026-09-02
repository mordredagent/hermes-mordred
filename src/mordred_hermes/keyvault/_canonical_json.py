"""Canonical JSON serialization shared by the keyvault's authenticated formats.

Every keyvault artifact that is hashed, MAC'd, signed, or used as AEAD
associated data — the vault manifest (``MVMF``), the ``MVLT`` file-container
header, the device-bound anchor, the audit-log header and its entries, the
``meta.json`` sidecar, the extension wallet config, and the backup manifest —
must serialize to the SAME bytes on every write. Compact separators plus
``sort_keys=True`` supply that determinism regardless of dict insertion order;
without it a re-serialization would produce a different digest and the
artifact would fail its own integrity check.

Because those bytes are already on disk and already authenticated, the output
here must stay byte-for-byte identical to
``json.dumps(obj, sort_keys=True, separators=(",", ":"))`` — this module is
pinned by :mod:`tests.test_keyvault_canonical_json`.

Stdlib-only leaf module: it imports :mod:`json` and nothing from the package,
so any keyvault module can depend on it without risking an import cycle.
"""

from __future__ import annotations

import json
from typing import Any

# Compact separators: no space after "," or ":". Pinned as a constant so the
# two entry points below cannot drift apart.
_SEPARATORS = (",", ":")


def canonical_json_text(obj: Any, *, ensure_ascii: bool = True) -> str:
    """Serialize *obj* to compact, key-sorted JSON text.

    ``ensure_ascii`` mirrors :func:`json.dumps`: the default escapes non-ASCII
    characters as ``\\uXXXX``; ``False`` emits them as themselves (what the
    audit log does, since its entries carry human-readable text).
    """
    return json.dumps(obj, sort_keys=True, separators=_SEPARATORS, ensure_ascii=ensure_ascii)


def canonical_json_bytes(obj: Any, *, ensure_ascii: bool = True) -> bytes:
    """Serialize *obj* to compact, key-sorted UTF-8 JSON bytes.

    The byte form every hashed / MAC'd / signed keyvault artifact is built
    from; see :func:`canonical_json_text` for ``ensure_ascii``.
    """
    return canonical_json_text(obj, ensure_ascii=ensure_ascii).encode("utf-8")
