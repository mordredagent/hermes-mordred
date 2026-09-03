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

There are deliberately two named byte forms rather than one function with an
``ensure_ascii`` switch: :func:`canonical_json_bytes` (ASCII-escaped, what
every authenticated header/manifest uses) and
:func:`canonical_json_bytes_unescaped` (non-ASCII emitted as itself, used only
for the human-readable audit-log *entries*). A call site picks the form by
name, so an authenticated format cannot silently get the wrong bytes by
flipping a flag.

Stdlib-only leaf module: it imports :mod:`json` and nothing from the package,
so any keyvault module can depend on it without risking an import cycle.
"""

from __future__ import annotations

import json
from typing import Any

# Compact separators: no space after "," or ":". Pinned as a constant so the
# entry points below cannot drift apart.
_SEPARATORS = (",", ":")


def canonical_json_text(obj: Any) -> str:
    """Serialize *obj* to compact, key-sorted, ASCII-escaped JSON text.

    Non-ASCII characters are escaped as ``\\uXXXX`` (``json.dumps``' default),
    so the text is identical on every platform and locale.
    """
    return json.dumps(obj, sort_keys=True, separators=_SEPARATORS)


def canonical_json_bytes(obj: Any) -> bytes:
    """Serialize *obj* to compact, key-sorted, ASCII-escaped UTF-8 JSON bytes.

    The byte form every hashed / MAC'd / signed keyvault artifact is built from.
    """
    return canonical_json_text(obj).encode("utf-8")


def canonical_json_bytes_unescaped(obj: Any) -> bytes:
    """Like :func:`canonical_json_bytes` but with non-ASCII emitted as itself.

    Used only for audit-log entries, whose plaintext carries human-readable
    text and is read back by people; the escaped form stays the default for
    every authenticated header. Still compact and key-sorted, so it is just as
    deterministic.
    """
    return json.dumps(obj, sort_keys=True, separators=_SEPARATORS, ensure_ascii=False).encode("utf-8")
