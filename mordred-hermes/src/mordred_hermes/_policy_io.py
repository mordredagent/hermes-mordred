"""Shared ``policy.json`` read helper for config-reading plugin code.

Single-sources the "open ``policy.json`` and hand back a mapping, or fall
back to empty on any read/parse failure" core that was independently
copy-pasted across four call sites (``network`` x1 whole-dict load,
``llm_guard`` x3: policy mode / enforce settings / local endpoint). Each
caller still owns its own extraction (the ``.get()`` chain) and its own
default; only the load core is shared.

This is the JSON sibling of :mod:`mordred_hermes._yaml_io`. The shape is
deliberately identical: an ``exists()`` pre-check, a narrow ``(OSError,
json.JSONDecodeError)`` catch routed to ``{}``, and a non-mapping root
collapsed to ``{}`` so callers can apply their own defaults without
crashing plugin registration. Unlike ``_yaml_io`` the catch set never
diverged across callers, so there is no ``catch`` parameter.

Intentionally NOT a client of this helper: ``network.hooks._read_policy_mode``.
That reader is *open-first* and fails CLOSED to ``"strict"`` on every error
other than a clean ``FileNotFoundError`` (M1 security review, 2026-06-11): an
``exists()`` pre-check would both race the open (TOCTOU) and misread a stat
failure -- e.g. search permission stripped from the parent dir -- as
"absent" -> ``off``, silently disabling strict enforcement. Collapsing its
missing-vs-unreadable distinction into a single ``{}`` would destroy that
fail-closed contract, so it keeps its bespoke loader.

As with ``_yaml_io``, the warning text is normalised here to
``"could not read ..."``. The per-site suffixes ("defaulting to empty",
"using safe defaults", "using default endpoint", "defaulting to <mode>")
are asserted by no test and are not part of the behavioural contract.

``json`` is imported at module scope (unlike the lazy ``ruamel`` import in
``_yaml_io``): it is stdlib and carries no plugin-discovery import cost
worth deferring.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any


def load_policy_mapping(
    path: Path,
    *,
    log: logging.Logger | None = None,
) -> dict[str, Any]:
    """Load ``path`` as a JSON mapping, collapsing every failure to ``{}``.

    A missing file, an unreadable file, a JSON parse error, or a top-level
    JSON value that is not an object all return ``{}`` so callers can apply
    their own defaults without crashing. When ``log`` is supplied, a
    swallowed read/parse error is warned on it.

    This uses an ``exists()`` pre-check and is therefore unsuitable for
    fail-closed readers that must distinguish "absent" from "unreadable"
    (see the module docstring re ``network.hooks``).
    """
    if not path.exists():
        return {}
    try:
        with path.open(encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        if log is not None:
            log.warning("could not read %s: %s", path, e)
        return {}
    return data if isinstance(data, dict) else {}
