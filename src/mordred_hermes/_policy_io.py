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

:func:`read_policy_mode_fail_closed` is the *other* reader this module
hosts: the open-first, fail-CLOSED policy-mode read (M1 security review,
2026-06-11). It exists because collapsing missing-vs-unreadable into a
single ``{}`` (what :func:`load_policy_mapping` does) silently disabled
strict enforcement when ``policy.json`` was corrupted or made unreadable.
An ``exists()`` pre-check would both race the open (TOCTOU) and misread a
stat failure -- e.g. search permission stripped from the parent dir -- as
"absent" -> default, so only a clean ``FileNotFoundError`` keeps the
fresh-install default; every other failure reads as ``"strict"``.
``network.hooks`` (where the M1 fix originally landed) and
``llm_guard._read_policy_mode`` both resolve through it, so the two
enforcement layers reading ``policy.json`` cannot diverge again.

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

from ._policy_types import VALID_POLICY_MODES


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


def read_policy_mode_fail_closed(
    path: Path,
    *,
    default: str,
    log: logging.Logger,
) -> str:
    """Open-first, fail-closed read of ``policy`` from ``path`` (M1 contract).

    Only a clean ``FileNotFoundError`` — including a dangling symlink,
    equivalent to deletion — returns ``default`` (the fresh-install mode:
    ``"off"`` for network, ``"lenient"`` for llm_guard). A file that EXISTS
    and cannot be opened, read, or parsed, a non-dict root, and an invalid
    ``policy`` value all read as ``"strict"``: falling back to the default
    meant corrupting policy.json silently disabled strict enforcement.
    ``default`` is also the mode when the file parses but has no ``policy``
    key — an incomplete file is user-authored, not an attack surface, and
    the pre-M1 readers agreed on that.
    """
    try:
        f = path.open(encoding="utf-8")
    except FileNotFoundError:
        return default
    except OSError as e:
        log.error("policy file %s exists but is unreadable (%s); failing closed to strict", path, e)
        return "strict"
    try:
        with f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        log.error("policy file %s exists but is unreadable (%s); failing closed to strict", path, e)
        return "strict"
    if not isinstance(data, dict):
        log.error("policy file %s has a non-dict root; failing closed to strict", path)
        return "strict"
    mode = data.get("policy", default)
    # isinstance before frozenset membership — ``in`` on a frozenset raises
    # TypeError for unhashable values like ``[]`` / ``{}`` (Codex round 3 P2).
    if isinstance(mode, str) and mode in VALID_POLICY_MODES:
        return mode
    log.error("invalid policy %r in %s; failing closed to strict", mode, path)
    return "strict"
