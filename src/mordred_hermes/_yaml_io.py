"""Shared YAML read helper for config-reading plugin code.

Single-sources the "open ``config.yaml`` and hand back a mapping, or fall
back to empty on any read/parse failure" core that was independently
copy-pasted across five call sites (``network`` x2, ``llm_guard`` x2,
``privacy_check`` x1). Each caller still owns its own extraction (the
``plugins.<section>`` / ``model.provider`` ``.get()`` chain) and its own
default; only the load core is shared.

:func:`load_yaml_mapping` keeps the two behaviours that genuinely diverged
across the call sites configurable, so each site's return values and
exception semantics are preserved exactly:

* ``catch`` -- the exception set routed to the degraded "empty mapping"
  path. Most callers narrow this to ``(OSError, YAMLError)`` so that
  programming errors still escape; two callers (``privacy_check._runtime``
  and ``llm_guard.harness_detect``) historically caught bare ``Exception``
  and pass ``catch=(Exception,)`` to preserve that wider net.
* ``log`` -- the caller's own logger, so the warning is attributed to the
  originating module. Passing ``None`` suppresses the warning entirely.

One thing is intentionally *not* preserved: the warning text is normalised
here to ``"could not read ..."``. The two broad-catch sites above previously
logged ``"failed to read ..."``; the wording is asserted by no test and is
not part of the behavioural contract (same normalisation precedent as the
``network/hooks`` audit-log message in #199).

The ``ruamel`` import is local (mirroring the previous per-site code) so
plugin discovery stays cheap and free of a hard ``ruamel`` import at
registration time.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any


def load_yaml_mapping(
    path: Path,
    *,
    catch: tuple[type[BaseException], ...] | None = None,
    log: logging.Logger | None = None,
) -> dict[str, Any]:
    """Load ``path`` as a YAML mapping, collapsing every failure to ``{}``.

    A missing file, an unreadable file, a parse error, or a top-level YAML
    value that is not a mapping all return ``{}`` so callers can apply their
    own defaults without crashing. ``catch`` selects which exceptions route
    to that degraded path (default ``(OSError, YAMLError)``); anything else
    propagates. When ``log`` is supplied, the swallowed error is warned on it.
    """
    if not path.exists():
        return {}
    from ruamel.yaml import YAML
    from ruamel.yaml.error import YAMLError

    if catch is None:
        catch = (OSError, YAMLError)
    yaml = YAML(typ="safe", pure=True)
    try:
        with path.open(encoding="utf-8") as f:
            data = yaml.load(f)
    except catch as e:
        if log is not None:
            log.warning("could not read %s: %s", path, e)
        return {}
    return data if isinstance(data, dict) else {}
