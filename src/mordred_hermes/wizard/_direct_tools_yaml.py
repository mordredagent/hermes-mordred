"""The read side of :mod:`.direct_tools`: config.yaml's ``tools.tool_search`` as Hermes reads it.

Hermes 0.21.5 loads config.yaml with ``hermes_yaml.safe_load`` (ruamel
``typ="safe"`` with ``version = (1, 1)``, the C parser first and the pure one
when it refuses: plain ``off``, ``no``, ``n`` and
``false`` are booleans, ``on``, ``yes``, ``y`` and ``true`` too), deep-merges it
over ``DEFAULT_CONFIG`` (``tools.tool_search.enabled: "auto"``; a ``None`` over a
default mapping is ignored, any other value replaces it) and resolves
``tools.tool_search`` with ``ToolSearchConfig.from_raw`` and ``_tri_state``.
:func:`hermes_data` uses the same loader setup and :func:`mode_of` re-implements
the rule. Nothing here writes config.yaml: :func:`.direct_tools.set_direct`
delegates the write to Hermes's own ``hermes config`` command.

**A child process parses.** ruamel's errors and warnings
(``ReusedAnchorWarning``, ``MantissaNoDotYAML1_1Warning``) quote source lines,
values included, and Python's warning sink is process-wide, so no parse runs in
the Hermes process. :mod:`.direct_tools` starts this module as a child
(``python -I``, ``main``): it gets the config.yaml text on stdin, never opens a
file, and prints exactly one JSON line, ``{"direct", "source", "existing"}`` or
``{"code": "config_unreadable"}``; the parent drops its stderr. Inside the child
every load still runs under :func:`_quiet`, and any error or warning is
``config_unreadable``. The functions stay pure, for the child and for tests.
"""

from __future__ import annotations

import json
import sys
import threading
import warnings
from collections import Counter
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from typing import Any, Final, Literal

__all__ = [
    "DEFERRED",
    "EXISTING",
    "DirectToolsError",
    "answer",
    "existing_value",
    "hermes_data",
    "is_off",
    "main",
    "mode_of",
]

#: The explicit deferrals ``on`` may replace (``_tri_state`` gives "auto" or "on" for them).
DEFERRED: Final = frozenset({"auto", "on", "true", "1", "yes"})
#: Parses in one process, one at a time (the reader child is single-threaded anyway).
_PARSE_LOCK = threading.RLock()
#: ``existing_value`` answers (``main`` prints one of them).
EXISTING: Final = frozenset({"absent", "deferral", "legacy", "other", "shared"})


class DirectToolsError(Exception):
    """A refusal with one of ``direct_tools.ERROR_CODES``; the message is the code alone."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@contextmanager
def _quiet() -> Iterator[list[warnings.WarningMessage]]:
    with _PARSE_LOCK, warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        yield caught


def _load(text: str, *, pure: bool) -> Any:
    from ruamel.yaml import YAML

    yaml = YAML(typ="safe", pure=pure)
    yaml.version = (1, 1)
    return yaml.load(text)


def hermes_data(text: str | None) -> Any:
    """The document as Hermes loads it; ``None`` for no or an empty file.

    Like ``hermes_yaml.safe_load``: the C parser first (it keeps YAML 1.1 even
    under a ``%YAML 1.2`` directive), the pure parser when the C one refuses.
    Raises ``config_unreadable`` for any YAML error or warning, dropping its text.
    """
    if text is None:
        return None
    from ruamel.yaml.error import YAMLError

    with _quiet() as caught:
        try:
            try:
                data = _load(text, pure=False)
            except YAMLError:
                data = _load(text, pure=True)
        except (YAMLError, ValueError, RecursionError):
            raise DirectToolsError("config_unreadable") from None
        if caught:
            caught.clear()  # the messages quote the document: dropped unread
            raise DirectToolsError("config_unreadable")
    return data


def _tri_state(value: Any) -> str:
    """``tools/tool_search.py::_tri_state`` (Hermes 0.21.5)."""
    aliases = {"true": "on", "1": "on", "yes": "on", "false": "off", "0": "off", "no": "off"}
    text = str(value).strip().lower()
    return aliases.get(text, text if text in ("auto", "on", "off") else "auto")


def is_off(value: Any) -> bool:
    """Hermes reads this ``enabled`` value (also printed by ``hermes config get``) as off."""
    return _tri_state(value) == "off"


def _search(data: Any) -> Any:
    if data is None:
        return None
    if not isinstance(data, Mapping):
        raise DirectToolsError("config_unreadable")
    tools = data.get("tools")
    return tools.get("tool_search") if isinstance(tools, Mapping) else None


def mode_of(data: Any) -> dict[str, Any]:
    """``{"direct": bool, "source": "config" | "default"}`` for :func:`hermes_data`.

    Absent or ``None`` values keep Hermes's default (``"auto"``, deferred). A
    legacy non-mapping ``tool_search`` is direct only when it is the boolean
    false (plain ``off``/``no``/``n``/``false``; the string ``"off"`` and the
    integer ``0`` are not). A mapping's ``enabled`` is direct when
    ``_tri_state`` gives ``"off"``, which covers the string ``'off'`` that
    ``hermes config set`` stores.
    """
    search = _search(data)
    if search is None:
        return {"direct": False, "source": "default"}
    if not isinstance(search, Mapping):
        return {"direct": search is False, "source": "config"}
    value = search.get("enabled")
    if value is None:
        return {"direct": False, "source": "default"}
    return {"direct": is_off(value), "source": "config"}


def _shared(data: Any) -> bool:
    """The ``tools`` or the ``tools.tool_search`` mapping is referenced from more than one place.

    Safe loading gives every alias (and every ``<<`` merge source) the same
    object, so counting object ids over every mapping and sequence finds them.
    Hermes's setter would change the other place too.
    """
    counts: Counter[int] = Counter()
    stack = [data]
    while stack:
        node = stack.pop()
        if not isinstance(node, Mapping | list):
            continue
        counts[id(node)] += 1
        if counts[id(node)] == 1:
            stack.extend(node.values() if isinstance(node, Mapping) else node)
    tools = data.get("tools") if isinstance(data, Mapping) else None
    search = tools.get("tool_search") if isinstance(tools, Mapping) else None
    return any(isinstance(node, Mapping) and counts[id(node)] > 1 for node in (tools, search))


def existing_value(data: Any) -> Literal["absent", "deferral", "legacy", "other", "shared"]:
    """What ``tools.tool_search`` holds: ``on`` replaces only "absent" and "deferral"; ``off``
    unsets ``tools.tool_search`` itself for "legacy"; "shared" (an alias) is never changed."""
    if _shared(data):
        return "shared"
    search = _search(data)
    if search is None:
        return "absent"
    if not isinstance(search, Mapping):
        return "legacy"
    value = search.get("enabled")
    if value is None:
        return "absent"
    return "deferral" if str(value).strip().lower() in DEFERRED else "other"


def answer(text: str, *, strict_empty: bool = False) -> dict[str, Any]:
    """The reader's answer for config.yaml ``text``: ``{"direct", "source", "existing"}`` or
    ``{"code": "config_unreadable"}``. ``strict_empty``: an empty or comment-only document is
    unreadable (the checked Windows reader's rule)."""
    try:
        data = hermes_data(text)
        if data is None and strict_empty:
            raise DirectToolsError("config_unreadable")
        mode = mode_of(data)
        return {"direct": mode["direct"], "source": mode["source"], "existing": existing_value(data)}
    except DirectToolsError:
        return {"code": "config_unreadable"}


def main(argv: list[str] | None = None) -> int:
    """The reader child: config.yaml's text on stdin (UTF-8), one JSON line on stdout."""
    args = sys.argv[1:] if argv is None else argv
    try:
        text = sys.stdin.buffer.read().decode("utf-8")
    except (OSError, ValueError):
        result: dict[str, Any] = {"code": "config_unreadable"}
    else:
        result = answer(text, strict_empty="strict" in args)
    sys.stdout.write(json.dumps(result) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
