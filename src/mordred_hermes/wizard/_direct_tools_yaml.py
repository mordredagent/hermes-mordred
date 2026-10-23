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

ruamel's errors and warnings (``ReusedAnchorWarning``,
``MantissaNoDotYAML1_1Warning``) quote source lines, values included, so every
load runs under :func:`_quiet` and any error or warning is ``config_unreadable``;
nothing of it is kept. ``warnings.catch_warnings`` swaps process-wide state, so
a warning another thread raises during a parse may be captured (and that parse
refuses) instead of shown.
"""

from __future__ import annotations

import threading
import warnings
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from typing import Any, Final, Literal

__all__ = ["DEFERRED", "DirectToolsError", "existing_value", "hermes_data", "is_off", "mode_of"]

#: The explicit deferrals ``on`` may replace (``_tri_state`` gives "auto" or "on" for them).
DEFERRED: Final = frozenset({"auto", "on", "true", "1", "yes"})
#: Mordred's own parses, one at a time (their warning filters must not interleave).
_PARSE_LOCK = threading.RLock()


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


def existing_value(data: Any) -> Literal["absent", "deferral", "legacy", "other"]:
    """What ``tools.tool_search`` holds: ``on`` replaces only "absent" and "deferral"; ``off``
    unsets ``tools.tool_search`` itself for "legacy"."""
    search = _search(data)
    if search is None:
        return "absent"
    if not isinstance(search, Mapping):
        return "legacy"
    value = search.get("enabled")
    if value is None:
        return "absent"
    return "deferral" if str(value).strip().lower() in DEFERRED else "other"
