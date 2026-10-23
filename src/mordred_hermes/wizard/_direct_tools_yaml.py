"""The YAML half of :mod:`.direct_tools`: Hermes's reading, safe shapes and comment-keeping edits.

- **Hermes's reading.** Hermes 0.21.5 loads config.yaml with
  ``hermes_yaml.safe_load`` (ruamel ``typ="safe"``, ``version = (1, 1)``:
  plain ``off``, ``no``, ``n``, ``false`` are booleans), deep-merges it over
  ``DEFAULT_CONFIG`` (``tools.tool_search.enabled: "auto"``; a ``None`` over
  a default mapping is ignored, any other value replaces it) and resolves
  ``tools.tool_search`` with ``ToolSearchConfig.from_raw``. :func:`mode_of`
  re-implements that rule on :func:`hermes_data` (the same loader); the
  round-trip tree is only used to edit.
- **No text escapes.** ruamel errors and warnings (``ReusedAnchorWarning``,
  ``MantissaNoDotYAML1_1Warning``) quote source lines, so every load runs
  under :func:`_quiet` and any error or warning is ``config_unreadable``.
- **Safe shapes only.** ``tools``, ``tool_search`` and ``enabled`` must not be
  aliases, anchors used elsewhere or inherited (or shadowed) through a merge
  key: editing them would change another setting, or removing a local value
  would reveal an inherited one (``config_unsupported_shape``). ``on`` replaces
  only an absent value or an explicit deferral (``auto``, ``on``, ``true``,
  ``yes``, ``1``, the legacy ``tool_search: true``), and refuses anything else
  (``config_has_setting``). Every edit is checked on its own output: the new
  text must read as asked and differ from the old one in this setting only.
- **Comments.** ruamel keeps the comment lines that follow a value on the last
  line of that value (``ca.items[key][2]`` in a mapping, ``[0]`` in a
  sequence): the line's own end-of-line comment, then the full-line comments
  up to the next key. Those lines belong to whatever comes next, so an
  inserted or removed block hands them on: to the previous key, or, when the
  first key goes, to the head of the mapping (``parent.ca.items[key][3]``, the
  document's head at the root).
"""

from __future__ import annotations

import copy
import io
import threading
import warnings
from collections import Counter
from collections.abc import Callable, Iterator, Mapping, MutableMapping
from contextlib import contextmanager
from typing import Any, Final, TypeVar

__all__ = ["DirectToolsError", "edited", "hermes_data", "mode_of"]

_T = TypeVar("_T")
#: ``_tri_state`` spellings that resolve to ``"off"`` (after ``str(value).strip().lower()``).
_OFF: Final = frozenset({"off", "false", "0", "no"})
#: Explicit deferrals ``on`` may replace (``"auto"``, ``"on"`` and the aliases of ``"on"``).
_DEFERRED: Final = frozenset({"auto", "on", "true", "1", "yes"})
_RAW_LIMIT: Final = 32
#: ``warnings.catch_warnings`` swaps process-wide state: Mordred's parses run one at a time.
_PARSE_LOCK = threading.RLock()


class DirectToolsError(Exception):
    """A refusal with one of ``direct_tools.ERROR_CODES``; the message is the code alone."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _windows() -> bool:
    from .. import _config_text_io

    return _config_text_io._windows()


# -- loading ------------------------------------------------------------------------------------


@contextmanager
def _quiet() -> Iterator[list[warnings.WarningMessage]]:
    """Record (never print) every warning raised meanwhile; a warning captured from another
    thread during the window only makes this parse refuse."""
    with _PARSE_LOCK, warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        yield caught


def _load(load: Callable[[], _T]) -> _T:
    from ruamel.yaml.error import YAMLError

    with _quiet() as caught:
        try:
            value = load()
        except (YAMLError, ValueError, RecursionError):
            raise DirectToolsError("config_unreadable") from None
        if caught:
            caught.clear()  # the messages quote the document: drop them unread
            raise DirectToolsError("config_unreadable")
    return value


def hermes_data(text: str | None) -> Any:
    """The document as Hermes loads it (``hermes_yaml.safe_load``); ``None`` for no or an empty file."""
    if text is None:
        return None

    def load() -> Any:
        from ruamel.yaml import YAML

        yaml = YAML(typ="safe", pure=True)
        yaml.version = (1, 1)
        return yaml.load(text)

    return _load(load)


def _round_trip(yaml: Any, text: str | None) -> Any:
    """The round-trip tree; anchors nobody references are kept too (ruamel drops them on dump)."""
    root = None if text is None else _load(lambda: yaml.load(text))
    seen: set[int] = set()
    stack = [root]
    while stack:
        node = stack.pop()
        if not isinstance(node, Mapping | list) or id(node) in seen:
            continue
        seen.add(id(node))
        anchor: Any = getattr(node, "anchor", None)
        if anchor is not None and anchor.value is not None:
            anchor.always_dump = True
        stack.extend(node.values() if isinstance(node, Mapping) else node)
    return root


# -- Hermes's rule ------------------------------------------------------------------------------


def _tri_state(value: Any) -> str:
    """``tools/tool_search.py::_tri_state`` (Hermes 0.21.5)."""
    aliases = {"true": "on", "1": "on", "yes": "on", "false": "off", "0": "off", "no": "off"}
    text = str(value).strip().lower()
    return aliases.get(text, text if text in ("auto", "on", "off") else "auto")


def _raw(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)[:_RAW_LIMIT]


def mode_of(data: Any) -> dict[str, Any]:
    """``{"direct", "source", "raw"}`` for :func:`hermes_data` (``ToolSearchConfig.from_raw``).

    Absent or ``None`` values keep Hermes's default (``"auto"``, deferred). A
    legacy non-mapping ``tool_search`` is direct only when it is the boolean
    false (plain ``off``/``no``/``n``/``false``; the string ``"off"`` and the
    integer ``0`` are not). A mapping's ``enabled`` is direct when
    ``_tri_state`` gives ``"off"``.
    """
    default: dict[str, Any] = {"direct": False, "source": "default", "raw": None}
    if data is None:
        return default
    if not isinstance(data, Mapping):
        raise DirectToolsError("config_unreadable")
    tools = data.get("tools")
    search = tools.get("tool_search") if isinstance(tools, Mapping) else None
    if search is None:
        return default
    if not isinstance(search, Mapping):
        return {"direct": search is False, "source": "config", "raw": _raw(search)}
    value = search.get("enabled")
    if value is None:
        return default
    return {"direct": _tri_state(value) == "off", "source": "config", "raw": _raw(value)}


def _without_setting(data: Any) -> Any:
    """``data`` without what :func:`edited` may change (and the mappings that leaves empty)."""
    data = copy.deepcopy(data) if isinstance(data, Mapping) else {}
    tools = data.get("tools")
    if isinstance(tools, dict) and "tool_search" in tools:
        search = tools["tool_search"]
        if isinstance(search, dict):
            search.pop("enabled", None)
        if not isinstance(search, dict) or not search:
            del tools["tool_search"]
        if not tools:
            del data["tools"]
    return data


# -- safe shapes ---------------------------------------------------------------------------------


def _merge_sources(mapping: Any) -> list[Any]:
    return [entry[1] if isinstance(entry, tuple) else entry for entry in getattr(mapping, "merge", None) or []]


def _inherited(mapping: Any, key: str) -> bool:
    """``key`` comes from (or is shadowed over) a merge key (``<<``) of ``mapping``."""
    return any(isinstance(source, Mapping) and key in source for source in _merge_sources(mapping))


def _occurrences(root: Any) -> Counter[int]:
    """How often each collection appears in the tree: an alias is the same object again."""
    counts: Counter[int] = Counter()
    stack = [root]
    while stack:
        node = stack.pop()
        if not isinstance(node, Mapping | list):
            continue
        counts[id(node)] += 1
        if counts[id(node)] > 1:
            continue  # counted; its children were (or will be) walked once
        if isinstance(node, Mapping):
            own = getattr(node, "_ok", None)
            stack.extend(value for key, value in node.items() if own is None or key in own)
            stack.extend(_merge_sources(node))
        else:
            stack.extend(node)
    return counts


def _anchored(value: Any) -> bool:
    return getattr(getattr(value, "anchor", None), "value", None) is not None


def _check_shape(root: Any, data: Any, enabled: bool) -> None:
    """Refuse aliases, shared anchors and merges on the path, and (``on``) a value Mordred keeps."""
    counts = _occurrences(root)
    unsupported = DirectToolsError("config_unsupported_shape")
    if _inherited(root, "tools"):
        raise unsupported
    tools = root.get("tools")
    if tools is None:
        return
    if not isinstance(tools, MutableMapping) or counts[id(tools)] > 1 or _inherited(tools, "tool_search"):
        raise unsupported
    search = tools.get("tool_search")
    if isinstance(search, MutableMapping):
        if counts[id(search)] > 1 or _inherited(search, "enabled") or _anchored(search.get("enabled")):
            raise unsupported
    elif _anchored(search):
        raise unsupported
    if enabled and search is not None:
        _check_replaceable(search, data)


def _check_replaceable(search: Any, data: Any) -> None:
    """``on`` replaces only an absent value or an explicit deferral (Hermes's view, YAML 1.1)."""
    tools = data.get("tools") if isinstance(data, Mapping) else None
    seen = tools.get("tool_search") if isinstance(tools, Mapping) else None
    if isinstance(search, MutableMapping):
        value = seen.get("enabled") if isinstance(seen, Mapping) else None
        if value is not None and str(value).strip().lower() not in _DEFERRED:
            raise DirectToolsError("config_has_setting")
    elif seen is not True:  # the legacy scalar: only ``true`` (Hermes's "auto") is replaced
        raise DirectToolsError("config_has_setting")


# -- comment-keeping edits ------------------------------------------------------------------------


def _block(value: Any) -> bool:
    from ruamel.yaml.comments import CommentedMap, CommentedSeq

    return isinstance(value, CommentedMap | CommentedSeq) and len(value) > 0 and not value.fa.flow_style()


def _slot(container: Any, key: Any) -> tuple[list[Any], int] | None:
    """The comment entry (and its index) of the last line of ``container[key]``."""
    from ruamel.yaml.comments import CommentedSeq

    value = container[key]
    while _block(value):
        container, key = value, (len(value) - 1 if isinstance(value, CommentedSeq) else list(value)[-1])
        value = container[key]
    if not hasattr(container, "ca"):
        return None
    entry: list[Any] = container.ca.items.setdefault(key, [None, None, None, None])
    return entry, 0 if isinstance(container, CommentedSeq) else 2


def _take_following(container: Any, key: Any) -> str:
    """Detach the full-line comments after ``container[key]``; its end-of-line comment stays."""
    slot = _slot(container, key)
    token = slot[0][slot[1]] if slot else None
    if token is None:
        return ""
    own, newline, following = str(token.value).partition("\n")
    token.value = own + newline
    return following


def _comment(text: str) -> Any:
    from ruamel.yaml.error import CommentMark
    from ruamel.yaml.tokens import CommentToken

    return CommentToken(text, CommentMark(0), None)


def _put_following(container: Any, key: Any, following: str) -> None:
    """Attach full-line comments after the last line of ``container[key]``."""
    slot = _slot(container, key) if following else None
    if slot is None:
        return
    entry, index = slot
    if entry[index] is None:
        entry[index] = _comment("\n" + following)  # the line itself has no end-of-line comment
    else:
        entry[index].value = str(entry[index].value) + following


def _set_block(mapping: Any, key: str, value: Any) -> None:
    """``mapping[key] = value`` (appended or replaced), handing on the comments that followed."""
    keys = list(mapping)
    following = _take_following(mapping, key if key in mapping else keys[-1]) if keys else ""
    mapping[key] = value
    _put_following(mapping, key, following)


def _remove(mapping: Any, key: str, parent: Any = None, parent_key: str | None = None) -> None:
    """``del mapping[key]``, keeping the comments that followed it in front of the next key."""
    keys = list(mapping)
    position = keys.index(key)
    following = _take_following(mapping, key)
    del mapping[key]
    if hasattr(mapping, "ca"):
        mapping.ca.items.pop(key, None)
    if not following:
        return
    if position > 0:
        _put_following(mapping, keys[position - 1], following)
    elif parent is not None and hasattr(parent, "ca"):
        # The first key went: the comments join the mapping's head, after any head comment.
        entry = parent.ca.items.setdefault(parent_key, [None, None, None, None])
        entry[3] = [*(entry[3] or []), _comment(following)]
    elif hasattr(mapping, "ca"):
        head, before = mapping.ca.comment if mapping.ca.comment else (None, None)
        mapping.ca.comment = [head, [*(before or []), _comment(following)]]


def _apply(root: Any, enabled: bool) -> None:
    """Make ``root`` direct (``enabled``) or deferred in place (its shape already checked)."""
    from ruamel.yaml.comments import CommentedMap
    from ruamel.yaml.scalarstring import DoubleQuotedScalarString

    tools = root.get("tools")
    if enabled:
        off = DoubleQuotedScalarString("off")
        if tools is None:
            _set_block(root, "tools", CommentedMap([("tool_search", CommentedMap([("enabled", off)]))]))
        elif not isinstance(tools.get("tool_search"), MutableMapping):  # absent, null or legacy true
            _set_block(tools, "tool_search", CommentedMap([("enabled", off)]))
        else:
            _set_block(tools["tool_search"], "enabled", off)
        return
    # Direct now: the legacy false, or a mapping whose ``enabled`` reads as off. Remove that and
    # every mapping it leaves empty, as one block.
    search = tools["tool_search"]
    if isinstance(search, MutableMapping) and len(search) > 1:
        _remove(search, "enabled", tools, "tool_search")
    elif len(tools) > 1:
        _remove(tools, "tool_search", root, "tools")
    else:
        _remove(root, "tools")


def _document_head(root: Any) -> str:
    """The comment lines before the first key (all that is left of a file whose keys are gone)."""
    comment = getattr(getattr(root, "ca", None), "comment", None)
    tokens = comment[1] if comment and comment[1] else []
    return "".join(str(getattr(token, "value", "")) for token in tokens)


def edited(yaml: Any, text: str | None, enabled: bool) -> str | None:
    """config.yaml's new text with direct tool calls ``enabled`` or not; ``None`` when unchanged.

    ``text`` ``None`` is no config.yaml. Raises :class:`DirectToolsError`
    (``config_unreadable``, ``config_unsupported_shape``,
    ``config_has_setting``). The result is verified: Hermes reads it as asked,
    and nothing but this setting differs from ``text`` in Hermes's view.
    """
    from ruamel.yaml.comments import CommentedMap

    data = hermes_data(text)
    if mode_of(data)["direct"] is enabled:
        return None
    root = _round_trip(yaml, text)
    if root is None and (text is None or not _windows()):
        root = CommentedMap()  # no file, or (POSIX) an empty or comment-only one
    if not isinstance(root, MutableMapping):
        raise DirectToolsError("config_unreadable")
    _check_shape(root, data, enabled)
    _apply(root, enabled)
    if len(root) == 0 and not _windows():
        result = _document_head(root)  # removed the only key: keep the comments, not "{}"
    else:
        buffer = io.StringIO()
        yaml.dump(root, buffer)
        # ruamel drops the comments of a document without a value: keep them in front.
        head = text if text and data is None else ""
        result = (head if not head or head.endswith("\n") else head + "\n") + buffer.getvalue()
    after = hermes_data(result) if result else None
    try:
        same = _without_setting(after) == _without_setting(data)
    except RecursionError:
        same = False
    if mode_of(after)["direct"] is not enabled or not same:
        raise DirectToolsError("config_unsupported_shape")
    return result
