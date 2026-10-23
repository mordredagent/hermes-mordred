"""Hermes's direct tool calls: ``tools.tool_search.enabled`` in ``<home>/config.yaml``.

Hermes 0.21 defers every plugin tool, so the model reaches Mordred's tools
(``mordred_mail_sync``, ``mordred_history_search``, ``telegram_ask``,
``telegram_chats``) only through its ``tool_search`` / ``tool_call`` bridge:
one extra model round trip per use, and smaller models sometimes break the
bridge arguments. ``tools.tool_search.enabled: "off"`` makes every selected
tool direct. The setting is Hermes-wide: every deferred tool schema then
enters the prompt and the bridge (and with it remote-connector tool
discovery) is gone. Mordred therefore never changes it on its own; only an
explicit request (``hermes-mordred direct-tools on|off``, the Desktop page's
Tool calls card) calls :func:`set_direct`.

- :func:`read_mode` reports the setting the way Hermes reads it
  (``ToolSearchConfig.from_raw``): direct when ``enabled`` is the boolean
  false or a string Hermes reads as off (``"off"``, also ``"false"``, ``"no"``,
  ``"0"``, any case), or when the legacy ``tools.tool_search`` itself is
  ``false``. Anything else, or no such key, is deferred.
- :func:`set_direct` writes ``enabled: "off"`` (``True``) or removes what
  makes the tools direct (``False``), and writes nothing when the setting is
  already as asked.

The file goes through the wizard's own round-trip writer: ruamel round-trip
(comments, key order and every other key preserved), the policy write lock,
and ``_atomic_write_text`` (temporary file plus ``os.replace``) with the
file's mode kept; on Windows the checked canonical transaction
(``PolicyWriter.transform_config``). A vault-managed config.yaml
(``encryption enable config``) is edited as its plaintext working copy when
one is on disk, like every other wizard writer, and the reseal re-enrolls the
changed copy; while the plaintext is sealed away the read answers
``unreadable`` and the write is refused with ``config_vault_managed``.

Failures are the closed codes of :data:`ERROR_CODES`. Nothing here logs,
returns or chains an exception that could carry another config value: a YAML
error message quotes the offending line, so it is dropped (``from None``).
"""

from __future__ import annotations

import io
import stat
from collections.abc import Mapping, MutableMapping
from pathlib import Path
from typing import Any, Final

__all__ = ["CONFIG_NAME", "ERROR_CODES", "DirectToolsError", "read_mode", "set_direct"]

CONFIG_NAME: Final = "config.yaml"
ERROR_CODES: Final = ("config_unreadable", "config_vault_managed", "config_write_failed")
#: What Hermes reads as "off" after ``str(value).strip().lower()`` (``tools/tool_search.py``).
_OFF: Final = frozenset({"off", "false", "0", "no"})
#: The longest ``raw`` value reported (the key's own value, never another one).
_RAW_LIMIT: Final = 32


class DirectToolsError(Exception):
    """A refusal with one of :data:`ERROR_CODES`; the message is the code alone."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _windows() -> bool:
    from .. import _config_text_io

    return _config_text_io._windows()


def _is_off(value: Any) -> bool:
    return str(value).strip().lower() in _OFF


def _raw(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)[:_RAW_LIMIT]


def _mode_of(root: Any) -> dict[str, Any]:
    """``{"direct", "source", "raw"}`` for a loaded config root (``None``: no config.yaml)."""
    default: dict[str, Any] = {"direct": False, "source": "default", "raw": None}
    tools = root.get("tools") if isinstance(root, Mapping) else None
    if not isinstance(tools, Mapping) or "tool_search" not in tools:
        return default
    search = tools["tool_search"]
    if isinstance(search, bool):  # the legacy shape: ``tools.tool_search: true | false``
        return {"direct": search is False, "source": "config", "raw": _raw(search)}
    if not isinstance(search, Mapping) or "enabled" not in search:
        return default
    value = search["enabled"]
    return {"direct": _is_off(value), "source": "config", "raw": _raw(value)}


def _managed(home: Path) -> bool:
    """config.yaml is on Mordred's vault lifecycle (``encryption enable config``); never on Windows."""
    if _windows():
        return False
    from ..keyvault._config_bootstrap import _marker_path

    return _marker_path(home).exists()


def _yaml() -> Any:
    from .policy_writer import _round_trip_yaml

    return _round_trip_yaml()


def _parse(yaml: Any, text: str | None) -> MutableMapping[str, Any] | None:
    """The round-trip root of ``text``; ``None`` for no file.

    An empty or comment-only file is an empty mapping on POSIX, like the other
    POSIX writers. The Windows checked writer never turns a present
    non-mapping config into fresh state, so there it is ``config_unreadable``.
    """
    from ruamel.yaml.comments import CommentedMap
    from ruamel.yaml.error import YAMLError

    if text is None:
        return None
    try:
        root = yaml.load(text)
    except (YAMLError, ValueError):
        raise DirectToolsError("config_unreadable") from None
    if root is None and not _windows():
        return CommentedMap()
    if not isinstance(root, MutableMapping):
        raise DirectToolsError("config_unreadable")
    return root


def _read_text(home: Path) -> str | None:
    """config.yaml's text, ``None`` when there is none.

    No plaintext while config.yaml is vault-managed means it is sealed away:
    ``config_vault_managed``. The marker is checked after the read, so a
    reseal that removes the plaintext meanwhile is refused too, never taken
    for "no config.yaml".
    """
    try:
        if _windows():
            from .._config_io import CanonicalPaths, read_canonical_snapshot

            snapshot = read_canonical_snapshot(CanonicalPaths(home))
            return None if snapshot.config is None else snapshot.config.data.decode("utf-8")
        from .policy_writer import _read_regular_text

        text = _read_regular_text(home / CONFIG_NAME)
        if text is None and _managed(home):
            raise DirectToolsError("config_vault_managed")
        return text
    except (OSError, ValueError):  # UnicodeDecodeError and PrivateFSError included
        raise DirectToolsError("config_unreadable") from None


def read_mode(home: Path) -> dict[str, Any]:
    """``{"direct": bool, "source": "config" | "default", "raw": str | None}``.

    ``raw`` is the key's own value (``enabled``, or the legacy
    ``tools.tool_search`` boolean) as text, at most 32 characters. A config
    that cannot be read answers ``{"direct": None, "source": "unreadable",
    "code": <code>}`` (``config_unreadable`` or ``config_vault_managed``).
    Read-only: it never waits for a lock (POSIX takes none; Windows reads the
    nonblocking checked snapshot) and creates no file or directory.
    """
    try:
        return _mode_of(_parse(_yaml(), _read_text(home)))
    except DirectToolsError as exc:
        return {"direct": None, "source": "unreadable", "code": exc.code}


# -- comments ---------------------------------------------------------------------------------------
#
# ruamel keeps the comment lines that follow a value on the last line of that value
# (``ca.items[key][2]`` in a mapping, ``ca.items[index][0]`` in a sequence): the
# line's own end-of-line comment first, then the full-line comments up to the next
# key. Those full lines belong to whatever comes next ("# provider settings below"),
# so an inserted or removed block hands them on instead of taking them along.


def _block(value: Any) -> bool:
    from ruamel.yaml.comments import CommentedMap, CommentedSeq

    return isinstance(value, CommentedMap | CommentedSeq) and len(value) > 0 and not value.fa.flow_style()


def _slot(container: Any, key: Any) -> tuple[list[Any], int]:
    """The comment entry (and its index) of the last line of ``container[key]``."""
    from ruamel.yaml.comments import CommentedSeq

    value = container[key]
    while _block(value):
        container, key = value, (len(value) - 1 if isinstance(value, CommentedSeq) else list(value)[-1])
        value = container[key]
    entry: list[Any] = container.ca.items.setdefault(key, [None, None, None, None])
    return entry, 0 if isinstance(container, CommentedSeq) else 2


def _take_following(container: Any, key: Any) -> str:
    """Detach the full-line comments after ``container[key]``; its end-of-line comment stays."""
    entry, index = _slot(container, key)
    token = entry[index]
    if token is None:
        return ""
    own, newline, following = str(token.value).partition("\n")
    if not following:
        return ""
    token.value = own + newline
    return following


def _comment(text: str) -> Any:
    from ruamel.yaml.error import CommentMark
    from ruamel.yaml.tokens import CommentToken

    return CommentToken(text, CommentMark(0), None)


def _put_following(container: Any, key: Any, following: str) -> None:
    """Attach full-line comments after the last line of ``container[key]``."""
    if not following:
        return
    entry, index = _slot(container, key)
    if entry[index] is None:
        entry[index] = _comment("\n" + following)  # the line itself has no end-of-line comment
    else:
        entry[index].value = str(entry[index].value) + following


def _set_block(mapping: Any, key: str, value: Any) -> None:
    """``mapping[key] = value`` (appended or replaced), handing on the comments that followed."""
    keys = list(mapping)
    if key in mapping:
        following = _take_following(mapping, key)
    elif keys:
        following = _take_following(mapping, keys[-1])
    else:
        following = ""
    mapping[key] = value
    _put_following(mapping, key, following)


def _remove(mapping: Any, key: str) -> None:
    """``del mapping[key]``, keeping the comments that followed it before the next key."""
    keys = list(mapping)
    position = keys.index(key)
    following = _take_following(mapping, key)
    del mapping[key]
    mapping.ca.items.pop(key, None)
    if not following:
        return
    if position > 0:
        _put_following(mapping, keys[position - 1], following)
        return
    # The first key: the comments now precede the mapping's first key (the document's, at the root).
    head, before = mapping.ca.comment if mapping.ca.comment else (None, None)
    mapping.ca.comment = [head, [*(before or []), _comment(following)]]


def _apply(root: MutableMapping[str, Any], enabled: bool) -> bool:
    """Make ``root`` direct (``enabled``) or deferred in place; ``False`` when it already was."""
    from ruamel.yaml.comments import CommentedMap
    from ruamel.yaml.scalarstring import DoubleQuotedScalarString

    if _mode_of(root)["direct"] is enabled:
        return False
    tools = root.get("tools")
    if enabled:
        off = DoubleQuotedScalarString("off")
        if tools is None:  # absent or null
            _set_block(root, "tools", CommentedMap([("tool_search", CommentedMap([("enabled", off)]))]))
        elif not isinstance(tools, MutableMapping):
            raise DirectToolsError("config_unreadable")  # never replace an unknown top-level value
        elif not isinstance(tools.get("tool_search"), MutableMapping):  # absent, null, legacy boolean, scalar
            _set_block(tools, "tool_search", CommentedMap([("enabled", off)]))
        else:
            _set_block(tools["tool_search"], "enabled", off)
        return True
    # Direct now: ``tool_search`` is the legacy false or a mapping whose ``enabled`` is off.
    # Remove that, and each mapping it leaves empty, as one block.
    if not isinstance(tools, MutableMapping):
        return False
    search = tools["tool_search"]
    mapping, key = (
        (search, "enabled") if isinstance(search, MutableMapping) and len(search) > 1 else (tools, "tool_search")
    )
    if mapping is tools and len(tools) == 1:
        mapping, key = root, "tools"
    _remove(mapping, key)
    return True


def _set_posix(home: Path, enabled: bool) -> None:
    from .policy_writer import _atomic_write_text, _policy_write_lock

    path = home / CONFIG_NAME
    try:
        with _policy_write_lock(home / "mordred"):
            text = _read_text(home)
            yaml = _yaml()
            root = _parse(yaml, text)
            if root is None:
                if not enabled:
                    return  # no config.yaml: Hermes's default is already deferred
                from ruamel.yaml.comments import CommentedMap

                root = CommentedMap()
            # ruamel drops the comments of a file without any value (empty or comment-only): keep its text.
            preamble = text if enabled and text and not root and yaml.load(text) is None else ""
            if not _apply(root, enabled):
                return
            buffer = io.StringIO()
            yaml.dump(root, buffer)
            if preamble and not preamble.endswith("\n"):
                preamble += "\n"
            mode = stat.S_IMODE(path.stat().st_mode) if text is not None else None
            _atomic_write_text(path, preamble + buffer.getvalue(), mode=mode)
    except OSError:
        raise DirectToolsError("config_write_failed") from None


class _Unchanged(Exception):
    """Leaves the canonical transaction without publishing: the setting already was as asked."""


def _set_windows(home: Path, enabled: bool) -> None:
    from ruamel.yaml.error import YAMLError

    from .policy_writer import PolicyWriter

    if read_mode(home)["direct"] is enabled:
        return  # never open a canonical transaction to rewrite an unchanged file
    mordred = home / "mordred"

    def edit(root: MutableMapping[str, Any]) -> None:
        if not _apply(root, enabled):  # changed by someone else since the read above
            raise _Unchanged

    try:
        PolicyWriter(home / CONFIG_NAME, mordred / "policy.json", mordred).transform_config(edit)
    except _Unchanged:
        return
    except (YAMLError, ValueError):
        raise DirectToolsError("config_unreadable") from None
    except OSError:
        raise DirectToolsError("config_write_failed") from None


def set_direct(home: Path, enabled: bool) -> None:
    """Turn Hermes's direct tool calls on (``enabled: "off"``) or off (the key removed).

    Writes only when the setting changes; every other key and comment is kept.
    Raises :class:`DirectToolsError` with ``config_unreadable``,
    ``config_vault_managed`` or ``config_write_failed``. Hermes reads the
    setting at start: the change takes effect after a restart.
    """
    if _windows():
        _set_windows(home, enabled)
    else:
        _set_posix(home, enabled)
