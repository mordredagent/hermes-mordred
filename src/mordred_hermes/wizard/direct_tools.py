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

- :func:`read_mode` reports the setting exactly as Hermes reads it (its YAML
  1.1 loader and ``ToolSearchConfig.from_raw``; see :mod:`._direct_tools_yaml`).
- :func:`set_direct` writes ``enabled: "off"`` (``True``) or removes what makes
  the tools direct (``False``), and writes nothing when the setting is already
  as asked. ``on`` replaces only an absent value or an explicit deferral.

The file goes through the wizard's own writer: ruamel round-trip (comments, key
order and every other key preserved), the policy write lock and
``_atomic_write_text`` (temporary file plus ``os.replace``) with the file's
mode kept; on Windows the checked canonical transaction (``PolicyWriter``).
Before the write, the new text must read as asked and differ in this setting
only; after it, the file is read again and, if Hermes would not read it as
asked, the previous bytes are put back (``config_write_failed``). A
vault-managed config.yaml (``encryption enable config``) is edited as its
plaintext working copy when one is on disk, like every other wizard writer,
and the reseal re-enrolls the changed copy; no plaintext means it is sealed
away (``config_vault_managed``), and a plaintext that disappears or changes
between the read and the write is refused, never recreated.

Failures are the closed codes of :data:`ERROR_CODES`. Nothing here logs,
prints, returns or chains anything that could carry another config value:
YAML errors and warnings quote source lines, so they are captured and dropped.
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path
from typing import Any, Final

from ._direct_tools_yaml import DirectToolsError, edited, hermes_data, mode_of

__all__ = ["CONFIG_NAME", "ERROR_CODES", "DirectToolsError", "read_mode", "set_direct"]

CONFIG_NAME: Final = "config.yaml"
ERROR_CODES: Final = (
    "config_unreadable",
    "config_vault_managed",
    "config_write_failed",
    "config_unsupported_shape",
    "config_has_setting",
)


def _windows() -> bool:
    from .. import _config_text_io

    return _config_text_io._windows()


def _managed(home: Path) -> bool:
    """config.yaml is on Mordred's vault lifecycle (``encryption enable config``); never on Windows."""
    if _windows():
        return False
    from ..keyvault._config_bootstrap import _marker_path

    return _marker_path(home).exists()


def _yaml() -> Any:
    from .policy_writer import _round_trip_yaml

    return _round_trip_yaml()


_Stamp = tuple[int, int, int, int, int]


def _stamp(path: Path) -> _Stamp | None:
    """Identity, size, mtime and mode of ``path`` (``None``: absent)."""
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return None
    return metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns, metadata.st_mode


def _read_posix(home: Path) -> tuple[str | None, _Stamp | None]:
    """config.yaml's text and stamp; refuses a sealed-away vault copy and a file changing meanwhile.

    The seal marker is checked after the read, so a reseal that removes the
    plaintext during it is refused too, never taken for "no config.yaml".
    """
    from .policy_writer import _read_regular_text

    path = home / CONFIG_NAME
    try:
        before = _stamp(path)
        text = _read_regular_text(path)
        after = _stamp(path)
        if after != before:  # sealed away (a reseal takes no lock) or replaced while being read
            sealed = after is None and _managed(home)
            raise DirectToolsError("config_vault_managed" if sealed else "config_write_failed")
        if text is None and _managed(home):
            raise DirectToolsError("config_vault_managed")
        return text, before
    except (OSError, ValueError):  # UnicodeDecodeError included
        raise DirectToolsError("config_unreadable") from None


def _read_windows(home: Path) -> str | None:
    from .._config_io import CanonicalPaths, read_canonical_snapshot

    try:
        snapshot = read_canonical_snapshot(CanonicalPaths(home))
        return None if snapshot.config is None else snapshot.config.data.decode("utf-8")
    except (OSError, ValueError):  # PrivateFSError and UnicodeDecodeError included
        raise DirectToolsError("config_unreadable") from None


def read_mode(home: Path) -> dict[str, Any]:
    """``{"direct": bool, "source": "config" | "default", "raw": str | None}``.

    ``raw`` is the key's own value as Hermes loads it (``enabled``, or the
    legacy ``tools.tool_search`` scalar) as text, at most 32 characters. A
    config that cannot be read answers ``{"direct": None, "source":
    "unreadable", "code": <code>}`` (``config_unreadable`` or
    ``config_vault_managed``). Read-only: it never waits for a lock (POSIX
    takes none; Windows reads the nonblocking checked snapshot) and creates
    no file or directory. On Windows an empty or comment-only config.yaml is
    unreadable, as for the checked writer.
    """
    try:
        text = _read_windows(home) if _windows() else _read_posix(home)[0]
        data = hermes_data(text)
        if data is None and text is not None and _windows():
            raise DirectToolsError("config_unreadable")
        return mode_of(data)
    except DirectToolsError as exc:
        return {"direct": None, "source": "unreadable", "code": exc.code}


def _verify_or_restore(home: Path, enabled: bool, restore: Any) -> None:
    """Read the file back; if Hermes would not read it as asked, put the old bytes back and refuse."""
    if read_mode(home)["direct"] is enabled:
        return
    with contextlib.suppress(DirectToolsError, OSError):
        restore()
    raise DirectToolsError("config_write_failed")


def _set_posix(home: Path, enabled: bool) -> None:
    from .policy_writer import _atomic_write_text, _policy_write_lock

    path = home / CONFIG_NAME
    try:
        with _policy_write_lock(home / "mordred"):
            text, stamp = _read_posix(home)
            mode = stamp[4] & 0o7777 if stamp is not None and text is not None else None
            result = edited(_yaml(), text, enabled)
            if result is None:
                return
            if _stamp(path) != stamp:  # sealed away, or rewritten, since the read: never recreate it
                raise DirectToolsError("config_vault_managed" if _managed(home) else "config_write_failed")
            _atomic_write_text(path, result, mode=mode)

            def restore() -> None:
                if text is None:
                    path.unlink(missing_ok=True)
                else:
                    _atomic_write_text(path, text, mode=mode)

            _verify_or_restore(home, enabled, restore)
    except OSError:
        raise DirectToolsError("config_write_failed") from None


class _Unchanged(Exception):
    """Leaves the canonical transaction without publishing: the setting already was as asked."""


def _set_windows(home: Path, enabled: bool) -> None:
    from ruamel.yaml.error import YAMLError

    from .._config_io import CONFIG_LIMIT
    from ._direct_tools_yaml import _quiet
    from .policy_writer import PolicyWriter, _bounded_utf8

    mordred = home / "mordred"
    writer = PolicyWriter(home / CONFIG_NAME, mordred / "policy.json", mordred)
    original: bytes | None = None
    try:
        # The checked edit parses the pair itself: its warnings are captured too.
        with _quiet() as caught, writer._checked_edit() as edit:
            if caught:
                caught.clear()
                raise DirectToolsError("config_unreadable")
            pair = edit.session.read_pair()
            original = None if pair.config is None else pair.config.data
            result = edited(_yaml(), None if original is None else original.decode("utf-8"), enabled)
            if result is None:
                raise _Unchanged
            edit.config_bytes = _bounded_utf8(result, CONFIG_LIMIT)
    except _Unchanged:
        return
    except (YAMLError, ValueError):
        raise DirectToolsError("config_unreadable") from None
    except OSError:
        raise DirectToolsError("config_write_failed") from None

    def restore() -> None:
        if original is not None:  # a config.yaml this call created stays (the checked writer cannot delete)
            with writer._checked_edit() as edit:
                edit.config_bytes = original

    _verify_or_restore(home, enabled, restore)


def set_direct(home: Path, enabled: bool) -> None:
    """Turn Hermes's direct tool calls on (``enabled: "off"``) or off (the setting removed).

    Writes only when the setting changes; every other key and comment is kept.
    Raises :class:`DirectToolsError` with one of :data:`ERROR_CODES`. Hermes
    reads the setting at start: the change takes effect after a restart.
    """
    if _windows():
        _set_windows(home, enabled)
    else:
        _set_posix(home, enabled)
