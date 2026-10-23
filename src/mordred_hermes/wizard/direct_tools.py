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

Mordred never edits config.yaml itself. :func:`read_mode` reads it the way
Hermes does (:mod:`._direct_tools_yaml`); :func:`set_direct` asks Hermes's own
writer through its CLI, in Hermes's environment::

    hermes config set tools.tool_search.enabled off     # on (stored as the string 'off')
    hermes config unset tools.tool_search.enabled       # off (tools.tool_search for the legacy false)
    hermes config get tools.tool_search.enabled         # the check afterwards

with ``HERMES_HOME`` set to the home, the home as working directory, no
``PYTHONPATH`` / ``PYTHONHOME``, ``MORDRED_CONFIG_DECRYPT=0``, a 60 s timeout
and its output captured and dropped: only the exit code is used, and the
result is a closed code. The change counts only when ``hermes config get``
then reads as asked. In a vault-managed home the plaintext working copy is on
disk only while a managed process (Hermes, Hermes Desktop or this
``hermes-mordred``) runs, and that process reseals it at exit; the child edits
that working copy and, with ``MORDRED_CONFIG_DECRYPT=0``, never materializes
or reseals it itself. A config sealed away while nothing runs is refused
before anything starts (``config_vault_managed``).
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Final

from ._direct_tools_yaml import DirectToolsError, existing_value, hermes_data, is_off, mode_of

__all__ = [
    "CONFIG_NAME",
    "ERROR_CODES",
    "KEY",
    "SNIPPET",
    "DirectToolsError",
    "hermes_command",
    "read_mode",
    "set_direct",
]

CONFIG_NAME: Final = "config.yaml"
KEY: Final = "tools.tool_search.enabled"
LEGACY_KEY: Final = "tools.tool_search"
ERROR_CODES: Final = (
    "config_unreadable",
    "config_vault_managed",
    "config_write_failed",
    "config_has_setting",
    "hermes_cli_missing",
)
#: What to add to config.yaml by hand when Hermes's CLI cannot do it.
SNIPPET: Final = 'tools:\n  tool_search:\n    enabled: "off"\n'
HERMES_TIMEOUT_S: Final = 60.0


def _windows() -> bool:
    from .. import _config_text_io

    return _config_text_io._windows()


def _managed(home: Path) -> bool:
    """config.yaml is on Mordred's vault lifecycle (``encryption enable config``); never on Windows."""
    if _windows():
        return False
    from ..keyvault._config_bootstrap import _marker_path

    return _marker_path(home).exists()


def _read_text(home: Path) -> str | None:
    """config.yaml's text, ``None`` when there is none; a sealed-away vault copy is refused."""
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
    except (OSError, ValueError):  # PrivateFSError and UnicodeDecodeError included
        raise DirectToolsError("config_unreadable") from None


def _data(home: Path) -> Any:
    text = _read_text(home)
    data = hermes_data(text)
    if data is None and text is not None and _windows():
        raise DirectToolsError("config_unreadable")  # the checked Windows reader refuses an empty config
    return data


def read_mode(home: Path) -> dict[str, Any]:
    """``{"direct": bool, "source": "config" | "default"}``, or ``{"direct": None, "source":
    "unreadable", "code": "config_unreadable" | "config_vault_managed"}``.

    Read-only: it never waits for a lock (POSIX takes none; Windows reads the
    nonblocking checked snapshot) and creates no file or directory.
    """
    try:
        return mode_of(_data(home))
    except DirectToolsError as exc:
        return {"direct": None, "source": "unreadable", "code": exc.code}


# -- Hermes's CLI -----------------------------------------------------------------------------------


def _python() -> str:
    return sys.executable


def hermes_command(home: Path) -> Path | None:
    """Hermes's ``hermes`` console script: next to this interpreter (the same venv) first, then
    Hermes's managed runtime venv and Hermes Desktop's launcher under the home."""
    if _windows():
        names = [Path(_python()).parent / "hermes.exe", home / "hermes-agent" / "venv" / "Scripts" / "hermes.exe"]
    else:
        names = [
            Path(_python()).parent / "hermes",
            home / "hermes-agent" / "venv" / "bin" / "hermes",
            home / "hermes-agent" / ".hermes" / "bin" / "hermes",
        ]
    return next((path for path in names if path.is_file() and os.access(path, os.X_OK)), None)


def _run(command: Path, home: Path, *args: str) -> tuple[int, str]:
    """``hermes config <args>`` for ``home``: the exit code and stdout (never shown or logged)."""
    env = {key: value for key, value in os.environ.items() if key not in ("PYTHONPATH", "PYTHONHOME")}
    env["HERMES_HOME"] = str(home)
    env["MORDRED_CONFIG_DECRYPT"] = "0"  # the running process's lifecycle owns the plaintext; the child only edits it
    try:
        done = subprocess.run(
            [str(command), "config", *args],
            cwd=home,
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=HERMES_TIMEOUT_S,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):  # not runnable, or the timeout
        return -1, ""
    return done.returncode, done.stdout or ""


def _hermes_reads_direct(command: Path, home: Path) -> bool | None:
    """``hermes config get tools.tool_search.enabled`` read with Hermes's rule; ``None``: no answer."""
    code, out = _run(command, home, "get", KEY)
    lines = [line.strip() for line in out.splitlines() if line.strip()]
    return is_off(lines[-1]) if code == 0 and lines else None


def set_direct(home: Path, enabled: bool) -> None:
    """Turn Hermes's direct tool calls on or off through Hermes's own ``hermes config``.

    Reads first: nothing runs when the setting already is as asked, and ``on``
    refuses a value other than an absent one or an explicit deferral
    (``config_has_setting``). Raises :class:`DirectToolsError` with one of
    :data:`ERROR_CODES`. Hermes reads the setting at start: a change takes
    effect after a restart.
    """
    data = _data(home)
    if mode_of(data)["direct"] is enabled:
        return
    held = existing_value(data)
    if enabled and held not in ("absent", "deferral"):
        raise DirectToolsError("config_has_setting")
    command = hermes_command(home)
    if command is None:
        raise DirectToolsError("hermes_cli_missing")
    args = ("set", KEY, "off") if enabled else ("unset", LEGACY_KEY if held == "legacy" else KEY)
    code, _ = _run(command, home, *args)
    if code != 0 or _hermes_reads_direct(command, home) is not enabled:
        raise DirectToolsError("config_write_failed")
