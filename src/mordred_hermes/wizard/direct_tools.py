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

import hashlib
import json
import os
import subprocess
import sys
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Any, Final

from ._direct_tools_yaml import EXISTING, DirectToolsError, is_off

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
    "config_unsupported_shape",
)
#: What to add to config.yaml by hand when Hermes's CLI cannot do it.
SNIPPET: Final = 'tools:\n  tool_search:\n    enabled: "off"\n'
HERMES_TIMEOUT_S: Final = 60.0
READER_TIMEOUT_S: Final = 20.0
#: The reader child's answers by the sha256 of the text it read (the status poll re-reads often).
_ANSWERS: OrderedDict[str, dict[str, Any]] = OrderedDict()
_ANSWERS_MAX: Final = 8
_ANSWERS_LOCK = threading.Lock()
#: One read/change/verify at a time: a second request sees the first one's result.
_SET_LOCK = threading.Lock()


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


# -- the reader child --------------------------------------------------------------------------------

_READER_BOOT: Final = (
    "import runpy, site, sys\n"
    "for directory in sys.argv[2:]:\n"
    "    site.addsitedir(directory)\n"
    "del sys.argv[2:]\n"
    "runpy.run_module('mordred_hermes.wizard._direct_tools_yaml', run_name='__main__', alter_sys=True)\n"
)


def _reader_argv(strict_empty: bool) -> list[str]:
    """``python -I`` running :mod:`._direct_tools_yaml` as ``__main__``.

    ``-I`` ignores ``PYTHONPATH`` and the user site. Under Hermes Desktop this
    interpreter is the base one with Hermes's environment only on ``sys.path``,
    so those ``site-packages`` (outside the interpreter's prefix) are added
    back for the child, as ``desktop.member`` does for its fresh-import probe.
    """
    prefix = Path(sys.prefix).resolve()
    overlays = []
    for entry in sys.path:
        path = Path(entry) if entry else None
        if path is not None and path.name == "site-packages" and path.is_dir() and prefix not in path.resolve().parents:
            overlays.append(str(path))
    return [sys.executable, "-I", "-c", _READER_BOOT, "strict" if strict_empty else "lenient", *overlays]


def _valid(answer: Any) -> bool:
    if not isinstance(answer, dict):
        return False
    if set(answer) == {"code"}:
        return bool(answer["code"] == "config_unreadable")
    return (
        set(answer) == {"direct", "source", "existing"}
        and isinstance(answer["direct"], bool)
        and isinstance(answer["source"], str)
        and answer["source"] in ("config", "default")
        and isinstance(answer["existing"], str)  # checked before the membership test: a list would raise
        and answer["existing"] in EXISTING
    )


def _spawn_reader(text: str, strict_empty: bool) -> dict[str, Any] | None:
    """The child's answer for ``text``; ``None`` when it could not answer (never cached)."""
    env = {key: value for key, value in os.environ.items() if key not in ("PYTHONPATH", "PYTHONHOME")}
    env["MORDRED_CONFIG_DECRYPT"] = "0"  # a reader: never on the config.yaml materialize/reseal lifecycle
    try:
        done = subprocess.run(
            _reader_argv(strict_empty),
            input=text.encode("utf-8"),
            capture_output=True,  # stderr (ruamel's warnings quote the document) is dropped unread
            cwd=None,
            env=env,
            timeout=READER_TIMEOUT_S,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode != 0:
        return None
    lines = [line for line in done.stdout.decode("utf-8", "replace").splitlines() if line.strip()]
    if len(lines) != 1:
        return None  # exactly one line: a second answer, or any other output, is not an answer
    try:
        answer = json.loads(lines[0])
    except ValueError:
        return None
    return answer if _valid(answer) else None


def _answer(text: str | None) -> dict[str, Any]:
    """``{"direct", "source", "existing"}`` for config.yaml ``text``; raises ``config_unreadable``."""
    if text is None:
        return {"direct": False, "source": "default", "existing": "absent"}
    strict_empty = _windows()  # the checked Windows reader refuses an empty config
    key = ("strict:" if strict_empty else "lenient:") + hashlib.sha256(text.encode("utf-8")).hexdigest()
    with _ANSWERS_LOCK:
        cached = _ANSWERS.get(key)
        if cached is not None:
            _ANSWERS.move_to_end(key)
    if cached is None:
        cached = _spawn_reader(text, strict_empty)
        if cached is None:
            raise DirectToolsError("config_unreadable")
        with _ANSWERS_LOCK:
            _ANSWERS[key] = cached
            while len(_ANSWERS) > _ANSWERS_MAX:
                _ANSWERS.popitem(last=False)
    if "code" in cached:
        raise DirectToolsError(str(cached["code"]))
    return dict(cached)


def read_mode(home: Path) -> dict[str, Any]:
    """``{"direct": bool, "source": "config" | "default"}``, or ``{"direct": None, "source":
    "unreadable", "code": "config_unreadable" | "config_vault_managed"}``.

    This process only reads the file (no lock: POSIX takes none, Windows reads
    the nonblocking checked snapshot, and nothing is created); a child process
    parses the text (see :func:`_answer`). A cached answer is immediate; a
    cache miss, or a file whose last answer failed, waits for the child, up to
    :data:`READER_TIMEOUT_S`.
    """
    home = Path(home).absolute()
    try:
        state = _answer(_read_text(home))
    except DirectToolsError as exc:
        return {"direct": None, "source": "unreadable", "code": exc.code}
    return {"direct": state["direct"], "source": state["source"]}


# -- Hermes's CLI -----------------------------------------------------------------------------------


def _python() -> str:
    return sys.executable


def hermes_command(home: Path) -> Path | None:
    """Hermes's ``hermes`` console script: next to this interpreter (the same venv) first, then
    Hermes's managed runtime venv and Hermes Desktop's launcher under the home."""
    home = Path(home).absolute()
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

    Reads first: nothing runs when the setting already is as asked; a ``tools``
    or ``tool_search`` mapping shared through a YAML alias is refused
    (``config_unsupported_shape``), and ``on`` refuses a value other than an
    absent one or an explicit deferral (``config_has_setting``). One request
    runs at a time. Raises :class:`DirectToolsError` with one of
    :data:`ERROR_CODES`. Hermes reads the setting at start: a change takes
    effect after a restart.
    """
    home = Path(home).absolute()  # the child's cwd and HERMES_HOME must name the same home
    with _SET_LOCK:  # read again under the lock: a request that waited sees the earlier result
        state = _answer(_read_text(home))
        if state["direct"] is enabled:
            return
        held = state["existing"]
        if held == "shared":
            raise DirectToolsError("config_unsupported_shape")
        if enabled and held not in ("absent", "deferral"):
            raise DirectToolsError("config_has_setting")
        command = hermes_command(home)
        if command is None:
            raise DirectToolsError("hermes_cli_missing")
        args = ("set", KEY, "off") if enabled else ("unset", LEGACY_KEY if held == "legacy" else KEY)
        code, _ = _run(command, home, *args)
        if code != 0 or _hermes_reads_direct(command, home) is not enabled:
            raise DirectToolsError("config_write_failed")
