"""Bounded Windows gateway inventory; denial never means an empty process table.

Every current-user process is inspected, including renamed Python executables.
The profile state file is a checked PID hint only. No process is stopped here.
"""

from __future__ import annotations

import json
import ntpath
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import psutil

from .._private_fs import PrivateFSError, open_optional_confidential_directory
from .._windows_runtime import environment_root
from ._runtime_probe import GatewayRuntime


@dataclass(frozen=True)
class GatewayInventory:
    state: Literal["known", "unknown"]
    runtimes: tuple[GatewayRuntime, ...]
    reasons: tuple[str, ...]


def _read_state_pid(home: Path) -> int | None:
    with open_optional_confidential_directory(home) as directory:
        if directory is None:
            return None
        try:
            raw = directory.read_bytes("gateway_state.json", max_bytes=65536)
        except PrivateFSError as exc:
            if exc.reason == "missing":
                return None
            raise
    data = json.loads(raw)
    pid = data.get("pid") if isinstance(data, dict) else None
    if type(pid) is not int or not 0 < pid <= 0xFFFFFFFF:
        raise ValueError("invalid state PID")
    return pid


def _gateway_argv(argv: list[str]) -> bool:
    # psutil already supplies argv: neither shlex nor state-file argv is used.
    tokens = [token.casefold() for token in argv]
    # Custom launchers need not expose the Hermes module name. Conservatively
    # include any current-user process with this verb pair, even another app.
    return any(tokens[i : i + 2] == ["gateway", "run"] for i in range(len(tokens) - 1))


def _gateway_python(exe: str) -> Path | None:
    """Structural attribution only; inventory must never run Python/bootstrap.

    A live gateway blocks the lifecycle independently of installed capability.
    Full C4 interpreter validation/proof happens outside custody locks. An
    unresolved native/Desktop launcher is unknown, never a successful absence.
    """
    path = Path(exe)
    if ntpath.basename(exe).casefold() == "pythonw.exe":
        path = path.with_name("python.exe")
    return path if environment_root(path) is not None else None


class _Uncertain(Exception):
    """Internal sanitized reason, never an external exception message."""


# These fixed-function OS images cannot be a supported Python/Hermes/Desktop
# runtime. Generic hosts (cmd, PowerShell, rundll32, wscript, mshta, etc.) are
# deliberately absent. A basename alone never admits an ordinary executable.
_PROTECTED_OS_IMAGES = frozenset(
    {
        "csrss.exe",
        "dwm.exe",
        "fontdrvhost.exe",
        "logonui.exe",
        "lsass.exe",
        "services.exe",
        "smss.exe",
        "svchost.exe",
        "wininit.exe",
        "winlogon.exe",
    }
)
_KERNEL_IMAGES = frozenset({"Registry", "MemCompression"})


def _system_directory() -> str | None:
    """Read the OS system directory, never a caller-controlled environment path."""
    if os.name != "nt":
        return None
    import ctypes
    from ctypes import wintypes

    win_dll = getattr(ctypes, "WinDLL", None)
    if win_dll is None:
        return None
    kernel = win_dll("kernel32", use_last_error=True)
    get_directory = kernel.GetSystemDirectoryW
    get_directory.argtypes = (wintypes.LPWSTR, wintypes.UINT)
    get_directory.restype = wintypes.UINT
    buffer = ctypes.create_unicode_buffer(32768)
    length = get_directory(buffer, len(buffer))
    if not 0 < length < len(buffer) or not ntpath.isabs(buffer.value):
        return None
    return buffer.value


def _protected_os_image(process: psutil.Process, name: str) -> bool:
    """Exclude only positively classified, stable native OS images.

    Called exclusively after ownership AccessDenied, and never for a PID hint.
    psutil's native exe query returns literal Registry/MemCompression for those
    kernel processes; an ordinary executable has a full image path instead.
    """
    pid = process.pid
    born = process.create_time()
    exe = process.exe()
    if exe in _KERNEL_IMAGES and name == exe:
        irrelevant = True
    elif name.casefold() in _PROTECTED_OS_IMAGES and ntpath.basename(exe).casefold() == name.casefold():
        directory = _system_directory()
        irrelevant = directory is not None and ntpath.dirname(exe).casefold() == directory.casefold()
    else:
        return False
    if not irrelevant:
        return False
    # Reopen by PID: neither psutil's cached creation time nor image/name can
    # authorize exclusion after a process exited, changed or was replaced.
    current = psutil.Process(pid)
    if current.create_time() != born or current.name() != name or current.exe() != exe:
        raise _Uncertain("process-changed")
    return True


def _belongs_to_user(process: psutil.Process, name: str, owner: str, *, hinted: bool) -> bool:
    try:
        actual_owner = process.username()
    except psutil.AccessDenied:
        if not hinted and _protected_os_image(process, name):
            return False
        raise
    if not actual_owner:
        raise _Uncertain("owner-unavailable")
    return bool(actual_owner.casefold() == owner.casefold())


def _inspect_process(pid: int, owner: str, *, hinted: bool) -> GatewayRuntime | None:
    process = psutil.Process(pid)
    name = process.name()
    # Only kernel pseudo-processes are exempt from positive ownership checks.
    if (pid, name.casefold()) in {(0, "system idle process"), (4, "system")} and not hinted:
        return None
    if not _belongs_to_user(process, name, owner, hinted=hinted):
        return None
    born = process.create_time()
    exe = process.exe()
    argv = process.cmdline()
    if not exe or not argv:
        raise _Uncertain("process-incomplete")
    # A fresh object avoids cached creation time/name/exe values.
    current = psutil.Process(pid)
    if (
        current.create_time() != born
        or current.username().casefold() != owner.casefold()
        or current.exe() != exe
        or current.cmdline() != argv
    ):
        raise _Uncertain("process-changed")
    if not _gateway_argv(argv):
        if hinted:
            raise _Uncertain("hint-not-gateway")
        return None
    python = _gateway_python(exe)
    if python is None:
        raise _Uncertain("interpreter-unverified")
    if psutil.Process(pid).create_time() != born:
        raise _Uncertain("process-changed")
    return GatewayRuntime(pid, python)


def _unknown(reasons: list[str], code: str, pid: int | None = None) -> None:
    if len(reasons) < 32:
        reasons.append(f"pid={pid}:{code}" if pid is not None else f"scan:{code}")
    elif len(reasons) == 32:
        reasons.append("scan:additional-uncertainty")


def _state_hints(home: Path, hinted_pids: tuple[int, ...], reasons: list[str]) -> set[int]:
    hints = set(hinted_pids)
    try:
        state_pid = _read_state_pid(home)
        if state_pid is not None:
            hints.add(state_pid)
    except (PrivateFSError, ValueError, OSError, RecursionError):
        _unknown(reasons, "state-unreadable")
    return hints


def inspect_windows_gateway_runtimes(home: Path, *, hinted_pids: tuple[int, ...] = ()) -> GatewayInventory:
    """Take a point-in-time inventory, conservatively covering every profile.

    Unknown association with ``home`` does not exclude a current-user gateway.
    This observation is not a lock against a newly starting process. Lifecycle
    callers must additionally serialize and revalidate managed state.
    """
    reasons: list[str] = []
    runtimes: list[GatewayRuntime] = []

    hints = _state_hints(home, hinted_pids, reasons)
    try:
        owner = psutil.Process(os.getpid()).username()
        if not owner:
            raise ValueError("unknown owner")
        pids = set(psutil.pids()) | hints
    except (psutil.Error, OSError, ValueError):
        _unknown(reasons, "inventory-unavailable")
        return GatewayInventory("unknown", (), tuple(reasons))
    deadline = time.monotonic() + 10.0
    for index, pid in enumerate(sorted(pids)):
        if index >= 4096 or time.monotonic() > deadline:
            _unknown(reasons, "inventory-limit")
            break
        try:
            runtime = _inspect_process(pid, owner, hinted=pid in hints)
            if runtime is not None:
                runtimes.append(runtime)
        except _Uncertain as exc:
            _unknown(reasons, str(exc), pid)
        except psutil.NoSuchProcess:
            continue
        except (psutil.Error, OSError, ValueError):
            _unknown(reasons, "inspection-denied", pid)
    return GatewayInventory("unknown" if reasons else "known", tuple(runtimes), tuple(reasons))
