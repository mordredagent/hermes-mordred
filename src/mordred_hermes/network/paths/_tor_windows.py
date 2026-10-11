"""Native Windows Tor child: checked image, private state and an exact lifetime.

POSIX launches never reach this module (see :func:`.tor.start_process`).

Launch sequence (``start_process``):

1. Resolve ``tor_binary`` to one absolute ``.exe`` and classify its image
   (:mod:`.._windows_exec`); strict refuses an untrusted image before any
   state or process is touched, lenient/off warn.
2. Open ``<home>/mordred/tor-data`` through the checked private-directory
   contract (created with the private ACL before any content; an existing
   unsafe directory, reparse point or unsafe member refuses, nothing is
   repaired) and take its exclusive transaction without waiting.
3. Startup cleanup under that transaction: a recorded daemon
   (``daemon.json``, bounded read, strict schema) whose process is gone is
   forgotten; a recorded Tor whose live identity (PID, creation time, image,
   user) still matches and whose recorded owner process is gone is terminated
   only after that revalidation; anything uncertain refuses. A current-user
   process whose command line names this profile's torrc but is not recorded
   is refused, never stopped and never reused.
4. Publish ``torrc`` and an empty pinned ``torrc-defaults`` through the same
   transaction (no-replace staging, then rename), so neither
   ``%APPDATA%\\tor\\torrc-defaults`` nor stdin configures the child.
5. Spawn ``[tor.exe, -f, torrc, --defaults-torrc, defaults]`` as an argument
   list with the explicit image, the image directory as working directory,
   ``CREATE_NO_WINDOW`` and stdin from ``NUL``. Assign it to a kill-on-close
   job (:mod:`.._windows_job`) before recording its identity. The rendered
   torrc also carries ``__OwningControllerProcess <parent pid>``.

Child lifetime: the job guarantees the child ends with the parent. The only
window is between process creation and job assignment (microseconds, before
Tor can bootstrap). A parent crash inside it leaves an unrecorded Tor that
still exits within Tor's own owning-controller poll interval; until then the
next startup refuses it through the command-line inventory, and Tor's own
DataDirectory lock refuses a second daemon on the same state. Teardown
terminates through the creation handle only after a psutil identity
revalidation, then closes the job (exact membership) and forgets the record.
"""

from __future__ import annotations

import contextlib
import json
import logging
import math
import ntpath
import os
import subprocess
import threading
import time
from collections.abc import Callable, Iterable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Literal, Protocol

import psutil

from ..._policy_types import PolicyMode
from ..._private_fs import (
    FileMetadata,
    PrivateDirectory,
    PrivateFSError,
    PrivateTransaction,
    open_private_directory,
    read_public_build_output,
)
from .._exceptions import BringupFailed
from .._windows_exec import (
    ExecutableTrust,
    ResolvedExecutable,
    describe_executable,
    enforce_executable_trust,
    resolve_windows_executable,
)
from .._windows_job import JobHandle, KillOnCloseJob

_LOG = logging.getLogger("mordred.network.paths.tor")

DAEMON_STATE: Final[str] = "daemon.json"
TORRC: Final[str] = "torrc"
TORRC_DEFAULTS: Final[str] = "torrc-defaults"
CONTROL_COOKIE: Final[str] = "control_auth_cookie"
MAX_DAEMON_STATE_BYTES: Final[int] = 4096
CONTROL_COOKIE_BYTES: Final[int] = 32
STATE_SCHEMA: Final[int] = 1
CREATE_NO_WINDOW: Final[int] = 0x08000000
MAX_SCANNED_PROCESSES: Final[int] = 4096
SCAN_SECONDS: Final[float] = 10.0
STALE_TERMINATE_SECONDS: Final[float] = 5.0
RELEASE_WAIT_SECONDS: Final[float] = 5.0
_MAX_PID: Final[int] = 0xFFFFFFFF
_MAX_TEXT: Final[int] = 1024  # per text field; encode also refuses a record over 4 KiB

CookieState = Literal["missing", "ok", "unsafe"]
COOKIE_PATH_UNREPORTED: Final[str] = "control-cookie-path-unreported"
COOKIE_PATH_OUTSIDE_TOR_DATA: Final[str] = "control-cookie-path-outside-tor-data"


class ProcessStateUncertain(Exception):
    """Process inspection could not prove identity or absence; ``reason`` is a code."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class ProcessIdentity:
    """A live process as psutil reports it; PID plus creation time is the key."""

    pid: int
    create_time: float
    exe: str
    username: str


@dataclass(frozen=True, slots=True)
class OwnerIdentity:
    """The Mordred (Hermes) process that launched a recorded Tor."""

    pid: int
    create_time: float


@dataclass(frozen=True, slots=True)
class DaemonRecord:
    """Contents of the private ``daemon.json``."""

    tor: ProcessIdentity
    owner: OwnerIdentity
    torrc: str


@dataclass(frozen=True)
class WindowsTorSystem:
    """Every operating-system seam of the Windows launch (tests inject fakes)."""

    resolve: Callable[[str], ResolvedExecutable]
    open_state: Callable[[Path], AbstractContextManager[PrivateDirectory]]
    popen: Callable[..., Any]
    new_job: Callable[[], JobHandle]
    identify: Callable[[int], ProcessIdentity | None]
    owner: Callable[[], OwnerIdentity]
    owner_alive: Callable[[OwnerIdentity], bool]
    terminate: Callable[[ProcessIdentity, float], bool]
    scan: Callable[[str], tuple[int, ...]]


def default_system() -> WindowsTorSystem:
    """Production seams: checked filesystem, real job objects and psutil."""
    return WindowsTorSystem(
        resolve=lambda binary: resolve_windows_executable(binary, purpose="tor"),
        open_state=lambda path: open_private_directory(path, create=True),
        popen=subprocess.Popen,
        new_job=KillOnCloseJob,
        identify=identify_process,
        owner=current_owner,
        owner_alive=owner_alive,
        terminate=terminate_identity,
        scan=scan_torrc_users,
    )


# --------------------------------------------------------------------------- #
# Launch                                                                      #
# --------------------------------------------------------------------------- #


def start_process(
    *,
    binary: str,
    torrc: str,
    data_dir: Path,
    policy_mode: PolicyMode,
    system: WindowsTorSystem | None = None,
) -> WindowsTorProcess:
    """Validate, clean up, publish private state, then spawn one job-bound Tor.

    Every refusal is a :class:`BringupFailed`: strict refuses the route; under
    lenient/off it is logged here and the runtime records its audited
    clearnet fallback.
    """
    try:
        return _launch(binary=binary, torrc=torrc, data_dir=data_dir, policy_mode=policy_mode, seams=system)
    except BringupFailed as refusal:
        if policy_mode != "strict":
            _LOG.warning("native Windows Tor launch refused (%s); %s policy degrades to clearnet", refusal, policy_mode)
        raise


def _launch(
    *, binary: str, torrc: str, data_dir: Path, policy_mode: PolicyMode, seams: WindowsTorSystem | None
) -> WindowsTorProcess:
    seams = seams or default_system()
    image = seams.resolve(binary)
    enforce_executable_trust(image, policy_mode=policy_mode, purpose="tor")
    torrc_path = str(data_dir / TORRC)
    defaults_path = str(data_dir / TORRC_DEFAULTS)
    owner = seams.owner()
    process: WindowsTorProcess | None = None
    failure: PrivateFSError | None = None
    try:
        with seams.open_state(data_dir) as directory, directory.transaction(blocking=False) as txn:
            _reconcile(txn, seams, torrc_path=torrc_path, owner=owner)
            _publish(txn, TORRC, torrc.encode("utf-8"))
            _publish(txn, TORRC_DEFAULTS, b"")
            process = _spawn_recorded(
                txn,
                seams,
                image=image,
                argv=[image.path, "-f", torrc_path, "--defaults-torrc", defaults_path],
                owner=owner,
                data_dir=data_dir,
                torrc_path=torrc_path,
            )
    except PrivateFSError as exc:
        failure = exc
    except BaseException:
        if process is not None:
            process.abort()
        raise
    if failure is not None:
        if process is not None:
            process.abort()
        # Raised outside the handler: only the sanitized classification remains.
        raise BringupFailed(
            "tor private state in the profile's tor-data directory was refused "
            f"({failure.reason}: {failure.operation}, {failure.commit_state}); inspect or remove it, "
            "Mordred does not repair or adopt unsafe state"
        )
    assert process is not None
    return process


def _publish(txn: PrivateTransaction, name: str, data: bytes) -> None:
    """Checked no-replace staging + rename; an unsafe existing member refuses."""
    if _optional_stat(txn, name) is None:
        txn.create_bytes(name, data)
    else:
        txn.replace_bytes(name, data)


def _optional_stat(txn: PrivateTransaction, name: str) -> FileMetadata | None:
    try:
        return txn.stat(name)
    except PrivateFSError as exc:
        if exc.reason == "missing":
            return None
        raise


def _spawn_recorded(
    txn: PrivateTransaction,
    seams: WindowsTorSystem,
    *,
    image: ResolvedExecutable,
    argv: list[str],
    owner: OwnerIdentity,
    data_dir: Path,
    torrc_path: str,
) -> WindowsTorProcess:
    try:
        popen = seams.popen(
            argv,
            executable=image.path,
            cwd=ntpath.dirname(image.path),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            close_fds=True,
            creationflags=CREATE_NO_WINDOW,
        )
    except OSError as exc:
        raise BringupFailed(
            f"tor executable {describe_executable(image.path)} could not be spawned "
            f"({type(exc).__name__}, error {getattr(exc, 'winerror', None) or exc.errno})"
        ) from None
    job: JobHandle | None = None
    stage = "job"
    try:
        job = seams.new_job()
        job.assign(popen.pid)
        stage = "identity"
        identity = seams.identify(popen.pid)
        if identity is None or identity.pid != popen.pid:
            raise ProcessStateUncertain("child-exited")
        stage = "record"
        record = DaemonRecord(tor=identity, owner=owner, torrc=torrc_path)
        txn.create_bytes(DAEMON_STATE, encode_record(record))
    except (OSError, ProcessStateUncertain) as exc:
        _abort_child(popen, job)
        if isinstance(exc, PrivateFSError):
            raise
        detail = exc.reason if isinstance(exc, ProcessStateUncertain) else type(exc).__name__
        reason = {
            "job": "could not be bound to a kill-on-close job",
            "identity": "exited or could not be identified after launch",
        }.get(stage, "could not be recorded in private daemon state")
        raise BringupFailed(f"tor child {reason} ({detail}); it was terminated") from None
    except BaseException:
        _abort_child(popen, job)
        raise
    return WindowsTorProcess(
        popen=popen, job=job, identity=identity, data_dir=data_dir, system=seams, image_trust=image.trust
    )


def _abort_child(popen: Any, job: JobHandle | None) -> None:
    """Terminate the just-created child through its creation handle, then its job."""
    with contextlib.suppress(OSError):
        if popen.poll() is None:
            popen.kill()
    with contextlib.suppress(OSError, subprocess.TimeoutExpired):
        popen.wait(timeout=RELEASE_WAIT_SECONDS)
    if job is not None:
        with contextlib.suppress(OSError):
            job.close()
    stdout = getattr(popen, "stdout", None)
    if stdout is not None:
        with contextlib.suppress(OSError, ValueError):
            stdout.close()


# --------------------------------------------------------------------------- #
# Startup cleanup                                                             #
# --------------------------------------------------------------------------- #


def _reconcile(txn: PrivateTransaction, seams: WindowsTorSystem, *, torrc_path: str, owner: OwnerIdentity) -> None:
    metadata = _optional_stat(txn, DAEMON_STATE)
    if metadata is not None:
        record = parse_record(_read_record_bytes(txn))
        _retire(record, seams, owner)
        txn.delete_file(DAEMON_STATE, expected_identity=metadata.identity)
    uncertain: str | None = None
    try:
        orphans = seams.scan(torrc_path)
    except ProcessStateUncertain as exc:
        uncertain = exc.reason
        orphans = ()
    if uncertain is not None:
        raise BringupFailed(
            f"tor process inventory is uncertain ({uncertain}); refusing to start another Tor on this profile"
        )
    if orphans:
        # The inventory matches any current-user process naming the torrc,
        # not only Tor images (TODO.md: C9 review residuals).
        raise BringupFailed(
            f"an unrecorded process (pid {orphans[0]}) names this profile's torrc in its command line; Mordred "
            "neither reuses nor stops it. Stop that process, then retry"
        )


def _read_record_bytes(txn: PrivateTransaction) -> bytes:
    """Bounded read; an oversized record is refused like a malformed one."""
    try:
        return txn.read_bytes(DAEMON_STATE, max_bytes=MAX_DAEMON_STATE_BYTES)
    except PrivateFSError as exc:
        if exc.operation != "read_limit":
            raise
    # Raised outside the handler: nothing of the read failure is retained.
    raise _malformed_record()


def _malformed_record() -> BringupFailed:
    """Actionable refusal naming only the file and its private directory."""
    return BringupFailed(
        f"tor daemon state file {DAEMON_STATE!r} in this profile's private mordred/tor-data directory is "
        "malformed or oversized; refusing as uncertain (no process was stopped). Make sure no Tor started "
        f"from this profile is still running, then remove that {DAEMON_STATE!r} file and retry"
    )


def _retire(record: DaemonRecord, seams: WindowsTorSystem, owner: OwnerIdentity) -> None:
    uncertain: str | None = None
    current: ProcessIdentity | None = None
    try:
        current = seams.identify(record.tor.pid)
    except ProcessStateUncertain as exc:
        uncertain = exc.reason
    if uncertain is not None:
        raise BringupFailed(
            f"the Tor recorded for this profile cannot be inspected ({uncertain}); refusing as uncertain"
        )
    if current is None or current.create_time != record.tor.create_time:
        _LOG.info("forgetting a stale Tor daemon record; the recorded process no longer exists")
        return
    if current != record.tor:
        raise BringupFailed(
            "tor daemon state does not match the live process it names (identity mismatch); "
            "refusing as uncertain, no process was stopped"
        )
    if record.owner == owner or seams.owner_alive(record.owner):
        raise BringupFailed(
            "the Tor recorded for this profile belongs to a live Mordred process; refusing to reuse or stop it"
        )
    if not seams.terminate(record.tor, STALE_TERMINATE_SECONDS):
        raise BringupFailed(
            "the stale Tor recorded for this profile could not be stopped after identity revalidation; refusing"
        )
    _LOG.warning("terminated a stale Tor (pid %s) left by an exited Mordred process", record.tor.pid)


# --------------------------------------------------------------------------- #
# Daemon record                                                               #
# --------------------------------------------------------------------------- #


def encode_record(record: DaemonRecord) -> bytes:
    """Serialize within the same bounds :func:`parse_record` accepts."""
    texts = (record.tor.exe, record.tor.username, record.torrc)
    if any(_text(text) is None for text in texts):
        raise ProcessStateUncertain("record-too-large")
    document = {
        "schema": STATE_SCHEMA,
        "tor": {
            "pid": record.tor.pid,
            "create_time": record.tor.create_time,
            "exe": record.tor.exe,
            "username": record.tor.username,
        },
        "owner": {"pid": record.owner.pid, "create_time": record.owner.create_time},
        "torrc": record.torrc,
    }
    raw = json.dumps(document, ensure_ascii=True, sort_keys=True).encode("ascii")
    if len(raw) > MAX_DAEMON_STATE_BYTES:
        raise ProcessStateUncertain("record-too-large")
    return raw


def parse_record(raw: bytes) -> DaemonRecord:
    """Strict schema; malformed state is uncertain and never echoed."""
    record: DaemonRecord | None = None
    try:
        record = _record_from(json.loads(raw.decode("utf-8")))
    except (UnicodeDecodeError, ValueError, TypeError, KeyError, RecursionError):
        record = None
    if record is None:
        # Raised outside the handler: no parser exception (or document) is retained.
        raise _malformed_record()
    return record


def _record_from(document: object) -> DaemonRecord | None:
    if not isinstance(document, dict) or set(document) != {"schema", "tor", "owner", "torrc"}:
        return None
    schema, tor, owner = document["schema"], document["tor"], document["owner"]
    if type(schema) is not int or schema != STATE_SCHEMA:
        return None
    if not isinstance(tor, dict) or set(tor) != {"pid", "create_time", "exe", "username"}:
        return None
    if not isinstance(owner, dict) or set(owner) != {"pid", "create_time"}:
        return None
    tor_pid, owner_pid = _pid(tor["pid"]), _pid(owner["pid"])
    tor_time, owner_time = _time(tor["create_time"]), _time(owner["create_time"])
    exe, username, torrc = _text(tor["exe"]), _text(tor["username"]), _text(document["torrc"])
    if tor_pid is None or owner_pid is None or tor_time is None or owner_time is None:
        return None
    if exe is None or username is None or torrc is None:
        return None
    return DaemonRecord(
        tor=ProcessIdentity(tor_pid, tor_time, exe, username),
        owner=OwnerIdentity(owner_pid, owner_time),
        torrc=torrc,
    )


def _pid(value: object) -> int | None:
    return value if type(value) is int and 0 < value <= _MAX_PID else None


def _time(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    number = float(value)
    return number if math.isfinite(number) and number >= 0 else None


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and 0 < len(value) <= _MAX_TEXT else None


# --------------------------------------------------------------------------- #
# Running child                                                               #
# --------------------------------------------------------------------------- #


class WindowsTorProcess:
    """The launched Tor, satisfying :class:`.tor._ProcessLike`.

    ``terminate``/``kill`` act through the creation handle only after the live
    psutil identity still equals the recorded one; a mismatch or uncertainty
    leaves termination to the exact job membership closed by ``release``.
    """

    def __init__(
        self,
        *,
        popen: Any,
        job: JobHandle | None,
        identity: ProcessIdentity,
        data_dir: Path,
        system: WindowsTorSystem,
        image_trust: ExecutableTrust,
    ) -> None:
        self._popen = popen
        self._job = job
        self.identity = identity
        self._data_dir = data_dir
        self._system = system
        self.image_trust: ExecutableTrust = image_trust
        self._lock = threading.Lock()
        self._released = False

    @property
    def stdout(self) -> Iterable[str] | None:
        stream: Iterable[str] | None = self._popen.stdout
        return stream

    @property
    def pid(self) -> int:
        return self.identity.pid

    def poll(self) -> int | None:
        code: int | None = self._popen.poll()
        return code

    def wait(self, timeout: float | None = None) -> int:
        code: int = self._popen.wait(timeout=timeout)
        return code

    def terminate(self) -> None:
        self._terminate_exact()

    def kill(self) -> None:
        self._terminate_exact()

    def _terminate_exact(self) -> None:
        if self._popen.poll() is not None:
            return
        try:
            current = self._system.identify(self.identity.pid)
        except ProcessStateUncertain as exc:
            _LOG.warning("tor identity could not be revalidated (%s); leaving termination to its job", exc.reason)
            return
        if current is None:
            return
        if current != self.identity:
            _LOG.warning("tor identity changed; not terminating by handle, its job ends exact members only")
            return
        with contextlib.suppress(OSError):
            self._popen.terminate()  # TerminateProcess on the creation handle

    def stop(self, *, grace_seconds: float) -> None:
        """Terminate, wait, escalate once, then release the job and record."""
        try:
            if self.poll() is None:
                self.terminate()
                try:
                    self.wait(timeout=grace_seconds)
                except subprocess.TimeoutExpired:
                    self.kill()
                    with contextlib.suppress(subprocess.TimeoutExpired):
                        self.wait(timeout=grace_seconds)
        finally:
            self.release()

    def abort(self) -> None:
        """Terminate a child whose launch failed after spawning (record kept)."""
        with self._lock:
            if self._released:
                return
            self._released = True
        job, self._job = self._job, None
        _abort_child(self._popen, job)

    def release(self) -> None:
        """Close the job (ends exact members), then forget a confirmed-exited record."""
        with self._lock:
            if self._released:
                return
            self._released = True
        job, self._job = self._job, None
        if job is not None:
            try:
                job.close()
            except OSError as exc:
                _LOG.warning("closing the Tor job failed (%s)", type(exc).__name__)
        if self.poll() is None:
            try:
                self.wait(timeout=RELEASE_WAIT_SECONDS)
            except subprocess.TimeoutExpired:
                _LOG.warning("tor exit is unconfirmed; keeping its record for the next startup cleanup")
                return
        self._forget_record()

    def _forget_record(self) -> None:
        try:
            with self._system.open_state(self._data_dir) as directory, directory.transaction(blocking=False) as txn:
                metadata = _optional_stat(txn, DAEMON_STATE)
                if metadata is None:
                    return
                record = parse_record(txn.read_bytes(DAEMON_STATE, max_bytes=MAX_DAEMON_STATE_BYTES))
                if record.tor != self.identity:
                    return  # not ours: the next startup cleanup decides
                txn.delete_file(DAEMON_STATE, expected_identity=metadata.identity)
        except (PrivateFSError, BringupFailed) as exc:
            _LOG.warning("tor daemon record was kept (%s); the next startup cleanup revalidates it", exc)


# --------------------------------------------------------------------------- #
# Checked control-cookie read                                                 #
# --------------------------------------------------------------------------- #


def control_cookie_state(data_dir: Path) -> CookieState:
    """Bounded, checked read of Tor's control cookie before authentication.

    Tor creates the cookie with its token's default DACL, which the stored
    private/confidential file validators intentionally reject. The read-only
    bounded reader still requires a trusted owner, no untrusted mutation
    grant, no reparse point, one volume and an unchanged file, and refuses
    anything over 32 bytes.
    """
    try:
        cookie = read_public_build_output(data_dir / CONTROL_COOKIE, max_bytes=CONTROL_COOKIE_BYTES)
    except PrivateFSError as exc:
        return "missing" if exc.reason == "missing" else "unsafe"
    except (OSError, ValueError):
        return "unsafe"
    return "ok" if len(cookie) == CONTROL_COOKIE_BYTES else "unsafe"


class ControlCookiePathRefused(Exception):
    """Tor reported a control-cookie path other than the private one; ``reason`` is a code."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class _ProtocolInfoSource(Protocol):
    def get_protocolinfo(self) -> object: ...


def pinned_protocolinfo(controller: _ProtocolInfoSource, data_dir: Path) -> object:
    """PROTOCOLINFO whose reported ``COOKIEFILE`` is this profile's private cookie.

    stem's ``authenticate`` re-reads the cookie with a raw ``open()`` at the
    path Tor reports, after :func:`control_cookie_state` checked the private
    one. The caller passes the returned response to
    ``authenticate(protocolinfo_response=...)``, so stem opens only
    ``<tor_data_dir>\\control_auth_cookie`` (case and separators compared the
    Windows way). A missing or different reported path refuses with a
    classified :class:`ControlCookiePathRefused`; the path is never echoed.
    """
    response = controller.get_protocolinfo()
    reported = getattr(response, "cookie_path", None)
    if not isinstance(reported, str) or not reported:
        raise ControlCookiePathRefused(COOKIE_PATH_UNREPORTED)
    if _path_key(reported) != _path_key(str(data_dir / CONTROL_COOKIE)):
        raise ControlCookiePathRefused(COOKIE_PATH_OUTSIDE_TOR_DATA)
    return response


def _path_key(path: str) -> str:
    return ntpath.normcase(ntpath.normpath(path))


# --------------------------------------------------------------------------- #
# psutil-backed process identity                                              #
# --------------------------------------------------------------------------- #


def identify_process(pid: int) -> ProcessIdentity | None:
    """``None`` only for a provably absent PID; denial is uncertainty."""
    try:
        process = psutil.Process(pid)
        with process.oneshot():
            identity = ProcessIdentity(pid, float(process.create_time()), process.exe(), process.username())
    except psutil.NoSuchProcess:
        return None
    except psutil.AccessDenied:
        raise ProcessStateUncertain("process-access-denied") from None
    except (psutil.Error, OSError):
        raise ProcessStateUncertain("process-inspection-failed") from None
    if not identity.exe or not identity.username:
        raise ProcessStateUncertain("process-incomplete")
    return identity


def current_owner() -> OwnerIdentity:
    try:
        process = psutil.Process(os.getpid())
        return OwnerIdentity(process.pid, float(process.create_time()))
    except (psutil.Error, OSError):
        raise BringupFailed("the current process identity could not be read; refusing to launch Tor") from None


def owner_alive(owner: OwnerIdentity) -> bool:
    """Uncertainty counts as alive: a live owner's Tor is never stopped."""
    try:
        return float(psutil.Process(owner.pid).create_time()) == owner.create_time
    except psutil.NoSuchProcess:
        return False
    except (psutil.Error, OSError):
        return True


def terminate_identity(identity: ProcessIdentity, timeout: float) -> bool:
    """Terminate exactly ``identity``; ``False`` when it cannot be proven or stopped."""
    try:
        process = psutil.Process(identity.pid)
        with process.oneshot():
            current = ProcessIdentity(identity.pid, float(process.create_time()), process.exe(), process.username())
        if current != identity:
            return False
        # psutil re-checks PID reuse (creation time) immediately before the
        # signal / TerminateProcess call.
        process.terminate()
        process.wait(timeout=timeout)
    except psutil.NoSuchProcess:
        return True
    except (psutil.TimeoutExpired, psutil.Error, OSError):
        return False
    return True


def scan_torrc_users(torrc_path: str) -> tuple[int, ...]:
    """Current-user processes whose argv names ``torrc_path`` (bounded)."""
    target = ntpath.normcase(torrc_path)
    try:
        owner = psutil.Process(os.getpid()).username()
    except (psutil.Error, OSError):
        raise ProcessStateUncertain("inventory-unavailable") from None
    if not owner:
        raise ProcessStateUncertain("inventory-unavailable")
    deadline = time.monotonic() + SCAN_SECONDS
    matches: list[int] = []
    try:
        for index, process in enumerate(psutil.process_iter(["pid", "username", "cmdline"])):
            if index >= MAX_SCANNED_PROCESSES or time.monotonic() > deadline:
                raise ProcessStateUncertain("inventory-limit")
            info = process.info
            username = info.get("username")
            if not isinstance(username, str) or username.casefold() != owner.casefold():
                continue
            argv = info.get("cmdline") or ()
            if any(isinstance(argument, str) and ntpath.normcase(argument) == target for argument in argv):
                matches.append(int(info["pid"]))
    except (psutil.Error, OSError):
        raise ProcessStateUncertain("inventory-unavailable") from None
    return tuple(sorted(matches))
