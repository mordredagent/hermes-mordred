"""Unit tests for the shared private-lockfile + ``flock`` primitive.

Covers :mod:`mordred_hermes._file_lock` -- the pure-stdlib module that
single-sources the descriptor lifecycle four cross-process mutexes used to
carry a near-verbatim copy of (``extension.pairing._state_lock``,
``_dotenv_io._dotenv_lock``,
``wizard.policy_writer._policy_write_lock``,
``keyvault._extension_config._wallet_file_lock``).

The security properties asserted here are the ones every copy had to get right
independently, and which a shared helper must therefore never relax:

* the lock file is created private (mode ``0o600``) and a widened one is
  refused rather than used;
* the check is made against the **opened descriptor**, so a swap after the
  ``lstat`` cannot slip a wider file through;
* a symlinked lock path is refused by ``O_NOFOLLOW`` at the kernel;
* the advisory lock genuinely excludes another process, and is released even
  when the guarded body raises;
* the descriptor is always closed.

Every failure point is a caller-supplied ``NoReturn`` handler, so the tests
also pin *that* contract: the helper must call the handler rather than invent
an exception of its own, and must re-raise the original :exc:`OSError`
unchanged when no handler is supplied.
"""

from __future__ import annotations

import errno
import os
import re
import stat
import subprocess
import sys
import types
from pathlib import Path
from typing import Any, NoReturn, cast

import pytest

from mordred_hermes import _file_lock
from mordred_hermes._file_lock import LOCK_MODE, private_flock
from tests._checked_fixture_helpers import file_symlink as file_symlink
from tests._platform_test_helpers import posix_modes as posix_modes
from tests._platform_test_helpers import rename_open_inode as rename_open_inode

try:
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - non-POSIX fallback
    _fcntl = None  # type: ignore[assignment]


class _LockOS:
    O_RDWR, O_CREAT = 1, 2

    def __init__(self):
        self.events = []
        self.mode = stat.S_IFREG | 0o600
        self.next_fd = 100
        self.open_error = None
        self.stat_error = None
        self.close_error = None

    def open(self, path, flags, mode):
        self.events.append(("open", str(path), flags, mode))
        if self.open_error is not None:
            raise self.open_error
        self.next_fd += 1
        return self.next_fd

    def fstat(self, fd):
        self.events.append(("fstat", fd))
        if self.stat_error is not None:
            raise self.stat_error
        return types.SimpleNamespace(st_mode=self.mode)

    def close(self, fd):
        self.events.append(("close", fd))
        if self.close_error is not None:
            raise self.close_error


@pytest.fixture
def lock_model(monkeypatch):
    """Descriptor lifecycle model; no native mode, no-follow or flock evidence."""
    model = _LockOS()

    def flock(fd, operation):
        model.events.append(("flock", fd, operation))

    monkeypatch.setattr(_file_lock, "os", model)
    monkeypatch.setattr(_file_lock, "fcntl", types.SimpleNamespace(LOCK_EX=1, LOCK_UN=2, flock=flock))
    for name, bit in (("_O_CLOEXEC", 4), ("_O_NOFOLLOW", 8), ("_O_NONBLOCK", 16)):
        monkeypatch.setattr(_file_lock, name, bit)
    return model


class _Sentinel(Exception):
    """Distinct type so a test can prove *its* handler ran, not a stray OSError."""


def _boom_unsafe(lock_path: Path) -> NoReturn:
    raise _Sentinel(f"unsafe:{lock_path}")


def _boom_open(lock_path: Path, exc: OSError) -> NoReturn:
    raise _Sentinel(f"open:{lock_path}") from exc


def _boom_lock(lock_path: Path, exc: OSError) -> NoReturn:
    raise _Sentinel(f"flock:{lock_path}") from exc


# --------------------------------------------------------------------------- #
# Creation and mode                                                           #
# --------------------------------------------------------------------------- #


@pytest.mark.usefixtures("posix_modes")
def test_creates_an_absent_lock_file_at_mode_0600(tmp_path: Path) -> None:
    lock = tmp_path / ".thing.lock"
    with private_flock(lock, on_unsafe=_boom_unsafe):
        assert lock.is_file()
        assert stat.S_IMODE(lock.stat().st_mode) == LOCK_MODE
    assert stat.S_IMODE(lock.stat().st_mode) == LOCK_MODE


@pytest.mark.usefixtures("posix_modes")
def test_reuses_an_existing_private_lock_file(tmp_path: Path) -> None:
    lock = tmp_path / ".thing.lock"
    lock.touch(mode=LOCK_MODE)
    before = lock.stat().st_ino
    with private_flock(lock, on_unsafe=_boom_unsafe):
        pass
    assert lock.stat().st_ino == before


@pytest.mark.parametrize("widened", [0o644, 0o660, 0o777])
@pytest.mark.usefixtures("posix_modes")
def test_refuses_a_lock_file_whose_mode_was_widened(tmp_path: Path, widened: int) -> None:
    """A lock nobody else can be excluded from is worse than no lock at all."""
    lock = tmp_path / ".thing.lock"
    lock.touch()
    os.chmod(lock, widened)

    with pytest.raises(_Sentinel, match=re.escape(f"unsafe:{lock}")), private_flock(lock, on_unsafe=_boom_unsafe):
        raise AssertionError("the guarded body must not run for an unsafe lock")  # pragma: no cover


def test_refuses_a_lock_path_that_is_a_directory(tmp_path, lock_model):
    lock = tmp_path / ".thing.lock"
    error = OSError(errno.EISDIR, "is a directory")
    lock_model.open_error = error
    with (
        pytest.raises(_Sentinel, match=re.escape(f"open:{lock}")) as caught,
        private_flock(lock, on_unsafe=_boom_unsafe, on_open_error=_boom_open),
    ):
        pytest.fail("body reached")
    assert caught.value.__cause__ is error
    assert [event[0] for event in lock_model.events] == ["open"]


@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="platform has no O_NOFOLLOW")
@pytest.mark.usefixtures("posix_modes", "file_symlink")
def test_refuses_to_follow_a_symlinked_lock_path(tmp_path: Path) -> None:
    """The whole point of O_NOFOLLOW: a planted symlink must not redirect the lock."""
    victim = tmp_path / "victim"
    victim.touch(mode=LOCK_MODE)
    lock = tmp_path / ".thing.lock"
    lock.symlink_to(victim)

    with (
        pytest.raises(_Sentinel, match=re.escape(f"open:{lock}")) as caught,
        private_flock(lock, on_unsafe=_boom_unsafe, on_open_error=_boom_open),
    ):
        pass
    cause = caught.value.__cause__
    assert isinstance(cause, OSError) and cause.errno in (errno.ELOOP, errno.EMLINK)


def test_without_an_open_handler_the_original_oserror_propagates(tmp_path, lock_model):
    error = FileNotFoundError(errno.ENOENT, "missing")
    lock_model.open_error = error
    with pytest.raises(FileNotFoundError) as caught, private_flock(tmp_path / "lock", on_unsafe=_boom_unsafe):
        pytest.fail("body reached")
    assert caught.value is error


@pytest.mark.usefixtures("posix_modes", "rename_open_inode")
def test_the_mode_check_reads_the_opened_descriptor_not_the_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A file swapped after ``os.open`` must still be judged by its own inode.

    ``fstat`` on the descriptor -- never a second ``stat`` on the name -- is
    what closes the TOCTOU window; this pins that the helper never regressed to
    a path-based re-check.
    """
    lock = tmp_path / ".thing.lock"
    lock.touch(mode=LOCK_MODE)
    decoy = tmp_path / "decoy"
    decoy.touch(mode=LOCK_MODE)

    real_open = os.open

    def swap_after_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        fd = real_open(path, flags, *args, **kwargs)
        if os.fspath(path) == os.fspath(lock):
            # The descriptor now points at the original (private) inode while
            # the *name* points at a world-writable one.
            os.chmod(decoy, 0o777)
            decoy.replace(lock)
        return fd

    monkeypatch.setattr(os, "open", swap_after_open)

    entered = False
    with private_flock(lock, on_unsafe=_boom_unsafe):
        entered = True
    assert entered, "the private descriptor we actually hold must still be accepted"


# --------------------------------------------------------------------------- #
# Locking, unlocking and descriptor hygiene                                   #
# --------------------------------------------------------------------------- #

_PROBE = """
import fcntl, os, sys
fd = os.open(sys.argv[1], os.O_RDWR)
try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    raise SystemExit(3)   # someone else holds it (distinct from a crash's 1)
raise SystemExit(0)       # free
"""


def _lock_is_free(lock: Path) -> bool:
    result = subprocess.run(
        [sys.executable, "-c", _PROBE, str(lock)],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode in (0, 3), result.stderr  # anything else = the probe itself crashed
    return result.returncode == 0


@pytest.mark.skipif(_fcntl is None, reason="fcntl is unavailable")
def test_excludes_another_process_while_held(tmp_path: Path) -> None:
    lock = tmp_path / ".thing.lock"
    with private_flock(lock, on_unsafe=_boom_unsafe):
        assert not _lock_is_free(lock)
    assert _lock_is_free(lock)


@pytest.mark.skipif(_fcntl is None, reason="fcntl is unavailable")
def test_releases_the_lock_when_the_guarded_body_raises(tmp_path: Path) -> None:
    """The unlock lives in a ``finally`` nested inside the close ``finally``."""
    lock = tmp_path / ".thing.lock"
    with pytest.raises(RuntimeError, match="body blew up"), private_flock(lock, on_unsafe=_boom_unsafe):
        raise RuntimeError("body blew up")
    assert _lock_is_free(lock)


def test_closes_the_descriptor_on_both_the_happy_and_failing_paths(tmp_path, lock_model):
    for fail in (False, True):
        try:
            with private_flock(tmp_path / "lock", on_unsafe=_boom_unsafe):
                if fail:
                    raise RuntimeError("body")
        except RuntimeError:
            assert fail
    assert [event[0] for event in lock_model.events] == ["open", "fstat", "flock", "flock", "close"] * 2
    assert lock_model.events[4] == ("close", 101)
    assert lock_model.events[9] == ("close", 102)


def test_a_flock_failure_reaches_the_lock_handler(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, lock_model) -> None:
    import mordred_hermes._file_lock as file_lock

    def refuse(fd: int, operation: int) -> None:
        raise OSError(errno.ENOLCK, "no locks available")

    monkeypatch.setattr(file_lock.fcntl, "flock", refuse)

    lock = tmp_path / ".thing.lock"
    with (
        pytest.raises(_Sentinel, match=re.escape(f"flock:{lock}")),
        private_flock(lock, on_unsafe=_boom_unsafe, on_lock_error=_boom_lock),
    ):
        pass


def test_without_a_lock_handler_a_flock_failure_propagates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, lock_model
) -> None:
    import mordred_hermes._file_lock as file_lock

    def refuse(fd: int, operation: int) -> None:
        raise OSError(errno.ENOLCK, "no locks available")

    monkeypatch.setattr(file_lock.fcntl, "flock", refuse)

    lock = tmp_path / ".thing.lock"
    with pytest.raises(OSError, match="no locks available") as caught, private_flock(lock, on_unsafe=_boom_unsafe):
        pass
    assert caught.value.errno == errno.ENOLCK


def test_unlock_errors_are_swallowed_only_when_asked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, lock_model
) -> None:
    """``_wallet_file_lock`` swallows them so teardown cannot mask the real error."""
    import mordred_hermes._file_lock as file_lock

    real_flock = file_lock.fcntl.flock

    def fail_on_unlock(fd: int, operation: int) -> None:
        if operation == file_lock.fcntl.LOCK_UN:
            raise OSError(errno.EBADF, "bad descriptor")
        real_flock(fd, operation)

    monkeypatch.setattr(file_lock.fcntl, "flock", fail_on_unlock)
    lock = tmp_path / ".thing.lock"

    with private_flock(lock, on_unsafe=_boom_unsafe, suppress_unlock_errors=True):
        pass

    with pytest.raises(OSError, match="bad descriptor"), private_flock(lock, on_unsafe=_boom_unsafe):
        pass


# --------------------------------------------------------------------------- #
# Open flags and reentrancy                                                   #
# --------------------------------------------------------------------------- #


def _flags_used(tmp_path, monkeypatch, *, nonblock):
    seen = []
    real_open = _file_lock.os.open

    def spy_open(path, flags, mode):
        seen.append(flags)
        return real_open(path, flags, mode)

    monkeypatch.setattr(_file_lock.os, "open", spy_open)
    with private_flock(tmp_path / "lock", on_unsafe=_boom_unsafe, nonblock=nonblock):
        pass
    return seen[0]


def test_open_flags_are_private_and_nofollow_by_default(tmp_path, monkeypatch, lock_model):
    assert _flags_used(tmp_path, monkeypatch, nonblock=True) == 1 | 2 | 4 | 8 | 16


def test_nonblock_false_omits_only_o_nonblock(tmp_path, monkeypatch, lock_model):
    assert _flags_used(tmp_path, monkeypatch, nonblock=False) == 1 | 2 | 4 | 8


def test_holds_no_reentrancy_state_of_its_own(tmp_path, lock_model):
    for _ in range(3):
        with private_flock(tmp_path / "lock", on_unsafe=_boom_unsafe):
            pass
    assert [event[1] for event in lock_model.events if event[0] == "close"] == [101, 102, 103]
    assert [event[0] for event in lock_model.events] == ["open", "fstat", "flock", "flock", "close"] * 3


# --------------------------------------------------------------------------- #
# Structural backstop: a handler that returns instead of raising is refused.
# --------------------------------------------------------------------------- #


def _returning_handler(*_args: object) -> None:
    return None


@pytest.mark.parametrize("mode", [stat.S_IFREG | 0o644, stat.S_IFDIR | 0o600])
def test_a_returning_on_unsafe_handler_is_refused_and_the_body_never_runs(tmp_path, lock_model, mode):
    lock_model.mode = mode
    with (
        pytest.raises(RuntimeError, match="on_unsafe returned"),
        private_flock(tmp_path / "lock", on_unsafe=cast(Any, _returning_handler)),
    ):
        pytest.fail("body reached")
    assert [event[0] for event in lock_model.events] == ["open", "fstat", "close"]


def test_a_returning_on_open_error_handler_is_refused(tmp_path, lock_model):
    lock_model.open_error = OSError(errno.EACCES, "denied")
    with (
        pytest.raises(RuntimeError, match="on_open_error returned"),
        private_flock(tmp_path / "lock", on_unsafe=_boom_unsafe, on_open_error=cast(Any, _returning_handler)),
    ):
        pytest.fail("body reached")
    assert [event[0] for event in lock_model.events] == ["open"]


def test_a_returning_on_lock_error_handler_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, lock_model
) -> None:
    real = _file_lock.fcntl
    assert real is not None

    def _flock(fd: int, op: int) -> None:
        if op == real.LOCK_EX:
            raise OSError(errno.EAGAIN, "busy")

    monkeypatch.setattr(
        _file_lock, "fcntl", types.SimpleNamespace(LOCK_EX=real.LOCK_EX, LOCK_UN=real.LOCK_UN, flock=_flock)
    )
    lock = tmp_path / "lock"
    ran = False
    with (
        pytest.raises(RuntimeError, match="on_lock_error returned"),
        private_flock(lock, on_unsafe=cast(Any, _returning_handler), on_lock_error=cast(Any, _returning_handler)),
    ):
        ran = True
    assert not ran


@pytest.mark.parametrize("point", ["fstat", "close"])
def test_descriptor_errors_propagate_after_required_cleanup(tmp_path, lock_model, point):
    error = OSError(errno.EBADF, "descriptor fault")
    setattr(lock_model, "stat_error" if point == "fstat" else "close_error", error)
    with pytest.raises(OSError) as caught, private_flock(tmp_path / "lock", on_unsafe=_boom_unsafe):
        assert point == "close"
    assert caught.value is error
    assert lock_model.events[-1] == ("close", 101)


@pytest.mark.skipif(_fcntl is None, reason="actual fcntl.flock process-exclusion capability")
@pytest.mark.usefixtures("posix_modes")
def test_real_sequential_entries_keep_private_mode_and_release(tmp_path):
    lock = tmp_path / ".thing.lock"
    for _ in range(3):
        with private_flock(lock, on_unsafe=_boom_unsafe):
            assert stat.S_IMODE(lock.stat().st_mode) == LOCK_MODE
    assert _lock_is_free(lock)
