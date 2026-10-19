"""Transaction-level failure and concurrency contracts for the shared owner."""

from __future__ import annotations

import errno
import os
import threading
from pathlib import Path

import pytest

from mordred_hermes import _dotenv_io

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX lockfile contracts; native canonical tests are separate")


def test_unsafe_lock_mode_refuses_without_transform_or_mutation(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text("KEEP=1\n")
    lock = tmp_path / ".env.lock"
    lock.touch(mode=0o644)
    lock.chmod(0o644)
    with pytest.raises(OSError) as error:
        _dotenv_io.update_dotenv_file(path, lambda _: pytest.fail("unsafe lock ran transform"))
    assert error.value.errno == errno.EPERM
    assert error.value.strerror == "dotenv lock must be a mode-0600 regular file"
    assert error.value.__cause__ is None
    assert path.read_text() == "KEEP=1\n"


def test_symlink_lock_preserves_open_error_chaining(tmp_path: Path) -> None:
    target = tmp_path / "victim"
    target.write_text("untouched")
    lock = tmp_path / ".env.lock"
    lock.symlink_to(target)
    with pytest.raises(OSError) as error:
        _dotenv_io.update_dotenv_file(tmp_path / ".env", lambda _: pytest.fail("unsafe lock ran transform"))
    assert error.value.errno == errno.EPERM
    assert error.value.strerror == "dotenv lock is unsafe or unavailable"
    assert isinstance(error.value.__cause__, OSError)
    assert target.read_text() == "untouched"
    assert not (tmp_path / ".env").exists()


def test_symlink_parent_is_refused_without_creating_lock(tmp_path: Path) -> None:
    target = tmp_path / "real"
    target.mkdir()
    parent = tmp_path / "linked"
    parent.symlink_to(target, target_is_directory=True)
    with pytest.raises(OSError) as error:
        _dotenv_io.update_dotenv_file(parent / ".env", lambda _: "KEY=value\n")
    assert error.value.errno == errno.ENOTDIR
    assert list(target.iterdir()) == []


def test_transform_failure_preserves_bytes_and_releases_lock(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_bytes(b"KEEP=old\r\n")

    def refuse(_source: str) -> str:
        raise ValueError("refused")

    with pytest.raises(ValueError, match="refused"):
        _dotenv_io.update_dotenv_file(path, refuse)
    assert path.read_bytes() == b"KEEP=old\r\n"
    _dotenv_io.update_dotenv_file(path, lambda source: source + "NEXT=value\n")
    assert path.read_bytes() == b"KEEP=old\r\nNEXT=value\n"


def test_concurrent_slack_no_overwrite_checks_share_the_write_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mordred_hermes.extension.api import _update_slack_env

    path = tmp_path / ".env"
    path.write_text("KEEP=1\n")
    committing = threading.Event()
    release = threading.Event()
    second_done = threading.Event()
    failures: list[BaseException] = []
    results: dict[str, bool] = {}
    write = _dotenv_io._atomic_write_text

    def hold_first(path: Path, text: str, *, mode: int | None = None) -> None:
        if threading.current_thread().name == "first":
            committing.set()
            if not release.wait(timeout=5):
                raise TimeoutError("commit release timed out")
        write(path, text, mode=mode)

    def setup(token: str) -> None:
        try:
            results[token] = _update_slack_env(path, {"SLACK_BOT_TOKEN": token}, False)
        except BaseException as exc:
            failures.append(exc)
        finally:
            if token == "second":
                second_done.set()

    monkeypatch.setattr(_dotenv_io, "_atomic_write_text", hold_first)
    first = threading.Thread(target=setup, args=("first",), name="first")
    second = threading.Thread(target=setup, args=("second",), name="second")
    first.start()
    try:
        assert committing.wait(timeout=5)
        second.start()
        assert not second_done.wait(timeout=0.1), "Slack overwrite check escaped the transaction"
    finally:
        release.set()
        first.join(timeout=5)
        if second.ident is not None:
            second.join(timeout=5)
    assert not first.is_alive() and not second.is_alive()
    assert failures == []
    assert results == {"first": True, "second": False}
    assert path.read_text() == "KEEP=1\nSLACK_BOT_TOKEN=first\n"
