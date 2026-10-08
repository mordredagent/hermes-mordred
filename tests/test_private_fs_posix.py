"""POSIX security and publication failures of the new, opt-in API."""

from __future__ import annotations

import errno
import importlib
import importlib.util
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX backend contract")


@pytest.fixture
def fs():
    assert importlib.util.find_spec("mordred_hermes._private_fs") is not None, "private filesystem API missing"
    return importlib.import_module("mordred_hermes._private_fs")


def test_symlink_and_hardlink_refused(fs, tmp_path: Path) -> None:
    root = tmp_path.resolve() / "private"
    with fs.open_private_directory(root, create=True) as d, d.transaction() as tx:
        tx.create_bytes("secret", b"original")
        (root / "symbolic").symlink_to(root / "secret")
        os.link(root / "secret", root / "hard")
        for name in ("symbolic", "hard", "secret"):
            with pytest.raises(fs.PrivateFSError) as err:
                d.read_bytes(name, max_bytes=100)
            assert err.value.reason == "unsafe"
        assert (root / "secret").read_bytes() == b"original"


@pytest.mark.parametrize("kind", ["directory", "file", "ancestor", "fifo"])
def test_unsafe_objects_never_repaired(fs, tmp_path: Path, kind: str) -> None:
    parent = tmp_path.resolve()
    root = parent / "private"
    root.mkdir(mode=0o700)
    if kind == "directory":
        root.chmod(0o755)
    elif kind == "ancestor":
        parent.chmod(0o777)
    else:
        if kind == "fifo":
            os.mkfifo(root / "secret", 0o600)
        else:
            (root / "secret").write_bytes(b"keep")
            (root / "secret").chmod(0o644)
    with pytest.raises(fs.PrivateFSError) as err, fs.open_private_directory(root) as d:
        d.read_bytes("secret", max_bytes=100)
    assert err.value.reason == "unsafe"
    if kind == "file":
        assert (root / "secret").read_bytes() == b"keep"
        assert stat.S_IMODE((root / "secret").stat().st_mode) == 0o644


def test_posix_import_does_not_load_windows(fs) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import mordred_hermes._private_fs; "
            'assert not any(n.startswith("mordred_hermes._private_fs._windows") for n in sys.modules)',
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_unsupported_os_never_falls_back(fs, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fs, "_platform", "unknown")
    with pytest.raises(fs.PrivateFSError) as err, fs.open_private_directory(tmp_path):
        pass
    assert err.value.reason == "unsupported"


@pytest.mark.parametrize("stage", ["write", "file_flush", "directory_flush"])
def test_publication_failure_preserves_correct_version(
    fs, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    root = tmp_path.resolve() / "private"
    with fs.open_private_directory(root, create=True) as d, d.transaction() as tx:
        tx.create_bytes("secret", b"old")
        real_fsync = os.fsync

        def fail_flush(fd):
            is_dir = stat.S_ISDIR(os.fstat(fd).st_mode)
            if (stage == "directory_flush") == is_dir:
                raise OSError(errno.EIO, "injected flush failure")
            real_fsync(fd)

        if stage == "write":
            monkeypatch.setattr(os, "write", lambda fd, data: 0)
        else:
            monkeypatch.setattr(os, "fsync", fail_flush)
        with pytest.raises(fs.PrivateFSError) as err:
            tx.replace_bytes("secret", b"new")
        assert err.value.commit_state == ("uncertain" if stage == "directory_flush" else "not_committed")
        assert (root / "secret").read_bytes() == (b"new" if stage == "directory_flush" else b"old")


def test_short_writes_do_not_truncate(fs, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real_write = os.write
    with fs.open_private_directory(tmp_path.resolve() / "private", create=True) as d, d.transaction() as tx:
        monkeypatch.setattr(os, "write", lambda fd, data: real_write(fd, data[:2]))
        tx.create_bytes("secret", b"complete payload")
        assert d.read_bytes("secret", max_bytes=100) == b"complete payload"
