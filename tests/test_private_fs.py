"""Behavioral contract for private storage; real files, not mocked contents."""

from __future__ import annotations

import importlib
import importlib.util
import os
from pathlib import Path

import pytest


@pytest.fixture
def fs():
    assert importlib.util.find_spec("mordred_hermes._private_fs") is not None, "private filesystem API missing"
    return importlib.import_module("mordred_hermes._private_fs")


@pytest.fixture
def private_path(tmp_path: Path) -> Path:
    return tmp_path.resolve() / "private"


def test_private_create_read_replace(fs, private_path: Path) -> None:
    with fs.open_private_directory(private_path, create=True) as directory:
        with directory.transaction() as tx:
            tx.create_bytes("秘密 with spaces", b"old\x00bytes")
            assert tx.read_bytes("秘密 with spaces", max_bytes=9) == b"old\x00bytes"
            tx.replace_bytes("秘密 with spaces", b"new")
        assert directory.read_bytes("秘密 with spaces", max_bytes=3) == b"new"
    if os.name == "posix":
        assert private_path.stat().st_mode & 0o777 == 0o700
        assert (private_path / "秘密 with spaces").stat().st_mode & 0o777 == 0o600


def test_create_preserves_existing(fs, private_path: Path) -> None:
    with fs.open_private_directory(private_path, create=True) as d, d.transaction() as tx:
        tx.create_bytes("secret", b"original")
        before = (private_path / "secret").stat().st_ino
        with pytest.raises(fs.PrivateFSError) as err:
            tx.create_bytes("secret", b"replacement")
        assert (err.value.reason, err.value.commit_state) == ("exists", "not_committed")
        assert tx.read_bytes("secret", max_bytes=100) == b"original"
        assert (private_path / "secret").stat().st_ino == before


def test_replace_requires_existing(fs, private_path: Path) -> None:
    with fs.open_private_directory(private_path, create=True) as d, d.transaction() as tx:
        with pytest.raises(fs.PrivateFSError) as err:
            tx.replace_bytes("missing", b"new")
        assert err.value.reason == "missing"
        assert not (private_path / "missing").exists()


def test_read_limit_refuses_oversize(fs, private_path: Path) -> None:
    with fs.open_private_directory(private_path, create=True) as d, d.transaction() as tx:
        tx.create_bytes("secret", b"1234")
        with pytest.raises(fs.PrivateFSError):
            d.read_bytes("secret", max_bytes=3)
        assert d.read_bytes("secret", max_bytes=4) == b"1234"
        for limit in (0, -1):
            with pytest.raises(ValueError):
                d.read_bytes("secret", max_bytes=limit)


def test_context_use_after_close(fs, private_path: Path) -> None:
    with fs.open_private_directory(private_path, create=True) as d:
        with d.transaction() as tx:
            tx.create_bytes("secret", b"original")
        with pytest.raises(RuntimeError):
            tx.replace_bytes("secret", b"wrong")
    with pytest.raises(RuntimeError):
        d.read_bytes("secret", max_bytes=100)
    with pytest.raises(RuntimeError), d.transaction():
        pass


@pytest.mark.parametrize(
    "name", ["", ".", "..", "../victim", "a/b", "a\\b", "x:y", "a\x00b", ".mordred-fs.lock", ".mordred-fs-tmp-forged"]
)
def test_reserved_leaf_refused(fs, private_path: Path, name: str) -> None:
    with fs.open_private_directory(private_path, create=True) as d, d.transaction() as tx:
        with pytest.raises(fs.PrivateFSError) as err:
            tx.create_bytes(name, b"data")
        assert err.value.reason == "unsafe"


def test_empty_payload_is_valid(fs, private_path: Path) -> None:
    with fs.open_private_directory(private_path, create=True) as d, d.transaction() as tx:
        tx.create_bytes("empty", b"")
        assert d.read_bytes("empty", max_bytes=1) == b""


def test_missing_directory_does_not_get_created_by_read(fs, private_path: Path) -> None:
    with pytest.raises(fs.PrivateFSError) as err, fs.open_private_directory(private_path):
        pass
    assert err.value.reason == "missing"
    assert not private_path.exists()
