"""Actual NTFS admission for extension master-key/history storage (Windows hosts only)."""

from __future__ import annotations

import contextlib
import hashlib
import os
import queue
import subprocess
import sys
import threading
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes._private_fs import open_private_directory
from mordred_hermes.extension import _windows_storage as storage
from mordred_hermes.extension import history, pairing

pytestmark = pytest.mark.skipif(os.name != "nt", reason="actual Windows extension storage admission")


def icacls(path: Path) -> bytes:
    return subprocess.check_output(["icacls.exe", str(path)])


def contents(directory: Path) -> dict[str, str]:
    """File digests only: never place aes_key bytes in assert operands."""
    return {
        entry.name: hashlib.sha256(entry.read_bytes()).hexdigest()
        for entry in sorted(directory.iterdir())
        if entry.is_file()
    }


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    root = tmp_path / "ホーム with spaces"
    root.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(root))
    monkeypatch.setattr(pairing, "se_available", lambda: False)
    assert storage.enabled()
    pairing._invalidate_state_cache()
    yield root
    pairing._invalidate_state_cache()


# A master that differs from the fixture's, for the write paths.
REPLACEMENT = pairing.Pairing(
    aes_key=b"\x01" * 32, ext_token="", ext_pubkey_b64="", hermes_pubkey_b64="", paired_at=1.0
)


@pytest.fixture
def paired(home: Path) -> pairing.Pairing:
    master = pairing.ensure_master()
    history.save_messages([{"role": "user", "content": "hello"}])
    return master


def refused_operations() -> list[Callable[[], object]]:
    return [
        pairing.ensure_master,
        pairing.load_pairing,
        lambda: pairing._save_pairing(REPLACEMENT),
        history.load_history,
        history.clear,
        pairing.clear_pairing,
    ]


def test_native_round_trip_keeps_exact_private_descriptors(paired: pairing.Pairing, home: Path) -> None:
    assert pairing.load_pairing() == paired
    assert history.projected_history().turns == [{"role": "user", "content": "hello"}]
    names = sorted(entry.name for entry in (home / "extension").iterdir())
    assert names == [".mordred-fs.lock", "history.enc", "state.json"]
    # The foundation's exact-private admission re-checks every stored file.
    with open_private_directory(home / "extension") as checked:
        assert all(checked.stat(name).size > 0 for name in names[1:])


def test_native_inherited_extension_directory_is_refused_without_repair(home: Path) -> None:
    directory = home / "extension"
    directory.mkdir()  # inherits the profile-style temporary directory ACL
    before = icacls(directory)
    for operation in refused_operations():
        with pytest.raises(storage.ExtensionStorageError):
            operation()
    assert icacls(directory) == before
    assert list(directory.iterdir()) == []


@pytest.mark.parametrize("target", ["extension", "state.json", "history.enc", ".mordred-fs.lock"])
def test_native_broadened_acl_refuses_without_repair(paired: pairing.Pairing, home: Path, target: str) -> None:
    directory = home / "extension"
    path = directory if target == "extension" else directory / target
    subprocess.run(["icacls.exe", str(path), "/grant", "*S-1-1-0:(R)"], check=True, capture_output=True)
    before, descriptor = contents(directory), icacls(path)
    checks = {
        "extension": pairing.load_pairing,
        "state.json": pairing.load_pairing,
        "history.enc": history.load_history,
        ".mordred-fs.lock": pairing.load_pairing,
    }
    with pytest.raises(storage.ExtensionStorageError):
        checks[target]()
    assert icacls(path) == descriptor
    assert contents(directory) == before


def test_native_hardlinked_state_refuses_without_change(paired: pairing.Pairing, home: Path) -> None:
    directory = home / "extension"
    os.link(directory / "state.json", directory / "alias")
    before = contents(directory)
    for operation in (pairing.load_pairing, lambda: pairing._save_pairing(REPLACEMENT)):
        with pytest.raises(storage.ExtensionStorageError):
            operation()
    assert contents(directory) == before


def test_native_extension_junction_is_refused_without_touching_target(paired: pairing.Pairing, home: Path) -> None:
    directory = home / "extension"
    target = home / "junction target"
    directory.rename(target)
    subprocess.run(["cmd.exe", "/c", "mklink", "/J", str(directory), str(target)], check=True, capture_output=True)
    try:
        before = contents(target)
        for operation in refused_operations():
            with pytest.raises(storage.ExtensionStorageError):
                operation()
        assert contents(target) == before
    finally:
        directory.rmdir()
        target.rename(directory)
    assert pairing.load_pairing() == paired


_HOLDER = """
import sys
from mordred_hermes._private_fs import open_private_directory
with open_private_directory(sys.argv[1]) as directory, directory.transaction():
    print("locked", flush=True)
    sys.stdin.readline()
"""


def test_native_lock_held_by_another_process_serializes_mutation(paired: pairing.Pairing, home: Path) -> None:
    holder = subprocess.Popen(
        [sys.executable, "-u", "-c", _HOLDER, str(home / "extension")],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    assert holder.stdout is not None
    done: queue.Queue[object] = queue.Queue()
    try:
        assert holder.stdout.readline().strip() == "locked"

        def mutate() -> None:
            try:
                done.put(pairing._save_pairing(REPLACEMENT))
            except BaseException as exc:  # pragma: no cover - reported through the queue
                done.put(exc)

        worker = threading.Thread(target=mutate, daemon=True)
        worker.start()
        with pytest.raises(queue.Empty):
            done.get(timeout=0.5)
    finally:
        with contextlib.suppress(Exception):
            holder.communicate("release\n", timeout=20)
    outcome: Any = done.get(timeout=20)
    assert not isinstance(outcome, BaseException)
    assert pairing.load_pairing() == REPLACEMENT
    assert holder.returncode == 0
