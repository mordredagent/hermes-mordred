"""Race/file-type regression tests for plaintext reseal capture."""

from __future__ import annotations

import os
import stat
import threading
from pathlib import Path

import pytest

from mordred_hermes.keyvault import _plaintext_capture


def test_raced_symlink_is_quarantined_without_chmodding_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live = tmp_path / ".env"
    live.write_bytes(b"original\n")
    target = tmp_path / "attacker-target"
    target.write_bytes(b"must-not-be-followed\n")
    target.chmod(0o644)

    temp_created = threading.Barrier(2)
    replacement_done = threading.Barrier(2)
    real_mkstemp = _plaintext_capture.tempfile.mkstemp

    def pausing_mkstemp(*args: object, **kwargs: object) -> tuple[int, str]:
        fd, name = real_mkstemp(*args, **kwargs)  # type: ignore[arg-type]
        temp_created.wait(timeout=5)
        replacement_done.wait(timeout=5)
        return fd, name

    def race_source() -> None:
        temp_created.wait(timeout=5)
        live.unlink()
        live.symlink_to(target)
        replacement_done.wait(timeout=5)

    monkeypatch.setattr(_plaintext_capture.tempfile, "mkstemp", pausing_mkstemp)
    racer = threading.Thread(target=race_source)
    racer.start()
    with pytest.raises(OSError, match="symbolic-link"):
        _plaintext_capture.capture_plaintext(live)
    racer.join(timeout=5)

    assert not racer.is_alive()
    assert stat.S_IMODE(target.stat().st_mode) == 0o644
    assert target.read_bytes() == b"must-not-be-followed\n"
    assert not (live.exists() or live.is_symlink())
    candidates = list(tmp_path.glob(".*.mordred-reseal-*"))
    assert len(candidates) == 1
    assert candidates[0].is_symlink()
    with pytest.raises(OSError, match="symbolic-link"):
        _plaintext_capture.restore_capture_no_replace(candidates[0], live)
    assert not (live.exists() or live.is_symlink())


def test_post_capture_chmod_failure_restores_original_without_replace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live = tmp_path / "config.yaml"
    live.write_bytes(b"important: true\n")
    live.chmod(0o644)
    real_fchmod = os.fchmod
    calls = 0

    def fail_first_fchmod(fd: int, mode: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("forced chmod failure")
        real_fchmod(fd, mode)

    monkeypatch.setattr(_plaintext_capture.os, "fchmod", fail_first_fchmod)
    with pytest.raises(OSError, match="forced chmod failure"):
        _plaintext_capture.capture_plaintext(live)

    assert live.read_bytes() == b"important: true\n"
    assert stat.S_IMODE(live.stat().st_mode) == 0o600
    assert not list(tmp_path.glob(".*.mordred-reseal-*"))


def test_capture_syncs_renamed_private_inode_before_return(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live = tmp_path / ".env"
    live.write_bytes(b"secret\n")
    observed: list[tuple[bool, list[Path]]] = []

    def observe_sync(_directory: Path) -> None:
        candidates = list(tmp_path.glob(".*.mordred-reseal-*"))
        observed.append((live.exists(), candidates))
        assert len(candidates) == 1
        assert stat.S_IMODE(candidates[0].stat().st_mode) == 0o600

    monkeypatch.setattr(_plaintext_capture, "_sync_directory", observe_sync)
    candidate = _plaintext_capture.capture_plaintext(live)

    assert candidate is not None
    assert observed == [(False, [candidate])]
    assert candidate.read_bytes() == b"secret\n"


def test_capture_directory_sync_failure_restores_live_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live = tmp_path / ".env"
    live.write_bytes(b"secret\n")
    calls = 0

    def fail_first_sync(_directory: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("forced capture-directory sync failure")

    monkeypatch.setattr(_plaintext_capture, "_sync_directory", fail_first_sync)
    with pytest.raises(OSError, match="forced capture-directory sync failure"):
        _plaintext_capture.capture_plaintext(live)

    assert calls == 3  # failed rename sync, durable restore link, durable cleanup
    assert live.read_bytes() == b"secret\n"
    assert not list(tmp_path.glob(".*.mordred-reseal-*"))


def test_restore_syncs_live_link_before_candidate_unlink_then_syncs_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live = tmp_path / "config.yaml"
    candidate = tmp_path / ".config.yaml.mordred-reseal-test"
    candidate.write_bytes(b"important: true\n")
    candidate.chmod(0o600)
    snapshots: list[tuple[bool, bool]] = []

    def observe_sync(_directory: Path) -> None:
        snapshots.append((live.exists(), candidate.exists()))

    monkeypatch.setattr(_plaintext_capture, "_sync_directory", observe_sync)

    assert _plaintext_capture.restore_capture_no_replace(candidate, live) is True
    assert snapshots == [(True, True), (True, False)]
    assert live.read_bytes() == b"important: true\n"


def test_restore_publication_sync_failure_keeps_durable_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live = tmp_path / ".env"
    candidate = tmp_path / ".env.mordred-reseal-test"
    candidate.write_bytes(b"must-survive\n")
    candidate.chmod(0o600)

    def fail_sync(_directory: Path) -> None:
        raise OSError("forced parent-directory sync failure")

    monkeypatch.setattr(_plaintext_capture, "_sync_directory", fail_sync)
    with pytest.raises(OSError, match="forced parent-directory sync failure"):
        _plaintext_capture.restore_capture_no_replace(candidate, live)

    # The live hard link may be visible, but the pre-existing recovery name
    # must not be unlinked until that publication is known durable.
    assert candidate.read_bytes() == b"must-survive\n"
    assert live.read_bytes() == b"must-survive\n"
    assert candidate.stat().st_ino == live.stat().st_ino


def test_discard_syncs_directory_after_candidate_unlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = tmp_path / ".env.mordred-reseal-test"
    candidate.write_bytes(b"already-enrolled\n")
    snapshots: list[bool] = []

    def observe_sync(_directory: Path) -> None:
        snapshots.append(candidate.exists())

    monkeypatch.setattr(_plaintext_capture, "_sync_directory", observe_sync)
    _plaintext_capture.discard_capture(candidate)

    assert snapshots == [False]


def test_no_replace_publication_sync_failure_retains_private_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live = tmp_path / "config.yaml"

    def fail_sync(_directory: Path) -> None:
        raise OSError("forced publication sync failure")

    monkeypatch.setattr(_plaintext_capture, "_sync_directory", fail_sync)
    with pytest.raises(OSError, match="forced publication sync failure"):
        _plaintext_capture.publish_plaintext_no_replace(live, b"complete: true\n")

    staging = list(tmp_path.glob(".config.yaml.mordred-materialize-*"))
    assert len(staging) == 1
    assert live.read_bytes() == b"complete: true\n"
    assert staging[0].read_bytes() == b"complete: true\n"
    assert live.stat().st_ino == staging[0].stat().st_ino


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO unsupported on this platform")
def test_regular_reader_rejects_fifo_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / "config.yaml"
    os.mkfifo(fifo, 0o600)

    with pytest.raises(OSError, match="regular file"):
        _plaintext_capture.read_regular_plaintext(fifo)
