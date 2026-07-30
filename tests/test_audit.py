"""Tests for the NDJSON audit writer (TODO §1.4 / PLAN §1.4)."""

from __future__ import annotations

import gzip
import json
import os
import re
import stat
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from mordred_hermes.privacy_check import audit as audit_mod
from mordred_hermes.privacy_check.audit import (
    DEFAULT_RETENTION_DAYS,
    MAX_ENTRY_BYTES,
    NDJSONWriter,
    _serialize,
)

_PARTIAL_APPEND_PROBE = r"""
import os
import sys
import time
from pathlib import Path

from mordred_hermes.privacy_check import audit as audit_mod
from mordred_hermes.privacy_check.audit import NDJSONWriter

log_path = Path(sys.argv[1])
ready_path = Path(sys.argv[2])
release_path = Path(sys.argv[3])
real_write = os.write
calls = 0

def partial_then_zero(fd, data):
    global calls
    calls += 1
    if calls == 1:
        written = real_write(fd, data[:7])
        ready_path.write_text("partial", encoding="utf-8")
        deadline = time.monotonic() + 10
        while not release_path.exists():
            if time.monotonic() >= deadline:
                raise RuntimeError("timed out waiting to release partial audit append")
            time.sleep(0.01)
        return written
    return 0

audit_mod.os.write = partial_then_zero
try:
    NDJSONWriter(path=log_path).append({"event": "failed-process", "decision": "allow"})
except OSError as exc:
    if "returned 0 bytes" not in str(exc):
        raise
else:
    raise AssertionError("partial append unexpectedly succeeded")
"""

_SECOND_APPEND_PROBE = r"""
import sys
from pathlib import Path

from mordred_hermes.privacy_check.audit import NDJSONWriter

log_path = Path(sys.argv[1])
started_path = Path(sys.argv[2])
started_path.write_text("started", encoding="utf-8")
NDJSONWriter(path=log_path).append({"event": "other-process", "decision": "allow"})
"""


def _read_lines(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


class TestAppend:
    def test_creates_file_with_0600_mode(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.log"
        writer = NDJSONWriter(path=log)
        writer.append({"event": "pre_install", "decision": "allow", "reason": None})
        assert log.exists()
        mode = stat.S_IMODE(log.stat().st_mode)
        assert mode == 0o600, f"expected 0600, got {oct(mode)}"

    def test_creates_parent_dir_with_0700_mode(self, tmp_path: Path) -> None:
        log = tmp_path / "mordred" / "audit.log"
        writer = NDJSONWriter(path=log)
        writer.append({"event": "x", "decision": "allow"})
        parent_mode = stat.S_IMODE(log.parent.stat().st_mode)
        # 0o700 is the request; the OS may apply umask leniency on
        # pre-existing parents — assert the new dir at least lacks
        # group/other permissions.
        assert parent_mode & 0o077 == 0, f"parent dir leaks perms: {oct(parent_mode)}"

    def test_appends_one_ndjson_line_per_call(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.log"
        writer = NDJSONWriter(path=log)
        writer.append({"event": "a", "decision": "allow"})
        writer.append({"event": "b", "decision": "block", "reason": "policy.strict.clearnet"})
        lines = _read_lines(log)
        assert [e["event"] for e in lines] == ["a", "b"]
        # Each line ends with exactly one newline
        text = log.read_text(encoding="utf-8")
        assert text.endswith("\n")
        assert "\n\n" not in text

    def test_retries_short_os_writes_until_entry_is_complete(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        real_write = os.write
        calls = 0

        def short_write(fd: int, data: bytes | memoryview) -> int:
            nonlocal calls
            calls += 1
            return real_write(fd, data[:7])

        monkeypatch.setattr(audit_mod.os, "write", short_write)
        log = tmp_path / "audit.log"
        NDJSONWriter(path=log).append({"event": "short-write", "decision": "allow"})

        assert calls > 1
        assert _read_lines(log)[0]["event"] == "short-write"

    def test_zero_byte_os_write_is_not_reported_as_success(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(audit_mod.os, "write", lambda _fd, _data: 0)

        with pytest.raises(OSError, match="returned 0 bytes"):
            NDJSONWriter(path=tmp_path / "audit.log").append({"event": "zero-write", "decision": "allow"})

    def test_partial_then_zero_write_rolls_back_the_incomplete_entry(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        log = tmp_path / "audit.log"
        writer = NDJSONWriter(path=log)
        writer.append({"event": "complete", "decision": "allow"})
        original = log.read_bytes()
        real_write = os.write
        calls = 0

        def partial_then_zero(fd: int, data: bytes | memoryview) -> int:
            nonlocal calls
            calls += 1
            if calls == 1:
                return real_write(fd, data[:7])
            return 0

        monkeypatch.setattr(audit_mod.os, "write", partial_then_zero)
        with pytest.raises(OSError, match="returned 0 bytes"):
            writer.append({"event": "incomplete", "decision": "allow"})

        assert calls == 2
        assert log.read_bytes() == original

    def test_adds_ts_when_missing(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.log"
        NDJSONWriter(path=log).append({"event": "x", "decision": "allow"})
        entry = _read_lines(log)[0]
        assert "ts" in entry
        # ISO-8601 UTC w/ millisecond precision
        assert isinstance(entry["ts"], str)
        assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$", entry["ts"])

    def test_caller_provided_ts_is_preserved(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.log"
        NDJSONWriter(path=log).append({"ts": "2026-01-01T00:00:00.000Z", "event": "x"})
        assert _read_lines(log)[0]["ts"] == "2026-01-01T00:00:00.000Z"

    def test_tightens_loose_perms_on_existing_file(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.log"
        log.write_text("", encoding="utf-8")
        os.chmod(log, 0o644)
        NDJSONWriter(path=log)  # __post_init__ chmods
        assert stat.S_IMODE(log.stat().st_mode) == 0o600

    def test_refuses_symlink_without_touching_its_target(self, tmp_path: Path) -> None:
        victim = tmp_path / "victim.log"
        victim.write_text("do-not-touch\n", encoding="utf-8")
        os.chmod(victim, 0o644)
        log = tmp_path / "audit.log"
        log.symlink_to(victim)

        with pytest.raises(OSError, match="regular file"):
            NDJSONWriter(path=log)

        assert victim.read_text(encoding="utf-8") == "do-not-touch\n"
        assert stat.S_IMODE(victim.stat().st_mode) == 0o644

    def test_refuses_fifo_without_blocking(self, tmp_path: Path) -> None:
        if not hasattr(os, "mkfifo"):
            pytest.skip("FIFO creation is unavailable")
        log = tmp_path / "audit.log"
        os.mkfifo(log)

        with pytest.raises(OSError, match="regular file"):
            NDJSONWriter(path=log)

    def test_refuses_symlinked_sidecar_without_touching_target(
        self,
        tmp_path: Path,
    ) -> None:
        victim = tmp_path / "victim.lock"
        victim.write_text("do-not-touch\n", encoding="utf-8")
        os.chmod(victim, 0o644)
        (tmp_path / ".audit.log.lock").symlink_to(victim)
        writer = NDJSONWriter(path=tmp_path / "audit.log")

        with pytest.raises(OSError, match="audit lock is unsafe"):
            writer.append({"event": "x"})

        assert victim.read_text(encoding="utf-8") == "do-not-touch\n"
        assert stat.S_IMODE(victim.stat().st_mode) == 0o644

    def test_refuses_corrupt_foreign_format_without_appending(
        self,
        tmp_path: Path,
    ) -> None:
        log = tmp_path / "audit.log"
        original = b'{"fmt":"MRAL","truncated":'
        log.write_bytes(original)
        writer = NDJSONWriter(log)

        with pytest.raises(OSError, match="unrecognized or corrupt"):
            writer.append({"event": "must-not-splice"})

        assert log.read_bytes() == original


class TestSerialization:
    def test_oversized_entry_raises(self) -> None:
        big = {"event": "x", "blob": "A" * MAX_ENTRY_BYTES}
        with pytest.raises(ValueError, match="exceeds"):
            _serialize(big)

    def test_serialize_keys_sorted(self) -> None:
        data = _serialize({"event": "x", "decision": "allow", "ts": "2026-01-01T00:00:00.000Z"})
        # sort_keys=True puts decision < event < ts
        assert data.startswith(b'{"decision":"allow","event":"x","ts":')


class TestRotation:
    def test_size_rotation_creates_gz_and_resets_active_file(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.log"
        # 1 KB cap so we trigger size rotation in a few writes
        writer = NDJSONWriter(path=log, rotate_bytes=1024)
        # Each entry is well under MAX_ENTRY_BYTES
        for i in range(20):
            writer.append({"event": "x", "decision": "allow", "i": i})
        # Active log exists (post-rotation continuation), and at least one .gz exists
        assert log.exists(), "active log should be re-created after rotation"
        rotated = list(tmp_path.glob("audit.log.*.gz"))
        assert rotated, f"expected rotated .gz files, found: {list(tmp_path.iterdir())}"
        # Rotated content is valid gzip + valid NDJSON
        with gzip.open(rotated[0], "rt", encoding="utf-8") as fh:
            for line in fh:
                json.loads(line)

    def test_rotated_files_are_0600(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.log"
        writer = NDJSONWriter(path=log, rotate_bytes=512)
        for i in range(20):
            writer.append({"event": "x", "i": i})
        for gz in tmp_path.glob("audit.log.*.gz"):
            assert stat.S_IMODE(gz.stat().st_mode) == 0o600, f"{gz} not 0600"

    def test_same_day_collision_uses_numeric_suffix(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.log"
        writer = NDJSONWriter(path=log, rotate_bytes=200)
        # Force several same-day rotations
        for i in range(40):
            writer.append({"event": "x", "i": i, "padding": "p" * 50})
        gzs = sorted(p.name for p in tmp_path.glob("audit.log.*.gz"))
        # At least one un-suffixed and one .N suffixed rotation
        assert len(gzs) >= 2
        # Names match audit.log.YYYY-MM-DD(.N)?.gz
        for name in gzs:
            assert re.match(r"^audit\.log\.\d{4}-\d{2}-\d{2}(\.\d+)?\.gz$", name), name


class TestRetention:
    def test_old_rotated_files_swept(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.log"
        # Plant an old rotated file with mtime past retention
        old = tmp_path / "audit.log.2025-01-01.gz"
        old.write_bytes(b"\x1f\x8b" + b"\0" * 10)  # plausible gzip header
        ancient = (datetime.now(UTC) - timedelta(days=DEFAULT_RETENTION_DAYS + 5)).timestamp()
        os.utime(old, (ancient, ancient))
        # Trigger rotation (which sweeps retention)
        writer = NDJSONWriter(path=log, rotate_bytes=64)
        for i in range(10):
            writer.append({"event": "x", "i": i})
        assert not old.exists(), "old rotated file should be swept"

    def test_recent_rotated_files_kept(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.log"
        recent = tmp_path / "audit.log.2026-04-01.gz"
        recent.write_bytes(b"\x1f\x8b" + b"\0" * 10)
        recent_ts = (datetime.now(UTC) - timedelta(days=2)).timestamp()
        os.utime(recent, (recent_ts, recent_ts))
        writer = NDJSONWriter(path=log, rotate_bytes=64)
        for i in range(10):
            writer.append({"event": "x", "i": i})
        assert recent.exists(), "recent rotated file should NOT be swept"

    def test_old_sidecar_lock_is_never_swept_as_rotated_history(
        self,
        tmp_path: Path,
    ) -> None:
        log = tmp_path / "audit.log"
        writer = NDJSONWriter(path=log, rotate_bytes=64)
        writer.append({"event": "first"})
        lock = tmp_path / ".audit.log.lock"
        ancient = (datetime.now(UTC) - timedelta(days=DEFAULT_RETENTION_DAYS + 5)).timestamp()
        os.utime(lock, (ancient, ancient))

        writer.append({"event": "rotate", "padding": "x" * 40})

        assert lock.exists()
        assert stat.S_IMODE(lock.stat().st_mode) == 0o600


class TestConcurrency:
    def test_threads_serialize_via_lock(self, tmp_path: Path) -> None:
        """All concurrent appends land — lines stay un-interleaved."""
        log = tmp_path / "audit.log"
        writer = NDJSONWriter(path=log)
        n_threads = 8
        per_thread = 25

        def worker(worker_id: int) -> None:
            for i in range(per_thread):
                writer.append({"event": "x", "worker": worker_id, "i": i})

        threads = [threading.Thread(target=worker, args=(w,)) for w in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        lines = _read_lines(log)
        assert len(lines) == n_threads * per_thread
        # Each line is independently valid JSON (would have failed _read_lines if interleaved)
        seen = {(int(e["worker"]), int(e["i"])) for e in lines}
        assert seen == {(w, i) for w in range(n_threads) for i in range(per_thread)}

    def test_failed_partial_append_cannot_truncate_another_process_entry(
        self,
        tmp_path: Path,
    ) -> None:
        """Rollback holds the process lock until its partial bytes are gone."""
        log = tmp_path / "audit.log"
        ready = tmp_path / "partial-ready"
        release = tmp_path / "release-partial"
        second_started = tmp_path / "second-started"
        processes: list[subprocess.Popen[str]] = []

        first = subprocess.Popen(
            [sys.executable, "-c", _PARTIAL_APPEND_PROBE, str(log), str(ready), str(release)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        processes.append(first)
        outputs: dict[int, tuple[str, str]] = {}
        try:
            deadline = time.monotonic() + 10
            while not ready.exists():
                if first.poll() is not None:
                    stdout, stderr = first.communicate()
                    pytest.fail(f"partial writer exited early: {stdout=} {stderr=}")
                if time.monotonic() >= deadline:
                    pytest.fail("partial writer did not reach its first short write")
                time.sleep(0.01)

            second = subprocess.Popen(
                [sys.executable, "-c", _SECOND_APPEND_PROBE, str(log), str(second_started)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            processes.append(second)
            deadline = time.monotonic() + 10
            while not second_started.exists():
                if second.poll() is not None:
                    stdout, stderr = second.communicate()
                    pytest.fail(f"second writer exited before append: {stdout=} {stderr=}")
                if time.monotonic() >= deadline:
                    pytest.fail("second writer did not start")
                time.sleep(0.01)

            # The second process is now attempting append but cannot finish
            # while the first still owns the sidecar lock.
            with pytest.raises(subprocess.TimeoutExpired):
                second.wait(timeout=0.5)
        finally:
            release.touch()
            for process in processes:
                try:
                    outputs[process.pid] = process.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    outputs[process.pid] = process.communicate()

        for process in processes:
            stdout, stderr = outputs[process.pid]
            assert process.returncode == 0, f"{stdout=} {stderr=}"
        assert [entry["event"] for entry in _read_lines(log)] == ["other-process"]
        assert stat.S_IMODE((tmp_path / ".audit.log.lock").stat().st_mode) == 0o600
