"""Tests for ``mordred_hermes.keyvault._storage`` — file-safety helpers.

Phase 4 PR4 step-B RED (2026-05-15) — implementation lands in step-B GREEN.

Codex pre-implementation review HIGH #4 demanded explicit file-safety
semantics for keyvault state:

- ``os.open(path, O_NOFOLLOW)`` to refuse symlink-following.
- File mode ``0600`` and directory mode ``0700`` enforced via ``fstat``
  after open (mode mismatch → ``KeyvaultPermissionError``).
- Atomic writes via ``<file>.tmp + fsync(tmp_fd) + os.replace(tmp, final)
  + fsync(parent_dir_fd)``.
- Exclusive ``fcntl.flock`` on ``<root>/.lock`` for the duration of any
  write transaction.
- ``meta.json`` corruption raises :exc:`KeyvaultCorruptError` whose
  ``str()`` does NOT include the corrupted contents (audit safety —
  partially-overwritten JSON could contain secret-shaped bytes).

These tests pin the contract. See SPEC.md §"PR4 API contract / File-
safety semantics" for the canonical wording.
"""

from __future__ import annotations

import fcntl
import json
import os
import stat
import threading
from pathlib import Path

import pytest

from mordred_hermes.keyvault import _storage

# ---------------------------- resolve_keyvault_dir ----------------------------


class TestResolveKeyvaultDir:
    def test_explicit_home_returns_keyvault_subdir(self, tmp_path: Path) -> None:
        assert _storage.resolve_keyvault_dir(tmp_path) == tmp_path / "mordred" / "keyvault"

    def test_none_home_uses_hermes_home(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # Monkeypatch the hermes_home resolver so the test does not depend on
        # the user's real ~/.hermes directory.
        monkeypatch.setattr("mordred_hermes.keyvault._storage._hermes_home", lambda: tmp_path)
        assert _storage.resolve_keyvault_dir(None) == tmp_path / "mordred" / "keyvault"

    def test_signature_matches_spec(self) -> None:
        import inspect
        import typing

        sig = inspect.signature(_storage.resolve_keyvault_dir)
        hints = typing.get_type_hints(_storage.resolve_keyvault_dir)
        assert list(sig.parameters) == ["home"]
        assert hints["home"] == (Path | None)
        assert hints["return"] is Path
        assert sig.parameters["home"].default is None


# ---------------------------- ensure_layout ----------------------------


class TestEnsureLayout:
    def test_creates_root_with_0700_mode(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        assert root.is_dir()
        assert stat.S_IMODE(root.stat().st_mode) == 0o700

    def test_creates_digests_subdir_with_0700(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        assert (root / "digests").is_dir()
        assert stat.S_IMODE((root / "digests").stat().st_mode) == 0o700

    def test_creates_ciphertexts_subdir_with_0700(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        assert (root / "ciphertexts").is_dir()
        assert stat.S_IMODE((root / "ciphertexts").stat().st_mode) == 0o700

    def test_creates_lock_file_with_0600(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        lock = root / ".lock"
        assert lock.is_file()
        assert stat.S_IMODE(lock.stat().st_mode) == 0o600

    def test_creates_initial_meta_json(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        meta = json.loads((root / "meta.json").read_text())
        assert meta == {"version": 1, "keys": {}}
        assert stat.S_IMODE((root / "meta.json").stat().st_mode) == 0o600

    def test_idempotent_on_existing_layout(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        # Stamp meta.json with a real key so we can verify it is not clobbered.
        (root / "meta.json").write_text('{"version": 1, "keys": {"k1": {}}}')
        _storage.ensure_layout(root)
        meta = json.loads((root / "meta.json").read_text())
        assert meta["keys"] == {"k1": {}}

    def test_existing_root_wrong_mode_raises_permission_error(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        root.mkdir(mode=0o755)  # too permissive
        with pytest.raises(_storage.KeyvaultPermissionError):
            _storage.ensure_layout(root)

    def test_existing_meta_wrong_mode_raises_permission_error(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        os.chmod(root / "meta.json", 0o644)  # too permissive
        with pytest.raises(_storage.KeyvaultPermissionError):
            _storage.ensure_layout(root)

    def test_lock_creation_race_is_tolerated(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Two processes racing the first ensure_layout: the loser's
        ``exists()`` pre-check sees no ``.lock`` yet, then its O_EXCL open
        hits ``FileExistsError`` because the winner created it in between.
        The loser must treat that as success (the winner's lock is just as
        good), not crash. Simulated by forcing the ``exists()`` pre-check
        to report False while the lock file is actually present."""
        root = tmp_path / "kv"
        _storage.ensure_layout(root)  # .lock now exists on disk
        real_exists = Path.exists

        def fake_exists(self: Path, **kwargs: bool) -> bool:
            if self.name == ".lock":
                return False  # the racing loser's stale pre-check view
            return real_exists(self, **kwargs)

        monkeypatch.setattr(Path, "exists", fake_exists)
        _storage.ensure_layout(root)  # must not raise FileExistsError


# ---------------------------- atomic_write ----------------------------


class TestAtomicWrite:
    def test_writes_data_to_final_path(self, tmp_path: Path) -> None:
        target = tmp_path / "file.bin"
        _storage.atomic_write(target, b"hello")
        assert target.read_bytes() == b"hello"

    def test_file_mode_is_0600_after_write(self, tmp_path: Path) -> None:
        target = tmp_path / "file.bin"
        _storage.atomic_write(target, b"x")
        assert stat.S_IMODE(target.stat().st_mode) == 0o600

    def test_overwrites_existing_atomically(self, tmp_path: Path) -> None:
        target = tmp_path / "file.bin"
        target.write_bytes(b"old")
        os.chmod(target, 0o600)
        _storage.atomic_write(target, b"new")
        assert target.read_bytes() == b"new"

    def test_tmp_file_removed_after_success(self, tmp_path: Path) -> None:
        target = tmp_path / "file.bin"
        _storage.atomic_write(target, b"data")
        # No leftover *.tmp files in the directory.
        assert list(tmp_path.glob("*.tmp")) == []

    def test_symlink_target_refused(self, tmp_path: Path) -> None:
        real = tmp_path / "real.bin"
        real.write_bytes(b"original")
        os.chmod(real, 0o600)
        link = tmp_path / "link.bin"
        link.symlink_to(real)
        with pytest.raises(_storage.KeyvaultPermissionError):
            _storage.atomic_write(link, b"attacker-controlled")
        # The symlink target must be untouched (O_NOFOLLOW prevented the write).
        assert real.read_bytes() == b"original"

    def test_existing_target_with_wrong_mode_refused(self, tmp_path: Path) -> None:
        target = tmp_path / "file.bin"
        target.write_bytes(b"x")
        os.chmod(target, 0o644)
        with pytest.raises(_storage.KeyvaultPermissionError):
            _storage.atomic_write(target, b"new")

    def test_tmp_file_cleaned_up_on_write_failure(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # Simulate a mid-write failure: force os.write to raise on the first call.
        target = tmp_path / "file.bin"
        original_write = os.write
        call_count = {"n": 0}

        def flaky_write(fd: int, data: bytes) -> int:
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise OSError("simulated write failure")
            return original_write(fd, data)

        monkeypatch.setattr("os.write", flaky_write)
        with pytest.raises(OSError):
            _storage.atomic_write(target, b"data")
        # No leftover tmp file from the failed write.
        assert list(tmp_path.glob("*.tmp")) == []
        # The final file does not exist either (we never committed via rename).
        assert not target.exists()


# ---------------------------- safe_read ----------------------------


class TestSafeRead:
    def test_reads_normal_file(self, tmp_path: Path) -> None:
        target = tmp_path / "file.bin"
        target.write_bytes(b"content")
        os.chmod(target, 0o600)
        assert _storage.safe_read(target) == b"content"

    def test_symlink_refused(self, tmp_path: Path) -> None:
        real = tmp_path / "real.bin"
        real.write_bytes(b"secret")
        os.chmod(real, 0o600)
        link = tmp_path / "link.bin"
        link.symlink_to(real)
        with pytest.raises(_storage.KeyvaultPermissionError):
            _storage.safe_read(link)

    def test_wrong_mode_refused(self, tmp_path: Path) -> None:
        target = tmp_path / "file.bin"
        target.write_bytes(b"x")
        os.chmod(target, 0o644)
        with pytest.raises(_storage.KeyvaultPermissionError):
            _storage.safe_read(target)

    def test_missing_file_raises_file_not_found_error(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            _storage.safe_read(tmp_path / "missing.bin")


# ---------------------------- keyvault_lock ----------------------------


class TestKeyvaultLock:
    def test_acquires_exclusive_lock(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        with _storage.keyvault_lock(root):
            # While we hold the lock, a non-blocking acquire from a separate
            # file descriptor must fail.
            fd = os.open(root / ".lock", os.O_RDWR)
            try:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(fd)

    def test_releases_on_context_exit(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        with _storage.keyvault_lock(root):
            pass
        # After release, a non-blocking acquire succeeds.
        fd = os.open(root / ".lock", os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def test_releases_on_exception(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        with pytest.raises(RuntimeError), _storage.keyvault_lock(root):
            raise RuntimeError("simulated")
        # Lock must still be released after the exception propagated.
        fd = os.open(root / ".lock", os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def test_serializes_concurrent_writers(self, tmp_path: Path) -> None:
        # Two threads contend on the lock; the second must wait for the first.
        import time

        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        order: list[str] = []

        def writer(name: str, hold_ms: int) -> None:
            with _storage.keyvault_lock(root):
                order.append(f"{name}-enter")
                time.sleep(hold_ms / 1000.0)
                order.append(f"{name}-exit")

        t1 = threading.Thread(target=writer, args=("A", 30))
        t2 = threading.Thread(target=writer, args=("B", 0))
        t1.start()
        # Give A a head start so the order is deterministic.
        time.sleep(0.005)
        t2.start()
        t1.join()
        t2.join()
        assert order == ["A-enter", "A-exit", "B-enter", "B-exit"]

    def test_lock_with_wrong_mode_refused(self, tmp_path: Path) -> None:
        """The lock file is part of the keyvault tree, so acquiring it must
        enforce the same 0o600 posture ``safe_read`` applies — a loosened
        lock file (e.g. chmod 0644 by a backup tool) is refused instead of
        silently flock'd."""
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        os.chmod(root / ".lock", 0o644)  # too permissive
        with pytest.raises(_storage.KeyvaultPermissionError), _storage.keyvault_lock(root):
            pass  # pragma: no cover — the lock must refuse before entry


# ---------------------------- load_meta / save_meta ----------------------------


class TestLoadMeta:
    def test_returns_empty_struct_when_missing(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        # ensure_layout writes the initial meta, so this hits the "exists" path.
        # Verify behavior when the file is then removed:
        (root / "meta.json").unlink()
        assert _storage.load_meta(root) == {"version": 1, "keys": {}}

    def test_parses_valid_meta(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        (root / "meta.json").write_text('{"version": 1, "keys": {"k1": {"foo": "bar"}}}')
        os.chmod(root / "meta.json", 0o600)
        meta = _storage.load_meta(root)
        assert meta == {"version": 1, "keys": {"k1": {"foo": "bar"}}}

    def test_invalid_json_raises_corrupt(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        (root / "meta.json").write_text("not json{{")
        with pytest.raises(_storage.KeyvaultCorruptError):
            _storage.load_meta(root)

    def test_missing_version_field_raises_corrupt(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        (root / "meta.json").write_text('{"keys": {}}')
        with pytest.raises(_storage.KeyvaultCorruptError):
            _storage.load_meta(root)

    def test_version_mismatch_raises_corrupt(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        (root / "meta.json").write_text('{"version": 2, "keys": {}}')
        with pytest.raises(_storage.KeyvaultCorruptError):
            _storage.load_meta(root)

    def test_corrupt_error_does_not_include_file_contents(self, tmp_path: Path) -> None:
        # Audit-safety: KeyvaultCorruptError's str() must not include the
        # corrupted JSON bytes, because a partially-overwritten file could
        # contain secret-shaped material that we do not want leaking into
        # exception traces or log scraping.
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        secret_marker = "SECRET_DO_NOT_LEAK_INTO_TRACEBACK"
        (root / "meta.json").write_text(f'{{"corrupt": "{secret_marker}"}}')
        try:
            _storage.load_meta(root)
        except _storage.KeyvaultCorruptError as exc:
            assert secret_marker not in str(exc)
            assert secret_marker not in repr(exc)
        else:
            pytest.fail("expected KeyvaultCorruptError")


class TestSaveMeta:
    def test_writes_canonical_json(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        _storage.save_meta(root, {"version": 1, "keys": {"k1": {"x": 1}}})
        on_disk = json.loads((root / "meta.json").read_text())
        assert on_disk == {"version": 1, "keys": {"k1": {"x": 1}}}

    def test_atomic_via_tmp_rename(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        _storage.save_meta(root, {"version": 1, "keys": {}})
        # No leftover tmp files.
        assert list(root.glob("*.tmp")) == []

    def test_round_trips_through_load(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        meta = {"version": 1, "keys": {"a": {"nested": [1, 2, 3]}, "b": {}}}
        _storage.save_meta(root, meta)
        assert _storage.load_meta(root) == meta

    def test_preserves_0600_mode(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        _storage.save_meta(root, {"version": 1, "keys": {"k": {}}})
        assert stat.S_IMODE((root / "meta.json").stat().st_mode) == 0o600


# ---------------------- codex pre-merge review-fix tests ----------------------


class TestEnsureLayoutRefusesSymlinks:
    """Codex P2-2: ``_check_dir_mode`` used ``path.stat()`` which follows
    symlinks. A symlinked root/digests/ciphertexts directory passed the
    mode check whenever the *target* had mode 0o700, redirecting later
    keyvault reads/writes outside the keyvault tree. The fix uses
    ``lstat`` (or equivalent ``O_NOFOLLOW`` open) so the symlink itself
    is rejected."""

    def test_symlinked_root_refused(self, tmp_path: Path) -> None:
        real = tmp_path / "real"
        real.mkdir(mode=0o700)
        link = tmp_path / "link"
        link.symlink_to(real)
        with pytest.raises(_storage.KeyvaultPermissionError):
            _storage.ensure_layout(link)

    def test_symlinked_digests_subdir_refused(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        root.mkdir(mode=0o700)
        target = tmp_path / "elsewhere"
        target.mkdir(mode=0o700)
        (root / "digests").symlink_to(target)
        with pytest.raises(_storage.KeyvaultPermissionError):
            _storage.ensure_layout(root)

    def test_symlinked_ciphertexts_subdir_refused(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        root.mkdir(mode=0o700)
        target = tmp_path / "elsewhere"
        target.mkdir(mode=0o700)
        (root / "ciphertexts").symlink_to(target)
        with pytest.raises(_storage.KeyvaultPermissionError):
            _storage.ensure_layout(root)


class TestAtomicWriteShortWrites:
    """Codex P2-3: ``os.write`` is not guaranteed to flush the full buffer;
    short writes truncated the file as if the transaction succeeded."""

    def test_partial_writes_are_resumed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        target = tmp_path / "file.bin"
        payload = bytes(range(256)) * 64  # 16 KiB
        original_write = os.write
        offsets: list[int] = []

        def chunked_write(fd: int, data: bytes) -> int:
            # Return at most 64 bytes per call to force the resume loop.
            offsets.append(len(data))
            return original_write(fd, data[:64])

        monkeypatch.setattr("os.write", chunked_write)
        _storage.atomic_write(target, payload)
        assert target.read_bytes() == payload
        # The implementation looped at least len(payload)/64 times.
        assert len(offsets) >= len(payload) // 64


class TestLoadMetaKeysFieldValidation:
    """Codex P2-4: ``load_meta`` accepted ``{"version": 1}`` (no keys) or
    ``{"version": 1, "keys": [...]}`` (wrong type). Both shapes break the
    read-modify-write pattern downstream. Fix: reject in load_meta."""

    def test_missing_keys_field_raises_corrupt(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        (root / "meta.json").write_text('{"version": 1}')
        with pytest.raises(_storage.KeyvaultCorruptError):
            _storage.load_meta(root)

    def test_keys_field_as_list_raises_corrupt(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        (root / "meta.json").write_text('{"version": 1, "keys": []}')
        with pytest.raises(_storage.KeyvaultCorruptError):
            _storage.load_meta(root)

    def test_keys_field_as_string_raises_corrupt(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        (root / "meta.json").write_text('{"version": 1, "keys": "oops"}')
        with pytest.raises(_storage.KeyvaultCorruptError):
            _storage.load_meta(root)

    def test_keys_field_as_null_raises_corrupt(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        _storage.ensure_layout(root)
        (root / "meta.json").write_text('{"version": 1, "keys": null}')
        with pytest.raises(_storage.KeyvaultCorruptError):
            _storage.load_meta(root)


# ---------------- second codex pass — P2-C non-regular file refusal ----------------


class TestNonRegularFileRefusal:
    """Codex second-pass P2-C: ``_check_file_mode`` only checked permission
    bits, so a FIFO / device / directory at mode 0o600 would have passed.
    ``ensure_layout`` could then ``bless`` a non-file as meta.json or
    .lock, and ``safe_read`` / ``keyvault_lock`` would block or operate
    on the wrong kind of inode."""

    def test_fifo_at_meta_json_path_refused_by_ensure_layout(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        root.mkdir(mode=0o700)
        (root / "digests").mkdir(mode=0o700)
        (root / "ciphertexts").mkdir(mode=0o700)
        # Create the .lock as a regular file so ensure_layout reaches meta.json.
        lock_fd = os.open(root / ".lock", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(lock_fd)
        # Replace meta.json with a FIFO at the expected mode.
        os.mkfifo(root / "meta.json", mode=0o600)
        with pytest.raises(_storage.KeyvaultPermissionError):
            _storage.ensure_layout(root)

    def test_fifo_at_lock_path_refused_by_ensure_layout(self, tmp_path: Path) -> None:
        root = tmp_path / "kv"
        root.mkdir(mode=0o700)
        (root / "digests").mkdir(mode=0o700)
        (root / "ciphertexts").mkdir(mode=0o700)
        os.mkfifo(root / ".lock", mode=0o600)
        # Touch a regular meta.json so the lock is the failing path.
        meta_fd = os.open(root / "meta.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(meta_fd)
        with pytest.raises(_storage.KeyvaultPermissionError):
            _storage.ensure_layout(root)

    def test_safe_read_refuses_fifo(self, tmp_path: Path) -> None:
        fifo = tmp_path / "fifo"
        os.mkfifo(fifo, mode=0o600)
        with pytest.raises(_storage.KeyvaultPermissionError):
            _storage.safe_read(fifo)


# ---------------------------- exception types ----------------------------


class TestExceptionTypes:
    def test_keyvault_permission_error_is_oserror(self) -> None:
        # Subclass OSError so callers using `except OSError` for FS error
        # handling catch it naturally.
        assert issubclass(_storage.KeyvaultPermissionError, OSError)

    def test_keyvault_corrupt_error_is_valueerror(self) -> None:
        # Subclass ValueError so callers using `except ValueError` for input
        # validation catch it (mirrors VerificationDigestMismatch from digest.py).
        assert issubclass(_storage.KeyvaultCorruptError, ValueError)

    def test_both_exceptions_are_publicly_accessible(self) -> None:
        from mordred_hermes.keyvault._storage import (
            KeyvaultCorruptError,
            KeyvaultPermissionError,
        )

        assert KeyvaultPermissionError is _storage.KeyvaultPermissionError
        assert KeyvaultCorruptError is _storage.KeyvaultCorruptError
