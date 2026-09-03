"""Tests for ``hermes-mordred keyvault reset`` — destroy all key material.

``reset`` deletes every Secure-Enclave wrapping key (the live key(s) recorded
in ``meta.json`` plus the well-known default + audit-log ids) and removes the
on-disk keyvault directory. It is irreversible, so the interactive path
requires the operator to type a confirmation phrase; ``--yes`` skips it for
scripted use.
"""

from __future__ import annotations

import argparse
import hashlib
import threading
from collections.abc import Sequence
from pathlib import Path

import pytest

from mordred_hermes.keyvault import _native_key_id, _storage
from mordred_hermes.keyvault._exceptions import WrapError
from mordred_hermes.keyvault.api import _DEFAULT_KEY_ID
from mordred_hermes.keyvault.log_encryption import AUDIT_LOG_KEY_ID, EncryptedWriter
from mordred_hermes.wizard import _keyvault_reset, keyvault_cli
from tests._keyvault_fakes import FakeBackend


def _key_id_hash(key_id: str) -> str:
    """On-disk key-id hash — ``SHA-256(key_id)[:16].hex()`` (api._hash_id)."""
    return hashlib.sha256(key_id.encode("utf-8")).digest()[:16].hex()


def _build_keyvault(home: Path, key_ids: Sequence[str]) -> Path:
    """Materialize a keyvault under ``home`` holding ``key_ids``. Returns the root."""
    root = _storage.resolve_keyvault_dir(home)
    _storage.ensure_layout(root)
    meta = _storage.load_meta(root)
    for key_id in key_ids:
        h = _key_id_hash(key_id)
        meta["keys"][h] = {
            "key_id": key_id,
            "created_at": "2026-05-16T00:00:00Z",
            _native_key_id.NATIVE_KEY_ID_FIELD: _native_key_id.scoped_native_key_id(root, key_id),
        }
        _storage.atomic_write(root / "digests" / f"{h}.commit", b"\x11" * 32)
    _storage.save_meta(root, meta)
    return root


def _seed_enclave(backend: FakeBackend, key_ids: Sequence[str]) -> None:
    """Pre-create the Secure-Enclave keys so deletes are observable, not no-ops."""
    for key_id in key_ids:
        backend.generate_enclave_key(key_id)


class _ScriptedPrompt:
    """Minimal :class:`PromptIO` stand-in returning a queued ``ask_text`` answer."""

    def __init__(self, text_answer: str) -> None:
        self._text = text_answer
        self.asked: list[str] = []

    def ask_choice(self, label: str, choices: Sequence[str], default: str) -> str:
        return default

    def ask_text(self, label: str, default: str = "") -> str:
        self.asked.append(label)
        return self._text

    def ask_bool(self, label: str, default: bool) -> bool:
        return default

    def ask_multi(self, label: str, choices: Sequence[str], default: Sequence[str] = ()) -> tuple[str, ...]:
        return tuple(default)

    def ask_password(self, label: str, default: str = "") -> str:
        return default


def _deleted(backend: FakeBackend) -> set[str]:
    """key_ids the backend was asked to delete."""
    return {key_id for op, key_id in backend.calls if op == "delete"}


def _physical(root: Path, key_id: str) -> str:
    return _native_key_id.scoped_native_key_id(root, key_id)


def _write_current_reset_journal(
    root: Path,
    *,
    retained_legacy: list[str] | None = None,
) -> None:
    """Publish the same durable retry target set as a confirmed reset."""

    key_ids, collected_retained, metadata_incomplete = _keyvault_reset._collect_reset_key_ids(root)
    retained = collected_retained if retained_legacy is None else retained_legacy
    _journal, encoded = _keyvault_reset._encode_reset_journal(
        root,
        key_ids,
        retained,
        metadata_incomplete,
    )
    with _storage.keyvault_lifecycle_lock(root):
        _storage.write_reset_journal(root, encoded)


class TestResetYes:
    def test_removes_ondisk_dir_and_deletes_enclave_keys(self, tmp_path: Path) -> None:
        root = _build_keyvault(tmp_path, ["default"])
        backend = FakeBackend()
        _seed_enclave(backend, [_DEFAULT_KEY_ID, AUDIT_LOG_KEY_ID])

        rc = _keyvault_reset.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True)

        assert rc == 0
        assert not root.exists()
        # Both the live key and the audit-log wrapping key are destroyed.
        assert _physical(root, _DEFAULT_KEY_ID) in _deleted(backend)
        assert _physical(root, AUDIT_LOG_KEY_ID) in _deleted(backend)

    def test_deletes_every_meta_key(self, tmp_path: Path) -> None:
        root = _build_keyvault(tmp_path, ["default", "payments"])
        backend = FakeBackend()

        rc = _keyvault_reset.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True)

        assert rc == 0
        assert {_physical(root, "default"), _physical(root, "payments")} <= _deleted(backend)

    def test_corrupt_meta_still_resets_known_keys(self, tmp_path: Path) -> None:
        root = _storage.resolve_keyvault_dir(tmp_path)
        _storage.ensure_layout(root)
        (root / "meta.json").write_text("{ this is not valid json", encoding="utf-8")
        backend = FakeBackend()

        rc = _keyvault_reset.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True)

        assert rc == 0
        assert not root.exists()
        # A corrupt meta must not strand the default / audit-log SE keys.
        assert {_physical(root, _DEFAULT_KEY_ID), _physical(root, AUDIT_LOG_KEY_ID)} <= _deleted(backend)

    def test_non_utf8_meta_still_resets_known_keys(self, tmp_path: Path) -> None:
        root = _storage.resolve_keyvault_dir(tmp_path)
        _storage.ensure_layout(root)
        (root / "meta.json").write_bytes(b"\xffnot-utf8")
        backend = FakeBackend()

        rc = _keyvault_reset.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True)

        assert rc == 0
        assert not root.exists()
        assert {_physical(root, _DEFAULT_KEY_ID), _physical(root, AUDIT_LOG_KEY_ID)} <= _deleted(backend)

    def test_wrong_metadata_hash_still_resets_scoped_row_and_warns(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        root = _build_keyvault(tmp_path, ["payments"])
        meta = _storage.load_meta(root)
        [(_key_hash, row)] = meta["keys"].items()
        meta["keys"] = {"../../../victim": row}
        _storage.save_meta(root, meta)
        backend = FakeBackend()

        rc = _keyvault_reset.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True)

        assert rc == 0
        assert _physical(root, "payments") in _deleted(backend)
        assert not root.exists()
        assert "metadata was incomplete" in capsys.readouterr().out.lower()

    def test_malformed_pending_and_audit_records_use_only_derived_targets(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        root = _build_keyvault(tmp_path, ["default"])
        meta = _storage.load_meta(root)
        meta[_native_key_id.PENDING_NATIVE_KEY_FIELD] = {
            "key_id": "payments",
            _native_key_id.NATIVE_KEY_ID_FIELD: "../../foreign-main",
        }
        meta[_native_key_id.AUDIT_KEY_FIELD] = {
            "key_id": AUDIT_LOG_KEY_ID,
            _native_key_id.NATIVE_KEY_ID_FIELD: "../../foreign-audit",
        }
        meta[_native_key_id.PENDING_AUDIT_KEY_FIELD] = ["malformed"]
        _storage.save_meta(root, meta)
        backend = FakeBackend()

        rc = _keyvault_reset.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True)

        assert rc == 0
        assert not root.exists()
        deleted = _deleted(backend)
        assert {
            _physical(root, _DEFAULT_KEY_ID),
            _physical(root, "payments"),
            _physical(root, AUDIT_LOG_KEY_ID),
        } <= deleted
        assert "../../foreign-main" not in deleted
        assert "../../foreign-audit" not in deleted
        assert "metadata was incomplete" in capsys.readouterr().out.lower()

    def test_retained_completion_escapes_terminal_controls(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        key_id = "legacy\n\x1b[31mowned"
        root = _build_keyvault(tmp_path, [key_id])
        meta = _storage.load_meta(root)
        del meta["keys"][_key_id_hash(key_id)][_native_key_id.NATIVE_KEY_ID_FIELD]
        _storage.save_meta(root, meta)

        assert _keyvault_reset.reset_keyvault(home=tmp_path, backend=FakeBackend(), assume_yes=True) == 0

        out = capsys.readouterr().out
        assert "\x1b" not in out
        assert key_id not in out
        assert "legacy\\n\\x1b[31mowned" in out


class _DeleteFailsBackend(FakeBackend):
    """FakeBackend whose SE-key delete always raises, to exercise best-effort."""

    def delete_enclave_key(self, key_id: str) -> None:
        self.calls.append(("delete", key_id))
        raise WrapError(f"simulated Enclave delete failure for {key_id!r}")


class _UnexpectedDeleteFailsBackend(FakeBackend):
    """Backend bug/transport failure outside the documented WrapError family."""

    def delete_enclave_key(self, key_id: str) -> None:
        self.calls.append(("delete", key_id))
        raise RuntimeError(f"unexpected backend failure for {key_id!r}")


class _FailsOneDeleteOnceBackend(FakeBackend):
    """Delete one custom id once, allowing an idempotent reset retry."""

    def __init__(self, failing_key_id: str) -> None:
        super().__init__()
        self._failing_key_id = failing_key_id
        self._failed = False

    def delete_enclave_key(self, key_id: str) -> None:
        if key_id == self._failing_key_id and not self._failed:
            self._failed = True
            self.calls.append(("delete", key_id))
            raise RuntimeError(f"one-shot backend failure for {key_id!r}")
        super().delete_enclave_key(key_id)


class TestResetDegradedPaths:
    def test_native_delete_failure_is_incomplete_and_retains_metadata_for_retry(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        root = _build_keyvault(tmp_path, ["default"])
        backend = _DeleteFailsBackend()

        rc = _keyvault_reset.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True)

        # A partial native cleanup must not erase the only durable list of
        # custom ids, nor claim that every kind of key material was destroyed.
        assert rc == 1
        assert root.is_dir()
        err = capsys.readouterr().err
        assert "could not delete native wrapping key" in err
        assert "incomplete" in err.lower()

    def test_unexpected_native_delete_exception_is_clean_and_retains_disk(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        root = _build_keyvault(tmp_path, ["default"])
        backend = _UnexpectedDeleteFailsBackend()

        rc = _keyvault_reset.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True)

        assert rc == 1
        assert root.is_dir()
        assert "unexpected backend failure" in capsys.readouterr().err

    def test_backend_resolution_failure_is_clean_and_retains_disk(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        root = _build_keyvault(tmp_path, ["default"])

        def fail_resolution(backend: object) -> object:
            del backend
            raise RuntimeError("backend unavailable")

        monkeypatch.setattr(_keyvault_reset, "resolve_backend", fail_resolution)
        rc = _keyvault_reset.reset_keyvault(home=tmp_path, backend=None, assume_yes=True)

        assert rc == 1
        assert root.is_dir()
        assert "could not initialize" in capsys.readouterr().err

    def test_journal_write_failure_happens_before_every_native_delete(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        root = _build_keyvault(tmp_path, ["default"])
        backend = FakeBackend()

        def _fail_journal(root_arg: Path, data: bytes) -> None:
            del root_arg, data
            raise OSError("simulated journal durability failure")

        monkeypatch.setattr(_storage, "write_reset_journal", _fail_journal)
        rc = _keyvault_reset.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True)

        assert rc == 1
        assert root.is_dir()
        assert _deleted(backend) == set()
        assert not _storage.reset_journal_path(root).exists()
        assert "no native keys were deleted" in capsys.readouterr().err

    def test_partial_native_delete_can_be_retried_from_retained_metadata(self, tmp_path: Path) -> None:
        root = _build_keyvault(tmp_path, ["default", "payments"])
        backend = _FailsOneDeleteOnceBackend(_physical(root, "payments"))

        first_rc = _keyvault_reset.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True)

        assert first_rc == 1
        assert root.is_dir()
        assert _storage.load_meta(root)["keys"]

        second_rc = _keyvault_reset.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True)

        assert second_rc == 0
        assert not root.exists()

    def test_rmtree_failure_reports_cleanly_without_traceback(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        root = _build_keyvault(tmp_path, ["default"])
        backend = FakeBackend()
        # A legacy global audit key is intentionally retained by scoped
        # profile reset. The journal—not key absence—must invalidate its
        # cached writer if directory removal fails.
        backend.generate_enclave_key(AUDIT_LOG_KEY_ID)
        log_path = tmp_path / "audit.log"
        writer = EncryptedWriter(
            log_path,
            backend=backend,
            keyvault_root=root,
        )
        writer.append({"event": "before-reset"})
        size_before = log_path.stat().st_size
        delete_saw_journal: list[bool] = []
        real_delete = backend.delete_enclave_key

        def _delete_after_journal(key_id: str) -> None:
            delete_saw_journal.append(_storage.reset_journal_path(root).is_file())
            real_delete(key_id)

        def _boom(*args: object, **kwargs: object) -> None:
            # Model rmtree removing in-root safety state before a later child
            # removal fails. The parent journal must survive this ordering.
            (root / "meta.json").unlink()
            raise OSError("simulated rmtree failure")

        monkeypatch.setattr(backend, "delete_enclave_key", _delete_after_journal)
        monkeypatch.setattr(_keyvault_reset.shutil, "rmtree", _boom)
        rc = _keyvault_reset.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True)

        # The SE keys were already deleted; a directory-removal failure must
        # report a clean error and return non-zero, never a traceback. The
        # durable reset tombstone is visible before every deletion and prevents
        # an old cached DEK from publishing undecryptable ciphertext afterward.
        assert rc == 1
        assert _physical(root, _DEFAULT_KEY_ID) in _deleted(backend)
        assert root.exists()  # rmtree was stubbed out
        assert delete_saw_journal and all(delete_saw_journal)
        assert _storage.reset_journal_path(root).is_file()
        backend.get_enclave_public_key(AUDIT_LOG_KEY_ID)
        with pytest.raises(_storage.KeyvaultResetInProgressError, match="reset"):
            writer.append({"event": "after-failed-reset"})
        assert log_path.stat().st_size == size_before
        assert "could not be removed" in capsys.readouterr().err.lower()

    def test_reset_resumes_from_parent_journal_after_root_was_removed(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        root = _build_keyvault(tmp_path, ["default", "payments"])
        backend = FakeBackend()
        real_rmtree = _keyvault_reset.shutil.rmtree

        def _remove_then_report_failure(path: Path) -> None:
            real_rmtree(path)
            raise OSError("simulated crash after directory removal")

        monkeypatch.setattr(_keyvault_reset.shutil, "rmtree", _remove_then_report_failure)
        assert _keyvault_reset.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True) == 1
        assert not root.exists()
        assert _storage.reset_journal_path(root).is_file()

        # Metadata is gone, so the exact custom target can only come from the
        # stable journal. Native deletion is idempotently retried, then the
        # journal is unlinked and its parent directory is flushed.
        backend.calls.clear()
        monkeypatch.setattr(_keyvault_reset.shutil, "rmtree", real_rmtree)
        assert _keyvault_reset.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True) == 0
        assert ("delete", _physical(root, "payments")) in backend.calls
        assert not _storage.reset_journal_path(root).exists()

    def test_root_removal_flush_failure_retains_journal_for_retry(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        root = _build_keyvault(tmp_path, ["default"])
        backend = FakeBackend()
        real_flush = _storage.fsync_keyvault_parent
        failed = False

        def fail_once(root_arg: Path) -> None:
            nonlocal failed
            if not failed and not root_arg.exists():
                failed = True
                raise OSError("simulated root-removal flush failure")
            real_flush(root_arg)

        monkeypatch.setattr(_storage, "fsync_keyvault_parent", fail_once)
        assert _keyvault_reset.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True) == 1
        assert not root.exists()
        assert _storage.reset_journal_path(root).is_file()

        assert _keyvault_reset.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True) == 0
        assert not _storage.reset_journal_path(root).exists()

    def test_pending_parent_journal_blocks_absent_root_recreation(self, tmp_path: Path) -> None:
        root = _build_keyvault(tmp_path, ["default"])
        with _storage.keyvault_lifecycle_lock(root):
            _storage.write_reset_journal(root, b"pending reset")
        _keyvault_reset.shutil.rmtree(root)

        with pytest.raises(_storage.KeyvaultResetInProgressError, match="reset"):
            _storage.ensure_layout(root)
        assert not root.exists()

    def test_non_directory_parent_preflight_reports_cleanly(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        (tmp_path / "mordred").write_text("not a directory", encoding="utf-8")

        assert _keyvault_reset.reset_keyvault(home=tmp_path, backend=FakeBackend(), assume_yes=True) == 1
        assert "cannot inspect keyvault root" in capsys.readouterr().err.lower()

    def test_symlinked_root_is_refused_before_any_native_delete(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        external_home = tmp_path / "external"
        external = _build_keyvault(external_home, ["external-key"])
        root = _storage.resolve_keyvault_dir(tmp_path)
        root.parent.mkdir(mode=0o700, parents=True)
        root.symlink_to(external, target_is_directory=True)
        backend = FakeBackend()

        rc = _keyvault_reset.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True)

        assert rc == 1
        assert root.is_symlink()
        assert external.is_dir()
        assert _deleted(backend) == set()
        assert "unsafe keyvault root" in capsys.readouterr().err.lower()

    def test_symlinked_lifecycle_lock_is_refused_before_native_delete(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        root = _build_keyvault(tmp_path, ["default"])
        lifecycle = root.parent / ".keyvault.lifecycle.lock"
        victim = tmp_path / "victim"
        victim.write_bytes(b"unchanged")
        lifecycle.unlink()
        lifecycle.symlink_to(victim)
        backend = FakeBackend()

        rc = _keyvault_reset.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True)

        assert rc == 1
        assert root.is_dir()
        assert victim.read_bytes() == b"unchanged"
        assert _deleted(backend) == set()
        assert "cannot lock keyvault lifecycle" in capsys.readouterr().err.lower()

    def test_reset_waits_for_active_keyvault_transaction(self, tmp_path: Path) -> None:
        root = _build_keyvault(tmp_path, ["default"])
        backend = FakeBackend()
        writer_entered = threading.Event()
        release_writer = threading.Event()
        reset_finished = threading.Event()
        result: list[int] = []

        def writer() -> None:
            with _storage.keyvault_lock(root):
                writer_entered.set()
                assert release_writer.wait(timeout=5)

        def resetter() -> None:
            result.append(_keyvault_reset.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True))
            reset_finished.set()

        writer_thread = threading.Thread(target=writer)
        reset_thread = threading.Thread(target=resetter)
        writer_thread.start()
        assert writer_entered.wait(timeout=5)
        reset_thread.start()
        try:
            assert not reset_finished.wait(timeout=0.1)
        finally:
            release_writer.set()
        writer_thread.join(timeout=5)
        reset_thread.join(timeout=5)

        assert not writer_thread.is_alive()
        assert not reset_thread.is_alive()
        assert result == [0]
        assert not root.exists()

    def test_reset_excludes_concurrent_layout_recreation_until_removal_finishes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _build_keyvault(tmp_path, ["default"])
        backend = FakeBackend()
        removal_entered = threading.Event()
        release_removal = threading.Event()
        reset_finished = threading.Event()
        creator_finished = threading.Event()
        reset_result: list[int] = []
        creator_errors: list[BaseException] = []
        real_rmtree = _keyvault_reset.shutil.rmtree

        def paused_rmtree(path: Path) -> None:
            removal_entered.set()
            assert release_removal.wait(timeout=5)
            real_rmtree(path)

        def resetter() -> None:
            reset_result.append(_keyvault_reset.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True))
            reset_finished.set()

        def creator() -> None:
            try:
                _storage.ensure_layout(root)
            except BaseException as exc:
                creator_errors.append(exc)
            finally:
                creator_finished.set()

        monkeypatch.setattr(_keyvault_reset.shutil, "rmtree", paused_rmtree)
        reset_thread = threading.Thread(target=resetter)
        creator_thread = threading.Thread(target=creator)
        reset_thread.start()
        assert removal_entered.wait(timeout=5)
        creator_thread.start()
        try:
            assert not creator_finished.wait(timeout=0.1)
            assert not reset_finished.is_set()
        finally:
            release_removal.set()

        reset_thread.join(timeout=5)
        creator_thread.join(timeout=5)
        assert not reset_thread.is_alive()
        assert not creator_thread.is_alive()
        assert reset_result == [0]
        assert creator_errors == []
        # The creator runs strictly after reset and therefore produces a
        # complete new layout, never a tree interleaved with rmtree.
        assert _storage.load_meta(root) == {"version": 1, "keys": {}}


class TestResetAbsent:
    def test_absent_keyvault_is_noop(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        backend = FakeBackend()

        rc = _keyvault_reset.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True)

        assert rc == 0
        # Outcome lines land on stdout (UX review 2026-07-07); stderr stays
        # reserved for diagnostics and the interactive WARNING chrome.
        assert "nothing to reset" in capsys.readouterr().out.lower()
        assert _deleted(backend) == set()  # never touched the Enclave


class TestResetConfirmation:
    def test_wrong_phrase_aborts_and_preserves_keyvault(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        root = _build_keyvault(tmp_path, ["default"])
        backend = FakeBackend()
        _seed_enclave(backend, [_DEFAULT_KEY_ID])

        rc = _keyvault_reset.reset_keyvault(
            home=tmp_path, backend=backend, prompt_io=_ScriptedPrompt("no"), assume_yes=False
        )

        assert rc == 1
        assert root.exists()  # nothing deleted on abort
        assert _deleted(backend) == set()
        assert "aborted" in capsys.readouterr().out.lower()

    def test_correct_phrase_proceeds(self, tmp_path: Path) -> None:
        root = _build_keyvault(tmp_path, ["default"])
        backend = FakeBackend()
        prompt = _ScriptedPrompt("reset")

        rc = _keyvault_reset.reset_keyvault(home=tmp_path, backend=backend, prompt_io=prompt, assume_yes=False)

        assert rc == 0
        assert not root.exists()
        assert prompt.asked  # the operator was prompted

    def test_phrase_match_tolerates_surrounding_whitespace(self, tmp_path: Path) -> None:
        root = _build_keyvault(tmp_path, ["default"])
        backend = FakeBackend()

        rc = _keyvault_reset.reset_keyvault(
            home=tmp_path, backend=backend, prompt_io=_ScriptedPrompt("  reset  "), assume_yes=False
        )

        assert rc == 0
        assert not root.exists()

    def test_existing_journal_requires_confirmation_before_backend_delete(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        key_id = "payments\n\x1b[2Jowned"
        retained = ["legacy\n\x1b]52;c;Y2xpcGJvYXJk\x07"]
        root = _build_keyvault(tmp_path, [key_id])
        _write_current_reset_journal(root, retained_legacy=retained)
        epoch_before = _storage.read_generation_epoch(root)
        backend = FakeBackend()
        prompt = _ScriptedPrompt("no")

        rc = _keyvault_reset.reset_keyvault(
            home=tmp_path,
            backend=backend,
            prompt_io=prompt,
            assume_yes=False,
        )

        captured = capsys.readouterr()
        assert rc == 1
        assert prompt.asked
        assert _deleted(backend) == set()
        assert root.is_dir()
        assert _storage.reset_journal_path(root).is_file()
        assert _storage.read_generation_epoch(root) == epoch_before
        assert "\x1b" not in captured.out + captured.err
        assert key_id not in captured.err
        assert retained[0] not in captured.err
        assert "payments\\n\\x1b[2Jowned" in captured.err
        assert "legacy\\n\\x1b]52;c;Y2xpcGJvYXJk\\x07" in captured.err

    def test_existing_journal_with_absent_root_still_requires_confirmation(
        self,
        tmp_path: Path,
    ) -> None:
        root = _build_keyvault(tmp_path, ["default"])
        _write_current_reset_journal(root)
        _keyvault_reset.shutil.rmtree(root)
        backend = FakeBackend()
        prompt = _ScriptedPrompt("no")

        rc = _keyvault_reset.reset_keyvault(
            home=tmp_path,
            backend=backend,
            prompt_io=prompt,
            assume_yes=False,
        )

        assert rc == 1
        assert prompt.asked
        assert _deleted(backend) == set()
        assert not root.exists()
        assert _storage.reset_journal_path(root).is_file()

    def test_existing_journal_assume_yes_skips_confirmation(self, tmp_path: Path) -> None:
        root = _build_keyvault(tmp_path, ["default"])
        _write_current_reset_journal(root)
        prompt = _ScriptedPrompt("no")

        rc = _keyvault_reset.reset_keyvault(
            home=tmp_path,
            backend=FakeBackend(),
            prompt_io=prompt,
            assume_yes=True,
        )

        assert rc == 0
        assert prompt.asked == []
        assert not root.exists()


class TestResetAdapter:
    def test_cli_reset_delegates_with_assume_yes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, object] = {}

        def _fake_reset(*, assume_yes: bool = False) -> int:
            captured["assume_yes"] = assume_yes
            return 0

        monkeypatch.setattr(keyvault_cli, "reset_keyvault", _fake_reset)
        rc = keyvault_cli.cli_reset(argparse.Namespace(assume_yes=True))

        assert rc == 0
        assert captured["assume_yes"] is True

    def test_cli_reset_defaults_assume_yes_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, object] = {}

        def _fake_reset(*, assume_yes: bool = False) -> int:
            captured["assume_yes"] = assume_yes
            return 0

        monkeypatch.setattr(keyvault_cli, "reset_keyvault", _fake_reset)
        rc = keyvault_cli.cli_reset(argparse.Namespace())

        assert rc == 0
        assert captured["assume_yes"] is False
