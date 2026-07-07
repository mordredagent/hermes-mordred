"""Tests for ``hermes mordred audit {tail,grep}``.

The wizard audit CLI is read-only over ``~/.hermes/mordred/audit.log``
(privacy_check is the sole writer per PATHS.md). Tests seed an audit
log under ``tmp_path`` and assert tail / grep output shape.

Phase 4 encryption is out of scope for PR2 -- the v1 read path detects
binary log headers (anything not starting with ``{``) and surfaces a
"use audit decrypt (Phase 4)" message rather than dumping garbage.
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from mordred_hermes.wizard import audit_cli
from tests._keyvault_fakes import FakeBackend


def _seed_audit_log(path: Path, entries: list[dict[str, object]]) -> None:
    """Write NDJSON in the same compact form privacy_check.audit emits."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e, separators=(",", ":"), sort_keys=True) + "\n")


def _seed_mral_log(path: Path, entries: list[dict[str, object]]) -> None:
    """Write a real Phase 4 ``MRAL``-encrypted audit log.

    Produced by the genuine :class:`~mordred_hermes.keyvault.log_encryption.EncryptedWriter`
    (software ``FakeBackend`` standing in for the Secure Enclave) so the
    fixture matches the on-disk format the encrypted-audit factory ships:
    line 0 is a ``{"fmt":"MRAL",...}`` JSON header.
    """
    from mordred_hermes.keyvault import log_encryption as le

    path.parent.mkdir(parents=True, exist_ok=True)
    backend = FakeBackend()
    backend.generate_enclave_key(le.AUDIT_LOG_KEY_ID)
    writer = le.EncryptedWriter(path, backend=backend)
    for entry in entries:
        writer.append(entry)
    writer.close()


class TestTail:
    def test_tail_returns_last_n_entries(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        log = tmp_path / "audit.log"
        entries = [{"ts": f"2026-05-10T00:00:0{i}.000Z", "event": "pre_install", "n": i} for i in range(5)]
        _seed_audit_log(log, entries)

        rc = audit_cli.tail(n=3, log_path=log)

        assert rc == 0
        out_lines = [ln for ln in capsys.readouterr().out.splitlines() if ln.strip()]
        assert len(out_lines) == 3
        # Last three entries are n=2, 3, 4 (oldest-to-newest order preserved).
        assert '"n":2' in out_lines[0]
        assert '"n":4' in out_lines[-1]

    def test_tail_handles_n_larger_than_file(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        log = tmp_path / "audit.log"
        _seed_audit_log(log, [{"ts": "2026-05-10T00:00:00.000Z", "event": "x"}])

        rc = audit_cli.tail(n=100, log_path=log)

        assert rc == 0
        out_lines = [ln for ln in capsys.readouterr().out.splitlines() if ln.strip()]
        assert len(out_lines) == 1

    def test_tail_zero_returns_no_output(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """``-n 0`` must print nothing, not dump the entire log.

        Regression guard for the ``lines[-max(n, 0):]`` slice that evaluates
        to ``lines[0:]`` (the whole list) when ``n == 0``.
        """
        log = tmp_path / "audit.log"
        _seed_audit_log(
            log,
            [{"ts": f"2026-05-10T00:00:0{i}.000Z", "event": "x", "n": i} for i in range(3)],
        )

        rc = audit_cli.tail(n=0, log_path=log)

        assert rc == 0
        assert capsys.readouterr().out == ""

    def test_tail_negative_returns_no_output(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Negative ``-n`` is treated as 0 — no surprising last-N-minus-K output."""
        log = tmp_path / "audit.log"
        _seed_audit_log(
            log,
            [{"ts": f"2026-05-10T00:00:0{i}.000Z", "event": "x", "n": i} for i in range(3)],
        )

        rc = audit_cli.tail(n=-5, log_path=log)

        assert rc == 0
        assert capsys.readouterr().out == ""

    def test_tail_missing_log_returns_1_with_stderr_message(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        log = tmp_path / "absent" / "audit.log"

        rc = audit_cli.tail(n=10, log_path=log)

        assert rc == 1
        assert "no audit log" in capsys.readouterr().err.lower()

    def test_tail_encrypted_log_returns_1_with_phase4_hint(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        log = tmp_path / "audit.log"
        log.write_bytes(b"\x00\x01encrypted-blob")

        rc = audit_cli.tail(n=10, log_path=log)

        assert rc == 1
        err = capsys.readouterr().err.lower()
        assert "encrypted" in err
        assert "phase 4" in err or "audit decrypt" in err

    def test_tail_mral_encrypted_log_is_detected_not_dumped(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """A Phase 4 ``MRAL`` log must be detected, not dumped as NDJSON.

        Regression for the ``raw[:1] != b"{"`` guard: the encrypted format's
        line 0 is a JSON header (``{"fmt":"MRAL",...}``), so it *also* starts
        with ``{`` and the byte-prefix check waves it through. ``tail`` then
        prints the header + base64 ciphertext instead of the redirect hint.
        """
        log = tmp_path / "audit.log"
        _seed_mral_log(log, [{"event": "policy.strict.tor"}])
        # The encrypted file genuinely starts with '{' — that is the trap.
        assert log.read_bytes()[:1] == b"{"

        rc = audit_cli.tail(n=10, log_path=log)

        out, err = capsys.readouterr()
        assert rc == 1
        assert "audit decrypt" in err.lower()
        # The header / ciphertext must never reach stdout.
        assert out == ""
        assert "MRAL" not in out


class TestGrep:
    def test_grep_returns_matching_lines(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        log = tmp_path / "audit.log"
        entries: list[dict[str, object]] = [
            {"ts": "2026-05-10T00:00:00.000Z", "event": "pre_install", "decision": "block"},
            {"ts": "2026-05-10T00:00:01.000Z", "event": "pre_install", "decision": "allow"},
            {"ts": "2026-05-10T00:00:02.000Z", "event": "policy_reload"},
        ]
        _seed_audit_log(log, entries)

        rc = audit_cli.grep(pattern="block", log_path=log)

        assert rc == 0
        out_lines = [ln for ln in capsys.readouterr().out.splitlines() if ln.strip()]
        assert len(out_lines) == 1
        assert '"decision":"block"' in out_lines[0]

    def test_grep_no_matches_returns_1(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        log = tmp_path / "audit.log"
        _seed_audit_log(log, [{"ts": "2026-05-10T00:00:00.000Z", "event": "x"}])

        rc = audit_cli.grep(pattern="zzzz_no_match", log_path=log)

        assert rc == 1
        assert capsys.readouterr().out == ""

    def test_grep_invalid_regex_returns_2(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        log = tmp_path / "audit.log"
        _seed_audit_log(log, [{"event": "x"}])

        rc = audit_cli.grep(pattern="[unterminated", log_path=log)

        assert rc == 2
        assert "invalid" in capsys.readouterr().err.lower()

    def test_grep_mral_encrypted_log_is_detected_not_searched(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """``grep`` over a Phase 4 ``MRAL`` log must redirect, not search ciphertext.

        Same root cause as :meth:`TestTail.test_tail_mral_encrypted_log_is_detected_not_dumped`
        — ``grep`` shares the ``_iter_lines`` reader.
        """
        log = tmp_path / "audit.log"
        _seed_mral_log(log, [{"event": "policy.strict.tor"}])

        rc = audit_cli.grep(pattern="fmt", log_path=log)

        out, err = capsys.readouterr()
        assert rc == 1
        assert "audit decrypt" in err.lower()
        assert out == ""


class TestCLIHandlers:
    def test_cli_tail_reads_n_from_args(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        log = tmp_path / "audit.log"
        _seed_audit_log(log, [{"ts": "2026-05-10T00:00:00.000Z", "event": "x"}])
        monkeypatch.setattr(audit_cli, "_resolve_active_audit_path", lambda: log)

        ns = argparse.Namespace(lines=1)
        rc = audit_cli.cli_tail(ns)

        assert rc == 0

    def test_cli_grep_reads_pattern_from_args(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        log = tmp_path / "audit.log"
        _seed_audit_log(log, [{"ts": "2026-05-10T00:00:00.000Z", "event": "pre_install"}])
        monkeypatch.setattr(audit_cli, "_resolve_active_audit_path", lambda: log)

        ns = argparse.Namespace(pattern="pre_install")
        rc = audit_cli.cli_grep(ns)

        assert rc == 0


class TestActivePathResolution:
    """Codex P2: audit tail/grep must read the SAME path the writer uses.

    privacy_check honours ``plugins.mordred_privacy_check.audit_log_path``
    when constructing its NDJSONWriter; if that key points elsewhere under
    ``~/.hermes``, the wizard CLI must follow.
    """

    def test_get_active_audit_path_honours_config_yaml(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """privacy_check.get_active_audit_path picks up custom audit_log_path."""
        from mordred_hermes.privacy_check import _runtime as pc_runtime

        # Sandbox _HERMES_BASE so the custom path passes the under-base guard.
        fake_hermes = tmp_path / ".hermes"
        fake_hermes.mkdir()
        monkeypatch.setattr(pc_runtime, "_HERMES_BASE", fake_hermes)
        monkeypatch.setattr(pc_runtime, "DEFAULT_AUDIT_PATH", fake_hermes / "mordred" / "audit.log")

        config = fake_hermes / "config.yaml"
        custom_log = fake_hermes / "alt" / "custom-audit.log"
        config.write_text(
            f"plugins:\n  mordred_privacy_check:\n    audit_log_path: {custom_log}\n",
            encoding="utf-8",
        )

        resolved = pc_runtime.get_active_audit_path(config_path=config)
        assert resolved == custom_log

    def test_get_active_audit_path_defaults_when_section_absent(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from mordred_hermes.privacy_check import _runtime as pc_runtime

        fake_default = tmp_path / "default-audit.log"
        monkeypatch.setattr(pc_runtime, "DEFAULT_AUDIT_PATH", fake_default)

        config = tmp_path / "empty-config.yaml"
        config.write_text("plugins: {}\n", encoding="utf-8")

        resolved = pc_runtime.get_active_audit_path(config_path=config)
        assert resolved == fake_default

    def test_cli_tail_follows_active_audit_path(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """End-to-end: writer's custom path = reader's resolved path."""
        custom_log = tmp_path / "custom-audit.log"
        _seed_audit_log(custom_log, [{"ts": "2026-05-10T00:00:00.000Z", "event": "from-custom"}])
        # Default path is intentionally absent -- cli_tail must NOT read it.
        monkeypatch.setattr(audit_cli, "DEFAULT_AUDIT_LOG_PATH", tmp_path / "default-must-not-be-read.log")
        monkeypatch.setattr(audit_cli, "_resolve_active_audit_path", lambda: custom_log)

        ns = argparse.Namespace(lines=5)
        rc = audit_cli.cli_tail(ns)

        assert rc == 0
        assert "from-custom" in capsys.readouterr().out

    def test_tail_direct_api_default_follows_active_path(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Codex P3-b: direct ``tail()`` call without log_path follows the active path.

        ``tail()`` and ``grep()`` are exported in ``__all__``; callers in
        wizard-internal code that pass no ``log_path`` must not hardcode
        ``DEFAULT_AUDIT_LOG_PATH`` -- they must resolve the writer's
        configured path the same way ``cli_tail`` / ``cli_grep`` do.
        """
        custom_log = tmp_path / "writer-configured.log"
        _seed_audit_log(custom_log, [{"ts": "2026-05-10T00:00:00.000Z", "event": "from-writer"}])
        monkeypatch.setattr(audit_cli, "DEFAULT_AUDIT_LOG_PATH", tmp_path / "must-not-be-read.log")
        monkeypatch.setattr(audit_cli, "_resolve_active_audit_path", lambda: custom_log)

        rc = audit_cli.tail(n=5)

        assert rc == 0
        assert "from-writer" in capsys.readouterr().out

    def test_grep_direct_api_default_follows_active_path(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Codex P3-b mirror: ``grep()`` default also follows active path."""
        custom_log = tmp_path / "writer-configured.log"
        _seed_audit_log(custom_log, [{"ts": "2026-05-10T00:00:00.000Z", "event": "match-me"}])
        monkeypatch.setattr(audit_cli, "DEFAULT_AUDIT_LOG_PATH", tmp_path / "must-not-be-read.log")
        monkeypatch.setattr(audit_cli, "_resolve_active_audit_path", lambda: custom_log)

        rc = audit_cli.grep(pattern="match-me")

        assert rc == 0
        assert "match-me" in capsys.readouterr().out


class TestPurge:
    """RED tests for Phase 4 PR8: ``hermes mordred audit purge --before``.

    Deletes rotated audit-log files (``audit.log.<date>[...]``) dated
    strictly before the ``--before`` cutoff — the manual cleanup path for
    pre-Phase-4 plaintext history (PATHS.md §Consumer CLI). The active
    ``audit.log`` is never touched. Backend-free.
    """

    def _seed_rotated(self, directory: Path, names: list[str]) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        for name in names:
            (directory / name).write_bytes(b"rotated audit data\n")

    def test_invalid_before_date_returns_2(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = audit_cli.purge(before="not-a-date", audit_dir=tmp_path)
        assert rc == 2
        assert "YYYY-MM-DD" in capsys.readouterr().err

    def test_deletes_files_strictly_before_cutoff(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        self._seed_rotated(
            tmp_path,
            [
                "audit.log.2026-01-01.gz",
                "audit.log.2026-02-15.3.gz",
                "audit.log.2026-03-01.gz",  # == cutoff, kept (strictly-before)
                "audit.log.2026-05-01",
            ],
        )
        (tmp_path / "audit.log").write_bytes(b'{"ts":"x"}\n')  # active log

        rc = audit_cli.purge(before="2026-03-01", audit_dir=tmp_path)

        assert rc == 0
        remaining = {p.name for p in tmp_path.iterdir()}
        assert "audit.log.2026-01-01.gz" not in remaining
        assert "audit.log.2026-02-15.3.gz" not in remaining
        assert remaining == {"audit.log", "audit.log.2026-03-01.gz", "audit.log.2026-05-01"}

    def test_active_log_is_never_deleted(self, tmp_path: Path) -> None:
        (tmp_path / "audit.log").write_bytes(b'{"ts":"x"}\n')
        self._seed_rotated(tmp_path, ["audit.log.2020-01-01.gz"])

        audit_cli.purge(before="2030-01-01", audit_dir=tmp_path)

        assert (tmp_path / "audit.log").exists()
        assert not (tmp_path / "audit.log.2020-01-01.gz").exists()

    def test_nothing_to_purge_returns_0(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        (tmp_path / "audit.log").write_bytes(b'{"ts":"x"}\n')
        rc = audit_cli.purge(before="2026-01-01", audit_dir=tmp_path)
        assert rc == 0
        assert "0" in capsys.readouterr().out

    def test_ignores_non_dated_rotation_files(self, tmp_path: Path) -> None:
        self._seed_rotated(tmp_path, ["audit.log.backup", "audit.log.2020-01-01.gz"])
        audit_cli.purge(before="2030-01-01", audit_dir=tmp_path)
        assert (tmp_path / "audit.log.backup").exists()  # not a dated rotation
        assert not (tmp_path / "audit.log.2020-01-01.gz").exists()

    def test_cli_purge_adapter_delegates(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self._seed_rotated(tmp_path, ["audit.log.2020-01-01.gz"])
        monkeypatch.setattr(audit_cli, "_resolve_active_audit_path", lambda: tmp_path / "audit.log")
        rc = audit_cli.cli_purge(argparse.Namespace(before="2030-01-01", yes=True))
        assert rc == 0
        assert not (tmp_path / "audit.log.2020-01-01.gz").exists()

    def test_cli_purge_refuses_without_yes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Destructive-verb convention (UX review 2026-07-07): like
        # `encryption purge`, deleting audit history demands --yes.
        self._seed_rotated(tmp_path, ["audit.log.2020-01-01.gz"])
        monkeypatch.setattr(audit_cli, "_resolve_active_audit_path", lambda: tmp_path / "audit.log")
        rc = audit_cli.cli_purge(argparse.Namespace(before="2030-01-01"))
        assert rc == 2
        assert (tmp_path / "audit.log.2020-01-01.gz").exists()  # nothing deleted
        err = capsys.readouterr().err
        assert "--yes" in err


class TestDecrypt:
    """``hermes mordred audit decrypt --date`` over MRAL-encrypted logs.

    Phase 4 PR10 step-B. Encrypted fixtures are produced by the real
    :class:`~mordred_hermes.keyvault.log_encryption.EncryptedWriter` with
    a software ``FakeBackend`` in place of the Secure Enclave.
    """

    @staticmethod
    def _backend() -> FakeBackend:
        from mordred_hermes.keyvault import log_encryption as le

        be = FakeBackend()
        be.generate_enclave_key(le.AUDIT_LOG_KEY_ID)
        return be

    @staticmethod
    def _write_encrypted(path: Path, backend: FakeBackend, entries: list[dict[str, object]]) -> None:
        from mordred_hermes.keyvault import log_encryption as le

        writer = le.EncryptedWriter(path, backend=backend)
        for entry in entries:
            writer.append(entry)
        writer.close()

    def test_invalid_date_returns_2(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = audit_cli.decrypt(date="2026/05/10", audit_dir=tmp_path)
        assert rc == 2
        assert "YYYY-MM-DD" in capsys.readouterr().err

    def test_no_file_for_date_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = audit_cli.decrypt(date="2026-05-10", audit_dir=tmp_path)
        assert rc == 1
        assert "2026-05-10" in capsys.readouterr().err

    def test_decrypts_rotated_file_for_date(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        be = self._backend()
        self._write_encrypted(
            tmp_path / "audit.log.2026-05-10",
            be,
            [{"event": "policy.strict.clearnet", "seq": 0}, {"event": "policy.strict.tor", "seq": 1}],
        )
        rc = audit_cli.decrypt(date="2026-05-10", audit_dir=tmp_path, backend=be)
        out = capsys.readouterr().out
        assert rc == 0
        assert "policy.strict.clearnet" in out
        assert "policy.strict.tor" in out

    def test_decrypts_active_log_for_today(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        be = self._backend()
        self._write_encrypted(tmp_path / "audit.log", be, [{"event": "keyvault.unwrap_authorized"}])
        today = datetime.now(UTC).date().isoformat()
        rc = audit_cli.decrypt(date=today, audit_dir=tmp_path, backend=be)
        assert rc == 0
        assert "keyvault.unwrap_authorized" in capsys.readouterr().out

    def test_corrupt_file_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        be = self._backend()
        # A pre-Phase-4 plaintext NDJSON line is valid JSON but lacks the
        # MRAL header — decrypt must reject it, not dump garbage.
        (tmp_path / "audit.log.2026-05-10").write_text('{"event":"plaintext"}\n', encoding="utf-8")
        rc = audit_cli.decrypt(date="2026-05-10", audit_dir=tmp_path, backend=be)
        assert rc == 1
        assert "2026-05-10" in capsys.readouterr().err

    def test_auth_cancelled_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        be = self._backend()
        self._write_encrypted(tmp_path / "audit.log.2026-05-10", be, [{"event": "x"}])
        be.denied_reason = "user_cancelled"  # the unwrap prompt is denied
        rc = audit_cli.decrypt(date="2026-05-10", audit_dir=tmp_path, backend=be)
        assert rc == 1
        assert "cancel" in capsys.readouterr().err.lower()

    def test_cli_decrypt_adapter_delegates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: dict[str, str] = {}

        def fake_decrypt(*, date: str) -> int:
            seen["date"] = date
            return 0

        monkeypatch.setattr(audit_cli, "decrypt", fake_decrypt)
        assert audit_cli.cli_decrypt(argparse.Namespace(date="2026-05-10")) == 0
        assert seen["date"] == "2026-05-10"


class TestGuidanceSpelling:
    """UX review 2026-06-11: the encrypted-log hint must name the working CLI form."""

    def test_encrypted_log_hint_points_at_working_decrypt_command(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        log = tmp_path / "audit.log"
        log.write_bytes(b"\x00\x01encrypted-blob")
        rc = audit_cli.tail(n=10, log_path=log)
        assert rc == 1
        assert "hermes-mordred audit decrypt" in capsys.readouterr().err


class TestErrorColour:
    """Audit-CLI errors route through ``_term.emit_error``: red ``error:`` on a tty, plain off it.

    Mirrors the network / vault / keyvault reproducers (PR #159 / #164 / #165).
    Uses the no-setup invalid-regex path (the pattern is compiled before any log
    is read), so the assertion needs no seeded log.
    """

    def test_grep_error_is_red_when_forced(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setenv("FORCE_COLOR", "1")
        rc = audit_cli.grep(pattern="[unterminated", log_path=tmp_path / "audit.log")
        assert rc == 2
        err = capsys.readouterr().err
        assert "\033[31m" in err  # red `error:` label
        assert "invalid regex" in err

    def test_grep_error_plain_and_prefixed_off_tty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.delenv("FORCE_COLOR", raising=False)
        monkeypatch.delenv("NO_COLOR", raising=False)
        rc = audit_cli.grep(pattern="[unterminated", log_path=tmp_path / "audit.log")
        assert rc == 2
        err = capsys.readouterr().err
        assert err.startswith("error: invalid regex")
        assert "\033" not in err
