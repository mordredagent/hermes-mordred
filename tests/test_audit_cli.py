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
from pathlib import Path

import pytest

from mordred_hermes.wizard import audit_cli


def _seed_audit_log(path: Path, entries: list[dict[str, object]]) -> None:
    """Write NDJSON in the same compact form privacy_check.audit emits."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e, separators=(",", ":"), sort_keys=True) + "\n")


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


class TestCLIHandlers:
    def test_cli_tail_reads_n_from_args(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        log = tmp_path / "audit.log"
        _seed_audit_log(log, [{"ts": "2026-05-10T00:00:00.000Z", "event": "x"}])
        monkeypatch.setattr(audit_cli, "DEFAULT_AUDIT_LOG_PATH", log)

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
        monkeypatch.setattr(audit_cli, "DEFAULT_AUDIT_LOG_PATH", log)

        ns = argparse.Namespace(pattern="pre_install")
        rc = audit_cli.cli_grep(ns)

        assert rc == 0
