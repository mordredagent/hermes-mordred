"""Tests for ``hermes mordred install <skill>`` dispatch glue.

The dispatch layer is a thin adapter over :mod:`privacy_check.install_wrapper`:

- Resolves the active :class:`PluginState` (policy mode + audit writer).
- Invokes :func:`install_wrapper.run`.
- Translates ``InstallBlocked`` into ``exit code 2 + stderr reason``.
- Forwards the install subprocess returncode on allow / warn.

These tests inject a synthetic state + runner so no real ``~/.hermes``
state is read and no real ``hermes skills install`` subprocess is spawned.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from mordred_hermes.privacy_check._runtime import PluginState
from mordred_hermes.privacy_check.audit import NDJSONWriter
from mordred_hermes.privacy_check.policy import PolicyMode
from mordred_hermes.wizard import install_dispatch

FIXTURES = Path(__file__).parent / "fixtures"
CLEARNET = FIXTURES / "clearnet_skill"
TOR = FIXTURES / "tor_skill"


@dataclass
class _RunnerSpy:
    calls: list[list[str]]
    returncode: int = 0

    def __call__(self, cmd: list[str]) -> subprocess.CompletedProcess[bytes]:
        self.calls.append(cmd)
        return subprocess.CompletedProcess(args=cmd, returncode=self.returncode, stdout=b"", stderr=b"")


def _make_state(tmp_path: Path, *, mode: PolicyMode) -> PluginState:
    return PluginState(
        policy_mode=mode,
        allow_cloud_llm=False,
        cloud_provider_allowlist=(),
        audit=NDJSONWriter(path=tmp_path / "audit.log"),
        config_path=tmp_path / "config.yaml",
    )


def _audit_lines(tmp_path: Path) -> list[dict[str, object]]:
    log = tmp_path / "audit.log"
    if not log.exists():
        return []
    return [json.loads(ln) for ln in log.read_text(encoding="utf-8").splitlines() if ln]


class TestRunBlock:
    def test_strict_clearnet_returns_2_and_logs_to_stderr(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        state = _make_state(tmp_path, mode="strict")
        runner = _RunnerSpy(calls=[])

        rc = install_dispatch.run(
            skill_arg=str(CLEARNET),
            state=state,
            runner=runner,
        )

        assert rc == 2
        assert runner.calls == [], "blocked install must not call hermes skills install"
        captured = capsys.readouterr()
        assert "blocked" in captured.err.lower()
        assert "clearnet-skill" in captured.err
        assert "policy.strict.clearnet" in captured.err
        assert captured.out == ""
        # Audit entry was written by install_wrapper before the raise.
        entries = _audit_lines(tmp_path)
        assert len(entries) == 1
        assert entries[0]["decision"] == "block"


class TestRunAllow:
    def test_tor_skill_in_strict_mode_returns_install_returncode(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        state = _make_state(tmp_path, mode="strict")
        runner = _RunnerSpy(calls=[], returncode=0)

        rc = install_dispatch.run(
            skill_arg=str(TOR),
            state=state,
            runner=runner,
        )

        assert rc == 0
        assert runner.calls == [["hermes", "skills", "install", str(TOR)]]
        # No stderr noise on success path.
        assert capsys.readouterr().err == ""

    def test_install_subprocess_failure_propagates_returncode(
        self,
        tmp_path: Path,
    ) -> None:
        state = _make_state(tmp_path, mode="lenient")
        runner = _RunnerSpy(calls=[], returncode=7)

        rc = install_dispatch.run(
            skill_arg=str(CLEARNET),
            state=state,
            runner=runner,
        )

        # lenient -> allow (with audit warn entry) -> forwards install rc.
        assert rc == 7
        assert runner.calls == [["hermes", "skills", "install", str(CLEARNET)]]


class TestRunMissingSkill:
    """A nonexistent / unreadable skill path is an operator error, not a crash.

    ``FileNotFoundError`` otherwise escaped ``run`` as a raw traceback
    (found in the 2026-07-09 CLI verification sweep:
    ``hermes-mordred install /tmp/no-such-skill``). Install did not happen,
    so exit code 2 matches the blocked paths.
    """

    def test_nonexistent_path_returns_2_with_clean_error(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        state = _make_state(tmp_path, mode="lenient")
        runner = _RunnerSpy(calls=[])

        rc = install_dispatch.run(
            skill_arg=str(tmp_path / "no-such-skill"),
            state=state,
            runner=runner,
        )

        assert rc == 2
        assert runner.calls == [], "unreadable skill must not reach hermes skills install"
        captured = capsys.readouterr()
        assert "error" in captured.err.lower()
        assert "no-such-skill" in captured.err
        assert captured.out == ""


class TestCLIHandler:
    """``cli_handler`` is the thin argparse adapter wired in cli.py."""

    def test_cli_handler_reads_skill_arg_and_returns_dispatch_rc(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        state = _make_state(tmp_path, mode="strict")
        captured: dict[str, object] = {}

        def fake_ensure_state() -> PluginState:
            captured["ensure_state_called"] = True
            return state

        monkeypatch.setattr(install_dispatch, "_ensure_state", fake_ensure_state)

        ns = argparse.Namespace(skill=str(CLEARNET))
        rc = install_dispatch.cli_handler(ns)

        assert rc == 2  # strict clearnet -> blocked
        assert captured["ensure_state_called"] is True
