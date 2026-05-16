"""Tests for ``hermes mordred install <skill>`` policy wrapper.

Uses checked-in fixture skills under ``tests/fixtures/`` so the install
matrix is identical across machines; audit logs land in pytest
``tmp_path`` so each test owns its own writer state.
"""

from __future__ import annotations

import contextlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from mordred_hermes.privacy_check.audit import NDJSONWriter
from mordred_hermes.privacy_check.install_wrapper import (
    InstallBlocked,
    InstallResult,
    run,
)
from mordred_hermes.privacy_check.policy import PolicyMode

FIXTURES = Path(__file__).parent / "fixtures"
CLEARNET = FIXTURES / "clearnet_skill"
TOR = FIXTURES / "tor_skill"
MISSING = FIXTURES / "missing_metadata_skill"
RKV = FIXTURES / "requires_keyvault_skill"


@dataclass
class _RunnerSpy:
    """Captures runner invocations and returns a synthetic CompletedProcess."""

    calls: list[list[str]]
    returncode: int = 0

    def __call__(self, cmd: list[str]) -> subprocess.CompletedProcess[bytes]:
        self.calls.append(cmd)
        return subprocess.CompletedProcess(args=cmd, returncode=self.returncode, stdout=b"", stderr=b"")


def _audit_entries(log_path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines() if line]


@pytest.fixture
def writer(tmp_path: Path) -> NDJSONWriter:
    return NDJSONWriter(path=tmp_path / "audit.log")


@pytest.fixture
def runner() -> _RunnerSpy:
    return _RunnerSpy(calls=[])


class TestStrict:
    def test_clearnet_skill_blocks(self, writer: NDJSONWriter, runner: _RunnerSpy, tmp_path: Path) -> None:
        with pytest.raises(InstallBlocked) as exc:
            run(skill_path=CLEARNET, policy_mode="strict", audit=writer, runner=runner)
        assert exc.value.reason == "policy.strict.clearnet"
        assert exc.value.skill_id == "clearnet-skill"
        assert runner.calls == [], "runner must not be invoked when blocked"
        entries = _audit_entries(tmp_path / "audit.log")
        assert len(entries) == 1
        assert entries[0]["event"] == "pre_install"
        assert entries[0]["decision"] == "block"
        assert entries[0]["reason"] == "policy.strict.clearnet"
        assert entries[0]["skill_id"] == "clearnet-skill"

    def test_missing_metadata_blocks(self, writer: NDJSONWriter, runner: _RunnerSpy, tmp_path: Path) -> None:
        with pytest.raises(InstallBlocked) as exc:
            run(skill_path=MISSING, policy_mode="strict", audit=writer, runner=runner)
        assert exc.value.reason == "policy.strict.unknown_metadata"
        assert runner.calls == []
        entry = _audit_entries(tmp_path / "audit.log")[0]
        assert entry["decision"] == "block"
        assert entry["reason"] == "policy.strict.unknown_metadata"

    def test_tor_skill_allows_and_invokes_runner(
        self, writer: NDJSONWriter, runner: _RunnerSpy, tmp_path: Path
    ) -> None:
        result = run(skill_path=TOR, policy_mode="strict", audit=writer, runner=runner)
        assert isinstance(result, InstallResult)
        assert result.skill_id == "tor-skill"
        assert result.outcome.decision == "allow"
        assert result.install_returncode == 0
        assert runner.calls == [["hermes", "skills", "install", str(TOR)]]
        entry = _audit_entries(tmp_path / "audit.log")[0]
        assert entry["decision"] == "allow"
        assert entry["reason"] is None


class TestLenient:
    def test_missing_metadata_warns_and_invokes_runner(
        self, writer: NDJSONWriter, runner: _RunnerSpy, tmp_path: Path
    ) -> None:
        result = run(skill_path=MISSING, policy_mode="lenient", audit=writer, runner=runner)
        assert result.outcome.decision == "warn"
        assert result.outcome.reason == "policy.lenient.unknown_metadata_warning"
        assert runner.calls == [["hermes", "skills", "install", str(MISSING)]]
        entry = _audit_entries(tmp_path / "audit.log")[0]
        assert entry["decision"] == "warn"
        assert entry["reason"] == "policy.lenient.unknown_metadata_warning"

    def test_clearnet_skill_allows(self, writer: NDJSONWriter, runner: _RunnerSpy, tmp_path: Path) -> None:
        result = run(skill_path=CLEARNET, policy_mode="lenient", audit=writer, runner=runner)
        assert result.outcome.decision == "allow"
        assert runner.calls == [["hermes", "skills", "install", str(CLEARNET)]]


class TestOff:
    @pytest.mark.parametrize("fixture", [CLEARNET, TOR, MISSING])
    def test_all_fixtures_allowed_silently(self, fixture: Path, writer: NDJSONWriter, runner: _RunnerSpy) -> None:
        result = run(skill_path=fixture, policy_mode="off", audit=writer, runner=runner)
        assert result.outcome.decision == "allow"
        assert result.outcome.reason is None
        assert runner.calls == [["hermes", "skills", "install", str(fixture)]]


class TestRunnerFailureSurfaces:
    """If the real installer exits non-zero, we still return its returncode."""

    def test_nonzero_returncode_propagates(self, writer: NDJSONWriter) -> None:
        runner = _RunnerSpy(calls=[], returncode=42)
        result = run(skill_path=TOR, policy_mode="strict", audit=writer, runner=runner)
        assert result.install_returncode == 42


class TestExplicitSkillMdPath:
    """Caller may pass either a directory or an explicit SKILL.md path."""

    @pytest.mark.parametrize(
        "skill_arg",
        [TOR, TOR / "SKILL.md"],
    )
    def test_both_forms_work(
        self,
        skill_arg: Path,
        writer: NDJSONWriter,
        runner: _RunnerSpy,
    ) -> None:
        result = run(skill_path=skill_arg, policy_mode="strict", audit=writer, runner=runner)
        assert result.skill_id == "tor-skill"


class TestAuditAlwaysWrittenBeforeSideEffect:
    """Audit lands even when the runner crashes."""

    def test_runner_exception_does_not_lose_audit(self, writer: NDJSONWriter, tmp_path: Path) -> None:
        def boom(_cmd: list[str]) -> subprocess.CompletedProcess[bytes]:
            raise RuntimeError("installer crashed")

        with pytest.raises(RuntimeError, match="installer crashed"):
            run(skill_path=TOR, policy_mode="strict", audit=writer, runner=boom)
        # Audit was written BEFORE the runner exception
        entries = _audit_entries(tmp_path / "audit.log")
        assert len(entries) == 1
        assert entries[0]["decision"] == "allow"


@pytest.mark.parametrize("mode", ["strict", "lenient", "off"])
def test_audit_records_skill_id_for_all_modes(
    mode: PolicyMode, writer: NDJSONWriter, runner: _RunnerSpy, tmp_path: Path
) -> None:
    """skill_id is always present in the audit entry (when frontmatter has name)."""
    with contextlib.suppress(InstallBlocked):
        run(skill_path=TOR, policy_mode=mode, audit=writer, runner=runner)
    entries = _audit_entries(tmp_path / "audit.log")
    assert len(entries) == 1
    assert entries[0]["skill_id"] == "tor-skill"


class TestRequiresKeyvault:
    """``metadata.mordred.requires_keyvault`` enforcement (TODO §4.1).

    The keyvault-initialized probe is injected; ``lambda: False`` models an
    uninitialized vault, ``lambda: True`` an initialized one.
    """

    def test_strict_blocks_when_keyvault_uninitialized(
        self, writer: NDJSONWriter, runner: _RunnerSpy, tmp_path: Path
    ) -> None:
        with pytest.raises(InstallBlocked) as exc:
            run(
                skill_path=RKV,
                policy_mode="strict",
                audit=writer,
                runner=runner,
                keyvault_probe=lambda: False,
            )
        assert exc.value.reason == "policy.strict.keyvault_uninitialized"
        assert exc.value.skill_id == "requires-keyvault-skill"
        assert runner.calls == [], "runner must not be invoked when blocked"
        entry = _audit_entries(tmp_path / "audit.log")[0]
        assert entry["event"] == "pre_install"
        assert entry["decision"] == "block"
        assert entry["reason"] == "policy.strict.keyvault_uninitialized"
        assert entry["skill_id"] == "requires-keyvault-skill"

    def test_strict_allows_when_keyvault_initialized(self, writer: NDJSONWriter, runner: _RunnerSpy) -> None:
        result = run(
            skill_path=RKV,
            policy_mode="strict",
            audit=writer,
            runner=runner,
            keyvault_probe=lambda: True,
        )
        assert result.outcome.decision == "allow"
        assert result.skill_id == "requires-keyvault-skill"
        assert runner.calls == [["hermes", "skills", "install", str(RKV)]]

    def test_lenient_warns_when_keyvault_uninitialized(
        self, writer: NDJSONWriter, runner: _RunnerSpy, tmp_path: Path
    ) -> None:
        result = run(
            skill_path=RKV,
            policy_mode="lenient",
            audit=writer,
            runner=runner,
            keyvault_probe=lambda: False,
        )
        assert result.outcome.decision == "warn"
        assert result.outcome.reason == "policy.lenient.keyvault_uninitialized_warning"
        assert runner.calls == [["hermes", "skills", "install", str(RKV)]]
        entry = _audit_entries(tmp_path / "audit.log")[0]
        assert entry["decision"] == "warn"
        assert entry["reason"] == "policy.lenient.keyvault_uninitialized_warning"

    def test_off_allows_when_keyvault_uninitialized(self, writer: NDJSONWriter, runner: _RunnerSpy) -> None:
        result = run(
            skill_path=RKV,
            policy_mode="off",
            audit=writer,
            runner=runner,
            keyvault_probe=lambda: False,
        )
        assert result.outcome.decision == "allow"
        assert result.outcome.reason is None
        assert runner.calls == [["hermes", "skills", "install", str(RKV)]]

    def test_probe_not_called_for_skill_without_opt_in(self, writer: NDJSONWriter, runner: _RunnerSpy) -> None:
        """A skill that does not declare ``requires_keyvault`` must never trigger the probe."""

        def boom() -> bool:
            raise AssertionError("keyvault probe must not run for non-opt-in skills")

        result = run(
            skill_path=TOR,
            policy_mode="strict",
            audit=writer,
            runner=runner,
            keyvault_probe=boom,
        )
        assert result.outcome.decision == "allow"
