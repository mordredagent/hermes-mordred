"""Phase C tests -- configure flow with scripted PromptIO + SetupRunner doubles.

No subprocess is spawned and no real prompt_toolkit call happens; both
seams go through Protocol-typed doubles. Persistence is verified by
reading the files PolicyWriter actually wrote.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from mordred_hermes.wizard import configure
from mordred_hermes.wizard.configure import (
    ConfigureResult,
    NonInteractiveAbort,
    PromptIO,
    SetupRunner,
    _RefusingPromptIO,
    cli_handler,
    collect_answers,
    run,
)
from mordred_hermes.wizard.policy_writer import PolicySnapshot, PolicyWriter

# -----------------------------------------------------------------------------
# Test doubles.
# -----------------------------------------------------------------------------


@dataclass
class _ScriptedPromptIO:
    """Pops a pre-recorded answer per call, in declaration order."""

    answers: list[object]
    seen: list[tuple[str, str, object]] = field(default_factory=list)

    def _pop(self, kind: str, label: str, default: object) -> object:
        if not self.answers:
            raise AssertionError(f"_ScriptedPromptIO ran out of answers at {kind}({label!r})")
        a = self.answers.pop(0)
        self.seen.append((kind, label, a))
        return a

    def ask_choice(self, label: str, choices: Sequence[str], default: str) -> str:
        return str(self._pop("choice", label, default))

    def ask_text(self, label: str, default: str = "") -> str:
        return str(self._pop("text", label, default))

    def ask_bool(self, label: str, default: bool) -> bool:
        return bool(self._pop("bool", label, default))


@dataclass
class _SetupRunnerSpy:
    calls: list[bool] = field(default_factory=list)
    returncode: int = 0

    def run(self, *, non_interactive: bool) -> int:
        self.calls.append(non_interactive)
        return self.returncode


def _writer(tmp_path: Path) -> PolicyWriter:
    return PolicyWriter(
        config_path=tmp_path / "config.yaml",
        policy_json_path=tmp_path / "mordred" / "policy.json",
        mordred_dir=tmp_path / "mordred",
    )


# -----------------------------------------------------------------------------
# collect_answers: prompt sequence + snapshot mapping.
# -----------------------------------------------------------------------------


class TestCollectAnswers:
    def test_strict_with_anthropic_allowlist(self) -> None:
        prompts = _ScriptedPromptIO(
            answers=[
                "strict",  # policy
                True,  # allow_cloud_llm
                "anthropic,openai",  # cloud_provider_allowlist
                "http://example/v1",  # local_llm_endpoint (Phase 2)
                "llama-3",  # local_llm_model_id (Phase 2)
                "prompt-once",  # cloud_attempt_action (Phase 2)
            ]
        )
        result = collect_answers(prompts)
        assert isinstance(result, ConfigureResult)
        assert result.snapshot == PolicySnapshot(
            policy="strict",
            allow_cloud_llm=True,
            cloud_provider_allowlist=("anthropic", "openai"),
        )
        assert result.phase2_fields == {
            "local_llm_endpoint": "http://example/v1",
            "local_llm_model_id": "llama-3",
            "cloud_attempt_action": "prompt-once",
        }

    def test_lenient_with_empty_allowlist(self) -> None:
        prompts = _ScriptedPromptIO(answers=["lenient", False, "", "http://localhost:1234/v1", "", "always-block"])
        result = collect_answers(prompts)
        assert result.snapshot.policy == "lenient"
        assert result.snapshot.allow_cloud_llm is False
        assert result.snapshot.cloud_provider_allowlist == ()

    def test_csv_whitespace_stripped(self) -> None:
        prompts = _ScriptedPromptIO(answers=["off", False, "  anthropic ,  openai  ,", "x", "", "always-block"])
        result = collect_answers(prompts)
        assert result.snapshot.cloud_provider_allowlist == ("anthropic", "openai")

    def test_prompt_order_is_stable(self) -> None:
        """Order matters for snapshot tests; lock it explicitly."""
        prompts = _ScriptedPromptIO(answers=["lenient", False, "", "x", "y", "always-block"])
        collect_answers(prompts)
        labels = [label for _, label, _ in prompts.seen]
        assert labels == [
            "Mordred policy mode",
            "Allow cloud LLM providers (passes through provider override)?",
            "Cloud provider allowlist (comma-separated; empty = none)",
            "Local LLM endpoint URL (Phase 2)",
            "Local LLM model id (Phase 2)",
            "On cloud LLM attempt under strict mode (Phase 2)",
        ]


# -----------------------------------------------------------------------------
# run(): full flow including SetupRunner spawn + PolicyWriter persistence.
# -----------------------------------------------------------------------------


class TestRun:
    def test_persists_snapshot_to_disk(self, tmp_path: Path) -> None:
        prompts = _ScriptedPromptIO(answers=["strict", False, "anthropic", "x", "", "always-block"])
        runner = _SetupRunnerSpy()
        w = _writer(tmp_path)

        result = run(setup_runner=runner, prompt_io=prompts, policy_writer=w)

        assert runner.calls == [False]
        body = json.loads((tmp_path / "mordred" / "policy.json").read_text(encoding="utf-8"))
        assert body == {
            "policy": "strict",
            "allow_cloud_llm": False,
            "cloud_provider_allowlist": ["anthropic"],
            "audit_log_path": None,
        }
        ytext = (tmp_path / "config.yaml").read_text(encoding="utf-8")
        assert "policy: strict" in ytext
        assert "mordred_privacy_check" in ytext
        assert result.snapshot.policy == "strict"

    def test_skip_hermes_setup_does_not_call_runner(self, tmp_path: Path) -> None:
        prompts = _ScriptedPromptIO(answers=["off", False, "", "x", "", "always-block"])
        runner = _SetupRunnerSpy()
        w = _writer(tmp_path)

        run(setup_runner=runner, prompt_io=prompts, policy_writer=w, skip_hermes_setup=True)
        assert runner.calls == [], "skip_hermes_setup must not invoke the runner"

    def test_setup_failure_warns_but_continues(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        prompts = _ScriptedPromptIO(answers=["lenient", False, "", "x", "", "always-block"])
        runner = _SetupRunnerSpy(returncode=42)
        w = _writer(tmp_path)

        import logging

        with caplog.at_level(logging.WARNING, logger="mordred.wizard.configure"):
            result = run(setup_runner=runner, prompt_io=prompts, policy_writer=w)
        assert result.snapshot.policy == "lenient"
        assert any("hermes setup" in r.getMessage() and "42" in r.getMessage() for r in caplog.records)

    def test_non_interactive_forwarded_to_runner(self, tmp_path: Path) -> None:
        prompts = _ScriptedPromptIO(answers=["lenient", False, "", "x", "", "always-block"])
        runner = _SetupRunnerSpy()
        w = _writer(tmp_path)

        run(setup_runner=runner, prompt_io=prompts, policy_writer=w, non_interactive=True)
        assert runner.calls == [True]


# -----------------------------------------------------------------------------
# _RefusingPromptIO: --non-interactive guard.
# -----------------------------------------------------------------------------


class TestRefusingPromptIO:
    def test_ask_choice_raises(self) -> None:
        rp = _RefusingPromptIO()
        with pytest.raises(NonInteractiveAbort, match="prompt required: 'policy mode'"):
            rp.ask_choice("policy mode", ("a", "b"), "a")

    def test_ask_text_raises(self) -> None:
        rp = _RefusingPromptIO()
        with pytest.raises(NonInteractiveAbort):
            rp.ask_text("name", "")

    def test_ask_bool_raises(self) -> None:
        rp = _RefusingPromptIO()
        with pytest.raises(NonInteractiveAbort):
            rp.ask_bool("ok?", False)


# -----------------------------------------------------------------------------
# cli_handler: --non-interactive triggers exit code 2.
# -----------------------------------------------------------------------------


def _patch_for_cli(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, prompt_io: PromptIO | None = None) -> None:
    class _ZeroSetup:
        def run(self, *, non_interactive: bool) -> int:
            return 0

    monkeypatch.setattr(configure, "SubprocessSetupRunner", _ZeroSetup)
    monkeypatch.setattr(
        configure,
        "PolicyWriter",
        lambda: PolicyWriter(
            config_path=tmp_path / "config.yaml",
            policy_json_path=tmp_path / "mordred" / "policy.json",
            mordred_dir=tmp_path / "mordred",
        ),
    )
    if prompt_io is not None:
        monkeypatch.setattr(configure, "PromptToolkitIO", lambda: prompt_io)


class TestCliHandler:
    def test_non_interactive_returns_exit_code_2(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _patch_for_cli(monkeypatch, tmp_path)
        ns = argparse.Namespace(non_interactive=True)
        rc = cli_handler(ns)
        assert rc == 2
        captured = capsys.readouterr()
        assert "non-interactive" in captured.err.lower()

    def test_interactive_path_runs_end_to_end(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        scripted = _ScriptedPromptIO(answers=["off", False, "", "x", "", "always-block"])
        _patch_for_cli(monkeypatch, tmp_path, prompt_io=scripted)
        ns = argparse.Namespace(non_interactive=False)
        rc = cli_handler(ns)
        assert rc == 0
        body = json.loads((tmp_path / "mordred" / "policy.json").read_text(encoding="utf-8"))
        assert body["policy"] == "off"


# -----------------------------------------------------------------------------
# Default subprocess runner -- assert command shape without spawning.
# -----------------------------------------------------------------------------


class TestSubprocessSetupRunner:
    def test_calls_subprocess_run_with_non_interactive_flag(self, monkeypatch: pytest.MonkeyPatch) -> None:
        called: list[list[str]] = []

        class _Completed:
            returncode = 0

        def _fake_run(cmd: list[str], check: bool = False) -> object:
            called.append(cmd)
            return _Completed()

        import subprocess

        monkeypatch.setattr(subprocess, "run", _fake_run)
        rc = configure.SubprocessSetupRunner().run(non_interactive=True)
        assert rc == 0
        assert called == [["hermes", "setup", "--non-interactive"]]

    def test_omits_non_interactive_flag_when_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        called: list[list[str]] = []

        class _Completed:
            returncode = 7

        def _fake_run(cmd: list[str], check: bool = False) -> object:
            called.append(cmd)
            return _Completed()

        import subprocess

        monkeypatch.setattr(subprocess, "run", _fake_run)
        rc = configure.SubprocessSetupRunner().run(non_interactive=False)
        assert rc == 7
        assert called == [["hermes", "setup"]]

    def test_missing_hermes_binary_returns_1_and_warns(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """``hermes`` not on PATH must not propagate FileNotFoundError."""

        def _raise(cmd: list[str], check: bool = False) -> object:
            raise FileNotFoundError(2, "No such file or directory: 'hermes'")

        import logging
        import subprocess

        monkeypatch.setattr(subprocess, "run", _raise)
        with caplog.at_level(logging.WARNING, logger="mordred.wizard.configure"):
            rc = configure.SubprocessSetupRunner().run(non_interactive=False)
        assert rc == 1
        assert any("not found on PATH" in r.getMessage() for r in caplog.records)


# -----------------------------------------------------------------------------
# Protocol structural conformance.
# -----------------------------------------------------------------------------


def test_scripted_prompt_io_matches_protocol() -> None:
    p: PromptIO = _ScriptedPromptIO(answers=[])
    assert p is not None


def test_refusing_prompt_io_matches_protocol() -> None:
    p: PromptIO = _RefusingPromptIO()
    assert p is not None


def test_setup_runner_spy_matches_protocol() -> None:
    r: SetupRunner = _SetupRunnerSpy()
    assert r is not None
