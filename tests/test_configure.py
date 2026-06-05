"""Phase C tests -- configure flow with scripted PromptIO + SetupRunner doubles.

No subprocess is spawned and no real prompt_toolkit call happens; both
seams go through Protocol-typed doubles. Persistence is verified by
reading the files PolicyWriter actually wrote.

Network-privacy prompts no longer live here: they moved to
``hermes mordred network init`` (see ``test_wizard_network_init.py``) so
first-run setup stays short and privacy is opt-in via an explicit command
(user request 2026-06-05). ``configure`` therefore must NOT touch the
``plugins.mordred_network`` section.
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

    def ask_password(self, label: str, default: str = "") -> str:
        """Same FIFO contract as ask_text but kind tag distinguishes for
        diagnostics so a future test can confirm the wizard used password
        prompting for secrets, not plain text."""
        return str(self._pop("password", label, default))


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


# The seven core prompts collected by ``configure`` after the network split.
# Order: policy, allow_cloud_llm, allowlist, local endpoint, local model,
# cloud attempt action, agent harness.
def _core_answers(
    *,
    policy: str = "lenient",
    allow_cloud: bool = False,
    allowlist: str = "",
    endpoint: str = "http://x/v1",
    model: str = "",
    cloud_attempt: str = "always-block",
    harness: str = "none",
) -> list[object]:
    return [policy, allow_cloud, allowlist, endpoint, model, cloud_attempt, harness]


# -----------------------------------------------------------------------------
# collect_answers: prompt sequence + snapshot mapping.
# -----------------------------------------------------------------------------


class TestCollectAnswers:
    def test_strict_with_anthropic_allowlist(self) -> None:
        prompts = _ScriptedPromptIO(
            answers=_core_answers(
                policy="strict",
                allow_cloud=True,
                allowlist="anthropic,openai",
                endpoint="http://example/v1",
                model="llama-3",
                cloud_attempt="prompt-once",
                harness="codex",
            )
        )
        result = collect_answers(prompts)
        assert isinstance(result, ConfigureResult)
        assert result.snapshot == PolicySnapshot(
            policy="strict",
            allow_cloud_llm=True,
            cloud_provider_allowlist=("anthropic", "openai"),
            local_llm_endpoint="http://example/v1",
            local_llm_model_id="llama-3",
            cloud_attempt_action="prompt-once",
            harness_primary="codex",
        )

    def test_lenient_with_empty_allowlist(self) -> None:
        prompts = _ScriptedPromptIO(answers=_core_answers(endpoint="http://localhost:1234/v1"))
        result = collect_answers(prompts)
        assert result.snapshot.policy == "lenient"
        assert result.snapshot.allow_cloud_llm is False
        assert result.snapshot.cloud_provider_allowlist == ()
        assert result.snapshot.harness_primary == "none"

    def test_csv_whitespace_stripped(self) -> None:
        prompts = _ScriptedPromptIO(answers=_core_answers(policy="off", allowlist="  anthropic ,  openai  ,"))
        result = collect_answers(prompts)
        assert result.snapshot.cloud_provider_allowlist == ("anthropic", "openai")

    def test_prompt_order_is_stable_and_jargon_free(self) -> None:
        """Order matters for snapshot tests; lock it explicitly. The labels
        must also carry no internal ``(Phase N)`` jargon (user request)."""
        prompts = _ScriptedPromptIO(answers=_core_answers())
        collect_answers(prompts)
        labels = [label for _, label, _ in prompts.seen]
        assert labels == [
            "Mordred policy mode",
            "Allow cloud LLM providers (passes through provider override)?",
            "Cloud provider allowlist (comma-separated; empty = none)",
            "Local LLM endpoint URL",
            "Local LLM model id",
            "On cloud LLM attempt under strict mode",
            "Agent harness (strict mode refuses if a known harness is detected)",
        ]
        for label in labels:
            assert "Phase" not in label, f"user-facing label leaks internal jargon: {label!r}"


# -----------------------------------------------------------------------------
# run(): full flow including SetupRunner spawn + PolicyWriter persistence.
# -----------------------------------------------------------------------------


class TestRun:
    def test_persists_snapshot_to_disk(self, tmp_path: Path) -> None:
        prompts = _ScriptedPromptIO(
            answers=_core_answers(
                policy="strict",
                allowlist="anthropic",
                endpoint="http://x/v1",
                model="qwen",
                cloud_attempt="prompt-once",
                harness="codex",
            )
        )
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
            "local_llm_endpoint": "http://x/v1",
            "local_llm_model_id": "qwen",
            "cloud_attempt_action": "prompt-once",
            # strict policy → disable_ipv6=True is computed by collect_answers.
            "disable_ipv6": True,
        }
        ytext = (tmp_path / "config.yaml").read_text(encoding="utf-8")
        assert "policy: strict" in ytext
        assert "mordred_privacy_check" in ytext
        assert "local_llm_endpoint" not in ytext
        assert "cloud_attempt_action" not in ytext
        assert "mordred_llm_guard" in ytext
        assert "harness_primary: codex" in ytext
        # configure must NOT write the network section -- that's `network init`.
        assert "default_path" not in ytext
        assert "tor_binary_path" not in ytext
        assert result.snapshot.policy == "strict"
        assert result.snapshot.local_llm_endpoint == "http://x/v1"
        assert result.snapshot.harness_primary == "codex"

    def test_skip_hermes_setup_does_not_call_runner(self, tmp_path: Path) -> None:
        prompts = _ScriptedPromptIO(answers=_core_answers(policy="off"))
        runner = _SetupRunnerSpy()
        w = _writer(tmp_path)

        run(setup_runner=runner, prompt_io=prompts, policy_writer=w, skip_hermes_setup=True)
        assert runner.calls == [], "skip_hermes_setup must not invoke the runner"

    def test_setup_failure_warns_but_continues(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        prompts = _ScriptedPromptIO(answers=_core_answers())
        runner = _SetupRunnerSpy(returncode=42)
        w = _writer(tmp_path)

        import logging

        with caplog.at_level(logging.WARNING, logger="mordred.wizard.configure"):
            result = run(setup_runner=runner, prompt_io=prompts, policy_writer=w)
        assert result.snapshot.policy == "lenient"
        assert any("hermes setup" in r.getMessage() and "42" in r.getMessage() for r in caplog.records)

    def test_non_interactive_forwarded_to_runner(self, tmp_path: Path) -> None:
        prompts = _ScriptedPromptIO(answers=_core_answers())
        runner = _SetupRunnerSpy()
        w = _writer(tmp_path)

        run(setup_runner=runner, prompt_io=prompts, policy_writer=w, non_interactive=True)
        assert runner.calls == [True]


class TestConfigureLeavesNetworkSectionIntact:
    """``configure`` is network-free after the split: an existing
    ``plugins.mordred_network`` section (written by ``network init`` or by
    hand) must survive a configure run untouched."""

    def test_existing_network_section_untouched(self, tmp_path: Path) -> None:
        config = tmp_path / "config.yaml"
        config.write_text(
            "plugins:\n"
            "  mordred_network:\n"
            "    default_path: tor\n"
            "    tor_binary_path: /opt/tor/bin/tor\n"
            "    mullvad_relay_country: jp\n",
            encoding="utf-8",
        )
        prompts = _ScriptedPromptIO(answers=_core_answers(policy="strict"))
        run(setup_runner=_SetupRunnerSpy(), prompt_io=prompts, policy_writer=_writer(tmp_path), skip_hermes_setup=True)

        from ruamel.yaml import YAML

        yaml = YAML(typ="safe", pure=True)
        with config.open(encoding="utf-8") as f:
            data = yaml.load(f)
        section = data["plugins"]["mordred_network"]
        assert section["default_path"] == "tor"
        assert section["tor_binary_path"] == "/opt/tor/bin/tor"
        assert section["mullvad_relay_country"] == "jp"
        # And configure still wrote its own sections alongside.
        assert data["plugins"]["mordred_privacy_check"]["policy"] == "strict"


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
        scripted = _ScriptedPromptIO(answers=_core_answers(policy="off"))
        _patch_for_cli(monkeypatch, tmp_path, prompt_io=scripted)
        ns = argparse.Namespace(non_interactive=False)
        rc = cli_handler(ns)
        assert rc == 0
        body = json.loads((tmp_path / "mordred" / "policy.json").read_text(encoding="utf-8"))
        assert body["policy"] == "off"

    def test_interactive_path_prints_network_init_hint(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """After configure, the user is pointed at the on-demand privacy command."""
        scripted = _ScriptedPromptIO(answers=_core_answers(policy="lenient"))
        _patch_for_cli(monkeypatch, tmp_path, prompt_io=scripted)
        cli_handler(argparse.Namespace(non_interactive=False))
        out = capsys.readouterr().out.lower()
        assert "network init" in out


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


# -----------------------------------------------------------------------------
# PromptIO.ask_password remains part of the shared prompt surface (reused by
# `network init` for the Mullvad secret).
# -----------------------------------------------------------------------------


class TestPromptIOAskPassword:
    def test_protocol_has_ask_password(self) -> None:
        import inspect

        sig = inspect.signature(PromptIO.ask_password)  # type: ignore[attr-defined]
        params = list(sig.parameters)
        assert "label" in params
        assert "default" in params

    def test_scripted_prompt_io_supports_ask_password(self) -> None:
        scripted = _ScriptedPromptIO(answers=["secret-123"])
        result = scripted.ask_password("Mullvad account id", default="")
        assert result == "secret-123"

    def test_refusing_prompt_io_ask_password_raises(self) -> None:
        rp = _RefusingPromptIO()
        with pytest.raises(NonInteractiveAbort):
            rp.ask_password("secret", default="")


# -----------------------------------------------------------------------------
# Completion summary (UX scope B): a structured recap printed after configure.
# -----------------------------------------------------------------------------


class TestConfigureSummary:
    def test_render_summary_contains_resolved_fields(self) -> None:
        from mordred_hermes.wizard.configure import _render_configure_summary

        snap = PolicySnapshot(policy="strict", allow_cloud_llm=True, harness_primary="codex")
        out = _render_configure_summary(snap)
        assert "strict" in out
        assert "codex" in out
        # cloud-LLM state is shown as a human yes/no, not the raw bool.
        assert "policy" in out.lower()
        assert "cloud" in out.lower()
        # Points the user at the on-demand network privacy command.
        assert "network init" in out

    def test_render_summary_reflects_cloud_disallowed(self) -> None:
        from mordred_hermes.wizard.configure import _render_configure_summary

        out = _render_configure_summary(PolicySnapshot(policy="lenient", allow_cloud_llm=False))
        assert "no" in out.lower()

    def test_cli_handler_prints_summary_with_chosen_values(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        scripted = _ScriptedPromptIO(answers=_core_answers(policy="strict", harness="codex"))
        _patch_for_cli(monkeypatch, tmp_path, prompt_io=scripted)
        rc = cli_handler(argparse.Namespace(non_interactive=False))
        assert rc == 0
        out = capsys.readouterr().out
        assert "strict" in out
        assert "codex" in out
        assert "network init" in out
