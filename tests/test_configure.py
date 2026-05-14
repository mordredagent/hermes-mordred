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
from typing import ClassVar

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
                "codex",  # harness_primary (Phase 2 PR2)
                # Phase 3 PR3a Task #6 — network prompt sextet:
                "clearnet",  # default_network_path
                "/usr/bin/tor",  # tor_binary_path
                "9050",  # tor_socks_port (ask_text)
                "",  # mullvad account (password; empty = no .env line)
                "auto",  # mullvad_relay_country
                False,  # mullvad_killswitch
            ]
        )
        result = collect_answers(prompts)
        assert isinstance(result, ConfigureResult)
        # Codex M3 (PR1): Phase 2 fields now live INSIDE the snapshot so
        # llm_guard can read them through policy.json without a separate
        # ConfigureResult.phase2_fields side channel.
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
        prompts = _ScriptedPromptIO(
            answers=[
                "lenient",
                False,
                "",
                "http://localhost:1234/v1",
                "",
                "always-block",
                "none",
                "clearnet",
                "/usr/bin/tor",
                "9050",
                "",
                "auto",
                False,
            ]
        )
        result = collect_answers(prompts)
        assert result.snapshot.policy == "lenient"
        assert result.snapshot.allow_cloud_llm is False
        assert result.snapshot.cloud_provider_allowlist == ()
        assert result.snapshot.harness_primary == "none"

    def test_csv_whitespace_stripped(self) -> None:
        prompts = _ScriptedPromptIO(
            answers=[
                "off",
                False,
                "  anthropic ,  openai  ,",
                "x",
                "",
                "always-block",
                "none",
                "clearnet",
                "/usr/bin/tor",
                "9050",
                "",
                "auto",
                False,
            ]
        )
        result = collect_answers(prompts)
        assert result.snapshot.cloud_provider_allowlist == ("anthropic", "openai")

    def test_prompt_order_is_stable(self) -> None:
        """Order matters for snapshot tests; lock it explicitly.

        Task #6 added 6 network prompts at the end. The leading 7 stay
        stable so Phase 1 / Phase 2 snapshot tests aren't disturbed.
        """
        prompts = _ScriptedPromptIO(
            answers=[
                "lenient",
                False,
                "",
                "x",
                "y",
                "always-block",
                "none",
                "clearnet",
                "/usr/bin/tor",
                "9050",
                "",
                "auto",
                False,
            ]
        )
        collect_answers(prompts)
        labels = [label for _, label, _ in prompts.seen]
        assert labels == [
            "Mordred policy mode",
            "Allow cloud LLM providers (passes through provider override)?",
            "Cloud provider allowlist (comma-separated; empty = none)",
            "Local LLM endpoint URL (Phase 2)",
            "Local LLM model id (Phase 2)",
            "On cloud LLM attempt under strict mode (Phase 2)",
            "Agent harness primary (Phase 2; strict mode refuses if a known harness)",
            "Default network path",
            "Tor binary path",
            "Tor SOCKS port",
            "Mullvad account number (stored in ~/.hermes/.env)",
            "Mullvad relay country (`auto` or 2-letter code)",
            "Mullvad killswitch (lockdown-mode)",
        ]


# -----------------------------------------------------------------------------
# run(): full flow including SetupRunner spawn + PolicyWriter persistence.
# -----------------------------------------------------------------------------


class TestRun:
    def test_persists_snapshot_to_disk(self, tmp_path: Path) -> None:
        prompts = _ScriptedPromptIO(
            answers=[
                "strict",
                False,
                "anthropic",
                "http://x/v1",
                "qwen",
                "prompt-once",
                "codex",
                "clearnet",
                "/usr/bin/tor",
                "9050",
                "",
                "auto",
                True,
            ]
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
            # Phase 2 fields persisted (Codex M3 — PR1 scope).
            "local_llm_endpoint": "http://x/v1",
            "local_llm_model_id": "qwen",
            "cloud_attempt_action": "prompt-once",
        }
        ytext = (tmp_path / "config.yaml").read_text(encoding="utf-8")
        assert "policy: strict" in ytext
        assert "mordred_privacy_check" in ytext
        # config.yaml privacy_check section must NOT carry Phase 2 fields
        # (plugin-boundary discipline — they belong to mordred_llm_guard).
        assert "local_llm_endpoint" not in ytext
        assert "cloud_attempt_action" not in ytext
        # Phase 2 PR2: mordred_llm_guard section gains harness_primary.
        assert "mordred_llm_guard" in ytext
        assert "harness_primary: codex" in ytext
        assert result.snapshot.policy == "strict"
        assert result.snapshot.local_llm_endpoint == "http://x/v1"
        assert result.snapshot.harness_primary == "codex"

    def test_skip_hermes_setup_does_not_call_runner(self, tmp_path: Path) -> None:
        prompts = _ScriptedPromptIO(
            answers=[
                "off",
                False,
                "",
                "x",
                "",
                "always-block",
                "none",
                "clearnet",
                "/usr/bin/tor",
                "9050",
                "",
                "auto",
                False,
            ]
        )
        runner = _SetupRunnerSpy()
        w = _writer(tmp_path)

        run(setup_runner=runner, prompt_io=prompts, policy_writer=w, skip_hermes_setup=True)
        assert runner.calls == [], "skip_hermes_setup must not invoke the runner"

    def test_setup_failure_warns_but_continues(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        prompts = _ScriptedPromptIO(
            answers=[
                "lenient",
                False,
                "",
                "x",
                "",
                "always-block",
                "none",
                "clearnet",
                "/usr/bin/tor",
                "9050",
                "",
                "auto",
                False,
            ]
        )
        runner = _SetupRunnerSpy(returncode=42)
        w = _writer(tmp_path)

        import logging

        with caplog.at_level(logging.WARNING, logger="mordred.wizard.configure"):
            result = run(setup_runner=runner, prompt_io=prompts, policy_writer=w)
        assert result.snapshot.policy == "lenient"
        assert any("hermes setup" in r.getMessage() and "42" in r.getMessage() for r in caplog.records)

    def test_non_interactive_forwarded_to_runner(self, tmp_path: Path) -> None:
        prompts = _ScriptedPromptIO(
            answers=[
                "lenient",
                False,
                "",
                "x",
                "",
                "always-block",
                "none",
                "clearnet",
                "/usr/bin/tor",
                "9050",
                "",
                "auto",
                False,
            ]
        )
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
        scripted = _ScriptedPromptIO(
            answers=[
                "off",
                False,
                "",
                "x",
                "",
                "always-block",
                "none",
                "clearnet",
                "/usr/bin/tor",
                "9050",
                "",
                "auto",
                False,
            ]
        )
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


# --------------------------------------------------------------------------- #
# Phase 3 PR3a Task #6: Mullvad / Tor wizard prompts + NetworkAnswers         #
# --------------------------------------------------------------------------- #


class TestPromptIOAskPassword:
    """``PromptIO`` grows an ``ask_password`` method so secrets (Mullvad
    account number) don't appear in shell history or _ScriptedPromptIO.seen
    string-coerced records.
    """

    def test_protocol_has_ask_password(self) -> None:
        """Static check: PromptIO.ask_password exists with the documented shape."""
        import inspect

        sig = inspect.signature(PromptIO.ask_password)  # type: ignore[attr-defined]
        params = list(sig.parameters)
        # self + label + default
        assert "label" in params
        assert "default" in params

    def test_scripted_prompt_io_supports_ask_password(self) -> None:
        scripted = _ScriptedPromptIO(answers=["secret-123"])
        result = scripted.ask_password("Mullvad account id", default="")  # type: ignore[attr-defined]
        assert result == "secret-123"

    def test_refusing_prompt_io_ask_password_raises(self) -> None:
        rp = _RefusingPromptIO()
        with pytest.raises(NonInteractiveAbort):
            rp.ask_password("secret", default="")  # type: ignore[attr-defined]


class TestNetworkAnswersDataclass:
    """A new ``NetworkAnswers`` dataclass carries the 5 (well, 6 with bool)
    new wizard outputs alongside ``ConfigureResult.snapshot``. Task #7 will
    fold these into ``PolicySnapshot`` proper; PR3a Task #6 keeps them on
    a sibling field so the prompt + writer slice ships first."""

    def test_network_answers_importable(self) -> None:
        from mordred_hermes.wizard.configure import NetworkAnswers

        assert NetworkAnswers is not None

    def test_network_answers_fields_present(self) -> None:
        import dataclasses

        from mordred_hermes.wizard.configure import NetworkAnswers

        names = {f.name for f in dataclasses.fields(NetworkAnswers)}
        assert names == {
            "default_network_path",
            "tor_binary_path",
            "tor_socks_port",
            "mullvad_account_id_env",
            "mullvad_relay_country",
            "mullvad_killswitch",
        }

    def test_network_answers_is_frozen(self) -> None:
        import dataclasses

        from mordred_hermes.wizard.configure import NetworkAnswers

        na = NetworkAnswers(
            default_network_path="clearnet",
            tor_binary_path="/usr/bin/tor",
            tor_socks_port=9050,
            mullvad_account_id_env="MORDRED_MULLVAD_ACCOUNT",
            mullvad_relay_country="auto",
            mullvad_killswitch=False,
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            na.default_network_path = "tor"  # type: ignore[misc]


class TestNetworkPrompts:
    """``collect_answers`` runs 6 new network prompts after the existing
    Phase 1 / Phase 2 fields. Default values mirror lenient-mode
    expectations (no Mullvad account, no killswitch); strict-mode
    operators set them via the prompts."""

    _BASE_ANSWERS: ClassVar[list[object]] = [
        "lenient",  # policy
        False,  # allow_cloud_llm
        "",  # cloud_provider_allowlist
        "http://x/v1",  # local_llm_endpoint
        "qwen",  # local_llm_model_id
        "always-block",  # cloud_attempt_action
        "none",  # harness_primary
    ]
    _NETWORK_ANSWERS: ClassVar[list[object]] = [
        "tor",  # default_network_path
        "/opt/tor/bin/tor",  # tor_binary_path
        "9150",  # tor_socks_port (ask_text -> coerce to int)
        "my-secret-account",  # mullvad_account_id (ask_password -> .env value, ConfigureResult holds env-var REF only)
        "jp",  # mullvad_relay_country
        True,  # mullvad_killswitch
    ]

    def test_collects_six_network_prompts(self) -> None:
        prompts = _ScriptedPromptIO(answers=[*self._BASE_ANSWERS, *self._NETWORK_ANSWERS])
        result = collect_answers(prompts)
        from mordred_hermes.wizard.configure import NetworkAnswers

        assert isinstance(result.network_answers, NetworkAnswers)  # type: ignore[attr-defined]
        na = result.network_answers  # type: ignore[attr-defined]
        assert na.default_network_path == "tor"
        assert na.tor_binary_path == "/opt/tor/bin/tor"
        assert na.tor_socks_port == 9150
        assert na.mullvad_account_id_env == "MORDRED_MULLVAD_ACCOUNT"
        assert na.mullvad_relay_country == "jp"
        assert na.mullvad_killswitch is True

    def test_empty_mullvad_account_yields_blank_env_ref(self) -> None:
        """User leaves Mullvad password blank → ``mullvad_account_id_env`` is
        still the canonical env-var name; the writer will see an empty value
        and decide whether to write the .env line."""
        prompts = _ScriptedPromptIO(
            answers=[
                *self._BASE_ANSWERS,
                "clearnet",
                "/usr/bin/tor",
                "9050",
                "",  # empty password
                "auto",
                False,
            ]
        )
        result = collect_answers(prompts)
        na = result.network_answers  # type: ignore[attr-defined]
        assert na.mullvad_account_id_env == "MORDRED_MULLVAD_ACCOUNT"
        # The actual secret is captured separately for the EnvFileWriter
        # (the prompts.seen record carries it). ConfigureResult only carries
        # the env-var reference.

    def test_prompt_order_now_includes_six_network_labels(self) -> None:
        """Label-order regression: the 6 new network labels come AFTER the
        existing 7 Phase 1/Phase 2 prompts so snapshot tests that depend on
        the leading prompts continue to pass."""
        prompts = _ScriptedPromptIO(
            answers=[*self._BASE_ANSWERS, "clearnet", "/usr/bin/tor", "9050", "", "auto", False]
        )
        collect_answers(prompts)
        labels = [label for _, label, _ in prompts.seen]
        # First 7 are unchanged (Phase 1 / Phase 2).
        assert labels[:7] == [
            "Mordred policy mode",
            "Allow cloud LLM providers (passes through provider override)?",
            "Cloud provider allowlist (comma-separated; empty = none)",
            "Local LLM endpoint URL (Phase 2)",
            "Local LLM model id (Phase 2)",
            "On cloud LLM attempt under strict mode (Phase 2)",
            "Agent harness primary (Phase 2; strict mode refuses if a known harness)",
        ]
        # Next 6 are the new network prompts.
        assert labels[7:] == [
            "Default network path",
            "Tor binary path",
            "Tor SOCKS port",
            "Mullvad account number (stored in ~/.hermes/.env)",
            "Mullvad relay country (`auto` or 2-letter code)",
            "Mullvad killswitch (lockdown-mode)",
        ]

    def test_tor_socks_port_coerced_to_int(self) -> None:
        """The text prompt returns a string; collect_answers must coerce."""
        prompts = _ScriptedPromptIO(answers=[*self._BASE_ANSWERS, "tor", "/usr/bin/tor", "9150", "", "auto", False])
        result = collect_answers(prompts)
        assert result.network_answers.tor_socks_port == 9150  # type: ignore[attr-defined]
        assert isinstance(result.network_answers.tor_socks_port, int)  # type: ignore[attr-defined]

    def test_invalid_tor_socks_port_falls_back_to_default(self) -> None:
        """A non-numeric port answer falls back to 9050 with a warning rather
        than aborting the whole configure flow."""
        prompts = _ScriptedPromptIO(
            answers=[*self._BASE_ANSWERS, "tor", "/usr/bin/tor", "not-a-port", "", "auto", False]
        )
        result = collect_answers(prompts)
        assert result.network_answers.tor_socks_port == 9050  # type: ignore[attr-defined]
