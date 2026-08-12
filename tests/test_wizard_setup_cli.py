"""Tests for ``hermes-mordred setup`` -- the one-command orchestrator.

Conventions mirror the sibling wizard test suites (``test_wizard_status_cli.py``,
``test_wizard_keyvault_native_cli.py``, ``test_wizard_network_init.py``):
direct function calls with ``home=tmp_path`` (no env vars unless the test is
specifically about one), a scripted :class:`PromptIO` double for interactive
flows, ``_RefusingPromptIO`` for never-prompt assertions, and monkeypatching
the ``setup_cli._probe_*`` / ``_run_*`` / ``_resolve_step_*`` seams so each
concern (orchestration order, a single step's decision logic, a real on-disk
probe) can be tested in isolation.
"""

from __future__ import annotations

import argparse
import hashlib
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.keyvault import _native_key_id, _storage
from mordred_hermes.wizard import cli, configure, setup_cli
from mordred_hermes.wizard._prompt_io import NonInteractiveAbort, _RefusingPromptIO
from mordred_hermes.wizard.encryption_cli import WorkspacePaths
from mordred_hermes.wizard.policy_writer import PolicyWriter

_STEP_HERMES = setup_cli._STEP_HERMES
_STEP_CONFIGURE = setup_cli._STEP_CONFIGURE
_STEP_NETWORK = setup_cli._STEP_NETWORK
_STEP_HARDWARE_HELPER = setup_cli._STEP_HARDWARE_HELPER
_STEP_KEYVAULT = setup_cli._STEP_KEYVAULT
_STEP_ENV_ENCRYPTION = setup_cli._STEP_ENV_ENCRYPTION

_ALL_STEPS = (
    _STEP_HERMES,
    _STEP_CONFIGURE,
    _STEP_NETWORK,
    _STEP_HARDWARE_HELPER,
    _STEP_KEYVAULT,
    _STEP_ENV_ENCRYPTION,
)

# --------------------------------------------------------------------------- #
# Test doubles + fixtures                                                     #
# --------------------------------------------------------------------------- #


@dataclass
class _DefaultEchoPromptIO:
    """Returns the supplied default for every prompt (simulates pressing Enter)."""

    def ask_choice(
        self,
        label: str,
        choices: Sequence[str],
        default: str,
        *,
        descriptions: Mapping[str, str] | None = None,
    ) -> str:
        return default

    def ask_text(self, label: str, default: str = "", *, description: str | None = None) -> str:
        return default

    def ask_bool(self, label: str, default: bool, *, description: str | None = None) -> bool:
        return default

    def ask_multi(self, label: str, choices: Sequence[str], default: Sequence[str] = ()) -> tuple[str, ...]:
        return tuple(default)

    def ask_password(self, label: str, default: str = "", *, description: str | None = None) -> str:
        return default


@dataclass
class _RecordingBoolPromptIO:
    """Records the ``(label, default)`` of every ``ask_bool`` call; other prompts fail the test."""

    answer: bool
    asked: list[tuple[str, bool]] = field(default_factory=list)

    def ask_choice(self, label: str, choices: Any, default: str, **kwargs: Any) -> str:
        raise AssertionError(f"unexpected ask_choice({label!r})")

    def ask_text(self, label: str, default: str = "", **kwargs: Any) -> str:
        raise AssertionError(f"unexpected ask_text({label!r})")

    def ask_bool(self, label: str, default: bool, *, description: str | None = None) -> bool:
        self.asked.append((label, default))
        return self.answer

    def ask_multi(self, label: str, choices: Any, default: Any = ()) -> tuple[str, ...]:
        raise AssertionError(f"unexpected ask_multi({label!r})")

    def ask_password(self, label: str, default: str = "", **kwargs: Any) -> str:
        raise AssertionError(f"unexpected ask_password({label!r})")


@dataclass
class _FakeSetupRunner:
    """Records every ``run(non_interactive=...)`` call; returns a fixed ``rc``."""

    rc: int = 0
    calls: list[bool] = field(default_factory=list)

    def run(self, *, non_interactive: bool) -> int:
        self.calls.append(non_interactive)
        return self.rc


class _RaisingSetupRunner:
    """A :class:`configure.SetupRunner` that fails the test if ever invoked."""

    def run(self, *, non_interactive: bool) -> int:
        raise AssertionError("setup_runner.run() must not be called")


def _raiser(message: str) -> Callable[..., Any]:
    """A keyword-only callable that fails the test if invoked -- for asserting a seam is never called."""

    def _fn(**kwargs: object) -> Any:
        raise AssertionError(message)

    return _fn


def _raise_non_interactive_abort(**kwargs: object) -> Any:
    """Simulates a delegated command aborting on a would-be prompt under ``--non-interactive``."""
    raise NonInteractiveAbort("simulated: a prompt would have been required")


def _workspace(tmp_path: Path) -> WorkspacePaths:
    return WorkspacePaths(
        image=tmp_path / "ws" / "img.sparsebundle",
        blob=tmp_path / "ws" / "passphrase.wrapped",
        mount=tmp_path / "ws-mnt",
    )


def _policy_writer(tmp_path: Path) -> PolicyWriter:
    return PolicyWriter(
        config_path=tmp_path / "config.yaml",
        policy_json_path=tmp_path / "mordred" / "policy.json",
        mordred_dir=tmp_path / "mordred",
    )


def _run_setup(
    tmp_path: Path,
    *,
    platform: str = "darwin",
    prompt_io: Any,
    options: setup_cli.SetupOptions,
    policy_writer: PolicyWriter | None = None,
    setup_runner: Any = None,
) -> int:
    return setup_cli.run_setup(
        home=tmp_path,
        root=_storage.resolve_keyvault_dir(tmp_path),
        platform=platform,
        workspace=_workspace(tmp_path),
        prompt_io=prompt_io,
        policy_writer=policy_writer if policy_writer is not None else _policy_writer(tmp_path),
        setup_runner=setup_runner if setup_runner is not None else _RaisingSetupRunner(),
        options=options,
    )


def _force_steps_done(monkeypatch: pytest.MonkeyPatch, *names: str) -> None:
    """Monkeypatch the given ``_resolve_step_*`` seams to report ``"done"`` immediately.

    Isolates a later step's behaviour from the earlier steps' own decision
    logic -- those are covered by their own dedicated tests.
    """
    attr_by_step = {
        _STEP_HERMES: "_resolve_step_hermes",
        _STEP_CONFIGURE: "_resolve_step_configure",
        _STEP_NETWORK: "_resolve_step_network",
        _STEP_HARDWARE_HELPER: "_resolve_step_hardware_helper",
        _STEP_KEYVAULT: "_resolve_step_keyvault",
        _STEP_ENV_ENCRYPTION: "_resolve_step_env_encryption",
    }
    for name in names:
        attr = attr_by_step[name]

        def _resolve(name: str = name, **kwargs: object) -> setup_cli.StepResult:
            return setup_cli.StepResult(name, "done", "forced done for test isolation")

        monkeypatch.setattr(setup_cli, attr, _resolve)


def _build_keyvault(home: Path, keys: dict[str, bytes]) -> Path:
    """Materialize a keyvault under ``home`` with the given ``{key_id: digest}``."""
    root = _storage.resolve_keyvault_dir(home)
    _storage.ensure_layout(root)
    meta = _storage.load_meta(root)
    for key_id, digest in keys.items():
        h = hashlib.sha256(key_id.encode("utf-8")).hexdigest()[:16]
        meta["keys"][h] = {"key_id": key_id, "created_at": "2026-06-11T00:00:00Z"}
        _storage.atomic_write(root / "digests" / f"{h}.commit", digest)
    _storage.save_meta(root, meta)
    return root


# --------------------------------------------------------------------------- #
# Orchestration -- run_setup()                                                #
# --------------------------------------------------------------------------- #


class TestRunSetupOrchestration:
    def test_everything_complete_reports_all_done_exit_0_no_runner_called(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(setup_cli, "_probe_hermes", lambda **kw: (True, "hermes ready"))
        monkeypatch.setattr(setup_cli, "_probe_configure", lambda **kw: (True, "configure ready"))
        monkeypatch.setattr(setup_cli, "_probe_network", lambda **kw: (True, "network ready"))
        monkeypatch.setattr(setup_cli, "_probe_se_helper", lambda: True)
        monkeypatch.setattr(setup_cli, "_probe_tpm_helper", lambda: True)
        monkeypatch.setattr(setup_cli, "_probe_keyvault", lambda **kw: ("initialised", "1 key"))
        monkeypatch.setattr(setup_cli, "_probe_env_encryption", lambda **kw: (True, "env ready"))

        for seam in ("_run_configure", "_run_network", "_run_se_helper", "_run_tpm_helper"):
            monkeypatch.setattr(setup_cli, seam, _raiser(f"{seam} must not be called"))
        monkeypatch.setattr(setup_cli, "_run_keyvault_init", _raiser("_run_keyvault_init must not be called"))
        monkeypatch.setattr(setup_cli, "_run_env_encryption", _raiser("_run_env_encryption must not be called"))

        rc = _run_setup(tmp_path, prompt_io=_RefusingPromptIO(), options=setup_cli.SetupOptions())

        assert rc == 0
        out = capsys.readouterr().out
        for step in _ALL_STEPS:
            assert step in out
        assert "already done" in out
        # The final status dashboard prints too (run wasn't stopped early).
        assert "Mordred status:" in out

    def test_fresh_darwin_system_runs_steps_in_fixed_order(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        call_order: list[str] = []
        attr_by_step = {
            _STEP_HERMES: "_resolve_step_hermes",
            _STEP_CONFIGURE: "_resolve_step_configure",
            _STEP_NETWORK: "_resolve_step_network",
            _STEP_HARDWARE_HELPER: "_resolve_step_hardware_helper",
            _STEP_KEYVAULT: "_resolve_step_keyvault",
            _STEP_ENV_ENCRYPTION: "_resolve_step_env_encryption",
        }
        for step, attr in attr_by_step.items():

            def _resolve(step: str = step, **kwargs: object) -> setup_cli.StepResult:
                call_order.append(step)
                return setup_cli.StepResult(step, "ran", "mock")

            monkeypatch.setattr(setup_cli, attr, _resolve)

        rc = _run_setup(tmp_path, platform="darwin", prompt_io=_RefusingPromptIO(), options=setup_cli.SetupOptions())

        assert call_order == list(_ALL_STEPS)
        assert rc == 0

    def test_keyvault_blocked_corrupt_meta_stops_run_without_touching_disk(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # ensure_layout() first (mode 0o700 dir, valid meta.json) so the
        # directory-mode gate passes and the corrupt *body* is what actually
        # trips -- a bare mkdir() leaves the dir at the umask default (0o755),
        # which fails _check_dir_mode's own 0o700 requirement first and would
        # silently test the wrong code path.
        root = _storage.resolve_keyvault_dir(tmp_path)
        _storage.ensure_layout(root)
        meta_path = root / "meta.json"
        meta_path.write_text("{not json", encoding="utf-8")
        meta_path.chmod(0o600)
        before = meta_path.read_bytes()

        _force_steps_done(monkeypatch, _STEP_HERMES, _STEP_CONFIGURE, _STEP_NETWORK, _STEP_HARDWARE_HELPER)
        monkeypatch.setattr(setup_cli, "_run_keyvault_init", _raiser("_run_keyvault_init must not be called"))

        rc = _run_setup(tmp_path, prompt_io=_RefusingPromptIO(), options=setup_cli.SetupOptions())

        assert rc == 1
        assert meta_path.read_bytes() == before
        out = capsys.readouterr().out
        # Corrupt meta.json is repaired by hand (mirrors _refuse_if_initialised's
        # wording); "keyvault reset" is the pending/residual-journal remedy, not this one.
        assert "repair or remove it" in out
        assert _STEP_ENV_ENCRYPTION not in out  # stopped before the next step

    def test_keyvault_blocked_pending_native_key_journal_stops_run_without_touching_disk(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        root = _build_keyvault(tmp_path, {"default": b"\x01" * 32})
        meta = _storage.load_meta(root)
        meta[_native_key_id.PENDING_NATIVE_KEY_FIELD] = {
            "key_id": "interrupted",
            _native_key_id.NATIVE_KEY_ID_FIELD: _native_key_id.scoped_native_key_id(root, "interrupted"),
        }
        _storage.save_meta(root, meta)
        before = (root / "meta.json").read_bytes()

        _force_steps_done(monkeypatch, _STEP_HERMES, _STEP_CONFIGURE, _STEP_NETWORK, _STEP_HARDWARE_HELPER)
        monkeypatch.setattr(setup_cli, "_run_keyvault_init", _raiser("_run_keyvault_init must not be called"))

        rc = _run_setup(tmp_path, prompt_io=_RefusingPromptIO(), options=setup_cli.SetupOptions())

        assert rc == 1
        assert (root / "meta.json").read_bytes() == before
        out = capsys.readouterr().out
        assert "keyvault reset" in out

    def test_resume_keyvault_failure_then_success_continues_to_env_step(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        _force_steps_done(monkeypatch, _STEP_HERMES, _STEP_CONFIGURE, _STEP_NETWORK, _STEP_HARDWARE_HELPER)
        monkeypatch.setattr(setup_cli, "_run_keyvault_init", lambda **kw: 1)  # fails
        env_calls: list[bool] = []

        def _env_step(**kwargs: object) -> setup_cli.StepResult:
            env_calls.append(True)
            return setup_cli.StepResult(_STEP_ENV_ENCRYPTION, "ran", "mock")

        monkeypatch.setattr(setup_cli, "_resolve_step_env_encryption", _env_step)

        rc1 = _run_setup(
            tmp_path,
            prompt_io=_RefusingPromptIO(),
            options=setup_cli.SetupOptions(unattended_keys=False),
        )
        assert rc1 == 1
        assert env_calls == []  # never reached: the run stopped at the failed keyvault step

        # Second run: keyvault now reports initialised (probe-driven resume).
        monkeypatch.setattr(setup_cli, "_probe_keyvault", lambda **kw: ("initialised", "1 key"))

        rc2 = _run_setup(tmp_path, prompt_io=_RefusingPromptIO(), options=setup_cli.SetupOptions())
        assert rc2 == 0
        assert env_calls == [True]  # earlier steps stayed "done"; the run continued past keyvault

    def test_non_interactive_keyvault_absent_exits_1_names_keyvault_init_never_prompts(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _force_steps_done(monkeypatch, _STEP_HERMES, _STEP_CONFIGURE, _STEP_NETWORK, _STEP_HARDWARE_HELPER)
        monkeypatch.setattr(setup_cli, "_run_keyvault_init", _raiser("_run_keyvault_init must not be called"))

        # `_RefusingPromptIO` raises on any prompt method; if the keyvault step
        # ever tried to prompt, this call would fail with an unhandled
        # NonInteractiveAbort instead of returning cleanly -- that IS the proof.
        rc = _run_setup(
            tmp_path,
            prompt_io=_RefusingPromptIO(),
            options=setup_cli.SetupOptions(non_interactive=True),
        )

        assert rc == 1
        out = capsys.readouterr().out
        assert "hermes-mordred keyvault init" in out

    def test_win32_platform_is_unsupported_and_stops_before_keyvault(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _force_steps_done(monkeypatch, _STEP_HERMES, _STEP_CONFIGURE, _STEP_NETWORK)
        monkeypatch.setattr(setup_cli, "_resolve_step_keyvault", _raiser("keyvault step must not run"))

        rc = _run_setup(tmp_path, platform="win32", prompt_io=_RefusingPromptIO(), options=setup_cli.SetupOptions())

        assert rc == 1
        out = capsys.readouterr().out
        assert "not supported" in out.lower()
        # The keyvault step's own report line never appears -- the raiser above
        # already proves _resolve_step_keyvault was never called (it would have
        # failed this test with an AssertionError otherwise). A plain substring
        # check for "keyvault" would false-positive on the hardware-helper
        # step's own detail text ("hardware keyvault requires macOS...").
        assert f"\n  {_STEP_KEYVAULT} " not in out

    def test_network_manual_in_non_interactive_mode_does_not_stop_the_run(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        _force_steps_done(monkeypatch, _STEP_HERMES, _STEP_CONFIGURE)
        # _resolve_step_network is left real: config.yaml has no network section
        # (probe incomplete) and prompt_io refuses -> "manual", must not stop.
        hw_calls: list[bool] = []

        def _hw_step(**kwargs: object) -> setup_cli.StepResult:
            hw_calls.append(True)
            return setup_cli.StepResult(_STEP_HARDWARE_HELPER, "done", "mock")

        monkeypatch.setattr(setup_cli, "_resolve_step_hardware_helper", _hw_step)
        monkeypatch.setattr(setup_cli, "_probe_keyvault", lambda **kw: ("initialised", "1 key"))
        monkeypatch.setattr(setup_cli, "_probe_env_encryption", lambda **kw: (True, "env ready"))

        rc = _run_setup(
            tmp_path,
            prompt_io=_RefusingPromptIO(),
            options=setup_cli.SetupOptions(non_interactive=True),
        )

        assert hw_calls == [True]  # the run continued past the network "manual" step
        assert rc == 1  # a "manual" step still makes the overall run non-clean


# --------------------------------------------------------------------------- #
# Step 1 -- hermes                                                            #
# --------------------------------------------------------------------------- #


class TestHermesStep:
    def test_probe_incomplete_when_hermes_missing_from_path(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr("shutil.which", lambda name: None)
        complete, detail = setup_cli._probe_hermes(home=tmp_path)
        assert complete is False
        assert "PATH" in detail

    def test_probe_complete_when_hermes_on_path_and_config_present(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr("shutil.which", lambda name: "/usr/local/bin/hermes" if name == "hermes" else None)
        (tmp_path / "config.yaml").write_text("plugins: {}\n", encoding="utf-8")
        complete, _ = setup_cli._probe_hermes(home=tmp_path)
        assert complete is True

    def test_skip_flag_skips_without_running(self, tmp_path: Path) -> None:
        result = setup_cli._resolve_step_hermes(
            home=tmp_path,
            prompt_io=_RefusingPromptIO(),
            setup_runner=_RaisingSetupRunner(),
            options=setup_cli.SetupOptions(skip_hermes_setup=True),
        )
        assert result.action == "skipped"

    def test_non_interactive_incomplete_runs_setup_runner_non_interactively(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr("shutil.which", lambda name: None)
        runner = _FakeSetupRunner(rc=0)
        result = setup_cli._resolve_step_hermes(
            home=tmp_path,
            prompt_io=_RefusingPromptIO(),
            setup_runner=runner,
            options=setup_cli.SetupOptions(non_interactive=True),
        )
        assert result.action == "ran"
        assert runner.calls == [True]

    def test_non_zero_exit_warns_and_continues_as_ran(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr("shutil.which", lambda name: None)
        runner = _FakeSetupRunner(rc=7)
        result = setup_cli._resolve_step_hermes(
            home=tmp_path,
            prompt_io=_RefusingPromptIO(),
            setup_runner=runner,
            options=setup_cli.SetupOptions(non_interactive=True),
        )
        assert result.action == "ran"
        assert "7" in result.detail

    def test_interactive_declines_prompt_is_skipped(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr("shutil.which", lambda name: None)

        class _DeclinePromptIO(_DefaultEchoPromptIO):
            def ask_bool(self, label: str, default: bool, *, description: str | None = None) -> bool:
                return False

        result = setup_cli._resolve_step_hermes(
            home=tmp_path,
            prompt_io=_DeclinePromptIO(),
            setup_runner=_RaisingSetupRunner(),
            options=setup_cli.SetupOptions(),
        )
        assert result.action == "skipped"

    def test_with_hermes_setup_forces_run_without_asking_even_when_done(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr("shutil.which", lambda name: "/usr/local/bin/hermes" if name == "hermes" else None)
        (tmp_path / "config.yaml").write_text("plugins: {}\n", encoding="utf-8")
        runner = _FakeSetupRunner(rc=0)

        class _NeverAskPromptIO(_DefaultEchoPromptIO):
            def ask_bool(self, label: str, default: bool, *, description: str | None = None) -> bool:
                raise AssertionError("must not ask when --with-hermes-setup forces the run")

        result = setup_cli._resolve_step_hermes(
            home=tmp_path,
            prompt_io=_NeverAskPromptIO(),
            setup_runner=runner,
            options=setup_cli.SetupOptions(with_hermes_setup=True),
        )
        assert result.action == "ran"
        assert runner.calls == [False]


# --------------------------------------------------------------------------- #
# Step 2 -- configure                                                         #
# --------------------------------------------------------------------------- #


class TestConfigureStep:
    def test_probe_incomplete_without_config_yaml(self, tmp_path: Path) -> None:
        complete, _ = setup_cli._probe_configure(policy_writer=_policy_writer(tmp_path))
        assert complete is False

    def test_probe_incomplete_with_config_yaml_but_no_policy_json(self, tmp_path: Path) -> None:
        pw = _policy_writer(tmp_path)
        pw.config_path.parent.mkdir(parents=True, exist_ok=True)
        pw.config_path.write_text("plugins: {}\n", encoding="utf-8")
        complete, detail = setup_cli._probe_configure(policy_writer=pw)
        assert complete is False
        assert "policy.json" in detail

    def test_probe_is_satisfied_by_a_real_configure_run(self, tmp_path: Path) -> None:
        """Regression guard for the probe/writer alignment: a genuine
        `configure` run (even with every prompt answered by its default) must
        always satisfy the probe -- otherwise `setup` would loop forever
        re-running `configure` on every invocation."""
        pw = _policy_writer(tmp_path)
        complete, detail = setup_cli._probe_configure(policy_writer=pw)
        assert complete is False, detail

        configure.run(
            setup_runner=_RaisingSetupRunner(),
            prompt_io=_DefaultEchoPromptIO(),
            policy_writer=pw,
            non_interactive=False,
            with_hermes_setup=False,
        )

        complete, detail = setup_cli._probe_configure(policy_writer=pw)
        assert complete is True, detail

    def test_non_interactive_incomplete_is_manual_and_does_not_write(self, tmp_path: Path) -> None:
        pw = _policy_writer(tmp_path)
        result = setup_cli._resolve_step_configure(
            prompt_io=_RefusingPromptIO(),
            policy_writer=pw,
            setup_runner=_RaisingSetupRunner(),
            options=setup_cli.SetupOptions(non_interactive=True),
        )
        assert result.action == "manual"
        assert "configure" in result.detail
        assert not pw.config_path.exists()
        assert not pw.policy_json_path.exists()

    def test_write_failure_is_failed(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        def _boom(**kwargs: object) -> None:
            raise OSError("disk full")

        monkeypatch.setattr(setup_cli, "_run_configure", _boom)
        result = setup_cli._resolve_step_configure(
            prompt_io=_DefaultEchoPromptIO(),
            policy_writer=_policy_writer(tmp_path),
            setup_runner=_RaisingSetupRunner(),
            options=setup_cli.SetupOptions(),
        )
        assert result.action == "failed"
        assert "disk full" in result.detail

    def test_partial_state_missing_llm_guard_section_is_incomplete(self, tmp_path: Path) -> None:
        pw = _policy_writer(tmp_path)
        pw.config_path.parent.mkdir(parents=True, exist_ok=True)
        pw.config_path.write_text(
            "plugins:\n  mordred_privacy_check:\n    policy: lenient\n  enabled: [mordred_privacy_check]\n",
            encoding="utf-8",
        )
        pw.policy_json_path.parent.mkdir(parents=True, exist_ok=True)
        pw.policy_json_path.write_text("{}", encoding="utf-8")
        complete, detail = setup_cli._probe_configure(policy_writer=pw)
        assert complete is False
        assert "llm_guard" in detail


# --------------------------------------------------------------------------- #
# Step 3 -- network                                                           #
# --------------------------------------------------------------------------- #


class TestNetworkStep:
    def test_probe_incomplete_without_section(self, tmp_path: Path) -> None:
        complete, _ = setup_cli._probe_network(config_path=tmp_path / "config.yaml")
        assert complete is False

    def test_probe_complete_with_valid_default_path(self, tmp_path: Path) -> None:
        (tmp_path / "config.yaml").write_text("plugins:\n  mordred_network:\n    default_path: tor\n", encoding="utf-8")
        complete, detail = setup_cli._probe_network(config_path=tmp_path / "config.yaml")
        assert complete is True
        assert "tor" in detail

    def test_probe_incomplete_with_invalid_default_path_value(self, tmp_path: Path) -> None:
        (tmp_path / "config.yaml").write_text(
            "plugins:\n  mordred_network:\n    default_path: not-a-real-path\n", encoding="utf-8"
        )
        complete, _ = setup_cli._probe_network(config_path=tmp_path / "config.yaml")
        assert complete is False

    def test_non_interactive_incomplete_is_manual_and_continues(self, tmp_path: Path) -> None:
        pw = _policy_writer(tmp_path)
        result = setup_cli._resolve_step_network(prompt_io=_RefusingPromptIO(), policy_writer=pw)
        assert result.action == "manual"
        assert "network init" in result.detail

    def test_run_failure_is_failed(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr(setup_cli, "_run_network", lambda **kw: 1)
        pw = _policy_writer(tmp_path)
        result = setup_cli._resolve_step_network(prompt_io=_DefaultEchoPromptIO(), policy_writer=pw)
        assert result.action == "failed"


# --------------------------------------------------------------------------- #
# Step 4 -- hardware helper                                                   #
# --------------------------------------------------------------------------- #


class TestHardwareHelperStep:
    def test_darwin_probe_true_reports_done_without_running(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr(setup_cli, "_probe_se_helper", lambda: True)
        monkeypatch.setattr(setup_cli, "_run_se_helper", _raiser("must not run enable-se"))
        result = setup_cli._resolve_step_hardware_helper(home=tmp_path, platform="darwin")
        assert result.action == "done"

    def test_darwin_probe_false_runs_enable_se(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr(setup_cli, "_probe_se_helper", lambda: False)
        calls: list[dict[str, object]] = []
        monkeypatch.setattr(setup_cli, "_run_se_helper", lambda **kw: (calls.append(kw), 0)[-1])
        result = setup_cli._resolve_step_hardware_helper(home=tmp_path, platform="darwin")
        assert result.action == "ran"
        assert calls == [{"home": tmp_path}]

    def test_darwin_enable_se_failure_is_failed(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr(setup_cli, "_probe_se_helper", lambda: False)
        monkeypatch.setattr(setup_cli, "_run_se_helper", lambda **kw: 1)
        result = setup_cli._resolve_step_hardware_helper(home=tmp_path, platform="darwin")
        assert result.action == "failed"

    def test_linux_dispatches_to_tpm_probe_and_runner(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr(setup_cli, "_probe_tpm_helper", lambda: False)
        calls: list[dict[str, object]] = []
        monkeypatch.setattr(setup_cli, "_run_tpm_helper", lambda **kw: (calls.append(kw), 0)[-1])
        result = setup_cli._resolve_step_hardware_helper(home=tmp_path, platform="linux")
        assert result.action == "ran"
        assert calls == [{"home": tmp_path}]

    def test_win32_is_unsupported(self, tmp_path: Path) -> None:
        result = setup_cli._resolve_step_hardware_helper(home=tmp_path, platform="win32")
        assert result.action == "unsupported"


# --------------------------------------------------------------------------- #
# Step 5 -- keyvault                                                          #
# --------------------------------------------------------------------------- #


class TestKeyvaultProbe:
    def test_fresh_keyvault_dir_is_absent(self, tmp_path: Path) -> None:
        state, _ = setup_cli._probe_keyvault(home=tmp_path)
        assert state == "absent"

    def test_empty_layout_with_no_keys_is_absent(self, tmp_path: Path) -> None:
        _storage.ensure_layout(_storage.resolve_keyvault_dir(tmp_path))
        state, _ = setup_cli._probe_keyvault(home=tmp_path)
        assert state == "absent"

    def test_keys_present_is_initialised(self, tmp_path: Path) -> None:
        _build_keyvault(tmp_path, {"default": b"\x01" * 32, "payments": b"\x02" * 32})
        state, detail = setup_cli._probe_keyvault(home=tmp_path)
        assert state == "initialised"
        assert "2 key" in detail

    def test_corrupt_meta_is_blocked(self, tmp_path: Path) -> None:
        # ensure_layout() first so the dir is mode 0o700 (passing the
        # directory-mode gate) and only the meta.json *body* is corrupt.
        root = _storage.resolve_keyvault_dir(tmp_path)
        _storage.ensure_layout(root)
        meta = root / "meta.json"
        meta.write_text("{not json", encoding="utf-8")
        meta.chmod(0o600)
        state, detail = setup_cli._probe_keyvault(home=tmp_path)
        assert state == "blocked"
        assert "corrupt" in detail.lower()

    def test_unreadable_dir_mode_is_blocked(self, tmp_path: Path) -> None:
        root = _storage.resolve_keyvault_dir(tmp_path)
        root.mkdir(parents=True)  # left at the umask default, not 0o700
        state, detail = setup_cli._probe_keyvault(home=tmp_path)
        assert state == "blocked"
        assert "unreadable" in detail.lower()

    def test_pending_native_key_journal_is_blocked(self, tmp_path: Path) -> None:
        root = _build_keyvault(tmp_path, {"default": b"\x01" * 32})
        meta = _storage.load_meta(root)
        meta[_native_key_id.PENDING_NATIVE_KEY_FIELD] = {
            "key_id": "interrupted",
            _native_key_id.NATIVE_KEY_ID_FIELD: _native_key_id.scoped_native_key_id(root, "interrupted"),
        }
        _storage.save_meta(root, meta)
        state, detail = setup_cli._probe_keyvault(home=tmp_path)
        assert state == "blocked"
        assert "keyvault reset" in detail

    @pytest.mark.parametrize("field_name", [_native_key_id.AUDIT_KEY_FIELD, _native_key_id.PENDING_AUDIT_KEY_FIELD])
    def test_residual_ownership_with_empty_keys_is_blocked(self, field_name: str, tmp_path: Path) -> None:
        root = _storage.resolve_keyvault_dir(tmp_path)
        _storage.ensure_layout(root)
        meta = _storage.load_meta(root)
        meta[field_name] = {"residual": True}
        _storage.save_meta(root, meta)
        state, detail = setup_cli._probe_keyvault(home=tmp_path)
        assert state == "blocked"
        assert "residual" in detail.lower()

    def test_pending_reset_journal_is_blocked(self, tmp_path: Path) -> None:
        root = _build_keyvault(tmp_path, {"default": b"\x01" * 32})
        with _storage.keyvault_lifecycle_lock(root):
            _storage.write_reset_journal(root, b"pending reset")
        state, detail = setup_cli._probe_keyvault(home=tmp_path)
        assert state == "blocked"
        assert "reset" in detail.lower()


class TestResolveUnattendedKeys:
    def test_unattended_flag_wins_regardless_of_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("MORDRED_SEKEY_UNATTENDED", raising=False)
        options = setup_cli.SetupOptions(unattended_keys=True)
        result = setup_cli._resolve_unattended_keys(options=options, prompt_io=_RefusingPromptIO())
        assert result is True

    def test_attended_flag_wins_over_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MORDRED_SEKEY_UNATTENDED", "1")
        options = setup_cli.SetupOptions(unattended_keys=False)
        result = setup_cli._resolve_unattended_keys(options=options, prompt_io=_RefusingPromptIO())
        assert result is False

    def test_env_true_without_flag_resolves_true(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MORDRED_SEKEY_UNATTENDED", "1")
        options = setup_cli.SetupOptions()
        result = setup_cli._resolve_unattended_keys(options=options, prompt_io=_RefusingPromptIO())
        assert result is True

    def test_interactive_no_flag_or_env_asks_with_default_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("MORDRED_SEKEY_UNATTENDED", raising=False)
        recorder = _RecordingBoolPromptIO(answer=True)
        options = setup_cli.SetupOptions()
        result = setup_cli._resolve_unattended_keys(options=options, prompt_io=recorder)
        assert result is True
        assert len(recorder.asked) == 1
        _, default = recorder.asked[0]
        assert default is False

    def test_non_interactive_no_flag_or_env_resolves_false_without_prompting(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("MORDRED_SEKEY_UNATTENDED", raising=False)
        options = setup_cli.SetupOptions(non_interactive=True)
        result = setup_cli._resolve_unattended_keys(options=options, prompt_io=_RefusingPromptIO())
        assert result is False


class TestKeyvaultStep:
    def test_initialised_is_done_without_running(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        _build_keyvault(tmp_path, {"default": b"\x01" * 32})
        monkeypatch.setattr(setup_cli, "_run_keyvault_init", _raiser("must not run init_keyvault"))
        result = setup_cli._resolve_step_keyvault(
            home=tmp_path, prompt_io=_RefusingPromptIO(), options=setup_cli.SetupOptions()
        )
        assert result.action == "done"

    def test_absent_runs_init_with_resolved_unattended(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        calls: list[dict[str, object]] = []
        monkeypatch.setattr(setup_cli, "_run_keyvault_init", lambda **kw: (calls.append(kw), 0)[-1])
        result = setup_cli._resolve_step_keyvault(
            home=tmp_path,
            prompt_io=_RefusingPromptIO(),
            options=setup_cli.SetupOptions(unattended_keys=True, store_seed_for_hd=False),
        )
        assert result.action == "ran"
        assert calls == [
            {"home": tmp_path, "prompt_io": calls[0]["prompt_io"], "store_seed_for_hd": False, "unattended": True}
        ]

    def test_absent_run_failure_is_failed(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr(setup_cli, "_run_keyvault_init", lambda **kw: 1)
        result = setup_cli._resolve_step_keyvault(
            home=tmp_path,
            prompt_io=_RefusingPromptIO(),
            options=setup_cli.SetupOptions(unattended_keys=False),
        )
        assert result.action == "failed"


# --------------------------------------------------------------------------- #
# Step 6 -- env encryption                                                    #
# --------------------------------------------------------------------------- #


class TestEnvEncryptionStep:
    def test_fresh_system_with_no_plaintext_env_is_benign_not_failed(self, tmp_path: Path) -> None:
        root = _storage.resolve_keyvault_dir(tmp_path)
        result = setup_cli._resolve_step_env_encryption(
            home=tmp_path, root=root, platform="darwin", prompt_io=_RefusingPromptIO()
        )
        assert result.action == "ran"
        assert "nothing to encrypt" in result.detail.lower() or ".env" in result.detail
        assert not (tmp_path / ".env").exists()

    def test_non_interactive_with_plaintext_and_no_vault_is_manual(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # _run_env_encryption is mocked to raise NonInteractiveAbort directly --
        # exactly what a real, non-interactive `enable()` does when it must
        # create the vault (a one-time recovery-passphrase prompt). This
        # isolates _resolve_step_env_encryption's own exception-handling
        # decision from env_decrypt_cli's real device-key-store chain, which
        # needs a real Keychain / pyobjc on macOS to even attempt.
        (tmp_path / ".env").write_text("FOO=bar\n", encoding="utf-8")
        root = _storage.resolve_keyvault_dir(tmp_path)
        monkeypatch.setattr(setup_cli, "_probe_env_encryption", lambda **kw: (False, "not enrolled"))
        monkeypatch.setattr(setup_cli, "_run_env_encryption", _raise_non_interactive_abort)
        result = setup_cli._resolve_step_env_encryption(
            home=tmp_path, root=root, platform="darwin", prompt_io=_RefusingPromptIO()
        )
        assert result.action == "manual"
        assert "encryption enable env" in result.detail

    def test_run_failure_is_failed(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        (tmp_path / ".env").write_text("FOO=bar\n", encoding="utf-8")
        root = _storage.resolve_keyvault_dir(tmp_path)
        monkeypatch.setattr(setup_cli, "_probe_env_encryption", lambda **kw: (False, "not enrolled"))
        monkeypatch.setattr(setup_cli, "_run_env_encryption", lambda **kw: 1)
        result = setup_cli._resolve_step_env_encryption(
            home=tmp_path, root=root, platform="darwin", prompt_io=_DefaultEchoPromptIO()
        )
        assert result.action == "failed"


# --------------------------------------------------------------------------- #
# render_report                                                               #
# --------------------------------------------------------------------------- #


class TestRenderReport:
    def test_renders_every_result(self) -> None:
        results = [
            setup_cli.StepResult(_STEP_HERMES, "done", "already there"),
            setup_cli.StepResult(_STEP_KEYVAULT, "blocked", "needs `hermes-mordred keyvault reset`"),
        ]
        text = setup_cli.render_report(results)
        assert "Setup summary:" in text
        assert _STEP_HERMES in text
        assert "already there" in text
        assert "BLOCKED" in text
        assert "keyvault reset" in text

    def test_unknown_action_degrades_to_raw_token(self) -> None:
        result = setup_cli.StepResult("mystery", "future-action", "detail")  # type: ignore[arg-type]
        text = setup_cli.render_report([result])
        assert "future-action" in text


# --------------------------------------------------------------------------- #
# argparse wiring                                                             #
# --------------------------------------------------------------------------- #


class TestCliWiring:
    def test_setup_command_is_wired(self) -> None:
        parser = argparse.ArgumentParser(prog="hermes-mordred")
        cli._setup_subparser(parser)
        ns = parser.parse_args(["setup", "--non-interactive"])
        assert ns.non_interactive is True
        assert ns.with_hermes_setup is False
        assert ns.skip_hermes_setup is False
        assert ns.unattended_keys is None
        assert ns.store_seed_for_hd is True
        assert callable(ns.func)

    def test_hermes_setup_flags_are_mutually_exclusive(self) -> None:
        parser = argparse.ArgumentParser(prog="hermes-mordred")
        cli._setup_subparser(parser)
        with pytest.raises(SystemExit):
            parser.parse_args(["setup", "--with-hermes-setup", "--skip-hermes-setup"])

    def test_unattended_key_flags_are_mutually_exclusive(self) -> None:
        parser = argparse.ArgumentParser(prog="hermes-mordred")
        cli._setup_subparser(parser)
        with pytest.raises(SystemExit):
            parser.parse_args(["setup", "--unattended-keys", "--attended-keys"])

    def test_seed_storage_flags_are_mutually_exclusive(self) -> None:
        parser = argparse.ArgumentParser(prog="hermes-mordred")
        cli._setup_subparser(parser)
        with pytest.raises(SystemExit):
            parser.parse_args(["setup", "--store-seed-for-hd", "--paper-only"])

    def test_unattended_keys_flag_resolves_to_explicit_bool(self) -> None:
        parser = argparse.ArgumentParser(prog="hermes-mordred")
        cli._setup_subparser(parser)
        ns = parser.parse_args(["setup", "--unattended-keys"])
        assert ns.unattended_keys is True
        ns = parser.parse_args(["setup", "--attended-keys"])
        assert ns.unattended_keys is False


# --------------------------------------------------------------------------- #
# cli_setup() -- the production argparse adapter                             #
# --------------------------------------------------------------------------- #


class TestCliSetupAdapter:
    def test_resolves_production_defaults_and_delegates_to_run_setup(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """``cli_setup`` must resolve the same production defaults
        ``status_cli.cli_status`` does, build the right :class:`SetupOptions`
        from the parsed flags, and pick ``_RefusingPromptIO`` iff
        ``--non-interactive`` was given."""
        monkeypatch.setattr(setup_cli, "_hermes_home", lambda: tmp_path)
        monkeypatch.setattr(setup_cli, "resolve_root", lambda override: tmp_path / "mordred" / "keyvault")
        monkeypatch.setattr(setup_cli, "_default_workspace_paths", lambda: _workspace(tmp_path))

        captured: dict[str, Any] = {}

        def _fake_run_setup(**kwargs: object) -> int:
            captured.update(kwargs)
            return 0

        monkeypatch.setattr(setup_cli, "run_setup", _fake_run_setup)

        args = argparse.Namespace(
            non_interactive=True,
            with_hermes_setup=False,
            skip_hermes_setup=True,
            unattended_keys=True,
            store_seed_for_hd=False,
        )
        rc = setup_cli.cli_setup(args)

        assert rc == 0
        assert captured["home"] == tmp_path
        assert isinstance(captured["prompt_io"], _RefusingPromptIO)
        options = captured["options"]
        assert isinstance(options, setup_cli.SetupOptions)
        assert options.non_interactive is True
        assert options.skip_hermes_setup is True
        assert options.unattended_keys is True
        assert options.store_seed_for_hd is False
        assert isinstance(captured["policy_writer"], PolicyWriter)
