"""``hermes mordred configure`` -- interactive Mordred setup.

Two-step flow:

1. Delegate first-run Hermes setup via ``subprocess.run(["hermes", "setup", ...])``
   (Hermes uses its own curses TUI -- ``hermes_cli/main.py:8704``).
2. Collect Mordred-specific prompts (policy mode, cloud allowlist, local LLM
   endpoint reservations for Phase 2) via :class:`PromptIO`.
3. Persist via :class:`PolicyWriter` (writes ``~/.hermes/mordred/policy.json``
   and the ``plugins.mordred_privacy_check`` section of ``~/.hermes/config.yaml``).

Both side effects -- the Hermes setup spawn AND the prompt collection -- go
through Protocol-typed seams (:class:`SetupRunner`, :class:`PromptIO`) so
tests inject scripted doubles. Production impls (:class:`SubprocessSetupRunner`,
:class:`PromptToolkitIO`) wrap subprocess and prompt_toolkit respectively.

Phase 2 fields (``local_llm_endpoint``, ``local_llm_model_id``,
``cloud_attempt_action``) are collected here but NOT yet persisted -- the
:class:`PolicySnapshot` schema gains them when Phase 2 lands. Collecting
them now means existing users will not need to re-run ``configure``.
"""

from __future__ import annotations

import argparse
import logging
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from .policy_writer import PolicySnapshot, PolicyWriter

_LOG = logging.getLogger("mordred.wizard.configure")


# -----------------------------------------------------------------------------
# Protocols -- production wraps subprocess / prompt_toolkit, tests script.
# -----------------------------------------------------------------------------


class SetupRunner(Protocol):
    """Spawn ``hermes setup``. Return its exit code (0 = success)."""

    def run(self, *, non_interactive: bool) -> int: ...


class PromptIO(Protocol):
    """Collect Mordred-specific answers from the user.

    Production impl wraps ``prompt_toolkit``. Tests inject a scripted FIFO
    that pops pre-recorded answers per call -- nothing in this module
    touches a real TTY.
    """

    def ask_choice(self, label: str, choices: Sequence[str], default: str) -> str: ...
    def ask_text(self, label: str, default: str = "") -> str: ...
    def ask_bool(self, label: str, default: bool) -> bool: ...


# -----------------------------------------------------------------------------
# Production implementations.
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SubprocessSetupRunner:
    """Default :class:`SetupRunner` -- shells out to ``hermes setup``.

    Returns the child process exit code on success. Returns ``1`` (with
    a logged warning) if the ``hermes`` binary is missing from PATH so
    that callers do not crash with an unhandled :class:`FileNotFoundError`
    -- the Mordred prompt sequence still runs and the user gets a clean
    exit code rather than a stack trace.
    """

    def run(self, *, non_interactive: bool) -> int:
        cmd = ["hermes", "setup"]
        if non_interactive:
            cmd.append("--non-interactive")
        try:
            completed = subprocess.run(cmd, check=False)
        except FileNotFoundError:
            _LOG.warning("`hermes` executable not found on PATH; skipping `hermes setup` step")
            return 1
        return completed.returncode


class PromptToolkitIO:
    """Default :class:`PromptIO` -- thin wrapper around ``prompt_toolkit``.

    Lazy-imports prompt_toolkit so that the test impl never has to install
    it. ``radiolist_dialog`` is used for choices because it renders well in
    SSH / Docker / TTY-without-tput environments.
    """

    def ask_choice(self, label: str, choices: Sequence[str], default: str) -> str:
        try:
            from prompt_toolkit.shortcuts import radiolist_dialog
        except ImportError as e:
            raise RuntimeError(
                "prompt_toolkit is required for interactive `hermes mordred configure`; "
                "rerun with --non-interactive or install via `pip install prompt_toolkit`"
            ) from e
        values = [(c, c) for c in choices]
        result: str | None = radiolist_dialog(title=label, values=values, default=default).run()
        return result if result is not None else default

    def ask_text(self, label: str, default: str = "") -> str:
        try:
            from prompt_toolkit import prompt
        except ImportError as e:
            raise RuntimeError("prompt_toolkit is required for interactive `hermes mordred configure`") from e
        suffix = f" [{default}]" if default else ""
        answer = prompt(f"{label}{suffix}: ")
        return answer.strip() or default

    def ask_bool(self, label: str, default: bool) -> bool:
        try:
            from prompt_toolkit import prompt
        except ImportError as e:
            raise RuntimeError("prompt_toolkit is required for interactive `hermes mordred configure`") from e
        suffix = "[Y/n]" if default else "[y/N]"
        answer = prompt(f"{label} {suffix}: ").strip().lower()
        if not answer:
            return default
        return answer in ("y", "yes")


# -----------------------------------------------------------------------------
# NonInteractive guard -- rejects prompts in CI / scripted use.
# -----------------------------------------------------------------------------


class NonInteractiveAbort(RuntimeError):
    """Raised when --non-interactive is set and a prompt would be required."""


@dataclass(frozen=True, slots=True)
class _RefusingPromptIO:
    """:class:`PromptIO` impl used when ``--non-interactive`` is set.

    Every method raises :class:`NonInteractiveAbort` -- the only way through
    the configure flow is for every value to be pre-specified (which Phase 1
    does not yet support since the wizard owns the prompts; that pathway
    arrives when ``hermes mordred configure`` accepts ``--policy=...`` flags
    in Phase 2).
    """

    def ask_choice(self, label: str, choices: Sequence[str], default: str) -> str:
        raise NonInteractiveAbort(f"--non-interactive set but prompt required: {label!r}")

    def ask_text(self, label: str, default: str = "") -> str:
        raise NonInteractiveAbort(f"--non-interactive set but prompt required: {label!r}")

    def ask_bool(self, label: str, default: bool) -> bool:
        raise NonInteractiveAbort(f"--non-interactive set but prompt required: {label!r}")


# -----------------------------------------------------------------------------
# Mordred-specific prompt sequence + run().
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ConfigureResult:
    """Resolved answers from the prompt sequence.

    The ``snapshot`` is what gets persisted in Phase 1. ``phase2_fields``
    is collected now but not yet wired -- Phase 2 will read from a
    similarly shaped dict (or extend :class:`PolicySnapshot`).
    """

    snapshot: PolicySnapshot
    phase2_fields: dict[str, Any] = field(default_factory=dict)


def collect_answers(prompt_io: PromptIO) -> ConfigureResult:
    """Run the Mordred prompt sequence (PLAN.md §1.3 L250).

    Order matters -- snapshot tests assert on the label / default sequence.
    """
    policy = prompt_io.ask_choice(
        label="Mordred policy mode",
        choices=("strict", "lenient", "off"),
        default="lenient",
    )
    allow_cloud_llm = prompt_io.ask_bool(
        label="Allow cloud LLM providers (passes through provider override)?",
        default=False,
    )
    cloud_csv = prompt_io.ask_text(
        label="Cloud provider allowlist (comma-separated; empty = none)",
        default="",
    )
    cloud_provider_allowlist = tuple(p.strip() for p in cloud_csv.split(",") if p.strip())

    # Phase 2 fields -- collected for forward compatibility, not persisted now.
    local_llm_endpoint = prompt_io.ask_text(
        label="Local LLM endpoint URL (Phase 2)",
        default="http://localhost:1234/v1",
    )
    local_llm_model_id = prompt_io.ask_text(
        label="Local LLM model id (Phase 2)",
        default="",
    )
    cloud_attempt_action = prompt_io.ask_choice(
        label="On cloud LLM attempt under strict mode (Phase 2)",
        choices=("always-block", "prompt-once"),
        default="always-block",
    )

    snapshot = PolicySnapshot(
        policy=policy,
        allow_cloud_llm=allow_cloud_llm,
        cloud_provider_allowlist=cloud_provider_allowlist,
    )
    phase2_fields = {
        "local_llm_endpoint": local_llm_endpoint,
        "local_llm_model_id": local_llm_model_id,
        "cloud_attempt_action": cloud_attempt_action,
    }
    return ConfigureResult(snapshot=snapshot, phase2_fields=phase2_fields)


def run(
    *,
    setup_runner: SetupRunner,
    prompt_io: PromptIO,
    policy_writer: PolicyWriter,
    non_interactive: bool = False,
    skip_hermes_setup: bool = False,
) -> ConfigureResult:
    """Top-level configure entry point.

    Args:
        setup_runner: Spawns ``hermes setup``. Production = :class:`SubprocessSetupRunner`.
        prompt_io: Collects Mordred answers. Tests inject a scripted double.
        policy_writer: Persists the resolved snapshot.
        non_interactive: Forwarded to :class:`SetupRunner`. Mordred prompts
            still run -- pass a :class:`_RefusingPromptIO` to abort on any
            prompt requirement.
        skip_hermes_setup: Tests use this to avoid spawning ``hermes setup``
            entirely. Production should leave it ``False``.
    """
    if not skip_hermes_setup:
        rc = setup_runner.run(non_interactive=non_interactive)
        if rc != 0:
            _LOG.warning("`hermes setup` exited with code %d; continuing with Mordred prompts anyway", rc)

    result = collect_answers(prompt_io)
    policy_writer.write(result.snapshot)
    return result


def cli_handler(args: argparse.Namespace) -> int:
    """Adapter from argparse Namespace to :func:`run`. Wired in cli.py.

    Production behavior:
    - ``--non-interactive``: use :class:`_RefusingPromptIO` -- Mordred prompts
      will abort because Phase 1 does not yet accept ``--policy=...`` flags
      to pre-specify answers.
    - Otherwise: real :class:`SubprocessSetupRunner` + :class:`PromptToolkitIO`.
    """
    non_interactive = bool(getattr(args, "non_interactive", False))
    prompt_io: PromptIO = _RefusingPromptIO() if non_interactive else PromptToolkitIO()
    try:
        run(
            setup_runner=SubprocessSetupRunner(),
            prompt_io=prompt_io,
            policy_writer=PolicyWriter(),
            non_interactive=non_interactive,
        )
    except NonInteractiveAbort as e:
        print(f"hermes mordred configure: {e}", file=sys.stderr)
        return 2
    return 0
