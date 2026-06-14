"""``hermes mordred configure`` -- interactive Mordred setup.

Two-step flow:

1. Delegate first-run Hermes setup via ``subprocess.run(["hermes", "setup", ...])``
   (Hermes uses its own curses TUI -- ``hermes_cli/main.py:8704``).
2. Collect Mordred-specific prompts (policy mode, cloud allowlist, local LLM
   endpoint, agent harness) via :class:`PromptIO`.
3. Persist via :class:`PolicyWriter` (writes ``~/.hermes/mordred/policy.json``
   and the ``plugins.mordred_privacy_check`` / ``plugins.mordred_llm_guard``
   sections of ``~/.hermes/config.yaml``).

Both side effects -- the Hermes setup spawn AND the prompt collection -- go
through Protocol-typed seams (:class:`SetupRunner`, :class:`PromptIO`) so
tests inject scripted doubles. Production impls (:class:`SubprocessSetupRunner`,
:class:`PromptToolkitIO`) wrap subprocess and prompt_toolkit respectively.

Network-privacy setup (Tor / VPN / clearnet, Mullvad) is NOT part of first-run
configure. It is opt-in via the dedicated, re-runnable
``hermes-mordred network init`` command (see :mod:`mordred_hermes.wizard.network_cli`).
"""

from __future__ import annotations

import argparse
import logging
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, Literal, Protocol

from mordred_hermes.network.provider_transport_flagger import KNOWN_PROVIDERS

from .policy_writer import PolicySnapshot, PolicyWriter

_LOG = logging.getLogger("mordred.wizard.configure")

#: Cloud providers offered as checkbox choices for the allowlist prompt.
#: Sourced from the network flagger's canonical registry so the wizard and the
#: transport-compat layer never drift. Localhost-only providers
#: (``mordred-local``) are excluded -- a local endpoint is never a *cloud*
#: allowlist entry.
_SELECTABLE_CLOUD_PROVIDERS: Final[tuple[str, ...]] = tuple(
    name for name, entry in KNOWN_PROVIDERS.items() if not entry.localhost_only
)


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

    :meth:`ask_password` keeps secret prompts (e.g. the Mullvad account number
    collected by ``network init``) out of shell history and test diagnostics.
    This shared prompt surface is reused by
    :mod:`mordred_hermes.wizard.network_cli`.
    """

    def ask_choice(self, label: str, choices: Sequence[str], default: str) -> str: ...
    def ask_text(self, label: str, default: str = "") -> str: ...
    def ask_bool(self, label: str, default: bool) -> bool: ...
    def ask_multi(self, label: str, choices: Sequence[str], default: Sequence[str] = ()) -> tuple[str, ...]: ...
    def ask_password(self, label: str, default: str = "") -> str: ...


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


#: ImportError guidance for every PromptToolkitIO method. Deliberately does
#: NOT suggest ``--non-interactive``: that flag installs _RefusingPromptIO,
#: which aborts on the first prompt, so it can never be a fix for a missing
#: prompt_toolkit (UX review 2026-06-11).
_PROMPT_TOOLKIT_REQUIRED = (
    "prompt_toolkit is required for interactive `hermes-mordred configure`; install it via `pip install prompt_toolkit`"
)

#: Answers accepted as "yes" at a [y/N]-style prompt. Anything else that is
#: non-empty is "no"; empty input keeps the default.
_TRUTHY_ANSWERS = frozenset({"y", "yes", "true", "1", "on"})


def _parse_bool_answer(answer: str, *, default: bool) -> bool:
    """Interpret a yes/no prompt answer robustly (UX review 2026-06-11).

    Users coming from config files type ``true`` / ``1`` / ``on``; treating
    those as "no" silently inverted their intent.
    """
    normalized = answer.strip().lower()
    if not normalized:
        return default
    return normalized in _TRUTHY_ANSWERS


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
            raise RuntimeError(_PROMPT_TOOLKIT_REQUIRED) from e
        values = [(c, c) for c in choices]
        result: str | None = radiolist_dialog(title=label, values=values, default=default).run()
        return result if result is not None else default

    def ask_text(self, label: str, default: str = "") -> str:
        try:
            from prompt_toolkit import prompt
        except ImportError as e:
            raise RuntimeError(_PROMPT_TOOLKIT_REQUIRED) from e
        suffix = f" [{default}]" if default else ""
        answer = prompt(f"{label}{suffix}: ")
        return answer.strip() or default

    def ask_bool(self, label: str, default: bool) -> bool:
        try:
            from prompt_toolkit import prompt
        except ImportError as e:
            raise RuntimeError(_PROMPT_TOOLKIT_REQUIRED) from e
        suffix = "[Y/n]" if default else "[y/N]"
        return _parse_bool_answer(prompt(f"{label} {suffix}: "), default=default)

    def ask_multi(self, label: str, choices: Sequence[str], default: Sequence[str] = ()) -> tuple[str, ...]:
        """Multi-select via ``checkboxlist_dialog``.

        Returns the chosen subset (empty tuple if the user selects nothing
        or cancels). Like :meth:`ask_choice`'s ``radiolist_dialog`` it renders
        in SSH / Docker / TTY-without-tput, and replaces the old free-text
        comma-separated entry so users pick from known providers instead of
        guessing names (UX request 2026-06-14).
        """
        try:
            from prompt_toolkit.shortcuts import checkboxlist_dialog
        except ImportError as e:
            raise RuntimeError(_PROMPT_TOOLKIT_REQUIRED) from e
        values = [(c, c) for c in choices]
        result: list[str] | None = checkboxlist_dialog(
            title=label,
            values=values,
            default_values=list(default),
        ).run()
        return tuple(result) if result is not None else ()

    def ask_password(self, label: str, default: str = "") -> str:
        """Read a secret with shell-history-safe echoing.

        ``is_password=True`` masks the input. Empty input → ``default`` so
        a user who already has the secret set elsewhere can decline to
        re-enter it.
        """
        try:
            from prompt_toolkit import prompt
        except ImportError as e:
            raise RuntimeError(_PROMPT_TOOLKIT_REQUIRED) from e
        answer = prompt(f"{label}: ", is_password=True)
        return answer.strip() or default


# -----------------------------------------------------------------------------
# NonInteractive guard -- rejects prompts in CI / scripted use.
# -----------------------------------------------------------------------------


class NonInteractiveAbort(RuntimeError):
    """Raised when --non-interactive is set and a prompt would be required."""


@dataclass(frozen=True, slots=True)
class _RefusingPromptIO:
    """:class:`PromptIO` impl used when ``--non-interactive`` is set.

    Every method raises :class:`NonInteractiveAbort` -- the only way through
    an interactive flow is for every value to be pre-specified, which the
    prompt-driven commands do not yet support.
    """

    def ask_choice(self, label: str, choices: Sequence[str], default: str) -> str:
        raise NonInteractiveAbort(f"--non-interactive set but prompt required: {label!r}")

    def ask_text(self, label: str, default: str = "") -> str:
        raise NonInteractiveAbort(f"--non-interactive set but prompt required: {label!r}")

    def ask_bool(self, label: str, default: bool) -> bool:
        raise NonInteractiveAbort(f"--non-interactive set but prompt required: {label!r}")

    def ask_multi(self, label: str, choices: Sequence[str], default: Sequence[str] = ()) -> tuple[str, ...]:
        raise NonInteractiveAbort(f"--non-interactive set but prompt required: {label!r}")

    def ask_password(self, label: str, default: str = "") -> str:
        raise NonInteractiveAbort(f"--non-interactive set but prompt required: {label!r}")


# -----------------------------------------------------------------------------
# Mordred-specific prompt sequence + run().
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ConfigureResult:
    """Resolved answers from the prompt sequence."""

    snapshot: PolicySnapshot


def collect_answers(prompt_io: PromptIO) -> ConfigureResult:
    """Run the Mordred prompt sequence.

    Order matters -- snapshot tests assert on the label / default sequence.
    Network-privacy prompts are NOT collected here; run
    ``hermes-mordred network init`` to set up Tor / VPN / Mullvad on demand.
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
    # Only ask *which* providers to permit when cloud is actually allowed. An
    # allowlist is meaningless under "no cloud", and it has no effect at all
    # outside strict mode (see ``llm_guard.enforce``), so skipping it keeps the
    # common local-only flow short (UX request 2026-06-14). The choices come
    # from a checkbox so users pick known provider ids instead of typing them.
    if allow_cloud_llm:
        cloud_provider_allowlist = prompt_io.ask_multi(
            label="Cloud provider allowlist (select which providers to permit)",
            choices=_SELECTABLE_CLOUD_PROVIDERS,
            default=(),
        )
    else:
        cloud_provider_allowlist = ()

    local_llm_endpoint = prompt_io.ask_text(
        label="Local LLM endpoint URL",
        default="http://localhost:1234/v1",
    )
    local_llm_model_id = prompt_io.ask_text(
        label="Local LLM model id",
        default="",
    )
    cloud_attempt_action_raw = prompt_io.ask_choice(
        label="On cloud LLM attempt under strict mode",
        choices=("always-block", "prompt-once"),
        default="always-block",
    )
    cloud_attempt_action = _coerce_cloud_attempt_action(cloud_attempt_action_raw)

    # The declared harness controls strict-mode abort behaviour in
    # ``mordred_llm_guard.harness_detect``. ``"none"`` is the safe default --
    # it doesn't match any harness pattern so existing users don't lose the
    # session. The known choices mirror the regex allowlist in
    # ``harness_detect._HARNESS_PATTERNS``.
    harness_primary = prompt_io.ask_choice(
        label="Agent harness (strict mode refuses if a known harness is detected)",
        choices=("none", "codex", "claude-cli", "cursor", "acp-claude", "acp-cline"),
        default="none",
    )

    snapshot = PolicySnapshot(
        policy=policy,
        allow_cloud_llm=allow_cloud_llm,
        cloud_provider_allowlist=cloud_provider_allowlist,
        local_llm_endpoint=local_llm_endpoint,
        local_llm_model_id=local_llm_model_id,
        cloud_attempt_action=cloud_attempt_action,
        harness_primary=harness_primary,
        # strict → disable IPv6 by default (mirrors the network reader's
        # ``_resolve_disable_ipv6``: strict → True, lenient/off → False).
        disable_ipv6=(policy == "strict"),
    )
    return ConfigureResult(snapshot=snapshot)


def _coerce_cloud_attempt_action(raw: str) -> Literal["always-block", "prompt-once"]:
    """Narrow ``ask_choice``'s ``str`` return to the snapshot Literal.

    The prompt only offers two choices so this never raises in production;
    the explicit check protects against test doubles that script invalid
    answers and satisfies mypy --strict at the construction site.
    """
    if raw == "always-block":
        return "always-block"
    if raw == "prompt-once":
        return "prompt-once"
    raise ValueError(f"invalid cloud_attempt_action: {raw!r}")


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
        policy_writer: Persists the resolved snapshot (policy.json +
            ``plugins.mordred_privacy_check`` / ``plugins.mordred_llm_guard``).
            The ``plugins.mordred_network`` section is intentionally left alone
            -- it is owned by ``hermes-mordred network init``.
        non_interactive: Forwarded to :class:`SetupRunner`. Mordred prompts
            still run -- pass a :class:`_RefusingPromptIO` to abort on any
            prompt requirement.
        skip_hermes_setup: Tests use this to avoid spawning ``hermes setup``
            entirely. Production should leave it ``False``.

    Returns:
        :class:`ConfigureResult` holding the resolved :class:`PolicySnapshot`.
    """
    if not skip_hermes_setup:
        rc = setup_runner.run(non_interactive=non_interactive)
        if rc != 0:
            _LOG.warning("`hermes setup` exited with code %d; continuing with Mordred prompts anyway", rc)

    result = collect_answers(prompt_io)
    policy_writer.write(result.snapshot)
    return result


def _render_configure_summary(snapshot: PolicySnapshot) -> str:
    """A structured recap printed after a successful ``configure``.

    Shown once all prompts complete (so it survives the full-screen
    ``radiolist_dialog`` prompts, which clear the terminal). Echoes the
    resolved choices and points the user at the on-demand network-privacy
    command, which first-run setup deliberately does not cover.
    """
    cloud = "yes" if snapshot.allow_cloud_llm else "no"
    return "\n".join(
        [
            "",
            "Mordred configured:",
            f"  policy mode       : {snapshot.policy}",
            f"  cloud LLM allowed : {cloud}",
            f"  agent harness     : {snapshot.harness_primary}",
            "",
            "Next: run `hermes-mordred network init` to set up network privacy (Tor / VPN / clearnet).",
        ]
    )


# -----------------------------------------------------------------------------
# Non-interactive (flag-driven) configure — mirrors network init's
# ``network_answers_from_args``: unspecified flags fall back to the existing
# on-disk settings, then to the same defaults the prompts use, so a re-run
# never clobbers prior answers (UX review 2026-06-11 Phase 4).
# -----------------------------------------------------------------------------


def _read_existing_policy_inputs(policy_writer: PolicyWriter) -> dict[str, object]:
    """Best-effort read of the current settings for non-interactive seeding.

    policy.json carries every snapshot field except ``harness_primary``,
    which lives in config.yaml under ``plugins.mordred_llm_guard`` (the
    same split the writers maintain). Any read/parse error collapses to
    ``{}`` — the flags then fall back to the prompt defaults.
    """
    import json

    existing: dict[str, object] = {}
    try:
        body = json.loads(policy_writer.policy_json_path.read_text(encoding="utf-8"))
        if isinstance(body, dict):
            existing.update(body)
    except (OSError, ValueError):
        pass

    from ruamel.yaml import YAML
    from ruamel.yaml.error import YAMLError

    try:
        with policy_writer.config_path.open(encoding="utf-8") as f:
            data = YAML(typ="safe", pure=True).load(f)
        plugins = data.get("plugins") if isinstance(data, dict) else None
        guard = plugins.get("mordred_llm_guard") if isinstance(plugins, dict) else None
        if isinstance(guard, dict) and isinstance(guard.get("harness_primary"), str):
            existing["harness_primary"] = guard["harness_primary"]
    except (OSError, ValueError, YAMLError):
        pass  # any unreadable config falls back to defaults
    return existing


def snapshot_from_args(
    args: argparse.Namespace,
    *,
    existing: Mapping[str, Any] | None = None,
) -> ConfigureResult:
    """Build a :class:`PolicySnapshot` from CLI flags (no prompts).

    Precedence per field: explicit flag > existing on-disk value > the
    default the interactive prompt would offer. ``disable_ipv6`` mirrors
    :func:`collect_answers`: derived from the resolved policy mode.
    """
    existing = existing or {}

    def _seeded(flag: str, existing_key: str, fallback: object) -> object:
        value = getattr(args, flag, None)
        if value is not None:
            return value
        value = existing.get(existing_key)
        return value if value is not None else fallback

    # Existing values come from a hand-editable policy.json — sanitize the
    # closed-set fields back to their defaults instead of crashing the
    # non-interactive path on a corrupt or downgraded file (review 2026-06-12).
    policy = str(_seeded("policy", "policy", "lenient"))
    if policy not in ("strict", "lenient", "off"):
        policy = "lenient"
    # M2 (security review 2026-06-11): only a real bool may enable —
    # ``bool(...)`` truthy-coerced a hand-edited ``"allow_cloud_llm": "false"``
    # into a written ``allow_cloud_llm: true``.
    raw_allow_cloud = _seeded("allow_cloud_llm", "allow_cloud_llm", False)
    allow_cloud_llm = raw_allow_cloud if isinstance(raw_allow_cloud, bool) else False
    raw_allowlist = _seeded("cloud_allowlist", "cloud_provider_allowlist", ())
    if isinstance(raw_allowlist, str):
        allowlist = tuple(p.strip() for p in raw_allowlist.split(",") if p.strip())
    elif isinstance(raw_allowlist, (list, tuple)):
        allowlist = tuple(str(p) for p in raw_allowlist)
    else:
        allowlist = ()
    raw_action = str(_seeded("cloud_attempt_action", "cloud_attempt_action", "always-block"))
    if raw_action not in ("always-block", "prompt-once"):
        raw_action = "always-block"
    cloud_attempt_action = _coerce_cloud_attempt_action(raw_action)

    snapshot = PolicySnapshot(
        policy=policy,
        allow_cloud_llm=allow_cloud_llm,
        cloud_provider_allowlist=allowlist,
        local_llm_endpoint=str(_seeded("local_llm_endpoint", "local_llm_endpoint", "http://localhost:1234/v1")),
        local_llm_model_id=str(_seeded("local_llm_model_id", "local_llm_model_id", "")),
        cloud_attempt_action=cloud_attempt_action,
        harness_primary=str(_seeded("harness", "harness_primary", "none")),
        disable_ipv6=(policy == "strict"),
    )
    return ConfigureResult(snapshot=snapshot)


def cli_handler(args: argparse.Namespace) -> int:
    """Adapter from argparse Namespace to :func:`run`. Wired in cli.py.

    Production behavior:
    - ``--non-interactive``: flag-driven, no prompts — answers come from the
      CLI flags, seeded from the existing policy.json / config.yaml (so a
      bare re-run keeps prior settings).
    - Otherwise: real :class:`SubprocessSetupRunner` + :class:`PromptToolkitIO`,
      then a hint pointing the user at the on-demand network-privacy command.
    """
    non_interactive = bool(getattr(args, "non_interactive", False))
    if non_interactive:
        setup_rc = SubprocessSetupRunner().run(non_interactive=True)
        if setup_rc != 0:
            _LOG.warning("`hermes setup` exited with code %d; continuing with Mordred flags anyway", setup_rc)
        writer = PolicyWriter()
        result = snapshot_from_args(args, existing=_read_existing_policy_inputs(writer))
        try:
            writer.write(result.snapshot)
        except OSError as e:
            print(f"hermes-mordred configure: failed to write policy: {e}", file=sys.stderr)
            return 1
        print(_render_configure_summary(result.snapshot))
        return 0

    result = run(
        setup_runner=SubprocessSetupRunner(),
        prompt_io=PromptToolkitIO(),
        policy_writer=PolicyWriter(),
        non_interactive=False,
    )
    print(_render_configure_summary(result.snapshot))
    return 0
