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
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, Protocol

from .credentials_writer import CredentialsWriter
from .env_file_writer import EnvFileWriter
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

    Phase 3 PR3a Task #6 added :meth:`ask_password` so secret prompts
    (the Mullvad account number) bypass shell history and don't appear in
    test diagnostics that log every user-typed value.
    """

    def ask_choice(self, label: str, choices: Sequence[str], default: str) -> str: ...
    def ask_text(self, label: str, default: str = "") -> str: ...
    def ask_bool(self, label: str, default: bool) -> bool: ...
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

    def ask_password(self, label: str, default: str = "") -> str:
        """Read a secret with shell-history-safe echoing.

        ``is_password=True`` masks the input. Empty input → ``default`` so
        a user who already has the env var set elsewhere can decline to
        re-enter the secret. Documented in PR3c playbook.
        """
        try:
            from prompt_toolkit import prompt
        except ImportError as e:
            raise RuntimeError("prompt_toolkit is required for interactive `hermes mordred configure`") from e
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

    def ask_password(self, label: str, default: str = "") -> str:
        raise NonInteractiveAbort(f"--non-interactive set but prompt required: {label!r}")


# -----------------------------------------------------------------------------
# Mordred-specific prompt sequence + run().
# -----------------------------------------------------------------------------


DEFAULT_TOR_SOCKS_PORT: Final[int] = 9050
MULLVAD_ACCOUNT_ENV_VAR_NAME: Final[str] = "MORDRED_MULLVAD_ACCOUNT"


@dataclass(frozen=True, slots=True)
class NetworkAnswers:
    """The 6 wizard outputs that drive Phase 3 path management.

    Lives on :class:`ConfigureResult` as a sibling of :class:`PolicySnapshot`.
    The Mullvad account *value* never appears here -- only the env-var
    REFERENCE. The actual secret flows through the :class:`EnvFileWriter`
    (Task #6b) which writes it to ``~/.hermes/.env`` at mode 0600.

    :meth:`to_config_yaml_section` (Task #7) returns the body
    PolicyWriter upserts into ``plugins.mordred_network``.
    """

    default_network_path: str  # "tor" | "vpn" | "clearnet"
    tor_binary_path: str  # filesystem path or shell-resolvable name
    tor_socks_port: int
    mullvad_account_id_env: str  # always ``MORDRED_MULLVAD_ACCOUNT``
    mullvad_relay_country: str  # "auto" | 2-letter code
    mullvad_killswitch: bool

    def to_config_yaml_section(self) -> dict[str, object]:
        """The body upserted into ``plugins.mordred_network`` in config.yaml.

        Key remap: the wizard's ``default_network_path`` becomes
        ``default_path`` on disk so the existing reader helper in
        ``mordred_hermes.network.__init__._read_default_path`` keeps
        working without a schema-version bump.
        """
        return {
            "default_path": self.default_network_path,
            "tor_binary_path": self.tor_binary_path,
            "tor_socks_port": self.tor_socks_port,
            "mullvad_account_id_env": self.mullvad_account_id_env,
            "mullvad_relay_country": self.mullvad_relay_country,
            "mullvad_killswitch": self.mullvad_killswitch,
        }


@dataclass(frozen=True, slots=True)
class ConfigureResult:
    """Resolved answers from the prompt sequence.

    Phase 2 fields (Codex M3 — moved into PR1) live INSIDE ``snapshot``
    via the extended :class:`PolicySnapshot`. Phase 3 PR3a Task #6 adds
    a sibling :class:`NetworkAnswers` payload; Task #7 will fold these
    into :class:`PolicySnapshot` proper.

    ``_mullvad_account_secret`` is a TRANSIENT private field carrying
    the secret from :func:`collect_answers` to :func:`run`. ``run()``
    routes it to the EnvFileWriter and then returns a NEW
    ConfigureResult with the field cleared so callers never see the
    raw value. Test contract:
    :func:`tests.test_configure.TestRunWiresNetworkWriters.test_secret_does_not_appear_in_returned_result`
    walks the returned dataclass tree to assert the secret is absent.
    """

    snapshot: PolicySnapshot
    network_answers: NetworkAnswers
    _mullvad_account_secret: str = ""


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

    # Phase 2 fields are persisted into policy.json via PolicySnapshot
    # (Codex M3, PR1). They are NOT pushed into the config.yaml
    # ``plugins.mordred_privacy_check`` section -- llm_guard reads them
    # from the policy.json mirror.
    local_llm_endpoint = prompt_io.ask_text(
        label="Local LLM endpoint URL (Phase 2)",
        default="http://localhost:1234/v1",
    )
    local_llm_model_id = prompt_io.ask_text(
        label="Local LLM model id (Phase 2)",
        default="",
    )
    cloud_attempt_action_raw = prompt_io.ask_choice(
        label="On cloud LLM attempt under strict mode (Phase 2)",
        choices=("always-block", "prompt-once"),
        default="always-block",
    )
    cloud_attempt_action = _coerce_cloud_attempt_action(cloud_attempt_action_raw)

    # Phase 2 PR2: declared harness primary controls strict-mode abort
    # behaviour in ``mordred_llm_guard.harness_detect``. ``"none"`` is the
    # safe default — it doesn't match any harness pattern so existing
    # users don't lose the session. The known choices mirror SPEC.md L143
    # / the regex allowlist in ``harness_detect._HARNESS_PATTERNS``.
    harness_primary = prompt_io.ask_choice(
        label="Agent harness primary (Phase 2; strict mode refuses if a known harness)",
        choices=("none", "codex", "claude-cli", "cursor", "acp-claude", "acp-cline"),
        default="none",
    )

    # Phase 3 PR3a Task #6: Mordred network path + Tor / Mullvad
    # configuration. Captured here on the ``NetworkAnswers`` sibling
    # payload; Task #7 will fold the fields into ``PolicySnapshot`` so
    # the PolicyWriter persists them to ``plugins.mordred_network`` in
    # config.yaml. The Mullvad secret is collected via ``ask_password``
    # and routed to the EnvFileWriter (Task #6b) rather than appearing
    # in any snapshot.
    default_network_path = prompt_io.ask_choice(
        label="Default network path",
        choices=("tor", "vpn", "clearnet"),
        default="clearnet",
    )
    tor_binary_path = prompt_io.ask_text(
        label="Tor binary path",
        default="tor",
    )
    tor_socks_port_raw = prompt_io.ask_text(
        label="Tor SOCKS port",
        default=str(DEFAULT_TOR_SOCKS_PORT),
    )
    tor_socks_port = _coerce_tor_socks_port(tor_socks_port_raw)
    # The secret never reaches NetworkAnswers — only the env-var REFERENCE.
    _mullvad_secret = prompt_io.ask_password(
        label="Mullvad account number (stored in ~/.hermes/.env)",
        default="",
    )
    # The secret travels through ConfigureResult on a transient
    # ``mullvad_account_secret`` field consumed by run() and then cleared
    # before the result is returned to the caller. Belt-and-suspenders
    # against accidental serialisation (see test_secret_does_not_appear_in_returned_result).
    captured_mullvad_secret = _mullvad_secret
    mullvad_relay_country = prompt_io.ask_text(
        label="Mullvad relay country (`auto` or 2-letter code)",
        default="auto",
    )
    mullvad_killswitch = prompt_io.ask_bool(
        label="Mullvad killswitch (lockdown-mode)",
        default=policy == "strict",
    )

    snapshot = PolicySnapshot(
        policy=policy,
        allow_cloud_llm=allow_cloud_llm,
        cloud_provider_allowlist=cloud_provider_allowlist,
        local_llm_endpoint=local_llm_endpoint,
        local_llm_model_id=local_llm_model_id,
        cloud_attempt_action=cloud_attempt_action,
        harness_primary=harness_primary,
        # Phase 3 PR3a Task #7: persist the policy-mode-dependent default
        # to policy.json explicitly so the network reader doesn't have to
        # apply the same heuristic. Mirrors
        # mordred_hermes.network._resolve_disable_ipv6: strict → True,
        # lenient/off → False.
        disable_ipv6=(policy == "strict"),
    )
    network_answers = NetworkAnswers(
        default_network_path=default_network_path,
        tor_binary_path=tor_binary_path,
        tor_socks_port=tor_socks_port,
        mullvad_account_id_env=MULLVAD_ACCOUNT_ENV_VAR_NAME,
        mullvad_relay_country=mullvad_relay_country,
        mullvad_killswitch=mullvad_killswitch,
    )
    return ConfigureResult(
        snapshot=snapshot,
        network_answers=network_answers,
        _mullvad_account_secret=captured_mullvad_secret,
    )


def _coerce_tor_socks_port(raw: str) -> int:
    """Parse a port string; fall back to the default 9050 on garbage input.

    Hard-aborting on bad input would force the user to abandon a whole
    configure session for a typo. A WARN log + safe-default lets them fix
    it later via ``hermes mordred network use`` or by re-editing the
    policy.json directly.
    """
    try:
        port = int(raw)
    except ValueError:
        _LOG.warning("Invalid Tor SOCKS port %r; falling back to default %d", raw, DEFAULT_TOR_SOCKS_PORT)
        return DEFAULT_TOR_SOCKS_PORT
    if port <= 0 or port > 65535:
        _LOG.warning("Tor SOCKS port %d out of range; falling back to default %d", port, DEFAULT_TOR_SOCKS_PORT)
        return DEFAULT_TOR_SOCKS_PORT
    return port


def _coerce_cloud_attempt_action(raw: str) -> Literal["always-block", "prompt-once"]:
    """Narrow ``ask_choice``'s ``str`` return to the snapshot Literal.

    The prompt only offers two choices so this never raises in production;
    the explicit check protects against test doubles that script invalid
    answers and satisfies mypy --strict at the construction site.
    """
    # Explicit per-branch return so mypy narrows ``raw`` to each Literal
    # member (a single ``if raw in {...}`` keeps the type as ``str``).
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
    env_writer: EnvFileWriter | None = None,
    credentials_writer: CredentialsWriter | None = None,
    env_path: Path | None = None,
    credentials_path: Path | None = None,
    non_interactive: bool = False,
    skip_hermes_setup: bool = False,
) -> ConfigureResult:
    """Top-level configure entry point.

    Args:
        setup_runner: Spawns ``hermes setup``. Production = :class:`SubprocessSetupRunner`.
        prompt_io: Collects Mordred answers. Tests inject a scripted double.
        policy_writer: Persists the resolved snapshot.
        env_writer: Optional Phase 3 PR3a Task #6c -- writes the Mullvad
            account number to ``~/.hermes/.env``. When ``None`` the secret
            is captured but not persisted (lets Phase 1 / Phase 2 tests
            use ``run()`` without the network slice).
        credentials_writer: Optional Phase 3 PR3a Task #6c -- writes
            ``~/.hermes/mordred/credentials/network.json`` with env-var
            REFERENCES.
        env_path: Override for the ``.env`` location. Defaults are derived
            from :data:`mordred_hermes._home.HERMES_BASE` at call time so
            test profile dirs work.
        credentials_path: Override for the credentials JSON location.
        non_interactive: Forwarded to :class:`SetupRunner`. Mordred prompts
            still run -- pass a :class:`_RefusingPromptIO` to abort on any
            prompt requirement.
        skip_hermes_setup: Tests use this to avoid spawning ``hermes setup``
            entirely. Production should leave it ``False``.

    Returns:
        :class:`ConfigureResult` with the Mullvad secret CLEARED so callers
        never see it in serialised form. The actual secret (if non-empty)
        is routed to ``env_writer.upsert`` BEFORE the return.
    """
    if not skip_hermes_setup:
        rc = setup_runner.run(non_interactive=non_interactive)
        if rc != 0:
            _LOG.warning("`hermes setup` exited with code %d; continuing with Mordred prompts anyway", rc)

    result = collect_answers(prompt_io)
    policy_writer.write(result.snapshot, network_answers=result.network_answers)

    if env_writer is not None and result._mullvad_account_secret:
        from .._home import HERMES_BASE

        resolved_env_path = env_path if env_path is not None else (HERMES_BASE / ".env")
        env_writer.upsert(
            resolved_env_path,
            key=result.network_answers.mullvad_account_id_env,
            value=result._mullvad_account_secret,
        )
    elif env_writer is not None:
        # User cleared the prompt; remove any stale line if present.
        from .._home import HERMES_BASE

        resolved_env_path = env_path if env_path is not None else (HERMES_BASE / ".env")
        env_writer.upsert(
            resolved_env_path,
            key=result.network_answers.mullvad_account_id_env,
            value="",
        )

    if credentials_writer is not None:
        from .._home import HERMES_BASE

        resolved_credentials_path = (
            credentials_path
            if credentials_path is not None
            else (HERMES_BASE / "mordred" / "credentials" / "network.json")
        )
        credentials_writer.write_network(
            resolved_credentials_path,
            mullvad_account_id_env=result.network_answers.mullvad_account_id_env,
            mullvad_relay_country=result.network_answers.mullvad_relay_country,
            mullvad_killswitch=result.network_answers.mullvad_killswitch,
        )

    # Belt-and-suspenders: clear the transient secret before returning so
    # the caller can serialise / log the result without leaking it.
    return ConfigureResult(
        snapshot=result.snapshot,
        network_answers=result.network_answers,
        _mullvad_account_secret="",
    )


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
