"""Mullvad VPN path — drives the official ``mullvad`` CLI.

PR1 scope: CLI detection, bring-up sequence, status polling, disconnect,
handshake-age liveness probe. PR2 wires :func:`detect_cli` /
:func:`bring_up` / :func:`disconnect` into :mod:`mordred_hermes.network.runtime`
and ties handshake-age failures to the audit log.

Subprocess I/O is factored through an injectable runner so tests can
replace it; production uses :func:`subprocess.run`.

The Mullvad client is daemonized externally — we don't track a
``Popen``. The handle records what *we* asked for so PR2 can decide
whether to preserve lockdown on disconnect (TODO §3.1 L311).

Platform: macOS Apple Silicon + Ubuntu/Debian. Windows is out of scope
for v1.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

from .._exceptions import BringupFailed

PATH_NAME: Final[str] = "vpn"

MACOS_APP_BUNDLE_PATH: Final[str] = "/Applications/Mullvad VPN.app/Contents/Resources/mullvad"

DEFAULT_CONNECT_TIMEOUT: Final[float] = 10.0
DEFAULT_POLL_INTERVAL: Final[float] = 0.5
DEFAULT_MAX_HANDSHAKE_AGE_SECONDS: Final[float] = 180.0

PolicyMode = Literal["strict", "lenient", "off"]

SubprocessRunner = Callable[..., subprocess.CompletedProcess[str]]


def _default_runner(
    argv: list[str] | tuple[str, ...],
    *,
    check: bool = False,
    capture_output: bool = True,
    text: bool = True,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[str]:
    """Production default for the injectable runner.

    Centralized so tests can swap in a fake and the production path
    retains a single subprocess invocation site.
    """
    return subprocess.run(
        list(argv),
        check=check,
        capture_output=capture_output,
        text=text,
        timeout=timeout,
    )


DEFAULT_RUNNER: Final[SubprocessRunner] = _default_runner


@dataclass(frozen=True, slots=True)
class MullvadHandle:
    """What we configured. The Mullvad daemon owns the actual tunnel state.

    Codex round 8 P1 (2026-05-14): the two ``*_applied_by_us`` flags
    record whether we changed a kill-switch setting from ``off`` to
    ``on`` (vs. the user already had it on before Mordred ran). Only
    settings WE flipped are eligible for rollback on disconnect /
    bring-up failure — undoing the user's pre-existing security
    posture would weaken their machine after a transient bring-up
    failure.
    """

    cli_path: str
    region: str
    lockdown_enforced: bool
    lockdown_applied_by_us: bool = False
    always_require_applied_by_us: bool = False


def detect_cli(*, which: Callable[[str], str | None] = shutil.which) -> str:
    """Resolve the path to the ``mullvad`` CLI.

    Checks ``$PATH`` first via the injected ``which``; falls back to the
    macOS app bundle location (TODO §3.1 L306). Raises
    :class:`BringupFailed` if neither is present so the caller can
    surface an actionable error.
    """
    path = which("mullvad")
    if path:
        return path
    if Path(MACOS_APP_BUNDLE_PATH).exists():
        return MACOS_APP_BUNDLE_PATH
    raise BringupFailed("mullvad client not installed (checked $PATH and macOS app bundle)")


def bring_up(
    *,
    cli_path: str,
    region: str,
    policy_mode: PolicyMode,
    runner: SubprocessRunner = DEFAULT_RUNNER,
) -> MullvadHandle:
    """Run the configured bring-up sequence.

    Strict mode enforces lockdown + always-require-vpn; lenient/off
    respect the user's existing settings. Region defaults to ``auto``
    when callers don't pass one.

    Does *not* block on ``Connected`` — call :func:`wait_connected`
    afterwards (split so callers can audit each step independently).

    Codex round 4 P1 (2026-05-14): every step now inspects
    ``returncode`` and raises :class:`BringupFailed` on non-zero so a
    failed ``lockdown-mode set on`` / ``always-require-vpn`` /
    ``relay`` / ``connect`` cannot produce a handle. Without this the
    runtime would mark the VPN path ``READY`` even though Mullvad
    refused the request — strict mode would fail open.
    """
    # Codex round 7 P2-A + round 8 P1-A (2026-05-14): only enable
    # strict kill-switch settings we found OFF, and only roll back the
    # ones WE flipped. Querying current state first prevents two bugs:
    #   (1) undoing the user's pre-existing lockdown after our bring-up
    #       fails — would weaken their security posture, and
    #   (2) re-applying a setting that was already on — pointless churn.
    lockdown_applied = False
    always_require_applied = False
    applied_strict: list[tuple[str, ...]] = []
    try:
        if policy_mode == "strict":
            if not _is_setting_on(runner, cli_path, "lockdown-mode"):
                _run_or_raise(runner, (cli_path, "lockdown-mode", "set", "on"))
                applied_strict.append((cli_path, "lockdown-mode", "set", "off"))
                lockdown_applied = True
            if not _is_setting_on(runner, cli_path, "always-require-vpn"):
                _run_or_raise(runner, (cli_path, "always-require-vpn", "set", "on"))
                applied_strict.append((cli_path, "always-require-vpn", "set", "off"))
                always_require_applied = True
        # Codex round 6 P1 (2026-05-14): the Mullvad CLI keyword for
        # automatic relay selection is ``any``, not ``auto``. We keep
        # ``auto`` as the user-facing alias (wizard prompt +
        # RuntimeConfig default) and translate at the CLI boundary so
        # the new returncode check from r4-P1 doesn't turn every
        # default-region bring-up into a :class:`BringupFailed`.
        cli_region = "any" if region == "auto" else region
        _run_or_raise(runner, (cli_path, "relay", "set", "location", cli_region))
        _run_or_raise(runner, (cli_path, "connect"))
    except BringupFailed:
        for rollback_argv in reversed(applied_strict):
            try:
                runner(rollback_argv)
            except Exception as rb_err:
                # A failed rollback must not mask the original error.
                # Log so the operator can clean up manually.
                import logging

                logging.getLogger("mordred.network.vpn").warning("rollback of %r failed: %s", rollback_argv, rb_err)
        raise
    return MullvadHandle(
        cli_path=cli_path,
        region=region,
        lockdown_enforced=(policy_mode == "strict"),
        lockdown_applied_by_us=lockdown_applied,
        always_require_applied_by_us=always_require_applied,
    )


def _is_setting_on(runner: SubprocessRunner, cli_path: str, setting: str) -> bool:
    """Query ``mullvad <setting> get`` and parse "on"/"off".

    Returns ``True`` when the setting is enabled, ``False`` otherwise
    (including when the query itself fails — failure-open here keeps
    bring-up robust against future ``mullvad`` CLI output changes; the
    worst case is we re-apply a setting that was already on, which is
    a no-op).
    """
    try:
        result = runner((cli_path, setting, "get"))
    except OSError:
        return False
    if result.returncode != 0:
        return False
    stdout = (result.stdout or "").lower()
    # Mullvad CLI output forms: "Network lockdown when disconnected: on"
    # / "Always require VPN: off". Look for the bare token; the labels
    # vary by Mullvad version but the value tokens are stable.
    return ": on" in stdout or " on\n" in stdout or stdout.strip().endswith("on")


def _run_or_raise(runner: SubprocessRunner, argv: tuple[str, ...]) -> None:
    """Invoke ``runner(argv)`` and translate non-zero returncode into
    :class:`BringupFailed`. Empty stderr defaults so the message is
    still actionable when the CLI is silent."""
    result = runner(argv)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise BringupFailed(f"mullvad command {' '.join(argv)!r} failed (rc={result.returncode}): {detail!r}")


def wait_connected(
    *,
    cli_path: str,
    runner: SubprocessRunner = DEFAULT_RUNNER,
    timeout: float = DEFAULT_CONNECT_TIMEOUT,
    poll_interval: float = DEFAULT_POLL_INTERVAL,
    clock: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> None:
    """Poll ``mullvad status`` until it reports ``Connected``.

    Raises :class:`BringupFailed` when the timeout elapses. Polling
    interval is conservative so we don't hammer the daemon — the
    bring-up window in practice is 1-3 seconds.
    """
    start = clock()
    while True:
        result = runner((cli_path, "status"))
        if "Connected" in (result.stdout or ""):
            return
        if clock() - start > timeout:
            raise BringupFailed(f"mullvad did not reach Connected within {timeout}s")
        sleeper(poll_interval)


def disconnect(
    handle: MullvadHandle,
    *,
    runner: SubprocessRunner = DEFAULT_RUNNER,
    preserve_lockdown: bool = True,
    clear_always_require: bool = False,
) -> None:
    """Disconnect the tunnel; optionally clear strict kill-switch settings.

    Strict-mode sessions preserve lockdown so the user must explicitly
    opt out next session — matches the TODO §3.1 L311 contract
    ("strict 中は lockdown 維持").

    Codex round 9 P1-A (2026-05-14): added ``clear_always_require``
    so runtime cleanup after a wait-timeout failure can roll back
    ``always-require-vpn set on`` (when WE applied it). Without this
    a partial bring-up leaves the user with always-require-vpn on
    blocking their traffic until manually reset.
    """
    runner((handle.cli_path, "disconnect"))
    if not preserve_lockdown:
        runner((handle.cli_path, "lockdown-mode", "set", "off"))
    if clear_always_require:
        runner((handle.cli_path, "always-require-vpn", "set", "off"))


_AGE_TOKEN_RE: Final = re.compile(
    r"(?P<value>\d+)\s+(?P<unit>second|minute|hour|day)s?",
    re.IGNORECASE,
)
_UNIT_SECONDS: Final[dict[str, float]] = {
    "second": 1.0,
    "minute": 60.0,
    "hour": 3600.0,
    "day": 86400.0,
}


def parse_handshake_age(wg_show_stdout: str) -> float | None:
    """Return the latest handshake age in seconds, or ``None`` if absent.

    Returns ``None`` for ``"latest handshake: (none)"`` so callers can
    distinguish "never handshook" from a successfully-parsed long age.
    Also returns ``None`` when no age token is present at all
    (handles malformed / truncated stdout gracefully).
    """
    if "(none)" in wg_show_stdout:
        return None
    matches = list(_AGE_TOKEN_RE.finditer(wg_show_stdout))
    if not matches:
        return None
    total = 0.0
    for m in matches:
        value = int(m.group("value"))
        unit = m.group("unit").lower()
        total += value * _UNIT_SECONDS[unit]
    return total


def health(
    handle: MullvadHandle,
    *,
    runner: SubprocessRunner = DEFAULT_RUNNER,
    max_handshake_age_seconds: float = DEFAULT_MAX_HANDSHAKE_AGE_SECONDS,
) -> bool:
    """Probe ``wg show`` and return ``True`` iff handshake age is fresh enough.

    Falls back to ``False`` on any subprocess failure — including the
    invocation itself failing (Codex P2 / HIGH-3, 2026-05-13). On hosts
    where ``wg`` is not on PATH the production ``subprocess.run`` raises
    :class:`FileNotFoundError`; with a runner-side ``timeout=`` kwarg
    (future PR2 wiring) :class:`subprocess.TimeoutExpired` is also
    possible. Both are coerced to ``unhealthy`` so the PR2 liveness
    worker records the path as down instead of crashing.
    """
    del handle
    try:
        result = runner(("wg", "show"))
    except (FileNotFoundError, PermissionError, subprocess.SubprocessError, OSError):
        return False
    if result.returncode != 0:
        return False
    age = parse_handshake_age(result.stdout or "")
    if age is None:
        return False
    return age <= max_handshake_age_seconds
