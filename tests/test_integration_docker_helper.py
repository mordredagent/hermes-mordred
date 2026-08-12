"""Unit tests for the bootstrap-retry logic in ``tests.integration._docker``.

The compose lifecycle helper only runs for real inside the
``integration``-marked suites, but the retry decision in
:func:`compose_up` is pure control flow — so it is covered here in the
default (hermetic) suite with the subprocess layer monkeypatched out.
The scenario that motivated it: Tor bootstrap wedging past the deadline
on CI, where the fix is a fresh container (new guard/directory draw),
not a longer wait.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tests.integration import _docker


class _Harness:
    """Record the helper's compose-level calls in order.

    ``events`` collects the compose subcommand of every ``_run_compose``
    call plus a ``"wait"`` marker per bootstrap-token wait, so tests can
    assert the exact up/wait/down sequence. ``wait_outcomes`` scripts
    each wait: an exception instance to raise, or ``None`` to succeed.
    """

    def __init__(self, wait_outcomes: list[Exception | None]) -> None:
        self.events: list[str] = []
        self._wait_outcomes = wait_outcomes

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(_docker, "skip_reason_if_unavailable", lambda: None)
        monkeypatch.setattr(_docker, "_run_compose", self._fake_run_compose)
        monkeypatch.setattr(_docker, "_wait_for_bootstrap_token", self._fake_wait)

    def _fake_run_compose(
        self,
        project_dir: Path,
        args: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        self.events.append(args[0])
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

    def _fake_wait(
        self,
        project_dir: Path,
        service: str,
        token: str,
        timeout: float,
        **kwargs: object,
    ) -> None:
        self.events.append("wait")
        outcome = self._wait_outcomes.pop(0)
        if outcome is not None:
            raise outcome


class TestComposeUpBootstrapRetry:
    def test_timeout_recreates_container_then_succeeds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """First wait times out → container is torn down and brought up
        fresh; second wait succeeds → the body runs, then normal teardown.
        """
        harness = _Harness([_docker.BootstrapTimeout("attempt 1"), None])
        harness.install(monkeypatch)

        with _docker.compose_up(
            project_dir=Path("/nonexistent"),
            service="tor",
            bootstrap_token="Bootstrapped 100%",
        ):
            harness.events.append("body")

        assert harness.events == ["up", "wait", "down", "up", "wait", "body", "down"]

    def test_timeout_on_last_attempt_raises_and_tears_down(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Every attempt times out → the final BootstrapTimeout propagates,
        no extra recreate happens after the last attempt, and teardown
        still runs.
        """
        harness = _Harness([_docker.BootstrapTimeout("attempt 1"), _docker.BootstrapTimeout("attempt 2")])
        harness.install(monkeypatch)

        with (
            pytest.raises(_docker.BootstrapTimeout, match="attempt 2"),
            _docker.compose_up(
                project_dir=Path("/nonexistent"),
                service="tor",
                bootstrap_token="Bootstrapped 100%",
                attempts=2,
            ),
        ):
            pytest.fail("body must not run when bootstrap never completes")

        assert harness.events == ["up", "wait", "down", "up", "wait", "down"]

    def test_no_bootstrap_token_never_waits(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """``bootstrap_token=None`` yields right after ``up`` — no waits,
        no retries."""
        harness = _Harness([])
        harness.install(monkeypatch)

        with _docker.compose_up(project_dir=Path("/nonexistent"), service="tor"):
            harness.events.append("body")

        assert harness.events == ["up", "body", "down"]

    def test_attempts_below_one_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """``attempts=0`` would silently skip readiness detection — the
        helper refuses it before touching docker."""
        harness = _Harness([])
        harness.install(monkeypatch)

        with (
            pytest.raises(ValueError, match="attempts"),
            _docker.compose_up(
                project_dir=Path("/nonexistent"),
                service="tor",
                bootstrap_token="Bootstrapped 100%",
                attempts=0,
            ),
        ):
            pytest.fail("body must not run")

        assert harness.events == []
