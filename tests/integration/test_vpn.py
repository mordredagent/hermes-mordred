"""Live-gated Mullvad integration tests.

Gated by ``MORDRED_LIVE_VPN_TEST=1`` and a real Mullvad account number
in ``MORDRED_MULLVAD_ACCOUNT``. Skipped by default so ``pytest -q`` on
CI and dev machines remains hermetic.

.. code-block:: bash

   MORDRED_LIVE_VPN_TEST=1 MORDRED_MULLVAD_ACCOUNT=XXXX-YYYY-ZZZZ \\
     pytest tests/integration/test_vpn.py -v

These tests are workflow_dispatch-only in CI — never run on every PR
because (a) the account number is a paid resource and (b) the bring-up
mutates real network state. See ``.github/workflows/integration-vpn.yml``.

Scope (Phase 3 PR3b, TODO §3.3):

1. ``bring_up`` → ``wait_connected`` → ``health`` → ``disconnect``
   roundtrip succeeds against a real ``mullvad`` daemon.
2. After ``disconnect(preserve_lockdown=False)``, the kill-switch
   actually returns to ``off`` when WE flipped it on (the
   ``MullvadHandle.lockdown_applied_by_us`` flag).
3. ``parse_handshake_age`` agrees with reality — the value returned
   immediately after connect is below the strict-mode 180s threshold.

The PR1 unit tests (``test_paths_vpn.py``) cover the parse / rollback
contract with fake runners; this file ensures the parse format we
expect actually matches what shipping ``mullvad`` / ``wg show`` emit.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Iterator

import pytest

from mordred_hermes.network.paths import vpn

_LIVE_GATE_ENV = "MORDRED_LIVE_VPN_TEST"
_ACCOUNT_ENV = "MORDRED_MULLVAD_ACCOUNT"


def _live_or_skip() -> tuple[str, str]:
    """Return ``(cli_path, account)`` or skip the test if gates are off."""
    if os.environ.get(_LIVE_GATE_ENV) != "1":
        pytest.skip(f"set {_LIVE_GATE_ENV}=1 to run live Mullvad integration tests")
    account = os.environ.get(_ACCOUNT_ENV)
    if not account:
        pytest.skip(f"{_ACCOUNT_ENV} env var must hold a Mullvad account number")
    try:
        cli_path = vpn.detect_cli()
    except vpn.BringupFailed as e:
        pytest.skip(f"mullvad CLI not installed: {e}")
    return cli_path, account


@pytest.fixture
def authenticated_cli() -> Iterator[str]:
    """Login the mullvad CLI for the duration of one test, logout on teardown.

    Each test that mutates connection state pays the login cost so a
    failure in test N doesn't poison test N+1's account session.
    """
    cli_path, account = _live_or_skip()

    subprocess.run(
        [cli_path, "account", "login", account],
        check=True,
        capture_output=True,
        text=True,
        timeout=30.0,
    )
    try:
        yield cli_path
    finally:
        subprocess.run(
            [cli_path, "disconnect"],
            check=False,
            capture_output=True,
            text=True,
            timeout=15.0,
        )
        subprocess.run(
            [cli_path, "account", "logout"],
            check=False,
            capture_output=True,
            text=True,
            timeout=15.0,
        )


class TestMullvadConnectionRoundtrip:
    """Acceptance gate row 2 (live verification — TODO §Phase 3 L379)."""

    def test_bring_up_wait_connected_disconnect(self, authenticated_cli: str) -> None:
        """Connect, wait for handshake, disconnect — full happy path."""
        handle = vpn.bring_up(
            cli_path=authenticated_cli,
            region="auto",
            policy_mode="lenient",
        )
        try:
            vpn.wait_connected(cli_path=authenticated_cli, timeout=30.0)
        finally:
            vpn.disconnect(handle, preserve_lockdown=True)


class TestMullvadLockdownRollback:
    """Codex round 7 P2-A / round 8 P1-A: only roll back kill-switch
    settings WE flipped on.
    """

    def test_lockdown_off_after_disconnect_when_we_applied_it(
        self,
        authenticated_cli: str,
    ) -> None:
        """If the user starts with lockdown off and we bring up in strict,
        ``MullvadHandle.lockdown_applied_by_us`` must be True, and
        disconnecting with ``preserve_lockdown=False`` must restore the
        pre-Mordred state.
        """
        subprocess.run(
            [authenticated_cli, "lockdown-mode", "set", "off"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10.0,
        )

        handle = vpn.bring_up(
            cli_path=authenticated_cli,
            region="auto",
            policy_mode="strict",
        )
        try:
            assert handle.lockdown_applied_by_us, "expected `bring_up` to flip lockdown-mode on (it was off pre-test)"
        finally:
            vpn.disconnect(handle, preserve_lockdown=False, clear_always_require=True)

        result = subprocess.run(
            [authenticated_cli, "lockdown-mode", "get"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10.0,
        )
        assert "off" in (result.stdout or "").lower(), (
            f"lockdown not restored to off after disconnect: {result.stdout!r}"
        )


class TestMullvadHandshakeFreshness:
    """Acceptance gate row 3 — health() returns truthful state right
    after a successful connect.
    """

    def test_health_passes_immediately_after_connect(
        self,
        authenticated_cli: str,
    ) -> None:
        """Right after ``wait_connected`` returns, ``health()`` should be
        True with handshake age well under the strict 180s threshold.

        Skips when ``wg`` is not on PATH (Mullvad's bundled wg may live
        elsewhere on macOS — the test then has nothing to parse).
        """
        if shutil.which("wg") is None:
            pytest.skip("wg binary not on $PATH; health() probe needs it")

        handle = vpn.bring_up(
            cli_path=authenticated_cli,
            region="auto",
            policy_mode="lenient",
        )
        try:
            vpn.wait_connected(cli_path=authenticated_cli, timeout=30.0)
            assert vpn.health(handle, max_handshake_age_seconds=180.0), (
                "wg show reported no fresh handshake despite connect succeeding"
            )
        finally:
            vpn.disconnect(handle, preserve_lockdown=True)
