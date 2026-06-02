"""Tests for ``mordred_hermes.network.runtime`` (Phase 3 PR2).

The runtime is the concrete singleton behind the PR1 ``api.Runtime``
Protocol. It owns:

- A state machine (``IDLE`` -> ``BRINGING_UP`` -> ``READY`` ->
  ``TEARING_DOWN`` -> ``IDLE``; lenient bring-up failure produces
  ``DEGRADED``).
- Path-specific subprocess handles (Tor / Mullvad / clearnet no-op),
  reached through injectable callables matching the PR1 path modules.
- ``os.environ`` mutation per :mod:`mordred_hermes.network.proxy_env`,
  with snapshot/restore on :meth:`Runtime.stop`.
- M9 liveness worker thread - tests run with sub-second interval and a
  configurable failure threshold so they stay hermetic.
- M3 audit field ``live_subprocess_count`` - informational signal that
  env updates are transitive only for *future* spawns. Counter is
  injectable so tests do not depend on the real process tree.

Every external touchpoint (subprocess, env, audit) is injectable so the
unit tests never spawn a real ``tor`` / ``mullvad`` daemon or mutate the
test process's actual ``os.environ``.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.network._exceptions import (
    AlreadySwitching,
    BringupFailed,
    UnknownPath,
)
from mordred_hermes.network.paths import tor as tor_mod
from mordred_hermes.network.paths import vpn as vpn_mod

# --------------------------------------------------------------------------- #
# Fakes                                                                       #
# --------------------------------------------------------------------------- #


class _FakeAudit:
    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    def append(self, entry: Mapping[str, Any]) -> None:
        self.entries.append(dict(entry))


class _FakeTorProcess:
    """Stand-in for :class:`subprocess.Popen`. Default: stays alive."""

    def __init__(self, *, alive: bool = True) -> None:
        self._alive = alive
        self.terminated = False
        self.killed = False

    @property
    def stdout(self) -> Any:
        return iter(["Bootstrapped 100% (done)\n"])

    def terminate(self) -> None:
        self.terminated = True
        self._alive = False

    def kill(self) -> None:
        self.killed = True
        self._alive = False

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        return 0

    def poll(self) -> int | None:
        return None if self._alive else 0


@dataclass
class _TorFakes:
    """Bundle of injectables matching the production tor module signatures."""

    pick_port_return: int = 9050
    pick_port_raises: BaseException | None = None
    wait_raises: BaseException | None = None
    process: _FakeTorProcess = field(default_factory=_FakeTorProcess)
    pick_port_calls: int = 0
    start_calls: list[dict[str, Any]] = field(default_factory=list)
    wait_calls: list[Any] = field(default_factory=list)
    stop_calls: list[Any] = field(default_factory=list)
    health_return: bool = True
    health_calls: int = 0

    def pick_free_port(self, **_: Any) -> int:
        self.pick_port_calls += 1
        if self.pick_port_raises is not None:
            raise self.pick_port_raises
        return self.pick_port_return

    def start_process(self, *, binary: str, torrc: str, **_: Any) -> _FakeTorProcess:
        self.start_calls.append({"binary": binary, "torrc": torrc})
        return self.process

    def wait_for_bootstrap(self, process: Any, **_: Any) -> None:
        self.wait_calls.append(process)
        if self.wait_raises is not None:
            raise self.wait_raises

    def stop(self, handle: Any, **_: Any) -> None:
        self.stop_calls.append(handle)

    def health(self, handle: Any) -> bool:
        del handle
        self.health_calls += 1
        return self.health_return


@dataclass
class _VpnFakes:
    cli_path: str = "/fake/mullvad"
    detect_raises: BaseException | None = None
    bring_up_raises: BaseException | None = None
    wait_raises: BaseException | None = None
    bring_up_calls: list[dict[str, Any]] = field(default_factory=list)
    wait_calls: list[dict[str, Any]] = field(default_factory=list)
    disconnect_calls: list[dict[str, Any]] = field(default_factory=list)
    health_return: bool = True

    def detect_cli(self, **_: Any) -> str:
        if self.detect_raises is not None:
            raise self.detect_raises
        return self.cli_path

    def bring_up(self, **kwargs: Any) -> vpn_mod.MullvadHandle:
        self.bring_up_calls.append(kwargs)
        if self.bring_up_raises is not None:
            raise self.bring_up_raises
        return vpn_mod.MullvadHandle(
            cli_path=kwargs["cli_path"],
            region=kwargs["region"],
            lockdown_enforced=(kwargs["policy_mode"] == "strict"),
        )

    def wait_connected(self, **kwargs: Any) -> None:
        self.wait_calls.append(kwargs)
        if self.wait_raises is not None:
            raise self.wait_raises

    def disconnect(self, handle: Any, **kwargs: Any) -> None:
        self.disconnect_calls.append({"handle": handle, **kwargs})

    def health(self, handle: Any, **_: Any) -> bool:
        del handle
        return self.health_return


def _make_runtime(
    *,
    policy_mode: str = "off",
    default_path: str = "clearnet",
    audit: _FakeAudit | None = None,
    env: dict[str, str] | None = None,
    tor_fakes: _TorFakes | None = None,
    vpn_fakes: _VpnFakes | None = None,
    subprocess_count: int = 0,
    liveness_interval: float = 0.01,
    liveness_threshold: int = 2,
    tor_socks_port: int = 0,
    mullvad_region: str = "auto",
    no_proxy_extra: tuple[str, ...] = (),
    disable_ipv6: bool = True,
    tor_data_dir: Path | None = None,
    isolation_token: str | None = None,
) -> Any:
    """Build a Runtime with fakes wired in. Used by every test below."""
    from mordred_hermes.network.runtime import Runtime, RuntimeConfig

    tor = tor_fakes or _TorFakes()
    vpn = vpn_fakes or _VpnFakes()
    cfg = RuntimeConfig(
        policy_mode=policy_mode,  # type: ignore[arg-type]
        default_path=default_path,  # type: ignore[arg-type]
        tor_binary="tor-bin",
        tor_socks_port=tor_socks_port,
        tor_data_dir=tor_data_dir or Path("/tmp/mordred-test-tor-data"),
        mullvad_region=mullvad_region,
        disable_ipv6=disable_ipv6,
        no_proxy_extra=no_proxy_extra,
        liveness_interval_seconds=liveness_interval,
        liveness_failure_threshold=liveness_threshold,
        isolation_token=isolation_token,
    )
    return Runtime(
        config=cfg,
        audit=audit,
        env=env if env is not None else {},
        subprocess_counter=lambda: subprocess_count,
        tor_pick_free_port=tor.pick_free_port,
        tor_start_process=tor.start_process,
        tor_wait_for_bootstrap=tor.wait_for_bootstrap,
        tor_stop=tor.stop,
        tor_health=tor.health,
        vpn_detect_cli=vpn.detect_cli,
        vpn_bring_up=vpn.bring_up,
        vpn_wait_connected=vpn.wait_connected,
        vpn_disconnect=vpn.disconnect,
        vpn_health=vpn.health,
    )


# --------------------------------------------------------------------------- #
# State machine + basic surface                                               #
# --------------------------------------------------------------------------- #


class TestInitialState:
    def test_idle_status_reports_clearnet_not_ready(self) -> None:
        rt = _make_runtime()
        s = rt.status()
        assert s.active_path == "clearnet"
        assert s.ready is False

    def test_health_returns_true_when_idle(self) -> None:
        rt = _make_runtime()
        assert rt.health() is True


class TestUseValidation:
    def test_unknown_path_raises(self) -> None:
        rt = _make_runtime()
        with pytest.raises(UnknownPath):
            rt.use("i2p")

    def test_unknown_path_does_not_change_state(self) -> None:
        rt = _make_runtime()
        with pytest.raises(UnknownPath):
            rt.use("i2p")
        s = rt.status()
        assert s.active_path == "clearnet"
        assert s.ready is False


class TestClearnetUse:
    def test_use_clearnet_sets_ready(self) -> None:
        rt = _make_runtime()
        rt.use("clearnet")
        s = rt.status()
        assert s.active_path == "clearnet"
        assert s.ready is True
        rt.stop()

    def test_use_clearnet_does_not_mutate_proxy_env(self) -> None:
        env: dict[str, str] = {"UNRELATED": "value"}
        rt = _make_runtime(env=env)
        rt.use("clearnet")
        assert "HTTPS_PROXY" not in env
        assert "HTTP_PROXY" not in env
        assert "ALL_PROXY" not in env
        assert env["NO_PROXY"] == "localhost,127.0.0.1,::1"
        assert env["UNRELATED"] == "value"
        rt.stop()


# --------------------------------------------------------------------------- #
# Tor path                                                                    #
# --------------------------------------------------------------------------- #


class TestTorUse:
    def test_use_tor_picks_free_port_and_starts_process(self) -> None:
        tor = _TorFakes(pick_port_return=9150)
        rt = _make_runtime(tor_fakes=tor)
        rt.use("tor")
        assert tor.pick_port_calls == 1
        assert len(tor.start_calls) == 1
        torrc = tor.start_calls[0]["torrc"]
        assert "SOCKSPort 127.0.0.1:9150" in torrc
        rt.stop()

    def test_use_tor_with_explicit_port_skips_picker(self) -> None:
        tor = _TorFakes()
        rt = _make_runtime(tor_fakes=tor, tor_socks_port=9999)
        rt.use("tor")
        assert tor.pick_port_calls == 0
        torrc = tor.start_calls[0]["torrc"]
        assert "SOCKSPort 127.0.0.1:9999" in torrc
        rt.stop()

    def test_use_tor_sets_socks5h_proxy_env(self) -> None:
        env: dict[str, str] = {}
        tor = _TorFakes(pick_port_return=9050)
        rt = _make_runtime(tor_fakes=tor, env=env)
        rt.use("tor")
        assert env["HTTPS_PROXY"] == "socks5h://127.0.0.1:9050"
        assert env["HTTP_PROXY"] == "socks5h://127.0.0.1:9050"
        assert env["ALL_PROXY"] == "socks5h://127.0.0.1:9050"
        assert env["NO_PROXY"] == "localhost,127.0.0.1,::1"
        rt.stop()

    def test_use_tor_with_isolation_token_sets_credential(self) -> None:
        """A configured isolation_token rides into the SOCKS proxy URL so Tor's
        IsolateSOCKSAuth gives this session its own circuit (v2-N1 wiring)."""
        env: dict[str, str] = {}
        tor = _TorFakes(pick_port_return=9050)
        rt = _make_runtime(tor_fakes=tor, env=env, isolation_token="sess-42")
        rt.use("tor")
        assert env["HTTPS_PROXY"] == "socks5h://sess-42:sess-42@127.0.0.1:9050"
        assert env["ALL_PROXY"] == "socks5h://sess-42:sess-42@127.0.0.1:9050"
        rt.stop()

    def test_set_isolation_token_then_use_applies_credential(self) -> None:
        """``set_isolation_token`` (mirrors ``update_policy_mode``) takes effect
        on the next path application."""
        env: dict[str, str] = {}
        tor = _TorFakes(pick_port_return=9050)
        rt = _make_runtime(tor_fakes=tor, env=env)
        rt.set_isolation_token("sess-9")
        rt.use("tor")
        assert env["HTTPS_PROXY"] == "socks5h://sess-9:sess-9@127.0.0.1:9050"
        rt.stop()

    def test_no_isolation_token_keeps_bare_url(self) -> None:
        """Regression guard: unset token → credential-free URL (unchanged)."""
        env: dict[str, str] = {}
        tor = _TorFakes(pick_port_return=9050)
        rt = _make_runtime(tor_fakes=tor, env=env)
        rt.use("tor")
        assert env["HTTPS_PROXY"] == "socks5h://127.0.0.1:9050"
        rt.stop()

    def test_status_reports_tor_active(self) -> None:
        rt = _make_runtime()
        rt.use("tor")
        s = rt.status()
        assert s.active_path == "tor"
        assert s.ready is True
        rt.stop()

    def test_tor_bringup_failure_strict_reraises(self) -> None:
        tor = _TorFakes(wait_raises=BringupFailed("bootstrap timeout"))
        rt = _make_runtime(tor_fakes=tor, policy_mode="strict")
        with pytest.raises(BringupFailed):
            rt.use("tor")
        s = rt.status()
        assert s.ready is False
        rt.stop()

    def test_tor_bringup_failure_lenient_falls_back_to_clearnet(self) -> None:
        audit = _FakeAudit()
        tor = _TorFakes(wait_raises=BringupFailed("bootstrap timeout"))
        env: dict[str, str] = {}
        rt = _make_runtime(
            tor_fakes=tor,
            policy_mode="lenient",
            audit=audit,
            env=env,
        )
        rt.use("tor")
        s = rt.status()
        assert s.active_path == "clearnet"
        assert "HTTPS_PROXY" not in env
        reasons = [e.get("reason") for e in audit.entries]
        assert "network.bringup_failed" in reasons
        rt.stop()


# --------------------------------------------------------------------------- #
# VPN path                                                                    #
# --------------------------------------------------------------------------- #


class TestVpnUse:
    def test_use_vpn_calls_bring_up_with_policy_mode(self) -> None:
        vpn = _VpnFakes()
        rt = _make_runtime(vpn_fakes=vpn, policy_mode="strict", mullvad_region="jp")
        rt.use("vpn")
        assert len(vpn.bring_up_calls) == 1
        call = vpn.bring_up_calls[0]
        assert call["policy_mode"] == "strict"
        assert call["region"] == "jp"
        assert call["cli_path"] == "/fake/mullvad"
        rt.stop()

    def test_use_vpn_waits_for_connected(self) -> None:
        vpn = _VpnFakes()
        rt = _make_runtime(vpn_fakes=vpn)
        rt.use("vpn")
        assert len(vpn.wait_calls) == 1
        rt.stop()

    def test_vpn_no_proxy_env_set(self) -> None:
        """VPN routes packets at the kernel level - no HTTPS_PROXY needed."""
        env: dict[str, str] = {}
        rt = _make_runtime(env=env)
        rt.use("vpn")
        assert "HTTPS_PROXY" not in env
        assert env["NO_PROXY"] == "localhost,127.0.0.1,::1"
        rt.stop()


# --------------------------------------------------------------------------- #
# Path switching                                                              #
# --------------------------------------------------------------------------- #


class TestPathSwitch:
    def test_switch_tor_to_vpn_tears_down_tor(self) -> None:
        tor = _TorFakes()
        vpn = _VpnFakes()
        rt = _make_runtime(tor_fakes=tor, vpn_fakes=vpn)
        rt.use("tor")
        rt.use("vpn")
        assert len(tor.stop_calls) == 1
        s = rt.status()
        assert s.active_path == "vpn"
        rt.stop()

    def test_switch_vpn_to_tor_disconnects_vpn_preserving_lockdown(self) -> None:
        tor = _TorFakes()
        vpn = _VpnFakes()
        rt = _make_runtime(tor_fakes=tor, vpn_fakes=vpn, policy_mode="strict")
        rt.use("vpn")
        rt.use("tor")
        assert len(vpn.disconnect_calls) == 1
        assert vpn.disconnect_calls[0].get("preserve_lockdown") is True
        rt.stop()

    def test_switch_clears_proxy_env_when_leaving_tor(self) -> None:
        env: dict[str, str] = {}
        rt = _make_runtime(env=env)
        rt.use("tor")
        assert "HTTPS_PROXY" in env
        rt.use("vpn")
        assert "HTTPS_PROXY" not in env
        rt.stop()


# --------------------------------------------------------------------------- #
# AlreadySwitching                                                            #
# --------------------------------------------------------------------------- #


class TestConcurrency:
    def test_already_switching_raises_when_state_is_bringing_up(self) -> None:
        from mordred_hermes.network.runtime import Runtime, State

        rt = _make_runtime()
        rt._state = State.BRINGING_UP  # type: ignore[attr-defined]
        with pytest.raises(AlreadySwitching):
            rt.use("tor")
        rt._state = State.IDLE  # type: ignore[attr-defined]
        assert isinstance(rt, Runtime)


# --------------------------------------------------------------------------- #
# Audit                                                                       #
# --------------------------------------------------------------------------- #


class TestAuditEmission:
    def test_successful_use_emits_network_use_with_subprocess_count(self) -> None:
        audit = _FakeAudit()
        rt = _make_runtime(audit=audit, subprocess_count=3)
        rt.use("tor")
        success_entries = [e for e in audit.entries if e.get("reason") == "network.use"]
        assert len(success_entries) == 1
        entry = success_entries[0]
        assert entry["decision"] == "override"
        assert entry["prev_path"] == "clearnet"
        assert entry["new_path"] == "tor"
        assert entry["live_subprocess_count"] == 3
        rt.stop()

    def test_failed_use_strict_emits_network_use_failed(self) -> None:
        audit = _FakeAudit()
        tor = _TorFakes(wait_raises=BringupFailed("timeout"))
        rt = _make_runtime(tor_fakes=tor, policy_mode="strict", audit=audit)
        with pytest.raises(BringupFailed):
            rt.use("tor")
        failed = [e for e in audit.entries if e.get("reason") == "network.use_failed"]
        assert len(failed) == 1
        assert failed[0]["decision"] == "raise"
        rt.stop()

    def test_lenient_bringup_failure_emits_bringup_failed(self) -> None:
        audit = _FakeAudit()
        tor = _TorFakes(wait_raises=BringupFailed("timeout"))
        rt = _make_runtime(tor_fakes=tor, policy_mode="lenient", audit=audit)
        rt.use("tor")
        fallback = [e for e in audit.entries if e.get("reason") == "network.bringup_failed"]
        assert len(fallback) == 1
        assert fallback[0]["attempted_path"] == "tor"
        assert fallback[0]["fallback_path"] == "clearnet"
        rt.stop()

    def test_no_audit_writer_does_not_crash(self) -> None:
        rt = _make_runtime(audit=None)
        rt.use("tor")
        rt.stop()


# --------------------------------------------------------------------------- #
# Env snapshot / restore                                                      #
# --------------------------------------------------------------------------- #


class TestEnvSnapshot:
    def test_stop_restores_pre_existing_proxy_env(self) -> None:
        env: dict[str, str] = {
            "HTTPS_PROXY": "http://corp-proxy:3128",
            "NO_PROXY": "internal.example.com",
        }
        rt = _make_runtime(env=env)
        rt.use("tor")
        assert env["HTTPS_PROXY"].startswith("socks5h://")
        rt.stop()
        assert env["HTTPS_PROXY"] == "http://corp-proxy:3128"
        assert env["NO_PROXY"] == "internal.example.com"

    def test_stop_clears_managed_keys_added_by_runtime(self) -> None:
        env: dict[str, str] = {}
        rt = _make_runtime(env=env)
        rt.use("tor")
        assert "HTTPS_PROXY" in env
        rt.stop()
        assert "HTTPS_PROXY" not in env
        assert "NO_PROXY" not in env


# --------------------------------------------------------------------------- #
# Liveness worker (M9)                                                        #
# --------------------------------------------------------------------------- #


class TestLivenessWorker:
    def test_worker_starts_after_ready(self) -> None:
        rt = _make_runtime()
        rt.use("clearnet")
        time.sleep(0.05)
        assert rt._worker_thread is not None  # type: ignore[attr-defined]
        assert rt._worker_thread.is_alive()  # type: ignore[attr-defined]
        rt.stop()

    def test_stop_joins_worker(self) -> None:
        rt = _make_runtime()
        rt.use("clearnet")
        worker = rt._worker_thread  # type: ignore[attr-defined]
        rt.stop()
        assert worker is not None
        worker.join(timeout=2.0)
        assert not worker.is_alive()

    def test_consecutive_failures_flip_dropped(self) -> None:
        audit = _FakeAudit()
        tor = _TorFakes(health_return=False)
        rt = _make_runtime(
            tor_fakes=tor,
            audit=audit,
            liveness_interval=0.01,
            liveness_threshold=2,
        )
        rt.use("tor")
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline and not rt.is_dropped():
            time.sleep(0.02)
        assert rt.is_dropped()
        drops = [e for e in audit.entries if e.get("reason") == "network.path_dropped"]
        assert len(drops) >= 1
        assert drops[0]["path"] == "tor"
        rt.stop()

    def test_strict_drop_decision_is_block(self) -> None:
        audit = _FakeAudit()
        tor = _TorFakes(health_return=False)
        rt = _make_runtime(
            tor_fakes=tor,
            audit=audit,
            liveness_interval=0.01,
            liveness_threshold=2,
            policy_mode="strict",
        )
        rt.use("tor")
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline and not rt.is_dropped():
            time.sleep(0.02)
        drops = [e for e in audit.entries if e.get("reason") == "network.path_dropped"]
        assert drops
        assert drops[0]["decision"] == "block"
        rt.stop()

    def test_lenient_drop_decision_is_warn(self) -> None:
        audit = _FakeAudit()
        tor = _TorFakes(health_return=False)
        rt = _make_runtime(
            tor_fakes=tor,
            audit=audit,
            liveness_interval=0.01,
            liveness_threshold=2,
            policy_mode="lenient",
        )
        rt.use("tor")
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline and not rt.is_dropped():
            time.sleep(0.02)
        drops = [e for e in audit.entries if e.get("reason") == "network.path_dropped"]
        assert drops
        assert drops[0]["decision"] == "warn"
        rt.stop()

    def test_healthy_probes_never_flip_dropped(self) -> None:
        audit = _FakeAudit()
        tor = _TorFakes(health_return=True)
        rt = _make_runtime(
            tor_fakes=tor,
            audit=audit,
            liveness_interval=0.01,
            liveness_threshold=2,
        )
        rt.use("tor")
        time.sleep(0.1)
        assert not rt.is_dropped()
        rt.stop()


# --------------------------------------------------------------------------- #
# Module-level register / singleton wiring                                    #
# --------------------------------------------------------------------------- #


class TestTorSpawnOSErrorWrapping:
    """Codex round 3 P1 (2026-05-14): if the Tor binary is missing or
    not executable, ``subprocess.Popen`` raises ``FileNotFoundError`` /
    ``PermissionError`` (both ``OSError`` subclasses), not
    :class:`BringupFailed`. The strict-mode escalation path in
    :meth:`_switch` catches only :class:`BringupFailed`, so a missing
    binary would bypass cleanup, leave the runtime in
    ``BRINGING_UP``, and let Hermes's ``invoke_hook`` swallow the
    OSError as an ordinary :class:`Exception` — strict mode would
    fail open instead of refusing the session.

    Property: ``Runtime.use("tor")`` translates ``OSError`` from the
    spawn site into :class:`BringupFailed`.
    """

    def test_tor_spawn_filenotfound_becomes_bringup_failed(self) -> None:
        tor = _TorFakes()

        def missing_binary(**_: Any) -> Any:
            raise FileNotFoundError("[Errno 2] No such file or directory: 'tor'")

        tor.start_process = missing_binary  # type: ignore[method-assign]
        rt = _make_runtime(tor_fakes=tor, policy_mode="strict")
        with pytest.raises(BringupFailed):
            rt.use("tor")
        rt.stop()

    def test_tor_spawn_permissionerror_becomes_bringup_failed(self) -> None:
        tor = _TorFakes()

        def non_executable(**_: Any) -> Any:
            raise PermissionError("[Errno 13] Permission denied: '/usr/bin/tor'")

        tor.start_process = non_executable  # type: ignore[method-assign]
        rt = _make_runtime(tor_fakes=tor, policy_mode="strict")
        with pytest.raises(BringupFailed):
            rt.use("tor")
        rt.stop()


class TestWorkerStopEventIsolation:
    """Codex round 7 P2-B (2026-05-14): each worker spawn must get its
    OWN stop event. Sharing one event across spawns means
    :meth:`_start_worker` clears the signal that was just set for an
    orphan worker still stuck in a slow health probe — the orphan
    continues looping and double-increments ``_failure_count``.

    Property: after stop + start, the previous worker's stop event
    stays ``set`` while the new worker's stop event is fresh.
    """

    def test_each_worker_has_isolated_stop_event(self) -> None:
        rt = _make_runtime()
        rt.use("clearnet")  # spawn worker 1
        first_event = rt._worker_stop  # type: ignore[attr-defined]
        rt.use("tor")  # internal stop + start cycle
        second_event = rt._worker_stop  # type: ignore[attr-defined]

        assert first_event is not second_event, (
            "worker spawns share the same Event; orphaned worker could be "
            "revived when _start_worker clears the shared event"
        )
        # First worker was told to stop; that signal must still be set
        # even if it timed out the join.
        assert first_event.is_set(), "first worker's stop event was reset; orphan would resume looping"
        rt.stop()


class TestHealthProbeLockRelease:
    """Codex round 5 P2 (2026-05-14): :meth:`Runtime.health` must not
    hold ``_lock`` while it runs the path-specific health probe.
    ``paths.vpn.health`` shells out to ``wg show``; if that subprocess
    stalls (slow Mullvad daemon, kernel module hung), every ``status``
    / ``use`` / ``stop`` caller waits behind the same lock. The
    acceptance gate's "switch within 2s" promise breaks specifically
    when liveness probes stall.

    Property: a long-running health probe does not block a concurrent
    ``status()`` call.
    """

    def test_status_does_not_block_during_slow_health_probe(self) -> None:
        import threading

        probe_started = threading.Event()
        probe_release = threading.Event()

        def slow_health(handle: Any) -> bool:
            probe_started.set()
            probe_release.wait(timeout=2.0)
            return True

        tor = _TorFakes()
        tor.health = slow_health  # type: ignore[method-assign]
        rt = _make_runtime(tor_fakes=tor, liveness_interval=10.0)
        rt.use("tor")

        # Drive health() from a background thread so it stalls.
        health_thread = threading.Thread(target=rt.health)
        health_thread.start()
        try:
            assert probe_started.wait(timeout=1.0), "health probe never invoked"
            start = time.monotonic()
            s = rt.status()
            elapsed = time.monotonic() - start
            assert elapsed < 0.3, f"status() blocked for {elapsed:.3f}s during health probe"
            assert s is not None
        finally:
            probe_release.set()
            health_thread.join(timeout=2.0)
            rt.stop()


class TestVpnWaitFailureRollback:
    """Codex round 9 P1-A (2026-05-14): if ``bring_up()`` succeeded
    (lockdown applied) but ``wait_connected()`` times out, runtime
    cleanup must roll back the setting it applied. Otherwise lockdown
    stays on after the session aborts and blocks the user's traffic.

    Mullvad CLI 2026.2 drift (2026-05-20): the standalone
    ``always-require-vpn`` rollback path was removed upstream;
    ``lockdown-mode`` is now the single kill-switch surface, so only
    its applied-by-us state needs to drive the cleanup.
    """

    def test_wait_failure_clears_lockdown_when_applied_by_us(self) -> None:
        from mordred_hermes.network.paths import vpn as vpn_real

        vpn = _VpnFakes()

        # We turn lockdown on, then wait_connected times out.
        def applying_bring_up(**kwargs: Any) -> Any:
            return vpn_real.MullvadHandle(
                cli_path=kwargs["cli_path"],
                region=kwargs["region"],
                lockdown_enforced=(kwargs["policy_mode"] == "strict"),
                lockdown_applied_by_us=True,
            )

        vpn.bring_up = applying_bring_up  # type: ignore[method-assign]

        def slow_wait(**_: Any) -> None:
            from mordred_hermes.network._exceptions import BringupFailed

            raise BringupFailed("status timeout")

        vpn.wait_connected = slow_wait  # type: ignore[method-assign]

        rt = _make_runtime(vpn_fakes=vpn, policy_mode="strict")
        with pytest.raises(BringupFailed):
            rt.use("vpn")

        # Runtime cleanup must have called disconnect with the flag
        # that clears the applied setting.
        assert len(vpn.disconnect_calls) == 1
        call = vpn.disconnect_calls[0]
        # Lockdown WAS applied by us → clear it on cleanup.
        assert call.get("preserve_lockdown") is False
        rt.stop()

    def test_wait_failure_preserves_user_lockdown_when_not_applied(self) -> None:
        from mordred_hermes.network.paths import vpn as vpn_real

        vpn = _VpnFakes()

        # User already had lockdown on, so we did NOT apply it.
        def neutral_bring_up(**kwargs: Any) -> Any:
            return vpn_real.MullvadHandle(
                cli_path=kwargs["cli_path"],
                region=kwargs["region"],
                lockdown_enforced=(kwargs["policy_mode"] == "strict"),
                lockdown_applied_by_us=False,
            )

        vpn.bring_up = neutral_bring_up  # type: ignore[method-assign]

        def slow_wait(**_: Any) -> None:
            from mordred_hermes.network._exceptions import BringupFailed

            raise BringupFailed("status timeout")

        vpn.wait_connected = slow_wait  # type: ignore[method-assign]

        rt = _make_runtime(vpn_fakes=vpn, policy_mode="strict")
        with pytest.raises(BringupFailed):
            rt.use("vpn")

        # Runtime cleanup must NOT touch a setting we did not apply.
        call = vpn.disconnect_calls[0]
        assert call.get("preserve_lockdown") is True
        rt.stop()


class TestVpnBringupOSErrorWrapping:
    """Codex round 4 P1 (2026-05-14): VPN path symmetric to Tor r3-P1.
    Mullvad CLI invocations can raise ``OSError`` from
    :func:`paths.vpn.detect_cli` / ``bring_up`` / ``wait_connected``
    if the binary is missing or unprivileged. The strict escalation
    path catches only :class:`BringupFailed` — bare ``OSError`` would
    be swallowed by Hermes' ``invoke_hook`` and fail open.
    """

    def test_vpn_detect_cli_filenotfound_becomes_bringup_failed(self) -> None:
        vpn = _VpnFakes()

        def missing_cli(**_: Any) -> Any:
            raise FileNotFoundError("[Errno 2] No such file or directory: 'mullvad'")

        vpn.detect_cli = missing_cli  # type: ignore[method-assign]
        rt = _make_runtime(vpn_fakes=vpn, policy_mode="strict")
        with pytest.raises(BringupFailed):
            rt.use("vpn")
        rt.stop()

    def test_vpn_bring_up_oserror_becomes_bringup_failed(self) -> None:
        vpn = _VpnFakes()

        def oserror_bring_up(**_: Any) -> Any:
            raise PermissionError("mullvad daemon socket not accessible")

        vpn.bring_up = oserror_bring_up  # type: ignore[method-assign]
        rt = _make_runtime(vpn_fakes=vpn, policy_mode="strict")
        with pytest.raises(BringupFailed):
            rt.use("vpn")
        rt.stop()

    def test_vpn_wait_connected_oserror_becomes_bringup_failed(self) -> None:
        vpn = _VpnFakes()

        def oserror_wait(**_: Any) -> None:
            raise OSError("socket disappeared mid-poll")

        vpn.wait_connected = oserror_wait  # type: ignore[method-assign]
        rt = _make_runtime(vpn_fakes=vpn, policy_mode="strict")
        with pytest.raises(BringupFailed):
            rt.use("vpn")
        rt.stop()


class TestSwitchLockStateOrdering:
    """Codex P2 round 2 (2026-05-14): ``_stop_worker_during_switch``
    releases the runtime lock to join the M9 worker thread. If
    ``_state`` is still ``READY`` at that moment, a concurrent
    ``api.use()`` racing through the join window would pass the
    ``AlreadySwitching`` check, enter ``_switch`` itself, and clear
    ``_handle`` — when the first caller resumes it asserts on
    ``self._handle is not None`` and crashes.

    Property to enforce: ``_state == BRINGING_UP`` BEFORE the lock is
    released for the worker join.
    """

    def test_state_is_bringing_up_when_worker_join_runs(self) -> None:
        from mordred_hermes.network.runtime import State

        rt = _make_runtime()
        rt.use("clearnet")  # establish a worker
        observed: list[State] = []
        original_stop = rt._stop_worker_during_switch  # type: ignore[attr-defined]

        def spy() -> None:
            observed.append(rt._state)  # type: ignore[attr-defined]
            original_stop()

        rt._stop_worker_during_switch = spy  # type: ignore[attr-defined]
        rt.use("tor")  # triggers _stop_worker_during_switch in the new _switch
        assert observed == [State.BRINGING_UP], (
            f"_state at worker-join time was {observed}, expected [BRINGING_UP]. "
            "Concurrent use() could see stale READY state and race."
        )
        rt.stop()


class TestStrictBringupFailureClearsState:
    """Codex P2 fix (2026-05-14): when a strict switch tears down the
    previous path and the new bring-up fails, the runtime must restore
    env + reset active_path. Otherwise status() lies and subsequent
    spawns inherit stale proxy URLs pointing at a dead daemon.
    """

    def test_strict_tor_to_failing_vpn_clears_tor_env(self) -> None:
        env: dict[str, str] = {}
        tor = _TorFakes()
        vpn = _VpnFakes(bring_up_raises=BringupFailed("mullvad cli missing"))
        rt = _make_runtime(
            tor_fakes=tor,
            vpn_fakes=vpn,
            policy_mode="strict",
            env=env,
        )
        rt.use("tor")
        # Tor env established.
        assert env["HTTPS_PROXY"].startswith("socks5h://")

        # Switch to VPN fails strict.
        with pytest.raises(BringupFailed):
            rt.use("vpn")

        # After the failed switch:
        # - Tor was torn down (handle gone), so HTTPS_PROXY pointing at
        #   the dead Tor SOCKS port would leak any subsequent spawn.
        # - status() must reflect reality: no path is active.
        assert "HTTPS_PROXY" not in env, "stale Tor proxy left in env after strict switch failure"
        s = rt.status()
        assert s.active_path == "clearnet", f"status() reports stale path {s.active_path!r} after teardown"
        assert s.ready is False
        rt.stop()

    def test_strict_tor_to_failing_vpn_status_not_ready(self) -> None:
        env: dict[str, str] = {}
        tor = _TorFakes()
        vpn = _VpnFakes(bring_up_raises=BringupFailed("oops"))
        rt = _make_runtime(
            tor_fakes=tor,
            vpn_fakes=vpn,
            policy_mode="strict",
            env=env,
        )
        rt.use("tor")
        with pytest.raises(BringupFailed):
            rt.use("vpn")
        # No path is active anymore: ready must be False.
        assert rt.status().ready is False
        rt.stop()


class TestSubprocessCounterLockContention:
    """M1 fix (review 2026-05-14): the ``pgrep``-based subprocess counter
    must be invoked OUTSIDE the runtime lock so a slow probe does not
    block concurrent ``api.status()`` / ``api.health()`` callers."""

    def test_status_does_not_block_during_slow_counter(self) -> None:
        import threading

        counter_started = threading.Event()
        counter_release = threading.Event()

        def slow_counter() -> int:
            counter_started.set()
            counter_release.wait(timeout=2.0)
            return 7

        from mordred_hermes.network.runtime import Runtime, RuntimeConfig

        cfg = RuntimeConfig(
            policy_mode="off",
            liveness_interval_seconds=10.0,  # keep worker quiet during the test
            liveness_failure_threshold=2,
        )
        tor = _TorFakes()
        rt = Runtime(
            config=cfg,
            audit=None,
            env={},
            subprocess_counter=slow_counter,
            tor_pick_free_port=tor.pick_free_port,
            tor_start_process=tor.start_process,
            tor_wait_for_bootstrap=tor.wait_for_bootstrap,
            tor_stop=tor.stop,
            tor_health=tor.health,
        )

        use_thread = threading.Thread(target=lambda: rt.use("clearnet"))
        use_thread.start()
        try:
            # Wait for the counter to actually be invoked.
            assert counter_started.wait(timeout=1.0), "counter never invoked"

            # While counter is blocked, status() must NOT be held back by
            # the runtime lock. Allow a small slack for thread scheduling.
            start = time.monotonic()
            s = rt.status()
            elapsed = time.monotonic() - start
            assert elapsed < 0.3, f"status() blocked for {elapsed:.3f}s while counter ran"
            # We don't care what status reports here — only that it returned.
            assert s is not None
        finally:
            counter_release.set()
            use_thread.join(timeout=2.0)
            rt.stop()


class TestApiIntegration:
    def test_runtime_implements_api_protocol(self) -> None:
        from mordred_hermes.network import api

        rt = _make_runtime()
        api.set_runtime(rt)
        try:
            rt.use("tor")
            s = api.status()
            assert s.active_path == "tor"
            assert s.ready is True
            assert api.health() in (True, False)
        finally:
            rt.stop()
            api.reset_runtime_for_tests()


# --------------------------------------------------------------------------- #
# Production module guardrail                                                 #
# --------------------------------------------------------------------------- #


def test_production_tor_module_not_invoked(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unit tests must inject path-module fakes, never fall back to subprocess."""

    def explode(*_: Any, **__: Any) -> Any:
        raise AssertionError("production tor.start_process called from unit test")

    monkeypatch.setattr(tor_mod, "start_process", explode)
    rt = _make_runtime()
    rt.use("tor")
    rt.stop()
