"""Tor path activation, configuration, and deep-health behavior."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.network._exceptions import BringupFailed, PathSwitchRequiresRestart
from mordred_hermes.network.paths import tor as tor_mod
from tests._network_runtime_fakes import (
    _FakeAudit,
    _FakeTorProcess,
    _make_runtime,
    _RecordingEnv,
    _TorFakes,
)


class TestTorHealthDefaultIsDeepProbe:
    """FIX 2 (2026-07-13): the runtime's DEFAULT Tor liveness probe must be
    the deep ``circuit_status_health`` (authenticated ControlPort
    ``GETINFO circuit-status``), not the shallow ``process.poll()`` health.
    A successfully authenticated empty response is healthy because idle Tor
    clients build circuits on demand. Control/auth/probe failures still fail
    closed. The probe self-degrades to the shallow check when the
    ``[tor-control]`` extra or control cookie is absent.

    These assertions fail if the default is reverted to ``tor_mod.health``.
    """

    def test_default_tor_health_is_circuit_status_health(self) -> None:
        from mordred_hermes.network.runtime import Runtime, RuntimeConfig

        # No ``tor_health=`` injection → the runtime must pick the deep probe.
        rt = Runtime(config=RuntimeConfig(), env={})
        assert rt._tor_health is tor_mod.circuit_status_health  # type: ignore[attr-defined]
        assert rt._tor_health is not tor_mod.health  # type: ignore[attr-defined]

    def test_injected_tor_health_still_overrides_default(self) -> None:
        """The ``tor_health=`` injection point must keep working so tests
        (and any future strict operator override) can swap in a fake."""
        from mordred_hermes.network.runtime import Runtime, RuntimeConfig

        def fake_health(_handle: Any) -> bool:
            return False

        rt = Runtime(config=RuntimeConfig(), env={}, tor_health=fake_health)
        assert rt._tor_health is fake_health  # type: ignore[attr-defined]

    def test_idle_deep_probe_does_not_mark_runtime_dropped(self, tmp_path: Path) -> None:
        """An authenticated empty circuit list remains healthy past the
        runtime's consecutive-failure threshold."""
        import functools

        from mordred_hermes.network.paths import tor as tor_paths
        from mordred_hermes.network.runtime import Runtime, RuntimeConfig, State, _ActiveHandle

        # A cookie file must exist so circuit_status_health opens the control
        # port instead of short-circuiting to the shallow fallback.
        data_dir = tmp_path
        (data_dir / "control_auth_cookie").write_bytes(b"\x00" * 32)

        class _NoBuiltController:
            def authenticate(self) -> None:
                return None

            def get_info(self, key: str) -> str:
                # A valid empty circuit list means Tor is idle and will
                # build a circuit when the next SOCKS request arrives; the
                # probe then confirms via Tor's own liveness verdict.
                if key == "network-liveness":
                    return "up"
                return ""

            def close(self) -> None:
                return None

            def __enter__(self) -> Any:
                return self

            def __exit__(self, *_: object) -> None:
                return None

        probe_count = 0

        def factory(*, host: str, port: int) -> Any:
            nonlocal probe_count
            del host, port
            probe_count += 1
            return _NoBuiltController()

        deep = functools.partial(tor_paths.circuit_status_health, controller_factory=factory)
        audit = _FakeAudit()
        rt = Runtime(
            config=RuntimeConfig(
                liveness_interval_seconds=0.01,
                liveness_failure_threshold=2,
            ),
            audit=audit,
            env={},
            tor_health=deep,
        )
        handle = tor_paths.TorHandle(process=_FakeTorProcess(), socks_port=9050, control_port=9051, data_dir=data_dir)
        rt._handle = _ActiveHandle("tor", handle)  # type: ignore[attr-defined]
        rt._state = State.READY  # type: ignore[attr-defined]
        rt._active_path = "tor"  # type: ignore[attr-defined]
        try:
            assert rt.health() is True
            rt._start_worker()  # type: ignore[attr-defined]
            deadline = time.monotonic() + 1.0
            while time.monotonic() < deadline and probe_count < 3:
                time.sleep(0.01)
            assert probe_count >= 3, "worker did not run two liveness probes"
            assert rt.is_dropped() is False
            assert not [e for e in audit.entries if e.get("reason") == "network.path_dropped"]
        finally:
            rt.stop()


class TestTorUse:
    def test_pinned_65535_is_rejected_before_rendering_invalid_control_port(self) -> None:
        tor = _TorFakes()
        rt = _make_runtime(tor_fakes=tor, tor_socks_port=65535, policy_mode="strict")

        with pytest.raises(BringupFailed, match=r"1\.\.65534"):
            rt.use("tor")

        assert tor.start_calls == []
        rt.stop()

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
        """A process-scoped token set before activation reaches the proxy URL."""
        env: dict[str, str] = {}
        tor = _TorFakes(pick_port_return=9050)
        rt = _make_runtime(tor_fakes=tor, env=env)
        rt.set_isolation_token("sess-9")
        rt.use("tor")
        assert env["HTTPS_PROXY"] == "socks5h://sess-9:sess-9@127.0.0.1:9050"
        rt.stop()

    def test_set_isolation_token_after_activation_requires_restart(self) -> None:
        rt = _make_runtime(isolation_token="process-a")
        rt.use("tor")

        with pytest.raises(PathSwitchRequiresRestart, match="process-scoped"):
            rt.set_isolation_token("session-b")

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


class TestApplyEnvNeverAllAbsentDuringSwitch:
    """``_apply_env`` must write the desired proxy vars BEFORE pruning the
    now-unwanted managed keys, never pop-all-then-set-all. See
    ``_RecordingEnv`` docstring for why: ``self._env`` is process-global
    ``os.environ`` and the runtime lock cannot stop another thread's
    ``subprocess.Popen`` from snapshotting it mid-switch.

    Property under test: for a switch INTO a proxied path (tor), the proxy
    var (``HTTPS_PROXY``) must be present in every recorded intermediate
    snapshot — it must never go through an all-managed-vars-absent window.
    """

    def test_ready_tor_to_tor_is_noop_without_env_reapply(self) -> None:
        env = _RecordingEnv()
        tor = _TorFakes()
        rt = _make_runtime(tor_fakes=tor, env=env)
        rt.use("tor")
        assert "HTTPS_PROXY" in env
        env.snapshots.clear()
        rt.use("tor")
        assert env.snapshots == []
        assert len(tor.start_calls) == 1
        assert tor.stop_calls == []
        rt.stop()

    def test_https_proxy_never_absent_across_clearnet_to_tor(self) -> None:
        env = _RecordingEnv()
        tor = _TorFakes()
        rt = _make_runtime(tor_fakes=tor, env=env)
        rt.use("clearnet")
        # Seed a pre-existing proxy value as if a prior process (or a
        # previous Mordred session) already had Tor active — this is the
        # shape that actually exercises the pop/set ordering, since an empty
        # starting env can't show an absence regression either way.
        env["HTTPS_PROXY"] = "socks5h://127.0.0.1:9050"
        env.snapshots.clear()
        rt.use("tor")
        assert env.snapshots, "expected _apply_env's mutations to be recorded"
        assert all("HTTPS_PROXY" in snap for snap in env.snapshots), (
            "HTTPS_PROXY was absent from the managed env at some point while "
            "switching into tor — a subprocess spawned in that window would "
            "have gone out direct/clearnet"
        )
        rt.stop()


class TestTorWaitUnicodeDecodeErrorWrapped:
    """``_bring_up_tor``'s catch around ``self._tor_wait(proc)`` was widened
    from ``except BringupFailed`` to ``except Exception``. ``_tor_wait``
    tails tor's stdout in text mode, so a non-UTF-8 byte in tor's log output
    raises ``UnicodeDecodeError`` — not ``BringupFailed``. Left uncaught,
    that (a) orphaned the spawned tor child (nothing terminated it) and (b)
    unwound past ``_switch``'s ``except BringupFailed`` with ``_state``
    still at ``BRINGING_UP``, bricking the runtime so every later ``use()``
    raised ``AlreadySwitching`` forever.
    """

    def _fakes(self) -> _TorFakes:
        # Constructed the way the real decoder raises it: a single invalid
        # start byte, matching a genuinely malformed UTF-8 log line.
        return _TorFakes(wait_raises=UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte"))

    def test_half_started_process_is_stopped_and_wrapped_as_bringup_failed(self) -> None:
        tor = self._fakes()
        rt = _make_runtime(tor_fakes=tor, policy_mode="strict")
        with pytest.raises(BringupFailed):
            rt.use("tor")
        assert len(tor.stop_calls) == 1, "half-started tor process must be cleaned up, not orphaned"
        rt.stop()

    def test_runtime_not_wedged_after_unicode_decode_error(self) -> None:
        tor = self._fakes()
        rt = _make_runtime(tor_fakes=tor, policy_mode="strict")
        with pytest.raises(BringupFailed):
            rt.use("tor")
        # Must not be stuck at BRINGING_UP: a subsequent use() succeeds
        # rather than raising AlreadySwitching.
        rt.use("clearnet")
        s = rt.status()
        assert s.active_path == "clearnet"
        assert s.ready is True
        rt.stop()


class TestBringUpTorRendersDisableIpv6:
    """``_bring_up_tor`` now threads ``self._config.disable_ipv6`` into
    ``render_torrc``. Before this wiring, the flag was resolved into
    ``RuntimeConfig`` from ``policy.json`` and then dropped on the floor —
    every torrc was rendered identically regardless of policy, so the
    advertised strict-mode ``ClientUseIPv6 0`` defence was a silent no-op.
    Exercises the REAL ``tor_mod.render_torrc`` (only the subprocess-facing
    calls are faked), so this catches a regression in the wiring itself,
    not just in ``render_torrc``'s own rendering logic (see
    ``TestTorrcRenderDisableIpv6`` in ``test_paths_tor.py`` for that).
    """

    def test_disable_ipv6_true_reaches_rendered_torrc(self) -> None:
        tor = _TorFakes()
        rt = _make_runtime(tor_fakes=tor, disable_ipv6=True)
        rt.use("tor")
        assert len(tor.start_calls) == 1
        assert "ClientUseIPv6 0" in tor.start_calls[0]["torrc"]
        rt.stop()

    def test_disable_ipv6_false_omitted_from_rendered_torrc(self) -> None:
        tor = _TorFakes()
        rt = _make_runtime(tor_fakes=tor, disable_ipv6=False)
        rt.use("tor")
        assert "ClientUseIPv6" not in tor.start_calls[0]["torrc"]
        rt.stop()
