"""Liveness workers, health probing, and Tor spawn resilience."""

from __future__ import annotations

import time
from typing import Any

import pytest

from mordred_hermes.network._exceptions import BringupFailed
from tests._network_runtime_fakes import _FakeAudit, _make_runtime, _TorFakes


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
        with pytest.raises(BringupFailed) as excinfo:
            rt.use("tor")
        msg = str(excinfo.value)
        assert "Install Tor" in msg
        assert "brew install tor" in msg
        assert "--tor-binary" in msg
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
