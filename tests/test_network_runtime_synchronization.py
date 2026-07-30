"""Runtime synchronization and failed-switch state recovery tests."""

from __future__ import annotations

import threading
import time

import pytest

from mordred_hermes.network._exceptions import AlreadySwitching, BringupFailed
from tests._network_runtime_fakes import _make_runtime, _TorFakes, _VpnFakes


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

    def test_stop_waits_for_switch_lock_release_window(self) -> None:
        """``stop`` cannot tear down the handle a switching caller still owns."""
        rt = _make_runtime()
        rt.use("clearnet")
        window_open = threading.Event()
        release_switch = threading.Event()
        errors: list[BaseException] = []

        def paused_worker_stop() -> None:
            rt._lock.release()  # type: ignore[attr-defined]
            try:
                window_open.set()
                release_switch.wait(timeout=2.0)
            finally:
                rt._lock.acquire()  # type: ignore[attr-defined]

        rt._stop_worker_during_switch = paused_worker_stop  # type: ignore[attr-defined]

        def switch() -> None:
            try:
                rt.use("tor")
            except BaseException as exc:
                errors.append(exc)

        switch_thread = threading.Thread(target=switch)
        switch_thread.start()
        assert window_open.wait(timeout=1.0)

        stop_thread = threading.Thread(target=rt.stop)
        stop_thread.start()
        time.sleep(0.05)
        assert stop_thread.is_alive(), "stop raced through an in-progress switch"

        release_switch.set()
        switch_thread.join(timeout=2.0)
        stop_thread.join(timeout=2.0)

        assert not switch_thread.is_alive()
        assert not stop_thread.is_alive()
        assert errors == []
        assert rt.status().ready is False

    @pytest.mark.parametrize("second_operation", ["use", "activate_and_freeze"])
    def test_competing_switch_fails_immediately_instead_of_waiting_for_bringup(
        self,
        second_operation: str,
    ) -> None:
        rt = _make_runtime()
        counter_entered = threading.Event()
        release_counter = threading.Event()
        errors: list[BaseException] = []

        def slow_subprocess_count() -> int:
            counter_entered.set()
            release_counter.wait(timeout=2.0)
            return 0

        rt._count_subprocesses = slow_subprocess_count  # type: ignore[attr-defined]

        def first_switch() -> None:
            try:
                rt.use("tor")
            except BaseException as exc:
                errors.append(exc)

        switch_thread = threading.Thread(target=first_switch)
        switch_thread.start()
        assert counter_entered.wait(timeout=1.0)

        started = time.monotonic()
        with pytest.raises(AlreadySwitching):
            getattr(rt, second_operation)("vpn")
        assert time.monotonic() - started < 0.2

        release_counter.set()
        switch_thread.join(timeout=2.0)
        assert not switch_thread.is_alive()
        assert errors == []
        rt.stop()

    def test_competing_switch_does_not_wait_for_runtime_state_lock(self) -> None:
        """The AlreadySwitching path must not acquire ``Runtime._lock``."""
        rt = _make_runtime()
        rt.use("clearnet")
        bringup_entered = threading.Event()
        release_bringup = threading.Event()
        first_errors: list[BaseException] = []
        second_errors: list[BaseException] = []
        second_elapsed: list[float] = []
        original_bring_up = rt._bring_up  # type: ignore[attr-defined]

        def stalled_bring_up(target: str):
            if target == "tor":
                bringup_entered.set()
                release_bringup.wait(timeout=2.0)
            return original_bring_up(target)

        rt._bring_up = stalled_bring_up  # type: ignore[attr-defined]

        def first_switch() -> None:
            try:
                rt.use("tor")
            except BaseException as exc:
                first_errors.append(exc)

        def competing_switch() -> None:
            started = time.monotonic()
            try:
                rt.use("vpn")
            except BaseException as exc:
                second_errors.append(exc)
            finally:
                second_elapsed.append(time.monotonic() - started)

        first_thread = threading.Thread(target=first_switch)
        first_thread.start()
        assert bringup_entered.wait(timeout=1.0)

        second_thread = threading.Thread(target=competing_switch)
        second_thread.start()
        try:
            second_thread.join(timeout=0.2)
            assert not second_thread.is_alive(), "operation-lock contention blocked on Runtime._lock held by bring-up"
        finally:
            release_bringup.set()
            first_thread.join(timeout=2.0)
            second_thread.join(timeout=2.0)

        assert first_errors == []
        assert len(second_errors) == 1
        assert isinstance(second_errors[0], AlreadySwitching)
        assert second_elapsed and second_elapsed[0] < 0.2
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

    def test_unexpected_provider_exception_is_normalized_to_idle(self) -> None:
        from mordred_hermes.network.runtime import State

        rt = _make_runtime(policy_mode="strict")

        def broken_provider(_target: str):
            raise ValueError("provider implementation bug")

        rt._bring_up = broken_provider  # type: ignore[attr-defined]
        with pytest.raises(BringupFailed, match=r"unexpectedly \(ValueError\)"):
            rt.use("vpn")

        assert rt._state is State.IDLE  # type: ignore[attr-defined]
        assert rt.status().active_path == "clearnet"
        assert rt.status().ready is False
        rt.stop()

    def test_lenient_unexpected_provider_exception_falls_back_cleanly(self) -> None:
        rt = _make_runtime(policy_mode="lenient")
        original_bring_up = rt._bring_up  # type: ignore[attr-defined]

        def broken_vpn_only(target: str):
            if target == "vpn":
                raise RuntimeError("provider bug with arbitrary detail")
            return original_bring_up(target)

        rt._bring_up = broken_vpn_only  # type: ignore[attr-defined]
        rt.use("vpn")

        status = rt.status()
        assert status.active_path == "clearnet"
        assert status.ready is True
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
