"""Shared fakes and runtime factory for network runtime tests.

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

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mordred_hermes.network.paths import vpn as vpn_mod
from mordred_hermes.network.vpn_providers import VpnCapabilities

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
    killswitch: bool = True  # drives capabilities.killswitch (Phase 2 strict gate)
    name: str = "fake-vpn"

    @property
    def capabilities(self) -> VpnCapabilities:
        return VpnCapabilities(killswitch=self.killswitch, dns_leak_safe=True)

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


class _RecordingEnv(dict[str, str]):
    """``dict`` subclass that snapshots its own contents after every mutation.

    Regression aid for the ``_apply_env`` set-then-prune fix: ``self._env`` in
    production IS ``os.environ`` — a global another thread can read via
    ``subprocess.Popen`` at any instant, and the runtime lock only serialises
    the runtime's OWN writers. A pop-all-then-set-all ordering left a real
    window where every managed proxy var was absent at once; a child spawned
    in that window would go out direct/clearnet. Recording a snapshot on
    every ``__setitem__`` / ``__delitem__`` / ``pop`` lets a test assert that
    window never existed, rather than only checking the before/after state.
    """

    def __init__(self, *args: Any, **kwargs: str) -> None:
        super().__init__(*args, **kwargs)
        self.snapshots: list[dict[str, str]] = []

    def _record(self) -> None:
        self.snapshots.append(dict(self))

    def __setitem__(self, key: str, value: str) -> None:
        super().__setitem__(key, value)
        self._record()

    def __delitem__(self, key: str) -> None:
        super().__delitem__(key)
        self._record()

    def pop(self, key: str, *default: str | None) -> str | None:
        result = super().pop(key, *default)
        self._record()
        return result


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
        vpn_provider=vpn,
    )
