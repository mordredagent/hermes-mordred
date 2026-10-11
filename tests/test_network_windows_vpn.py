"""Native Windows route capabilities, runtime gates and process-only routing (host-emulated).

Windows ruling for this slice: Tor is the supported private route; Mullvad
and WireGuard report ``supported=False`` (``not-ported-on-windows``); the
custom provider is supported only with validated ``.exe`` images. Strict mode
never falls back to clearnet. No VPN client, Tor, registry, WinINET or system
proxy setting is touched: every runner and filesystem view is injected.
"""

from __future__ import annotations

import ast
import dataclasses
import json
import ntpath
import subprocess
import sys
import time
from collections.abc import Iterator, MutableMapping
from pathlib import Path
from typing import Any

import psutil
import pytest

import mordred_hermes.network as network
from mordred_hermes import _config_io as cio
from mordred_hermes._config_io import CanonicalPaths, canonical_session
from mordred_hermes._private_fs import FileIdentity, FileMetadata, PrivateFSError
from mordred_hermes.network import _windows_exec as wexec
from mordred_hermes.network import api, hooks
from mordred_hermes.network import runtime as runtime_mod
from mordred_hermes.network._exceptions import BringupFailed, MordredPathDropped, UnknownVpnProvider
from mordred_hermes.network.paths import vpn as vpn_mod
from mordred_hermes.network.runtime import Runtime, RuntimeConfig, State
from mordred_hermes.network.vpn_providers import (
    CustomCommandProvider,
    WireGuardProvider,
    provider_capability,
)
from mordred_hermes.network.vpn_providers.registry import NOT_PORTED_ON_WINDOWS, ProviderCapability
from tests._network_hooks_helpers import _reset_api
from tests._network_runtime_fakes import _FakeAudit, _FakeTorProcess, _make_runtime, _TorFakes, _VpnFakes

pytestmark = pytest.mark.usefixtures(_reset_api.__name__)

TOOLS = r"C:\Program Files\Vendor VPN"
VPNCTL = TOOLS + r"\vpnctl.exe"
PUBLIC = r"C:\Users\Public\vpnctl.exe"
NETWORK_PACKAGE = Path(network.__file__).parent


@pytest.fixture
def windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "win32")


class WindowsImages:
    """Patches the resolver's filesystem and admission seams module-wide."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.files: set[str] = set()
        self.managed: set[str] = set()
        self.private: set[str] = set()
        monkeypatch.setattr(wexec, "_is_file", lambda path: ntpath.normcase(path) in self.files)
        monkeypatch.setattr(wexec, "inspect_managed_installation_image", self._managed)
        monkeypatch.setattr(wexec, "admit_current_user_image", self._private)
        monkeypatch.setenv("PATH", f"{TOOLS};C:\\Users\\Public")

    def add(self, path: str, trust: str) -> None:
        self.files.add(ntpath.normcase(path))
        if trust == "managed":
            self.managed.add(ntpath.normcase(path))
        elif trust == "user-private":
            self.private.add(ntpath.normcase(path))

    def _managed(self, path: str) -> FileMetadata:
        if ntpath.normcase(path) in self.managed:
            return FileMetadata(FileIdentity(1, b"img"), 1, 0)
        raise PrivateFSError("unsafe", "managed_image_acl")

    def _private(self, path: str) -> None:
        if ntpath.normcase(path) not in self.private:
            raise PrivateFSError("unsafe", "confidential_acl")


@pytest.fixture
def images(monkeypatch: pytest.MonkeyPatch, windows: None) -> WindowsImages:
    return WindowsImages(monkeypatch)


# --------------------------------------------------------------------------- #
# Capability table                                                            #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("name", ["mullvad", "wireguard"])
@pytest.mark.parametrize("mode", ["strict", "lenient", "off"])
def test_windows_mullvad_and_wireguard_are_not_ported(windows: None, name: str, mode: str) -> None:
    capability = provider_capability(name, policy_mode=mode)  # type: ignore[arg-type]
    assert capability == ProviderCapability(supported=False, available=False, reason=NOT_PORTED_ON_WINDOWS)
    supported, available, reason = capability
    assert (supported, available, reason) == (False, False, "not-ported-on-windows")


def test_windows_custom_capability_requires_a_configured_command(images: WindowsImages) -> None:
    assert provider_capability("custom") == ProviderCapability(True, False, "custom-command-not-configured")


def test_windows_custom_capability_with_validated_executables(images: WindowsImages) -> None:
    images.add(VPNCTL, "managed")
    capability = provider_capability(
        "custom",
        policy_mode="strict",
        custom_up_cmd=("vpnctl", "connect"),
        custom_down_cmd=(VPNCTL, "disconnect"),
        custom_health_cmd=("vpnctl.exe", "status"),
    )
    assert capability == ProviderCapability(True, True, None)


@pytest.mark.parametrize(
    ("command", "reason"),
    [
        (("vpnctl.cmd", "connect"), "executable-not-exe"),
        (("missing", "connect"), "executable-not-found"),
        ((r"tools\vpnctl.exe",), "executable-path-relative"),
        ((r"\\server\share\vpnctl.exe",), "executable-path-unsupported"),
    ],
)
def test_windows_custom_capability_reports_unusable_executables(
    images: WindowsImages, command: tuple[str, ...], reason: str
) -> None:
    images.add(VPNCTL, "managed")
    capability = provider_capability("custom", policy_mode="lenient", custom_up_cmd=command)
    assert capability == ProviderCapability(True, False, reason)


def test_windows_custom_capability_with_an_unusable_teardown_command(images: WindowsImages) -> None:
    images.add(VPNCTL, "managed")
    capability = provider_capability("custom", custom_up_cmd=("vpnctl",), custom_down_cmd=("down.bat",))
    assert capability == ProviderCapability(True, False, "executable-not-exe")


def test_windows_custom_capability_untrusted_image_depends_on_policy(images: WindowsImages) -> None:
    images.add(PUBLIC, "untrusted")
    strict = provider_capability("custom", policy_mode="strict", custom_up_cmd=(PUBLIC, "connect"))
    lenient = provider_capability("custom", policy_mode="lenient", custom_up_cmd=(PUBLIC, "connect"))
    assert strict == ProviderCapability(True, False, "executable-untrusted-location")
    assert lenient == ProviderCapability(True, True, "executable-untrusted-location")


def test_unknown_provider_capability_raises(windows: None) -> None:
    with pytest.raises(UnknownVpnProvider):
        provider_capability("nordvpn")


def test_posix_capabilities_report_installation_only() -> None:
    def which(name: str) -> str | None:
        return {"mullvad": "/usr/bin/mullvad", "wg-quick": "/usr/bin/wg-quick", "vpnctl": "/usr/bin/vpnctl"}.get(name)

    def nothing(_name: str) -> None:
        return None

    common: dict[str, Any] = {"platform": "linux", "exists": lambda path: path == "/etc/wireguard/wg0.conf"}
    assert provider_capability("mullvad", which=which, **common) == ProviderCapability(True, True, None)
    assert provider_capability("mullvad", which=nothing, **common) == ProviderCapability(True, False, "not-installed")
    assert provider_capability(
        "wireguard", which=which, wireguard_config_path="/etc/wireguard/wg0.conf", **common
    ) == ProviderCapability(True, True, None)
    assert provider_capability("wireguard", which=which, **common) == ProviderCapability(True, False, "not-configured")
    assert provider_capability("custom", which=which, custom_up_cmd=("vpnctl", "up"), **common) == ProviderCapability(
        True, True, None
    )
    assert provider_capability("custom", which=which, **common) == ProviderCapability(
        True, False, "custom-command-not-configured"
    )


# --------------------------------------------------------------------------- #
# Providers refuse before any subprocess                                      #
# --------------------------------------------------------------------------- #


class NeverRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, argv: Any, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append(tuple(argv))
        raise AssertionError("no subprocess may run for an unsupported Windows provider")


def test_windows_mullvad_path_refuses_before_any_subprocess(windows: None) -> None:
    runner = NeverRunner()
    handle = vpn_mod.MullvadHandle(
        cli_path=r"C:\Program Files\Mullvad VPN\mullvad.exe", region="auto", lockdown_enforced=True
    )
    with pytest.raises(BringupFailed, match=NOT_PORTED_ON_WINDOWS):
        vpn_mod.detect_cli(which=lambda name: r"C:\Program Files\Mullvad VPN\mullvad.exe")
    with pytest.raises(BringupFailed, match=NOT_PORTED_ON_WINDOWS):
        vpn_mod.bring_up(cli_path=handle.cli_path, region="auto", policy_mode="strict", runner=runner)
    with pytest.raises(BringupFailed, match=NOT_PORTED_ON_WINDOWS):
        vpn_mod.wait_connected(cli_path=handle.cli_path, runner=runner)
    with pytest.raises(BringupFailed, match=NOT_PORTED_ON_WINDOWS):
        vpn_mod.disconnect(handle, runner=runner)
    assert vpn_mod.health(handle, runner=runner) is False
    assert runner.calls == []


def test_windows_wireguard_provider_refuses_before_any_subprocess(windows: None) -> None:
    runner = NeverRunner()
    provider = WireGuardProvider(config_path=r"C:\wg\wg0.conf", exists=lambda path: True)
    with pytest.raises(BringupFailed, match=NOT_PORTED_ON_WINDOWS):
        provider.detect_cli(which=lambda name: r"C:\Program Files\WireGuard\wireguard.exe")
    with pytest.raises(BringupFailed, match=NOT_PORTED_ON_WINDOWS):
        provider.bring_up(cli_path="wg-quick", region="auto", policy_mode="lenient", runner=runner)
    from mordred_hermes.network.vpn_providers.wireguard import WireGuardHandle

    handle = WireGuardHandle(wg_quick_path="wg-quick", config_path=r"C:\wg\wg0.conf")
    with pytest.raises(BringupFailed, match=NOT_PORTED_ON_WINDOWS):
        provider.disconnect(handle, runner=runner)
    assert provider.health(handle, runner=runner) is False
    assert runner.calls == []


class RecordingRunner:
    def __init__(self, returncode: int = 0) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.returncode = returncode

    def __call__(self, argv: Any, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        assert isinstance(argv, tuple | list)
        self.calls.append(tuple(argv))
        return subprocess.CompletedProcess(list(argv), self.returncode, "", "")


def test_windows_custom_provider_runs_only_resolved_absolute_exe_argv(images: WindowsImages) -> None:
    images.add(VPNCTL, "managed")
    provider = CustomCommandProvider(
        up_cmd=("vpnctl", "connect", "--fast"), down_cmd=("vpnctl", "disconnect"), health_cmd=("vpnctl", "status")
    )
    runner = RecordingRunner()
    assert provider.detect_cli() == VPNCTL
    handle = provider.bring_up(cli_path="ignored", region="auto", policy_mode="lenient", runner=runner)
    assert provider.health(handle, runner=runner) is True
    provider.disconnect(handle, runner=runner)
    assert runner.calls == [
        (VPNCTL, "connect", "--fast"),
        (VPNCTL, "status"),
        (VPNCTL, "disconnect"),
    ]


@pytest.mark.parametrize("command", [("vpn.cmd", "connect"), ("vpn.bat",), (r"bin\vpn.exe",)])
def test_windows_custom_provider_refuses_non_exe_or_relative_commands(
    images: WindowsImages, command: tuple[str, ...]
) -> None:
    runner = NeverRunner()
    provider = CustomCommandProvider(up_cmd=command, down_cmd=())
    with pytest.raises(BringupFailed):
        provider.detect_cli()
    with pytest.raises(BringupFailed):
        provider.bring_up(cli_path="x", region="auto", policy_mode="lenient", runner=runner)
    assert runner.calls == []


def test_windows_custom_provider_strict_refuses_untrusted_images_lenient_warns(
    images: WindowsImages, caplog: pytest.LogCaptureFixture
) -> None:
    images.add(PUBLIC, "untrusted")
    runner = RecordingRunner()
    provider = CustomCommandProvider(up_cmd=(PUBLIC, "connect"), down_cmd=())
    with pytest.raises(wexec.ExecutableRefused):
        provider.bring_up(cli_path="x", region="auto", policy_mode="strict", runner=runner)
    assert runner.calls == []
    with caplog.at_level("WARNING", logger="mordred.network"):
        provider.bring_up(cli_path="x", region="auto", policy_mode="lenient", runner=runner)
    assert runner.calls == [(PUBLIC, "connect")]
    assert any("untrusted" in record.getMessage() for record in caplog.records)


def test_windows_default_runner_passes_argv_lists_with_an_explicit_image(
    windows: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[Any, dict[str, Any]]] = []

    def fake_run(args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    vpn_mod._default_runner((VPNCTL, "connect"), timeout=5.0)
    [(args, kwargs)] = calls
    assert args == [VPNCTL, "connect"]
    assert kwargs["executable"] == VPNCTL
    assert kwargs["stdin"] is subprocess.DEVNULL
    assert kwargs["creationflags"] & 0x08000000
    assert kwargs.get("shell", False) is False
    assert kwargs["timeout"] == 5.0


def test_posix_default_runner_is_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    calls: list[tuple[Any, dict[str, Any]]] = []

    def fake_run(args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    vpn_mod._default_runner(("/usr/bin/mullvad", "status"), timeout=5.0)
    assert calls == [
        (["/usr/bin/mullvad", "status"], {"check": False, "capture_output": True, "text": True, "timeout": 5.0})
    ]


# --------------------------------------------------------------------------- #
# Runtime gates: strict refuses, never clearnet                               #
# --------------------------------------------------------------------------- #


def _no_fallback(audit: _FakeAudit) -> bool:
    return not any(entry.get("decision") == "fallback" for entry in audit.entries)


@pytest.mark.parametrize("name", ["mullvad", "wireguard"])
def test_windows_strict_vpn_refuses_unported_provider_before_any_provider_call(windows: None, name: str) -> None:
    audit = _FakeAudit()
    vpn = _VpnFakes(name=name, detect_raises=AssertionError("detect must not run"))
    env: dict[str, str] = {}
    rt = _make_runtime(policy_mode="strict", default_path="vpn", audit=audit, vpn_fakes=vpn, env=env)
    with pytest.raises(BringupFailed, match=NOT_PORTED_ON_WINDOWS):
        rt.use("vpn")
    assert vpn.bring_up_calls == []
    assert rt.status().ready is False
    assert rt._state is State.IDLE
    assert _no_fallback(audit)
    assert not any(key.upper().endswith("_PROXY") and key.upper() != "NO_PROXY" for key in env)


def test_windows_lenient_vpn_records_the_classified_fallback(windows: None, caplog: pytest.LogCaptureFixture) -> None:
    audit = _FakeAudit()
    vpn = _VpnFakes(name="mullvad", detect_raises=AssertionError("detect must not run"))
    rt = _make_runtime(policy_mode="lenient", default_path="vpn", audit=audit, vpn_fakes=vpn)
    with caplog.at_level("WARNING", logger="mordred.network"):
        rt.use("vpn")
    assert any("degrades to clearnet" in entry.getMessage() for entry in caplog.records)
    assert rt.status().active_path == "clearnet"
    assert rt._state is State.DEGRADED
    [fallback] = [entry for entry in audit.entries if entry.get("decision") == "fallback"]
    assert NOT_PORTED_ON_WINDOWS in fallback["error"]
    assert vpn.bring_up_calls == []


def _custom_runtime(policy_mode: str, audit: _FakeAudit, env: dict[str, str]) -> Runtime:
    config = RuntimeConfig(
        policy_mode=policy_mode,  # type: ignore[arg-type]
        default_path="vpn",
        vpn_provider="custom",
        custom_up_cmd=("vpnctl", "connect"),
        custom_down_cmd=("vpnctl", "disconnect"),
        custom_health_cmd=None,
    )
    return Runtime(config=config, audit=audit, env=env, subprocess_counter=lambda: 0)


def test_windows_strict_custom_vpn_refuses_on_the_kill_switch_gate(
    images: WindowsImages, monkeypatch: pytest.MonkeyPatch
) -> None:
    images.add(VPNCTL, "managed")
    monkeypatch.setattr(subprocess, "run", NeverRunner())
    audit = _FakeAudit()
    rt = _custom_runtime("strict", audit, {})
    with pytest.raises(BringupFailed, match="kill-switch"):
        rt.use("vpn")
    assert _no_fallback(audit)


def test_windows_lenient_custom_vpn_runs_the_validated_image(
    images: WindowsImages, monkeypatch: pytest.MonkeyPatch
) -> None:
    images.add(VPNCTL, "managed")
    calls: list[tuple[Any, dict[str, Any]]] = []

    def fake_run(args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    rt = _custom_runtime("lenient", _FakeAudit(), {})
    rt.use("vpn")
    assert rt.status().active_path == "vpn"
    rt.stop()
    assert [args for args, _ in calls] == [[VPNCTL, "connect"], [VPNCTL, "disconnect"]]
    assert all(kwargs["executable"] == VPNCTL and "shell" not in kwargs for _, kwargs in calls)


def test_windows_lenient_custom_vpn_with_unusable_command_degrades(images: WindowsImages) -> None:
    audit = _FakeAudit()
    rt = _custom_runtime("lenient", audit, {})
    rt.use("vpn")
    assert rt._state is State.DEGRADED
    [fallback] = [entry for entry in audit.entries if entry.get("decision") == "fallback"]
    assert "executable-not-found" in fallback["error"]


class _StartRecorder:
    def __init__(self, raises: BaseException | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self.raises = raises

    def __call__(self, **kwargs: Any) -> _FakeTorProcess:
        self.calls.append(kwargs)
        if self.raises is not None:
            raise self.raises
        return _FakeTorProcess()


def _tor_runtime(policy_mode: str, start: _StartRecorder, audit: _FakeAudit, env: dict[str, str], tmp: Path) -> Runtime:
    fakes = _TorFakes(pick_port_return=9150)
    config = RuntimeConfig(
        policy_mode=policy_mode,  # type: ignore[arg-type]
        default_path="tor",
        tor_binary="tor",
        tor_data_dir=tmp / "tor-data",
    )
    return Runtime(
        config=config,
        audit=audit,
        env=env,
        subprocess_counter=lambda: 0,
        tor_pick_free_port=fakes.pick_free_port,
        tor_start_process=start,
        tor_wait_for_bootstrap=fakes.wait_for_bootstrap,
        tor_stop=fakes.stop,
        tor_health=fakes.health,
        vpn_provider=_VpnFakes(),
    )


def test_windows_tor_bring_up_passes_private_state_and_policy(windows: None, tmp_path: Path) -> None:
    import os

    start = _StartRecorder()
    rt = _tor_runtime("strict", start, _FakeAudit(), {}, tmp_path)
    rt.use("tor")
    [call] = start.calls
    assert call["binary"] == "tor"
    assert call["data_dir"] == tmp_path / "tor-data"
    assert call["policy_mode"] == "strict"
    escaped = str(tmp_path / "tor-data").replace("\\", "\\\\").replace('"', '\\"')
    assert f'DataDirectory "{escaped}"\n' in call["torrc"]
    assert f"__OwningControllerProcess {os.getpid()}\n" in call["torrc"]
    assert "SOCKSPort 127.0.0.1:9150 IsolateSOCKSAuth\n" in call["torrc"]


def test_posix_tor_bring_up_call_is_unchanged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    start = _StartRecorder()
    rt = _tor_runtime("strict", start, _FakeAudit(), {}, tmp_path)
    rt.use("tor")
    [call] = start.calls
    assert set(call) == {"binary", "torrc"}
    assert f"DataDirectory {tmp_path / 'tor-data'}\n" in call["torrc"]
    assert "__OwningControllerProcess" not in call["torrc"]


def test_windows_strict_tor_refusal_never_falls_back(windows: None, tmp_path: Path) -> None:
    audit = _FakeAudit()
    env: dict[str, str] = {}
    refusal = wexec.ExecutableRefused("executable-untrusted-location", "tor executable 'tor.exe' is untrusted")
    rt = _tor_runtime("strict", _StartRecorder(raises=refusal), audit, env, tmp_path)
    with pytest.raises(BringupFailed, match="executable-untrusted-location"):
        rt.use("tor")
    assert rt.status().ready is False
    assert _no_fallback(audit)
    assert "HTTPS_PROXY" not in env


def test_windows_lenient_tor_refusal_degrades_with_an_audited_fallback(windows: None, tmp_path: Path) -> None:
    audit = _FakeAudit()
    refusal = wexec.ExecutableRefused("executable-not-found", "tor executable 'tor.exe' was not found")
    rt = _tor_runtime("lenient", _StartRecorder(raises=refusal), audit, {}, tmp_path)
    rt.use("tor")
    assert rt._state is State.DEGRADED
    [fallback] = [entry for entry in audit.entries if entry.get("decision") == "fallback"]
    assert "executable-not-found" in fallback["error"]


# --------------------------------------------------------------------------- #
# Liveness: a dropped Tor in strict refuses; no clearnet fallback             #
# --------------------------------------------------------------------------- #


def _publish(paths: CanonicalPaths, *, policy: Any, config: Any) -> None:
    with canonical_session(paths, scope="policy", create=True) as session, session.policy_update() as update:
        update.put_config(json.dumps(config).encode())
        update.put_policy(json.dumps(policy).encode())
        update.commit()


@pytest.fixture
def strict_tor_profile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> CanonicalPaths:
    import os

    if os.name != "nt":
        from mordred_hermes._private_fs import open_private_directory

        monkeypatch.setattr(cio, "open_confidential_directory", open_private_directory)
        monkeypatch.setattr(cio, "open_optional_confidential_directory", open_private_directory)
        monkeypatch.setattr(cio, "open_optional_private_directory", open_private_directory)
    paths = CanonicalPaths(tmp_path / "home")
    _publish(
        paths,
        policy={"policy": "strict"},
        config={"plugins": {"mordred_network": {"default_path": "tor"}}, "model": {"provider": "anthropic"}},
    )
    original = network._runtime_config

    def fast_liveness(**kwargs: Any) -> RuntimeConfig:
        return dataclasses.replace(original(**kwargs), liveness_interval_seconds=0.01, liveness_failure_threshold=2)

    monkeypatch.setattr(network, "_runtime_config", fast_liveness)
    monkeypatch.setattr(sys, "platform", "win32")
    return paths


def test_windows_strict_liveness_drop_refuses_tool_calls_without_clearnet_fallback(
    strict_tor_profile: CanonicalPaths,
) -> None:
    policy = strict_tor_profile.home / "mordred" / "policy.json"
    config = strict_tor_profile.home / "config.yaml"
    fakes = _TorFakes()
    env: dict[str, str] = {}
    runtime_config = network._load_runtime_config(policy_json_path=policy, config_path=config)
    rt = Runtime(
        config=runtime_config,
        env=env,
        subprocess_counter=lambda: 0,
        tor_pick_free_port=fakes.pick_free_port,
        tor_start_process=fakes.start_process,
        tor_wait_for_bootstrap=fakes.wait_for_bootstrap,
        tor_stop=fakes.stop,
        tor_health=fakes.health,
        vpn_provider=_VpnFakes(),
    )
    rt.activate_and_freeze("tor")
    api.set_runtime(rt)
    assert hooks.pre_tool_call(policy_json_path=policy, config_path=config, tool_name="web_search") is None
    socks = env["HTTPS_PROXY"]
    fakes.health_return = False
    deadline = time.monotonic() + 10
    while not rt.is_dropped() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert rt.is_dropped()
    with pytest.raises(MordredPathDropped):
        hooks.pre_tool_call(policy_json_path=policy, config_path=config, tool_name="web_search")
    # The route stays the frozen Tor route; nothing switched to clearnet.
    assert rt.status().active_path == "tor"
    assert env["HTTPS_PROXY"] == socks
    assert fakes.stop_calls == []


# --------------------------------------------------------------------------- #
# Process inventory and process-only proxy environment                         #
# --------------------------------------------------------------------------- #


def test_windows_subprocess_counter_counts_children_through_psutil(
    windows: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(subprocess, "run", NeverRunner())

    class Parent:
        def __init__(self, pid: int | None = None) -> None:
            self.pid = pid

        def children(self) -> list[int]:
            return [11, 12, 13]

    monkeypatch.setattr(runtime_mod.psutil, "Process", Parent)
    assert runtime_mod._default_subprocess_counter() == 3

    class Denied(Parent):
        def children(self) -> list[int]:
            raise psutil.AccessDenied(1)

    monkeypatch.setattr(runtime_mod.psutil, "Process", Denied)
    assert runtime_mod._default_subprocess_counter() == 0


class WindowsEnviron(MutableMapping[str, str]):
    """``os.environ`` on Windows: one variable per case-insensitive name."""

    def __init__(self, initial: dict[str, str]) -> None:
        self._data = {key.upper(): value for key, value in initial.items()}

    def __getitem__(self, key: str) -> str:
        return self._data[key.upper()]

    def __setitem__(self, key: str, value: str) -> None:
        self._data[key.upper()] = value

    def __delitem__(self, key: str) -> None:
        del self._data[key.upper()]

    def __iter__(self) -> Iterator[str]:
        return iter(dict(self._data))

    def __len__(self) -> int:
        return len(self._data)

    def snapshot(self) -> dict[str, str]:
        return dict(self._data)


@pytest.mark.parametrize("mode", ["strict", "lenient", "off"])
def test_windows_proxy_environment_is_process_only_and_restored_exactly(windows: None, mode: str) -> None:
    env = WindowsEnviron({"https_proxy": "http://corp:8080", "Path": r"C:\Windows", "no_proxy": "corp.local"})
    before = env.snapshot()
    rt = _make_runtime(policy_mode=mode, default_path="tor", env=env)  # type: ignore[arg-type]
    rt.use("tor")
    assert env["HTTPS_PROXY"].startswith("socks5h://127.0.0.1:")
    assert env["https_proxy"] == env["HTTPS_PROXY"]
    rt.use("clearnet")
    rt.stop()
    assert env.snapshot() == before


FORBIDDEN_COMMANDS = {"netsh", "reg", "setx", "taskkill", "wmic", "powershell", "pwsh", "cmd", "sc", "bitsadmin"}
FORBIDDEN_SUBSTRINGS = ("RegSetValue", "RegCreateKey", "InternetSetOption", "WinHttpSetDefaultProxy", "SetProxy")


def _network_sources() -> list[tuple[Path, ast.Module]]:
    return [(path, ast.parse(path.read_text(encoding="utf-8"))) for path in sorted(NETWORK_PACKAGE.rglob("*.py"))]


def test_network_package_never_writes_registry_or_system_proxy_settings() -> None:
    for path, tree in _network_sources():
        for node in ast.walk(tree):
            if isinstance(node, ast.Import | ast.ImportFrom):
                names = [alias.name for alias in node.names] + [getattr(node, "module", None) or ""]
                assert not any(name.split(".")[0] in {"winreg", "_winreg"} for name in names), path
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                base = ntpath.splitext(node.value.strip().casefold())[0]
                assert base not in FORBIDDEN_COMMANDS, (path, node.value)
                assert not any(token in node.value for token in FORBIDDEN_SUBSTRINGS), (path, node.value)
            if isinstance(node, ast.Attribute):
                assert not any(token in node.attr for token in FORBIDDEN_SUBSTRINGS), (path, node.attr)


_LAUNCHERS = {"run", "Popen", "call", "check_call", "check_output", "popen", "popen_factory"}
_SHELL_HELPERS = {
    ("os", "system"),
    ("os", "popen"),
    ("os", "startfile"),
    ("subprocess", "getoutput"),
    ("subprocess", "getstatusoutput"),
}


def _callee(node: ast.Call) -> tuple[str, str]:
    func = node.func
    if isinstance(func, ast.Attribute):
        owner = func.value.id if isinstance(func.value, ast.Name) else ""
        return owner, func.attr
    if isinstance(func, ast.Name):
        return "", func.id
    return "", ""


def test_no_shell_or_string_command_reaches_subprocess_in_the_network_package() -> None:
    launches = 0
    for path, tree in _network_sources():
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            owner, name = _callee(node)
            assert (owner, name) not in _SHELL_HELPERS, (path, node.lineno)
            assert not (owner == "os" and name.startswith(("spawn", "exec"))), (path, node.lineno)
            for keyword in node.keywords:
                if keyword.arg == "shell":
                    assert isinstance(keyword.value, ast.Constant) and keyword.value.value is False, (path, node.lineno)
            if name in _LAUNCHERS and node.args:
                launches += 1
                first = node.args[0]
                is_string = (isinstance(first, ast.Constant) and isinstance(first.value, str)) or isinstance(
                    first, ast.JoinedStr | ast.BinOp
                )
                assert not is_string, (path, node.lineno)
    assert launches >= 4  # tor POSIX/Windows spawn, VPN runner, subprocess counter
