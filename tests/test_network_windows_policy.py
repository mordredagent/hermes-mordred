"""Checked Windows network decisions, exercised above the real coordinator."""

from __future__ import annotations

import json
import os
import re
import sys
import traceback
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import mordred_hermes.network as network
from mordred_hermes import _config_io as cio
from mordred_hermes._config_io import POLICY_TRANSACTION_MARKER, CanonicalPaths, canonical_session
from mordred_hermes.network import _windows_policy, api, hooks
from mordred_hermes.network import settings as settings_mod
from mordred_hermes.network._exceptions import MordredNetworkError, MordredPathBringupFailed
from mordred_hermes.network._windows_policy import read_network_decision
from tests._network_hooks_helpers import _FakeCtx, _FakeRuntime, _reset_api

pytestmark = pytest.mark.usefixtures(_reset_api.__name__)

SECRET = "mordred-c8-secret-bytes"
TOR_CONFIG: dict[str, Any] = {
    "plugins": {"mordred_network": {"default_path": "tor"}},
    "model": {"provider": "anthropic"},
}


class Audit:
    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    def append(self, entry: Any) -> None:
        self.entries.append(dict(entry))


def policy_path(paths: CanonicalPaths) -> Path:
    return paths.home / "mordred" / paths.policy_name


def config_path(paths: CanonicalPaths) -> Path:
    return paths.home / paths.config_name


def encode(value: Any) -> bytes:
    return value if isinstance(value, bytes) else json.dumps(value).encode()


def publish(paths: CanonicalPaths, *, policy: Any = None, config: Any = None) -> None:
    """Publish a complete generation through the canonical pair protocol."""
    with canonical_session(paths, scope="policy", create=True) as session, session.policy_update() as update:
        if config is not None:
            update.put_config(encode(config))
        if policy is not None:
            update.put_policy(encode(policy))
        update.commit()


@pytest.fixture
def profile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> CanonicalPaths:
    if os.name != "nt":
        from mordred_hermes._private_fs import open_private_directory

        # The confidential adapter exists only on Windows; substitute the
        # stricter POSIX capability beneath the real coordinator on this host.
        monkeypatch.setattr(cio, "open_confidential_directory", open_private_directory)
        monkeypatch.setattr(cio, "open_optional_confidential_directory", open_private_directory)
        monkeypatch.setattr(cio, "open_optional_private_directory", open_private_directory)
    paths = CanonicalPaths(tmp_path / "home")
    publish(paths, policy={"policy": "strict"}, config=TOR_CONFIG)
    monkeypatch.setattr(sys, "platform", "win32")
    return paths


@pytest.fixture
def tor_runtime() -> _FakeRuntime:
    runtime = _FakeRuntime()
    runtime.use("tor")
    api.set_runtime(runtime)
    return runtime


@pytest.fixture
def wired(profile: CanonicalPaths, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """Point the registered plugin at the checked profile with a fake route."""
    audit = Audit()
    runtime = _FakeRuntime()
    constructed: list[Any] = []
    passthrough: list[Any] = []

    def build(**kwargs: Any) -> _FakeRuntime:
        constructed.append(kwargs["config"])
        return runtime

    # Hermes' execute_code passthrough registry is host state, not policy.
    monkeypatch.setattr(network, "_register_proxy_env_passthrough", lambda **kw: passthrough.append(kw["config"]))

    monkeypatch.setattr(network, "DEFAULT_POLICY_JSON_PATH", policy_path(profile))
    monkeypatch.setattr(network, "DEFAULT_CONFIG_PATH", config_path(profile))
    monkeypatch.setattr(network, "DEFAULT_AUTH_JSON_PATH", profile.home / "auth.json")
    monkeypatch.setattr(network, "_build_audit_writer", lambda path: audit)
    monkeypatch.setattr(network, "Runtime", build)
    return SimpleNamespace(
        audit=audit, runtime=runtime, constructed=constructed, passthrough=passthrough, ctx=_FakeCtx()
    )


def session_wrapper(ctx: _FakeCtx) -> Any:
    return [callback for name, callback in ctx.hooks if name == "on_session_start"][1]


def run(entrypoint: str, paths: CanonicalPaths, *, audit: Audit | None = None, provider: str = "anthropic") -> Any:
    policy, config = policy_path(paths), config_path(paths)
    if entrypoint == "pre_api_request":
        return hooks.pre_api_request(policy_json_path=policy, config_path=config, provider=provider, audit=audit)
    if entrypoint == "pre_tool_call":
        return hooks.pre_tool_call(policy_json_path=policy, config_path=config, tool_name="web_search", audit=audit)
    if entrypoint == "on_session_start":
        return hooks.on_session_start(
            policy_json_path=policy, config_path=config, auth_json_path=paths.home / "auth.json", audit=audit
        )
    if entrypoint == "runtime_config":
        return network._load_runtime_config(policy_json_path=policy, config_path=config)
    raise AssertionError(entrypoint)


ENTRYPOINTS = ["pre_api_request", "pre_tool_call", "on_session_start", "runtime_config"]


def assert_sanitized(error: BaseException, *audits: Audit) -> None:
    """No policy/config bytes or parser diagnostics reach messages or audit."""
    assert SECRET not in "".join(traceback.format_exception(type(error), error, error.__traceback__))
    current: BaseException | None = error
    while current is not None:
        assert SECRET not in str(current)
        assert current.__suppress_context__
        current = current.__cause__
    for audit in audits:
        assert SECRET not in json.dumps(audit.entries)


# --------------------------------------------------------------------------- #
# The checked reader                                                          #
# --------------------------------------------------------------------------- #


def test_clean_state_reads_one_checked_generation(profile: CanonicalPaths) -> None:
    decision = read_network_decision(policy_path(profile), config_path(profile))
    assert decision is not None
    assert (decision.mode, decision.default_path) == ("strict", "tor")
    assert decision.section == {"default_path": "tor"}
    assert decision.disable_ipv6 is True
    assert decision.provider_overrides == {}
    assert decision.config_provider == "anthropic"
    assert re.fullmatch(r"[0-9a-f]{64}", decision.generation)
    again = read_network_decision(policy_path(profile), config_path(profile))
    assert again is not None and again.generation == decision.generation


def test_posix_platform_keeps_existing_readers(profile: CanonicalPaths, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(_windows_policy, "read_canonical_snapshot", lambda paths: pytest.fail("POSIX read checked"))
    assert read_network_decision(policy_path(profile), config_path(profile)) is None


def test_generation_digest_covers_both_members(profile: CanonicalPaths) -> None:
    first = read_network_decision(policy_path(profile), config_path(profile))
    publish(profile, config={**TOR_CONFIG, "unrelated": True})
    second = read_network_decision(policy_path(profile), config_path(profile))
    publish(profile, policy={"policy": "strict", "unrelated": True})
    third = read_network_decision(policy_path(profile), config_path(profile))
    assert first is not None and second is not None and third is not None
    assert len({first.generation, second.generation, third.generation}) == 3


@pytest.mark.parametrize(
    "policy_leaf, config_leaf",
    [("policy.json", "config.yaml"), ("mordred/policy.json", "other/config.yaml")],
    ids=["policy-outside-mordred", "config-other-home"],
)
def test_non_canonical_pair_refuses(profile: CanonicalPaths, policy_leaf: str, config_leaf: str) -> None:
    with pytest.raises(MordredPathBringupFailed):
        read_network_decision(profile.home / policy_leaf, profile.home / config_leaf)


# --------------------------------------------------------------------------- #
# Every decision point refuses unsafe canonical state                         #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("entrypoint", ENTRYPOINTS)
def test_pending_marker_refuses_previously_allowed_decision(
    profile: CanonicalPaths, tor_runtime: _FakeRuntime, entrypoint: str
) -> None:
    run(entrypoint, profile, audit=Audit())
    use_calls = list(tor_runtime.use_calls)
    policy_path(profile).with_name(POLICY_TRANSACTION_MARKER).write_bytes(b"pending")
    with pytest.raises(MordredPathBringupFailed):
        run(entrypoint, profile, audit=Audit())
    assert tor_runtime.use_calls == use_calls
    assert tor_runtime.stop_called is False
    assert tor_runtime.status().active_path == "tor"


def test_strict_default_path_reader_uses_checked_generation(profile: CanonicalPaths) -> None:
    # Its contract (and the extension caller) expects an ordinary exception.
    assert settings_mod.read_default_path_strict(config_path(profile)) == "tor"
    policy_path(profile).with_name(POLICY_TRANSACTION_MARKER).write_bytes(SECRET.encode())
    with pytest.raises(ValueError) as caught:
        settings_mod.read_default_path_strict(config_path(profile))
    assert_sanitized(caught.value)


@pytest.mark.parametrize("fault", ["home:open", "policy:open", "home:close", "policy:close"])
def test_admission_and_cleanup_errors_never_authorize(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, fault: str
) -> None:
    from tests.test_config_io import Backend

    backend = Backend()
    monkeypatch.setattr(cio, "open_optional_confidential_directory", backend.open_home)
    monkeypatch.setattr(cio, "open_optional_private_directory", backend.open_policy)
    monkeypatch.setattr(sys, "platform", "win32")
    backend.fault = fault
    paths = CanonicalPaths(tmp_path / "home")
    with pytest.raises(MordredPathBringupFailed):
        run("pre_tool_call", paths, audit=Audit())
    assert not backend.home.locked and not backend.policy.locked


def test_only_checked_absence_of_home_keeps_defaults(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from tests.test_config_io import Backend

    backend = Backend()
    backend.home_present = False
    monkeypatch.setattr(cio, "open_optional_confidential_directory", backend.open_home)
    monkeypatch.setattr(sys, "platform", "win32")
    paths = CanonicalPaths(tmp_path / "home")
    decision = read_network_decision(policy_path(paths), config_path(paths))
    assert decision is not None
    assert (decision.mode, decision.default_path, decision.disable_ipv6) == ("off", "clearnet", False)
    assert run("pre_tool_call", paths) is None


def test_checked_absence_of_both_files_keeps_fresh_install_defaults(profile: CanonicalPaths) -> None:
    config_path(profile).unlink()
    policy_path(profile).unlink()
    config = run("runtime_config", profile)
    assert (config.policy_mode, config.default_path, config.disable_ipv6) == ("off", "clearnet", False)
    assert run("pre_api_request", profile, provider="bedrock") is None
    assert run("pre_tool_call", profile) is None


@pytest.mark.parametrize(
    "target, document",
    [
        ("policy", b'{"policy": "strict", "' + SECRET.encode()),
        ("policy", b'["' + SECRET.encode() + b'"]'),
        ("policy", b"\xff" + SECRET.encode()),
        ("config", b"plugins: [" + SECRET.encode()),
        ("config", b"- " + SECRET.encode()),
        ("config", b"\xff" + SECRET.encode()),
        ("config", b"#" + SECRET.encode() + b" " * (8 * 1024 * 1024)),
    ],
    ids=["policy-json", "policy-root", "policy-encoding", "config-yaml", "config-root", "config-encoding", "oversize"],
)
@pytest.mark.parametrize("entrypoint", ["pre_api_request", "pre_tool_call", "on_session_start"])
def test_malformed_documents_refuse_without_exposing_bytes(
    profile: CanonicalPaths, tor_runtime: _FakeRuntime, target: str, document: bytes, entrypoint: str
) -> None:
    path = policy_path(profile) if target == "policy" else config_path(profile)
    path.write_bytes(document)
    audit = Audit()
    with pytest.raises(MordredPathBringupFailed) as caught:
        run(entrypoint, profile, audit=audit)
    assert_sanitized(caught.value, audit)
    assert path.read_bytes() == document


NETWORK_FIELD_DAMAGE = [
    {"default_path": "darknet"},
    {"default_path": None},
    {"tor_binary_path": 42},
    {"tor_socks_port": True},
    {"tor_socks_port": 70000},
    {"tor_socks_port": -1},
    {"tor_socks_port": "9050"},
    {"vpn_provider": "nordvpn"},
    {"vpn_provider": 1},
    {"wireguard_config_path": []},
    {"custom_up_cmd": "vpn up"},
    {"custom_down_cmd": ["vpn", 1]},
    {"custom_health_cmd": {"cmd": "x"}},
    {"mullvad_relay_country": 46},
]


@pytest.mark.parametrize(
    "policy, config",
    [
        ({"policy": []}, None),
        ({"policy": "paranoid"}, None),
        ({"policy": "off", "disable_ipv6": "false"}, None),
        ({"policy": "off", "disable_ipv6": None}, None),
        ({"policy": "off", "provider_overrides": []}, None),
        ({"policy": "off", "provider_overrides": {"acme": {"bogus": True}}}, None),
        ({"policy": "off", "provider_overrides": {"acme": {"respects_socks5h": "yes"}}}, None),
        ({"policy": "off"}, {"plugins": []}),
        ({"policy": "off"}, {"plugins": {"mordred_network": []}}),
        ({"policy": "off"}, {"plugins": {"mordred_network": None}}),
        ({"policy": "off"}, {"model": 42}),
        ({"policy": "off"}, {"model": {"provider": False}}),
        *(({"policy": "off"}, {"plugins": {"mordred_network": damage}}) for damage in NETWORK_FIELD_DAMAGE),
    ],
)
def test_malformed_fields_refuse_even_in_off_mode(
    profile: CanonicalPaths, tor_runtime: _FakeRuntime, policy: Any, config: Any
) -> None:
    publish(profile, policy=policy, config=config if config is not None else TOR_CONFIG)
    for entrypoint in ENTRYPOINTS:
        with pytest.raises(MordredPathBringupFailed):
            run(entrypoint, profile, audit=Audit())


@pytest.mark.parametrize(
    "section",
    [
        {
            "default_path": "vpn",
            "tor_binary_path": "",
            "tor_socks_port": 0,
            "vpn_provider": None,
            "wireguard_config_path": None,
            "custom_up_cmd": None,
            "custom_down_cmd": None,
            "custom_health_cmd": None,
            "mullvad_relay_country": None,
            "mullvad_account_id_env": "MULLVAD_ACCOUNT",
            "mullvad_killswitch": True,
        },
        {
            "default_path": "tor",
            "tor_binary_path": "C:/Program Files/Tor Browser/tor.exe",
            "tor_socks_port": 9150,
            "vpn_provider": "custom",
            "wireguard_config_path": "C:/wg/mordred.conf",
            "custom_up_cmd": ["vpn", "up"],
            "custom_down_cmd": ["vpn", "down"],
            "custom_health_cmd": [],
            "mullvad_relay_country": "se",
        },
    ],
    ids=["unset-and-wizard-only", "explicit"],
)
@pytest.mark.parametrize("mode", ["strict", "lenient", "off"])
def test_valid_values_match_posix_resolvers(
    profile: CanonicalPaths, monkeypatch: pytest.MonkeyPatch, section: dict[str, Any], mode: str
) -> None:
    publish(profile, policy={"policy": mode, "disable_ipv6": False}, config={"plugins": {"mordred_network": section}})
    checked = run("runtime_config", profile)
    monkeypatch.setattr(sys, "platform", "linux")
    assert run("runtime_config", profile) == checked


# --------------------------------------------------------------------------- #
# Generations and caches                                                      #
# --------------------------------------------------------------------------- #


def test_generation_change_withdraws_previous_override_allow(
    profile: CanonicalPaths, tor_runtime: _FakeRuntime
) -> None:
    override = {
        "transport": "https",
        "respects_proxy": True,
        "respects_socks5h": True,
        "unverified_baseline": False,
        "respects_ipv6_proxy": True,
    }
    publish(profile, policy={"policy": "strict", "provider_overrides": {"acme": override}})
    run("pre_api_request", profile, provider="acme")
    publish(profile, policy={"policy": "strict"})
    audit = Audit()
    with pytest.raises(MordredPathBringupFailed, match="outbound API request"):
        run("pre_api_request", profile, provider="acme", audit=audit)
    assert [entry["decision"] for entry in audit.entries] == ["block"]


@pytest.mark.parametrize("entrypoint", ["pre_api_request", "pre_tool_call"])
def test_generation_change_refreshes_mode_and_required_route(profile: CanonicalPaths, entrypoint: str) -> None:
    runtime = _FakeRuntime()
    runtime.use("clearnet")
    api.set_runtime(runtime)
    publish(profile, policy={"policy": "lenient"})
    assert run(entrypoint, profile, provider="bedrock") is None
    publish(profile, policy={"policy": "strict"})
    with pytest.raises(MordredPathBringupFailed, match="not active"):
        run(entrypoint, profile, provider="bedrock", audit=Audit())


@pytest.mark.parametrize("entrypoint", [*ENTRYPOINTS, "default_path_strict"])
def test_one_checked_generation_per_decision(
    profile: CanonicalPaths, tor_runtime: _FakeRuntime, monkeypatch: pytest.MonkeyPatch, entrypoint: str
) -> None:
    original = _windows_policy.read_canonical_snapshot
    reads: list[CanonicalPaths] = []

    def reader(paths: CanonicalPaths) -> Any:
        reads.append(paths)
        result = original(paths)
        # A concurrent writer publishes a refused generation after this read.
        publish(paths, policy={"policy": "strict", "provider_overrides": []})
        return result

    monkeypatch.setattr(_windows_policy, "read_canonical_snapshot", reader)
    if entrypoint == "default_path_strict":
        assert settings_mod.read_default_path_strict(config_path(profile)) == "tor"
    else:
        run(entrypoint, profile, audit=Audit())
    assert len(reads) == 1
    monkeypatch.setattr(_windows_policy, "read_canonical_snapshot", original)
    with pytest.raises((MordredPathBringupFailed, ValueError)):
        if entrypoint == "default_path_strict":
            settings_mod.read_default_path_strict(config_path(profile))
        else:
            run(entrypoint, profile, audit=Audit())


def test_posix_tolerant_readers_are_unreachable_on_windows(
    profile: CanonicalPaths, wired: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("tolerant POSIX reader reached from a Windows decision point")

    for owner, name in [
        (hooks, "_read_policy_mode"),
        (hooks, "_read_default_network_path"),
        (hooks, "_read_default_network_path_strict"),
        (hooks, "_read_provider_overrides"),
        (hooks, "_read_disable_ipv6"),
        (hooks, "_read_config_model_provider"),
        (hooks, "load_policy_mapping"),
        (network, "_load_policy_json"),
        (network, "_load_network_section"),
        (settings_mod, "read_policy_mode"),
        (settings_mod, "read_default_path"),
        (settings_mod, "load_plugin_section"),
    ]:
        monkeypatch.setattr(owner, name, forbidden)
    network.register(wired.ctx)
    session_wrapper(wired.ctx)()
    for entrypoint in ENTRYPOINTS:
        run(entrypoint, profile, audit=Audit())


def test_configured_provider_comes_from_the_checked_generation(
    profile: CanonicalPaths, tor_runtime: _FakeRuntime, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(hooks, "_read_config_model_provider", lambda path: pytest.fail("unchecked config read"))
    publish(profile, config={**TOR_CONFIG, "model": {"provider": " Bedrock "}})
    audit = Audit()
    with pytest.raises(MordredPathBringupFailed, match="incompatible"):
        run("on_session_start", profile, audit=audit)
    aborted = [entry["provider"] for entry in audit.entries if entry.get("severity") == "abort"]
    assert aborted and set(aborted) == {"bedrock"}


# --------------------------------------------------------------------------- #
# Registration and the Hermes hook boundary                                   #
# --------------------------------------------------------------------------- #


def test_registration_and_session_start_share_one_generation(
    wired: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = _windows_policy.read_canonical_snapshot
    reads: list[CanonicalPaths] = []

    def reader(paths: CanonicalPaths) -> Any:
        reads.append(paths)
        return original(paths)

    monkeypatch.setattr(_windows_policy, "read_canonical_snapshot", reader)
    network.register(wired.ctx)
    assert len(reads) == 1
    assert [config.default_path for config in wired.constructed] == ["tor"]
    session_wrapper(wired.ctx)()
    assert len(reads) == 2
    assert wired.passthrough == [wired.constructed[0], wired.constructed[0]]


def test_strict_refused_registration_never_falls_back_to_clearnet(
    profile: CanonicalPaths, wired: SimpleNamespace
) -> None:
    policy_path(profile).write_bytes(b'{"policy": "strict", "x": "' + SECRET.encode())
    with pytest.raises(MordredPathBringupFailed) as caught:
        network.register(wired.ctx)
    assert wired.constructed == []
    assert wired.ctx.hooks == []
    with pytest.raises(MordredNetworkError):
        api.status()
    assert_sanitized(caught.value, wired.audit)
    assert [(entry["event"], entry["decision"]) for entry in wired.audit.entries] == [("network.register", "block")]


def test_session_start_after_generation_damage_refuses_before_route_reuse(
    profile: CanonicalPaths, wired: SimpleNamespace
) -> None:
    network.register(wired.ctx)
    use_calls = list(wired.runtime.use_calls)
    policy_path(profile).with_name(POLICY_TRANSACTION_MARKER).write_bytes(SECRET.encode())
    with pytest.raises(MordredPathBringupFailed) as caught:
        session_wrapper(wired.ctx)()
    assert wired.runtime.use_calls == use_calls
    assert wired.runtime.stop_called is False
    assert_sanitized(caught.value, wired.audit)


@pytest.mark.parametrize("entrypoint", ["pre_api_request", "pre_tool_call", "on_session_start"])
def test_unexpected_checked_reader_failure_escapes_hermes_wrapper(
    profile: CanonicalPaths, tor_runtime: _FakeRuntime, monkeypatch: pytest.MonkeyPatch, entrypoint: str
) -> None:
    def broken(paths: CanonicalPaths) -> Any:
        raise RuntimeError(SECRET)

    monkeypatch.setattr(_windows_policy, "read_canonical_snapshot", broken)
    swallowed: list[Exception] = []
    with pytest.raises(MordredPathBringupFailed) as caught:
        try:
            run(entrypoint, profile, audit=Audit())
        except Exception as exc:  # Hermes' hook dispatcher swallows ordinary errors.
            swallowed.append(exc)
    assert swallowed == []
    assert_sanitized(caught.value)


def test_canonical_locks_are_released_before_route_and_network_calls(
    wired: SimpleNamespace, profile: CanonicalPaths
) -> None:
    probes: list[str] = []

    def probe(label: str) -> None:
        # Another thread can only admit the pair if no handle or lock survived.
        with ThreadPoolExecutor(max_workers=1) as pool:
            snapshot = pool.submit(cio.read_canonical_snapshot, profile).result(timeout=10)
        assert snapshot.config is not None and snapshot.policy is not None
        probes.append(label)

    original_use = wired.runtime.use

    def use(path: str) -> None:
        probe(f"use:{path}")
        original_use(path)

    wired.runtime.use = use
    original_status = wired.runtime.status

    def status() -> Any:
        probe("status")
        return original_status()

    wired.runtime.status = status
    network.register(wired.ctx)
    session_wrapper(wired.ctx)()
    run("pre_api_request", profile, audit=Audit())
    run("pre_tool_call", profile, audit=Audit())
    assert "use:tor" in probes and probes.count("status") >= 3
