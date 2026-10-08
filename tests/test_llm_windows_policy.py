"""Fresh checked Windows policy decisions, exercised above the real coordinator."""

from __future__ import annotations

import json
import os
import sys
from types import SimpleNamespace

import pytest

from mordred_hermes import llm_guard
from mordred_hermes._config_io import CanonicalPaths, canonical_session
from mordred_hermes.llm_guard import auxiliary_guard, enforce, harness_detect, local_adapter
from mordred_hermes.llm_guard._exceptions import MordredSessionRefused


class Audit:
    def __init__(self):
        self.entries = []

    def append(self, entry):
        self.entries.append(entry)


@pytest.fixture
def profile(tmp_path, monkeypatch):
    if os.name != "nt":
        from mordred_hermes import _config_io as cio
        from mordred_hermes._private_fs import open_private_directory

        monkeypatch.setattr(cio, "open_confidential_directory", open_private_directory)
        monkeypatch.setattr(cio, "open_optional_confidential_directory", open_private_directory)
        monkeypatch.setattr(cio, "open_optional_private_directory", open_private_directory)
    paths = CanonicalPaths(tmp_path / "home")
    with canonical_session(paths, scope="policy", create=True) as session, session.policy_update() as update:
        update.put_config(b"{}")
        update.put_policy(
            json.dumps({"policy": "strict", "allow_cloud_llm": True, "cloud_provider_allowlist": ["openai"]}).encode()
        )
        update.commit()
    monkeypatch.setattr(sys, "platform", "win32")
    enforce._reset_state()
    auxiliary_guard.reset_caches()
    return paths


def run_provider(paths, **kwargs):
    enforce.check_runtime_provider(
        policy_mode="off",
        policy_json_path=paths.home / "mordred" / paths.policy_name,
        active_provider="openai",
        audit=Audit(),
        **kwargs,
    )


def test_runtime_reads_actual_mode_before_early_allow(profile):
    with canonical_session(profile, scope="policy") as session, session.policy_update() as update:
        update.put_policy(b'{"policy":"strict"}')
        update.commit()
    with pytest.raises(MordredSessionRefused):
        run_provider(profile)


@pytest.mark.parametrize("damage", ["pending", "bad-policy", "bad-config", "policy-shape", "config-shape"])
def test_previously_allowed_request_refuses_damaged_pair(profile, damage):
    run_provider(profile)
    target = profile.home / "mordred" / "policy.json"
    data = b"not json"
    if damage == "pending":
        target = target.with_name(".policy-write.pending")
        data = b"pending"
    elif damage == "bad-config":
        target = profile.home / "config.yaml"
        data = b"["
    elif damage == "policy-shape":
        data = b"[]"
    elif damage == "config-shape":
        target = profile.home / "config.yaml"
        data = b"[]"
    target.write_bytes(data)
    with pytest.raises(MordredSessionRefused):
        run_provider(profile)


@pytest.mark.parametrize("entrypoint", ["harness", "adapter", "session", "aux-cache"])
def test_all_entrypoints_refuse_pending(profile, entrypoint):
    policy = profile.home / "mordred" / "policy.json"
    if entrypoint == "aux-cache":
        auxiliary_guard._guard_inputs(policy)
    policy.with_name(".policy-write.pending").write_bytes(b"pending")
    with pytest.raises(MordredSessionRefused):
        if entrypoint == "harness":
            harness_detect.check_harness_primary(
                policy_mode="off", config_path=profile.home / "config.yaml", audit=Audit()
            )
        elif entrypoint == "adapter":
            local_adapter.build_mordred_local_profile(policy_json_path=policy)
        elif entrypoint == "session":
            enforce.check_session_provider(
                policy_mode="off", policy_json_path=policy, active_provider="openai", audit=Audit()
            )
        else:
            auxiliary_guard._guard_inputs(policy)


def test_auxiliary_refuses_before_resolver_operation(profile):
    calls = []
    module = SimpleNamespace(resolve=lambda provider: calls.append(provider))
    policy = profile.home / "mordred" / "policy.json"
    auxiliary_guard._wrap_pair_resolver(
        module, "resolve", policy_json_path=policy, audit_path=policy.with_name("audit.log")
    )
    policy.with_name(".policy-write.pending").write_bytes(b"pending")
    with pytest.raises(MordredSessionRefused):
        module.resolve("openai")
    assert not calls


def test_session_wrapper_does_not_swallow_unsafe_configuration(profile, monkeypatch):
    monkeypatch.setattr(llm_guard, "DEFAULT_POLICY_JSON_PATH", profile.home / "mordred" / "policy.json")
    monkeypatch.setattr(llm_guard, "DEFAULT_CONFIG_PATH", profile.home / "config.yaml")
    monkeypatch.setattr(llm_guard, "_build_audit_writer", lambda path: Audit())
    (profile.home / "config.yaml").write_bytes(b"[]")
    with pytest.raises(MordredSessionRefused):
        llm_guard._on_session_start_enforce()


def test_hook_cannot_fail_open_when_audit_construction_fails(profile, monkeypatch):
    monkeypatch.setattr(llm_guard, "DEFAULT_POLICY_JSON_PATH", profile.home / "mordred" / "policy.json")
    monkeypatch.setattr(llm_guard, "DEFAULT_CONFIG_PATH", profile.home / "config.yaml")

    def broken(path):
        raise OSError("audit unavailable")

    monkeypatch.setattr(llm_guard, "_build_audit_writer", broken)
    with pytest.raises(MordredSessionRefused):
        try:  # noqa: SIM105 -- reproduce Hermes hook swallowing boundary.
            llm_guard._on_pre_api_request_enforce(provider="openai")
        except Exception:
            pass  # Hermes' hook dispatcher swallows ordinary errors.


def test_prompt_grant_expires_on_checked_generation_change(profile):
    def publish(config=b"{}"):
        with canonical_session(profile, scope="policy") as session, session.policy_update() as update:
            update.put_config(config)
            update.put_policy(b'{"policy":"strict","cloud_attempt_action":"prompt-once"}')
            update.commit()

    publish()
    prompts = []
    run_provider(profile, prompt_fn=lambda provider: prompts.append(provider) or True)
    run_provider(profile, prompt_fn=lambda provider: pytest.fail("same generation prompted twice"))
    publish(b"model: {provider: openai}")
    with pytest.raises(MordredSessionRefused):
        run_provider(profile, prompt_fn=lambda provider: False)
    assert prompts == ["openai"]


def test_checked_snapshot_is_single_and_released_before_prompt(profile, monkeypatch):
    from mordred_hermes import _config_io as cio

    calls = []
    original = cio.read_canonical_snapshot

    def reader(paths):
        calls.append(paths)
        result = original(paths)
        # A concurrent writer changes the pair after this generation was read.
        with canonical_session(paths, scope="policy") as session, session.policy_update() as update:
            update.put_policy(b'{"policy":"strict"}')
            update.commit()
        return result

    with canonical_session(profile, scope="policy") as session, session.policy_update() as update:
        update.put_policy(b'{"policy":"strict","cloud_attempt_action":"prompt-once"}')
        update.commit()
    from mordred_hermes.llm_guard import _windows_policy

    monkeypatch.setattr(_windows_policy, "read_canonical_snapshot", reader)

    def prompt(provider):
        # Nonblocking admission proves no canonical lock survives the snapshot.
        with canonical_session(profile, scope="policy", blocking=False):
            pass
        return True

    run_provider(profile, prompt_fn=prompt)
    assert len(calls) == 1
    with pytest.raises(MordredSessionRefused):
        run_provider(profile, prompt_fn=prompt)


@pytest.mark.parametrize("fault", ["home:open", "policy:open", "home:close", "policy:close"])
def test_admission_and_cleanup_errors_never_authorize(monkeypatch, tmp_path, fault):
    from mordred_hermes import _config_io as cio
    from tests.test_config_io import Backend

    backend = Backend()
    monkeypatch.setattr(cio, "open_optional_confidential_directory", backend.open_home)
    monkeypatch.setattr(cio, "open_optional_private_directory", backend.open_policy)
    monkeypatch.setattr(sys, "platform", "win32")
    backend.fault = fault
    with pytest.raises(MordredSessionRefused):
        run_provider(CanonicalPaths(tmp_path / "home"))
    assert not backend.home.locked and not backend.policy.locked


def test_only_checked_absence_keeps_fresh_install_default(monkeypatch, tmp_path):
    from mordred_hermes import _config_io as cio
    from tests.test_config_io import Backend

    backend = Backend()
    backend.home_present = False
    monkeypatch.setattr(cio, "open_optional_confidential_directory", backend.open_home)
    monkeypatch.setattr(sys, "platform", "win32")
    run_provider(CanonicalPaths(tmp_path / "home"))


@pytest.mark.parametrize(
    "malformed",
    [
        b'{"policy":[]}',
        b'{"policy":"off","allow_cloud_llm":"false"}',
        b'{"policy":"off","cloud_provider_allowlist":[true]}',
        b'{"policy":"off","cloud_attempt_action":[]}',
        b'{"policy":"off","local_llm_endpoint":12}',
    ],
    ids=["mode", "bool", "allowlist", "action", "endpoint"],
)
def test_malformed_fields_never_authorize_off_mode(profile, malformed):
    (profile.home / "mordred" / "policy.json").write_bytes(malformed)
    with pytest.raises(MordredSessionRefused):
        run_provider(profile)


def test_oversize_policy_refuses_without_touching_bytes(profile):
    target = profile.home / "mordred" / "policy.json"
    content = b" " * (8 * 1024 * 1024 + 1)
    target.write_bytes(content)
    with pytest.raises(MordredSessionRefused):
        run_provider(profile)
    assert target.read_bytes() == content


def test_auxiliary_mode_endpoint_and_grant_share_one_generation(profile, monkeypatch):
    from mordred_hermes.llm_guard import _windows_policy

    original = _windows_policy.read_canonical_snapshot
    reads = []

    def once(paths):
        reads.append(paths)
        assert len(reads) == 1, "one auxiliary decision read competing generations"
        return original(paths)

    monkeypatch.setattr(_windows_policy, "read_canonical_snapshot", once)
    monkeypatch.setattr(auxiliary_guard, "build_audit_writer", lambda path: Audit())
    policy = profile.home / "mordred" / "policy.json"
    client = SimpleNamespace(base_url="https://api.openai.com/v1")
    module = SimpleNamespace(resolve=lambda provider: (client, "model"))
    auxiliary_guard._wrap_pair_resolver(
        module, "resolve", policy_json_path=policy, audit_path=policy.with_name("audit.log")
    )
    assert module.resolve("openai") == (client, "model")
    assert len(reads) == 1


@pytest.mark.parametrize(
    "bad_config",
    [b"plugins: []", b"auxiliary: {vision: []}", b"fallback_providers: nope", b"model: {provider: false}"],
    ids=["plugins", "auxiliary", "fallback", "provider"],
)
def test_invalid_config_shape_cannot_opt_out(profile, bad_config):
    (profile.home / "mordred" / "policy.json").write_bytes(b'{"policy":"off"}')
    (profile.home / "config.yaml").write_bytes(bad_config)
    with pytest.raises(MordredSessionRefused):
        run_provider(profile)


def test_explicit_custom_config_leaf_is_part_of_runtime_decision(profile):
    custom = profile.home / "settings.yaml"
    custom.write_bytes(b"[]")
    custom.chmod(0o600)
    with pytest.raises(MordredSessionRefused):
        enforce.check_runtime_provider(
            policy_mode="off",
            policy_json_path=profile.home / "mordred" / "policy.json",
            config_path=custom,
            active_provider="openai",
            audit=Audit(),
        )


def test_unexpected_checked_reader_failure_escapes_hermes_wrapper(profile, monkeypatch):
    from mordred_hermes.llm_guard import _windows_policy

    def broken(paths):
        raise RuntimeError("cleanup could not be completed")

    monkeypatch.setattr(_windows_policy, "read_canonical_snapshot", broken)
    with pytest.raises(MordredSessionRefused):
        try:  # noqa: SIM105 -- reproduce Hermes hook swallowing boundary.
            run_provider(profile)
        except Exception:
            pass


def test_nested_auxiliary_resolvers_share_one_generation(profile, monkeypatch):
    from mordred_hermes.llm_guard import _windows_policy

    original = _windows_policy.read_canonical_snapshot
    reads = []

    def reader(paths):
        reads.append(paths)
        return original(paths)

    monkeypatch.setattr(_windows_policy, "read_canonical_snapshot", reader)
    monkeypatch.setattr(auxiliary_guard, "build_audit_writer", lambda path: Audit())
    policy = profile.home / "mordred" / "policy.json"
    client = SimpleNamespace(base_url="https://api.openai.com/v1")
    module = SimpleNamespace(_get_cached_client=lambda provider: (client, "model"))
    module.resolve_provider_client = lambda provider: module._get_cached_client(provider)
    for name in ("_get_cached_client", "resolve_provider_client"):
        auxiliary_guard._wrap_pair_resolver(
            module, name, policy_json_path=policy, audit_path=policy.with_name("audit.log")
        )
    assert module.resolve_provider_client("openai") == (client, "model")
    assert len(reads) == 1
    assert module.resolve_provider_client("openai") == (client, "model")
    assert len(reads) == 2


def test_copied_resolver_context_cannot_reuse_completed_admission(profile, monkeypatch):
    from contextvars import copy_context

    contexts = []
    policy = profile.home / "mordred" / "policy.json"
    client = SimpleNamespace(base_url="https://api.openai.com/v1")

    def resolve(provider):
        contexts.append(copy_context())
        return client, "model"

    module = SimpleNamespace(resolve=resolve)
    monkeypatch.setattr(auxiliary_guard, "build_audit_writer", lambda path: Audit())
    auxiliary_guard._wrap_pair_resolver(
        module, "resolve", policy_json_path=policy, audit_path=policy.with_name("audit.log")
    )
    module.resolve("openai")
    policy.with_name(".policy-write.pending").write_bytes(b"pending")
    with pytest.raises(MordredSessionRefused):
        contexts[0].run(module.resolve, "openai")
    assert len(contexts) == 1


def test_reentrant_public_resolver_requires_fresh_admission(profile, monkeypatch):
    policy = profile.home / "mordred" / "policy.json"
    client = SimpleNamespace(base_url="https://api.openai.com/v1")
    calls = []
    module = SimpleNamespace()

    def resolve(provider):
        calls.append(provider)
        if len(calls) == 1:
            policy.with_name(".policy-write.pending").write_bytes(b"pending")
            return module.resolve_provider_client(provider)
        return client, "model"

    module.resolve_provider_client = resolve
    monkeypatch.setattr(auxiliary_guard, "build_audit_writer", lambda path: Audit())
    auxiliary_guard._wrap_pair_resolver(
        module, "resolve_provider_client", policy_json_path=policy, audit_path=policy.with_name("audit.log")
    )
    with pytest.raises(MordredSessionRefused):
        module.resolve_provider_client("openai")
    assert calls == ["openai"]


def test_another_async_task_cannot_borrow_active_resolver_admission(profile, monkeypatch):
    import asyncio

    policy = profile.home / "mordred" / "policy.json"
    client = SimpleNamespace(base_url="https://api.openai.com/v1")
    module = SimpleNamespace(_get_cached_client=lambda provider: (client, "model"))

    async def other_task():
        return module._get_cached_client("openai")

    def resolve(provider):
        policy.with_name(".policy-write.pending").write_bytes(b"pending")
        return asyncio.run(other_task())

    module.resolve_provider_client = resolve
    monkeypatch.setattr(auxiliary_guard, "build_audit_writer", lambda path: Audit())
    for name in ("_get_cached_client", "resolve_provider_client"):
        auxiliary_guard._wrap_pair_resolver(
            module, name, policy_json_path=policy, audit_path=policy.with_name("audit.log")
        )
    with pytest.raises(MordredSessionRefused):
        module.resolve_provider_client("openai")


def test_audit_callback_cannot_reuse_outer_cache_admission(profile, monkeypatch):
    policy = profile.home / "mordred" / "policy.json"
    local = SimpleNamespace(base_url="http://localhost:1234/v1")
    cloud = SimpleNamespace(base_url="https://api.openai.com/v1")
    module = SimpleNamespace(_get_cached_client=lambda provider: (local if provider == "mordred-local" else cloud, "m"))
    module.resolve_provider_client = lambda provider: module._get_cached_client(provider)

    def probe(endpoint):
        policy.with_name(".policy-write.pending").write_bytes(b"pending")
        module._get_cached_client("openai")

    monkeypatch.setattr(auxiliary_guard, "_memoized_health_probe", probe)
    monkeypatch.setattr(auxiliary_guard, "build_audit_writer", lambda path: Audit())
    for name in ("_get_cached_client", "resolve_provider_client"):
        auxiliary_guard._wrap_pair_resolver(
            module, name, policy_json_path=policy, audit_path=policy.with_name("audit.log")
        )
    with pytest.raises(MordredSessionRefused):
        module.resolve_provider_client("mordred-local")


def test_automatic_disk_provider_is_unknown_without_unchecked_auth(profile, monkeypatch):
    (profile.home / "config.yaml").write_bytes(b"model: {provider: auto}")
    audit = Audit()
    monkeypatch.setattr(llm_guard, "DEFAULT_POLICY_JSON_PATH", profile.home / "mordred" / "policy.json")
    monkeypatch.setattr(llm_guard, "DEFAULT_CONFIG_PATH", profile.home / "config.yaml")
    monkeypatch.setattr(llm_guard, "_build_audit_writer", lambda path: audit)
    monkeypatch.setattr(local_adapter, "register_provider", lambda profile: None)
    llm_guard._on_session_start_enforce()
    assert any(entry.get("reason") == "mordred.degraded.no_resolved_provider" for entry in audit.entries)


def test_unicode_fold_collision_does_not_share_another_profiles_grant(profile, monkeypatch):
    from dataclasses import replace

    from mordred_hermes.llm_guard import _windows_policy

    snapshot = _windows_policy.read_canonical_snapshot(profile)
    first = profile.home.parent / "ßhome" / "mordred" / "policy.json"
    second = profile.home.parent / "sshome" / "mordred" / "policy.json"
    refused = replace(snapshot, policy=replace(snapshot.policy, data=b'{"policy":"strict"}'))
    monkeypatch.setattr(
        _windows_policy, "read_canonical_snapshot", lambda paths: snapshot if paths.home.name == "ßhome" else refused
    )
    monkeypatch.setattr(auxiliary_guard, "build_audit_writer", lambda path: Audit())
    client = SimpleNamespace(base_url="https://api.openai.com/v1")
    module = SimpleNamespace(_get_cached_client=lambda provider: (client, "model"))
    module.resolve_provider_client = lambda provider: module._get_cached_client(provider)
    auxiliary_guard._wrap_pair_resolver(
        module, "_get_cached_client", policy_json_path=second, audit_path=second.with_name("audit.log")
    )
    auxiliary_guard._wrap_pair_resolver(
        module, "resolve_provider_client", policy_json_path=first, audit_path=first.with_name("audit.log")
    )
    with pytest.raises(MordredSessionRefused):
        module.resolve_provider_client("openai")


def test_another_thread_cannot_borrow_active_resolver_admission(profile, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from contextvars import copy_context

    policy = profile.home / "mordred" / "policy.json"
    client = SimpleNamespace(base_url="https://api.openai.com/v1")
    module = SimpleNamespace(_get_cached_client=lambda provider: (client, "model"))

    def resolve(provider):
        policy.with_name(".policy-write.pending").write_bytes(b"pending")
        copied = copy_context()
        with ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(copied.run, module._get_cached_client, "openai").result(timeout=10)

    module.resolve_provider_client = resolve
    monkeypatch.setattr(auxiliary_guard, "build_audit_writer", lambda path: Audit())
    for name in ("_get_cached_client", "resolve_provider_client"):
        auxiliary_guard._wrap_pair_resolver(
            module, name, policy_json_path=policy, audit_path=policy.with_name("audit.log")
        )
    with pytest.raises(MordredSessionRefused):
        module.resolve_provider_client("openai")


@pytest.mark.parametrize(
    "bad_config",
    [
        b"auxiliary: {vision: {provider: true}}",
        b'auxiliary: {vision: {enabled: "false"}}',
        b"auxiliary: {vision: {fallback_chain: [{base_url: []}]}}",
        b"fallback_providers: [{provider: openai, model: []}]",
    ],
    ids=["route-provider", "route-enabled", "route-chain", "fallback-model"],
)
def test_malformed_route_fields_cannot_bypass_admission_in_off_mode(profile, bad_config):
    (profile.home / "mordred" / "policy.json").write_bytes(b'{"policy":"off"}')
    (profile.home / "config.yaml").write_bytes(bad_config)
    with pytest.raises(MordredSessionRefused):
        run_provider(profile)


@pytest.mark.parametrize("field", ["base_url", "default", "model"])
@pytest.mark.parametrize("value", [[], {}, False, 0], ids=["list", "object", "boolean", "number"])
def test_malformed_main_model_fields_refuse_before_off_mode_exit(profile, field, value):
    config = json.dumps({"model": {"provider": "openai", field: value}}).encode()
    (profile.home / "mordred" / "policy.json").write_bytes(b'{"policy":"off"}')
    target = profile.home / "config.yaml"
    target.write_bytes(config)
    with pytest.raises(MordredSessionRefused):
        run_provider(profile)
    assert target.read_bytes() == config


@pytest.mark.parametrize("field", ["base_url", "default", "model"])
@pytest.mark.parametrize("value", [None, "", "https://api.openai.com/v1"], ids=["unset", "empty", "string"])
def test_main_model_string_and_unset_fields_keep_off_mode(profile, field, value):
    (profile.home / "mordred" / "policy.json").write_bytes(b'{"policy":"off"}')
    (profile.home / "config.yaml").write_bytes(json.dumps({"model": {"provider": "openai", field: value}}).encode())
    run_provider(profile)
