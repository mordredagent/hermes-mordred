"""Regression tests for Hermes 0.19 auxiliary LLM enforcement."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from mordred_hermes.llm_guard import auxiliary_guard
from mordred_hermes.llm_guard._exceptions import (
    MordredLocalUnreachable,
    MordredSessionRefused,
)


@pytest.fixture(autouse=True)
def _clear_guard_caches() -> None:
    """Keep the hot-path memos from leaking policy state between scenarios."""
    auxiliary_guard.reset_caches()


def _policy(tmp_path: Path, *, providers: tuple[str, ...]) -> Path:
    path = tmp_path / "policy.json"
    path.write_text(
        json.dumps(
            {
                "policy": "strict",
                "allow_cloud_llm": True,
                "cloud_provider_allowlist": list(providers),
                "local_llm_endpoint": "http://localhost:1234/v1",
            }
        ),
        encoding="utf-8",
    )
    return path


class TestHotPathMemos:
    """``_get_cached_client`` is wrapped, so the guard runs per request."""

    def test_repeated_guard_calls_reuse_one_policy_read(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        policy = _policy(tmp_path, providers=("openai",))
        reads: list[Path] = []
        real_mode = auxiliary_guard._policy_mode

        def counting_mode(path: Path) -> str:
            reads.append(path)
            return real_mode(path)

        monkeypatch.setattr(auxiliary_guard, "_policy_mode", counting_mode)
        for _ in range(5):
            assert auxiliary_guard._guard_inputs(policy) == ("strict", "http://localhost:1234/v1")
        assert len(reads) == 1

    def test_policy_edit_invalidates_the_memo(self, tmp_path: Path) -> None:
        policy = _policy(tmp_path, providers=("openai",))
        assert auxiliary_guard._guard_inputs(policy)[0] == "strict"

        policy.write_text(
            json.dumps({"policy": "lenient", "local_llm_endpoint": "http://localhost:9999/v1"}),
            encoding="utf-8",
        )
        # A same-nanosecond rewrite would be indistinguishable by mtime alone,
        # so assert on the size/content change that a real edit also carries.
        assert auxiliary_guard._guard_inputs(policy) == ("lenient", "http://localhost:9999/v1")

    def test_failed_probe_is_never_memoized(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list[str] = []

        def failing_probe(endpoint: str) -> None:
            calls.append(endpoint)
            raise MordredLocalUnreachable("down")

        monkeypatch.setattr(auxiliary_guard.enforce, "_default_health_probe", failing_probe)
        for _ in range(3):
            with pytest.raises(MordredLocalUnreachable):
                auxiliary_guard._memoized_health_probe("http://localhost:1234/v1")
        assert len(calls) == 3, "an unreachable local LLM must fail closed on every call"

    def test_successful_probe_is_shared_within_the_ttl(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list[str] = []
        monkeypatch.setattr(
            auxiliary_guard.enforce,
            "_default_health_probe",
            lambda endpoint: calls.append(endpoint),
        )
        for _ in range(4):
            auxiliary_guard._memoized_health_probe("http://localhost:1234/v1")
        assert len(calls) == 1

    def test_probe_runs_again_once_the_ttl_expires(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list[str] = []
        monkeypatch.setattr(
            auxiliary_guard.enforce,
            "_default_health_probe",
            lambda endpoint: calls.append(endpoint),
        )
        clock = iter([0.0, 0.0, 100.0, 100.0])
        monkeypatch.setattr(auxiliary_guard.time, "monotonic", lambda: next(clock))
        auxiliary_guard._memoized_health_probe("http://localhost:1234/v1")
        auxiliary_guard._memoized_health_probe("http://localhost:1234/v1")
        assert len(calls) == 2


def test_resolved_auxiliary_client_is_bound_to_actual_endpoint(tmp_path: Path) -> None:
    policy = _policy(tmp_path, providers=("openai",))
    client = SimpleNamespace(base_url="https://collector.example/v1")

    with pytest.raises(MordredSessionRefused):
        auxiliary_guard._guard_resolved_client(
            provider="openai",
            client=client,
            policy_json_path=policy,
            audit_path=tmp_path / "audit.log",
        )


def test_auxiliary_refusal_redacts_endpoint_credentials(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.log"
    secret_url = "https://aux-user:password-secret@collector.example/v1?api_key=query-secret#fragment-secret"

    with pytest.raises(MordredSessionRefused):
        auxiliary_guard._refuse_auxiliary(
            audit=auxiliary_guard.build_audit_writer(audit_path),
            provider_id="openai",
            base_url=secret_url,
            cause="declared base_url is not a provider-owned endpoint",
        )

    rendered = audit_path.read_text(encoding="utf-8")
    assert "https://collector.example" in rendered
    for secret in (
        "aux-user",
        "password-secret",
        "query-secret",
        "fragment-secret",
    ):
        assert secret not in rendered


def test_auto_auxiliary_client_is_inferred_and_allowed_by_endpoint(tmp_path: Path) -> None:
    policy = _policy(tmp_path, providers=("anthropic",))
    client = SimpleNamespace(base_url="https://api.anthropic.com")

    auxiliary_guard._guard_resolved_client(
        provider="auto",
        client=client,
        policy_json_path=policy,
        audit_path=tmp_path / "audit.log",
    )


@pytest.mark.parametrize("provider", ["api-key", "custom:company", "local/custom"])
def test_indirect_auxiliary_labels_are_inferred_from_actual_cloud_endpoint(
    tmp_path: Path,
    provider: str,
) -> None:
    policy = _policy(tmp_path, providers=("anthropic",))
    client = SimpleNamespace(base_url="https://api.anthropic.com")

    auxiliary_guard._guard_resolved_client(
        provider=provider,
        client=client,
        policy_json_path=policy,
        audit_path=tmp_path / "audit.log",
    )


def test_api_key_meta_label_distinguishes_opencode_routes_by_path(tmp_path: Path) -> None:
    policy = _policy(tmp_path, providers=("opencode-zen",))

    auxiliary_guard._guard_resolved_client(
        provider="api-key",
        client=SimpleNamespace(base_url="https://opencode.ai/zen/v1"),
        policy_json_path=policy,
        audit_path=tmp_path / "audit.log",
    )


def test_real_chain_labels_are_guarded_after_candidate_resolution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _policy(tmp_path, providers=("anthropic",))
    audit_path = tmp_path / "audit.log"
    probed: list[str] = []
    monkeypatch.setattr(
        auxiliary_guard.enforce,
        "_default_health_probe",
        lambda endpoint: probed.append(endpoint),
    )
    module = SimpleNamespace(
        _get_provider_chain=lambda: [
            (
                "local/custom",
                lambda: (
                    SimpleNamespace(base_url="http://localhost:1234/v1/"),
                    "local-model",
                ),
            ),
            (
                "api-key",
                lambda: (
                    SimpleNamespace(base_url="https://api.anthropic.com"),
                    "claude",
                ),
            ),
        ]
    )
    auxiliary_guard._wrap_provider_chain(
        module,
        policy_json_path=policy,
        audit_path=audit_path,
    )

    for _label, resolver in module._get_provider_chain():
        resolver()

    assert probed == ["http://localhost:1234/v1/"]


@pytest.mark.parametrize("provider", ["auto", "custom", "mordred-local"])
def test_resolved_local_auxiliary_client_uses_strict_local_route(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    provider: str,
) -> None:
    policy = _policy(tmp_path, providers=())
    client = SimpleNamespace(base_url="http://localhost:1234/v1/")
    probed: list[str] = []
    monkeypatch.setattr(
        auxiliary_guard.enforce,
        "_default_health_probe",
        lambda endpoint: probed.append(endpoint),
    )

    auxiliary_guard._guard_resolved_client(
        provider=provider,
        client=client,
        policy_json_path=policy,
        audit_path=tmp_path / "audit.log",
    )

    assert probed == ["http://localhost:1234/v1/"]


def test_named_local_auxiliary_client_is_classified_by_configured_endpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _policy(tmp_path, providers=())
    probed: list[str] = []
    monkeypatch.setattr(
        auxiliary_guard.enforce,
        "_default_health_probe",
        lambda endpoint: probed.append(endpoint),
    )

    auxiliary_guard._guard_resolved_client(
        provider="lmstudio",
        client=SimpleNamespace(base_url="http://localhost:1234/v1/"),
        policy_json_path=policy,
        audit_path=tmp_path / "audit.log",
    )

    assert probed == ["http://localhost:1234/v1/"]


def test_declared_mordred_local_without_base_url_is_accepted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _policy(tmp_path, providers=())
    config = tmp_path / "config.yaml"
    config.write_text(
        """\
auxiliary:
  compression:
    provider: mordred-local
""",
        encoding="utf-8",
    )
    audit_path = tmp_path / "audit.log"
    monkeypatch.setattr(auxiliary_guard, "_installed", True)
    monkeypatch.setattr(auxiliary_guard, "_installed_paths", (policy, audit_path))
    monkeypatch.setattr(auxiliary_guard, "_runtime_seams_guarded", lambda: True)

    auxiliary_guard.validate_session(
        policy_json_path=policy,
        config_path=config,
        audit_path=audit_path,
    )


def test_session_rejects_disallowed_configured_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _policy(tmp_path, providers=("anthropic",))
    config = tmp_path / "config.yaml"
    config.write_text(
        """\
auxiliary:
  compression:
    provider: anthropic
    fallback_chain:
      - provider: openai
        model: gpt-4.1-mini
""",
        encoding="utf-8",
    )
    monkeypatch.setattr(auxiliary_guard, "_installed", True)
    monkeypatch.setattr(auxiliary_guard, "_installed_paths", (policy, tmp_path / "audit.log"))
    monkeypatch.setattr(auxiliary_guard, "_runtime_seams_guarded", lambda: True)

    with pytest.raises(MordredSessionRefused, match=r"compression\.fallback_chain\[0\]"):
        auxiliary_guard.validate_session(
            policy_json_path=policy,
            config_path=config,
            audit_path=tmp_path / "audit.log",
        )


def test_session_rejects_disallowed_main_fallback_inherited_by_auto(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _policy(tmp_path, providers=("anthropic",))
    config = tmp_path / "config.yaml"
    config.write_text(
        """\
auxiliary:
  compression:
    provider: auto
fallback_providers:
  - provider: openai-api
    model: gpt-5-mini
""",
        encoding="utf-8",
    )
    audit_path = tmp_path / "audit.log"
    monkeypatch.setattr(auxiliary_guard, "_installed", True)
    monkeypatch.setattr(auxiliary_guard, "_installed_paths", (policy, audit_path))
    monkeypatch.setattr(auxiliary_guard, "_runtime_seams_guarded", lambda: True)

    with pytest.raises(MordredSessionRefused, match=r"fallback_providers\[0\]"):
        auxiliary_guard.validate_session(
            policy_json_path=policy,
            config_path=config,
            audit_path=audit_path,
        )


def test_auto_configuration_is_accepted_because_runtime_resolution_is_guarded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _policy(tmp_path, providers=("anthropic",))
    config = tmp_path / "config.yaml"
    config.write_text(
        """\
auxiliary:
  compression:
    provider: auto
""",
        encoding="utf-8",
    )
    monkeypatch.setattr(auxiliary_guard, "_installed", True)
    monkeypatch.setattr(auxiliary_guard, "_installed_paths", (policy, tmp_path / "audit.log"))
    monkeypatch.setattr(auxiliary_guard, "_runtime_seams_guarded", lambda: True)

    auxiliary_guard.validate_session(
        policy_json_path=policy,
        config_path=config,
        audit_path=tmp_path / "audit.log",
    )


def test_session_refuses_when_guarded_resolver_is_replaced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agent import auxiliary_client

    policy = _policy(tmp_path, providers=("anthropic",))
    config = tmp_path / "config.yaml"
    config.write_text("auxiliary: {}\n", encoding="utf-8")
    audit_path = tmp_path / "audit.log"

    # Model a successfully installed process, then an upstream force-rescan or
    # mutation replacing one of the four security-boundary callables.
    for name in auxiliary_guard._REQUIRED_RESOLVER_SEAMS:
        candidate = getattr(auxiliary_client, name)
        monkeypatch.setattr(
            candidate,
            auxiliary_guard._WRAPPED_MARKER,
            True,
            raising=False,
        )
    monkeypatch.setattr(auxiliary_client, "_get_cached_client", lambda *_a, **_k: (None, None))
    monkeypatch.setattr(auxiliary_guard, "_installed", True)
    monkeypatch.setattr(auxiliary_guard, "_installed_paths", (policy, audit_path))

    with pytest.raises(MordredSessionRefused, match="resolver seams were replaced"):
        auxiliary_guard.validate_session(
            policy_json_path=policy,
            config_path=config,
            audit_path=audit_path,
        )


def test_runtime_seam_proof_includes_bound_policy_and_audit_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agent import auxiliary_client

    expected = (tmp_path / "policy.json", tmp_path / "audit.log")
    monkeypatch.setattr(auxiliary_guard, "_installed_paths", expected)
    for name in auxiliary_guard._REQUIRED_RESOLVER_SEAMS:
        candidate = getattr(auxiliary_client, name)
        monkeypatch.setattr(
            candidate,
            auxiliary_guard._WRAPPED_MARKER,
            True,
            raising=False,
        )
        monkeypatch.setattr(
            candidate,
            auxiliary_guard._BOUND_PATHS_MARKER,
            (tmp_path / "other-policy.json", tmp_path / "other-audit.log"),
            raising=False,
        )

    assert auxiliary_guard._runtime_seams_guarded() is False


def test_validate_session_rejects_guard_bound_to_different_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _policy(tmp_path, providers=("anthropic",))
    audit_path = tmp_path / "audit.log"
    config = tmp_path / "config.yaml"
    config.write_text("auxiliary: {}\n", encoding="utf-8")
    monkeypatch.setattr(auxiliary_guard, "_installed", True)
    monkeypatch.setattr(
        auxiliary_guard,
        "_installed_paths",
        (tmp_path / "other-policy.json", tmp_path / "other-audit.log"),
    )
    monkeypatch.setattr(auxiliary_guard, "_runtime_seams_guarded", lambda: True)

    with pytest.raises(MordredSessionRefused):
        auxiliary_guard.validate_session(
            policy_json_path=policy,
            config_path=config,
            audit_path=audit_path,
        )


# ---------------------------------------------------------------------------
# _prepare_rebind / _finish_rebind: the single choke point every resolver
# wrapper goes through. Pin the two fail-safe branches directly.
# ---------------------------------------------------------------------------


def _bound_paths(tmp_path: Path) -> tuple[Path, Path]:
    return (tmp_path / "policy.json", tmp_path / "audit.log")


def test_prepare_rebind_returns_the_plain_seam(tmp_path: Path) -> None:
    def resolver() -> str:
        return "plain"

    module = SimpleNamespace(resolve=resolver)
    assert (
        auxiliary_guard._prepare_rebind(module=module, name="resolve", bound_paths=_bound_paths(tmp_path)) is resolver
    )


def test_prepare_rebind_is_a_noop_when_already_guarded_for_the_same_paths(tmp_path: Path) -> None:
    def original() -> str:
        return "original"

    def guarded() -> str:
        return "guarded"

    module = SimpleNamespace(resolve=original)
    auxiliary_guard._finish_rebind(module=module, name="resolve", guarded=guarded, bound_paths=_bound_paths(tmp_path))
    assert module.resolve is guarded
    assert getattr(guarded, auxiliary_guard._WRAPPED_MARKER) is True
    assert getattr(guarded, auxiliary_guard._BOUND_PATHS_MARKER) == _bound_paths(tmp_path)

    assert auxiliary_guard._prepare_rebind(module=module, name="resolve", bound_paths=_bound_paths(tmp_path)) is None


def test_prepare_rebind_unwraps_a_guard_bound_to_different_paths(tmp_path: Path) -> None:
    def original() -> str:
        return "original"

    def guarded() -> str:
        return "guarded"

    guarded.__wrapped__ = original  # type: ignore[attr-defined]
    module = SimpleNamespace(resolve=original)
    auxiliary_guard._finish_rebind(module=module, name="resolve", guarded=guarded, bound_paths=_bound_paths(tmp_path))

    other = (tmp_path / "other-policy.json", tmp_path / "other-audit.log")
    # Guards never stack: the *original* is handed back for re-wrapping.
    assert auxiliary_guard._prepare_rebind(module=module, name="resolve", bound_paths=other) is original


@pytest.mark.parametrize(
    "seam",
    [
        pytest.param("not callable", id="plain_non_callable"),
        pytest.param(None, id="none"),
    ],
)
def test_prepare_rebind_refuses_a_non_callable_seam(tmp_path: Path, seam: object) -> None:
    module = SimpleNamespace(resolve=seam)
    with pytest.raises(RuntimeError, match="'resolve' cannot be rebound"):
        auxiliary_guard._prepare_rebind(module=module, name="resolve", bound_paths=_bound_paths(tmp_path))


def test_prepare_rebind_refuses_a_marked_guard_without_wrapped(tmp_path: Path) -> None:
    """A marker without ``__wrapped__`` must fail closed, not hand back ``None``
    as if the seam were already guarded."""

    def stale_guard() -> str:
        return "stale"

    setattr(stale_guard, auxiliary_guard._WRAPPED_MARKER, True)
    module = SimpleNamespace(resolve=stale_guard)
    other = (tmp_path / "other-policy.json", tmp_path / "other-audit.log")
    with pytest.raises(RuntimeError, match="'resolve' cannot be rebound"):
        auxiliary_guard._prepare_rebind(module=module, name="resolve", bound_paths=other)
