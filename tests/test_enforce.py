"""Tests for ``mordred_hermes.llm_guard.enforce`` — TDD Cycle A.

Phase 2 PR2 — v1 refuse-only decision matrix. Cycle A covers the three
"do not raise" axes:

- off mode: silent no-op regardless of provider
- lenient mode: silent no-op (v1 stays silent to avoid per-session spam)
- strict + cloud provider in allowlist AND ``allow_cloud_llm: true``:
  passthrough with an ``allow``-decision audit entry

Later cycles (B/C/D) extend this file with the refuse paths, the
mordred-local probe path, and policy.json fallbacks. Audit-reason shape
gets its own dedicated file (``test_enforce_audit.py``, Cycle E).

Patterns mirror ``test_harness_detect.py``:

- ``_FakeAuditWriter`` captures appended dicts for shape assertions.
- ``_write_policy_json`` synthesises a minimal ``policy.json`` fixture
  per case so the decision-matrix axes are independent.
- ``_noop_probe`` is injected as ``health_probe`` so the local-provider
  branch (added in Cycle C) doesn't touch real HTTP.
"""

from __future__ import annotations

import json
import os
import socket
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.llm_guard import enforce
from mordred_hermes.llm_guard._exceptions import (
    MordredLocalUnreachable,
    MordredSessionRefused,
)


class _FakeAuditWriter:
    """Captures audit appends so tests can assert reason / decision / fields."""

    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    def append(self, entry: Mapping[str, Any]) -> None:
        self.entries.append(entry)


def _noop_probe(_endpoint: str) -> None:
    """Health probe that always succeeds — used by Cycle C strict+local tests."""
    return None


def _failing_probe(_endpoint: str) -> None:
    raise MordredLocalUnreachable("simulated probe failure")


def _write_policy_json(
    tmp_path: Path,
    *,
    policy: str = "strict",
    allow_cloud_llm: bool = False,
    cloud_provider_allowlist: tuple[str, ...] = (),
    local_llm_endpoint: str = "http://localhost:1234/v1",
) -> Path:
    body = {
        "policy": policy,
        "allow_cloud_llm": allow_cloud_llm,
        "cloud_provider_allowlist": list(cloud_provider_allowlist),
        "local_llm_endpoint": local_llm_endpoint,
    }
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(body), encoding="utf-8")
    return path


def _check_strict_local_endpoint(
    tmp_path: Path,
    *,
    source: str,
    endpoint: str,
    audit: _FakeAuditWriter,
    health_probe: Callable[[str], None],
) -> None:
    """Exercise the policy.json or runtime-base-url local endpoint path."""
    policy_endpoint = endpoint if source == "policy" else "http://127.0.0.1:1234/v1"
    cfg = _write_policy_json(tmp_path, policy="strict", local_llm_endpoint=policy_endpoint)
    if source == "policy":
        enforce.check_session_provider(
            policy_mode="strict",
            policy_json_path=cfg,
            active_provider="mordred-local",
            audit=audit,
            health_probe=health_probe,
        )
        return
    enforce.check_runtime_provider(
        policy_mode="strict",
        policy_json_path=cfg,
        active_provider="mordred-local",
        audit=audit,
        health_probe=health_probe,
        runtime_base_url=endpoint,
    )


# --------------------------------------------------------------------------- #
# off mode — silent no-op                                                     #
# --------------------------------------------------------------------------- #


class TestOffMode:
    @pytest.mark.parametrize(
        "active_provider",
        [None, "mordred-local", "anthropic", "openai", "totally-unknown"],
    )
    def test_off_is_noop(self, tmp_path: Path, active_provider: str | None) -> None:
        cfg = _write_policy_json(tmp_path, policy="off")
        audit = _FakeAuditWriter()

        enforce.check_session_provider(
            policy_mode="off",
            policy_json_path=cfg,
            active_provider=active_provider,
            audit=audit,
            health_probe=_noop_probe,
        )

        assert audit.entries == [], "off mode must not write to audit"


# --------------------------------------------------------------------------- #
# lenient mode — silent no-op                                                 #
# --------------------------------------------------------------------------- #


class TestLenientMode:
    @pytest.mark.parametrize(
        "active_provider",
        [None, "mordred-local", "anthropic", "totally-unknown"],
    )
    def test_lenient_does_not_raise(self, tmp_path: Path, active_provider: str | None) -> None:
        cfg = _write_policy_json(tmp_path, policy="lenient")
        audit = _FakeAuditWriter()
        enforce.check_session_provider(
            policy_mode="lenient",
            policy_json_path=cfg,
            active_provider=active_provider,
            audit=audit,
            health_probe=_noop_probe,
        )

    def test_lenient_is_silent(self, tmp_path: Path) -> None:
        """v1 emits nothing under lenient — future versions may emit an
        allow-with-reason; revisit then.
        """
        cfg = _write_policy_json(tmp_path, policy="lenient")
        audit = _FakeAuditWriter()
        enforce.check_session_provider(
            policy_mode="lenient",
            policy_json_path=cfg,
            active_provider="anthropic",
            audit=audit,
            health_probe=_noop_probe,
        )
        assert audit.entries == []


# --------------------------------------------------------------------------- #
# strict + cloud allowlisted (with allow_cloud_llm=True) — passthrough        #
# --------------------------------------------------------------------------- #


class TestStrictCloudAllowlisted:
    def test_strict_cloud_in_allowlist_allow(self, tmp_path: Path) -> None:
        cfg = _write_policy_json(
            tmp_path,
            policy="strict",
            allow_cloud_llm=True,
            cloud_provider_allowlist=("anthropic", "openai"),
        )
        audit = _FakeAuditWriter()

        enforce.check_session_provider(
            policy_mode="strict",
            policy_json_path=cfg,
            active_provider="anthropic",
            audit=audit,
            health_probe=_noop_probe,
        )

        assert audit.entries, "allowlisted cloud must emit an allow audit"
        entry = audit.entries[-1]
        assert entry["decision"] == "allow"
        assert entry["provider_id"] == "anthropic"

    def test_strict_cloud_allowed_does_not_raise(self, tmp_path: Path) -> None:
        cfg = _write_policy_json(
            tmp_path,
            policy="strict",
            allow_cloud_llm=True,
            cloud_provider_allowlist=("openai",),
        )
        audit = _FakeAuditWriter()
        enforce.check_session_provider(
            policy_mode="strict",
            policy_json_path=cfg,
            active_provider="openai",
            audit=audit,
            health_probe=_noop_probe,
        )


# --------------------------------------------------------------------------- #
# Cycle B — strict + cloud NOT allowlisted (refuse)                           #
# --------------------------------------------------------------------------- #


class TestStrictCloudRefused:
    def test_strict_provider_not_in_allowlist_raises(self, tmp_path: Path) -> None:
        cfg = _write_policy_json(
            tmp_path,
            policy="strict",
            allow_cloud_llm=True,
            cloud_provider_allowlist=("anthropic",),  # NOT openai
        )
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused, match="openai"):
            enforce.check_session_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider="openai",
                audit=audit,
                health_probe=_noop_probe,
            )

    def test_strict_allow_cloud_llm_false_vetoes_allowlist(self, tmp_path: Path) -> None:
        """``allow_cloud_llm: false`` must veto allowlist membership.

        TODO L244: "strict + active provider が cloud_provider_allowlist
        に該当 + allow_cloud_llm: true → passthrough" — both axes are
        required.
        """
        cfg = _write_policy_json(
            tmp_path,
            policy="strict",
            allow_cloud_llm=False,
            cloud_provider_allowlist=("anthropic",),
        )
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused, match="allow_cloud_llm"):
            enforce.check_session_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider="anthropic",
                audit=audit,
                health_probe=_noop_probe,
            )

    def test_refusal_emits_both_classification_and_action(self, tmp_path: Path) -> None:
        """Codex N1 (POLICY.md row 8): classification reason
        ``policy.strict.cloud_not_allowlisted`` is emitted alongside the
        action ``policy.strict.session_refused`` so consumers can filter
        on either axis.
        """
        cfg = _write_policy_json(
            tmp_path,
            policy="strict",
            allow_cloud_llm=True,
            cloud_provider_allowlist=("anthropic",),
        )
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused):
            enforce.check_session_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider="bedrock",
                audit=audit,
                health_probe=_noop_probe,
            )

        reasons = [e["reason"] for e in audit.entries]
        assert "policy.strict.cloud_not_allowlisted" in reasons
        assert "policy.strict.session_refused" in reasons

    def test_refusal_escapes_except_exception(self, tmp_path: Path) -> None:
        """Codex H2: ``MordredSessionRefused`` is ``BaseException``-derived
        so cleanup-style ``except Exception:`` cannot swallow it.
        """
        cfg = _write_policy_json(tmp_path, policy="strict")  # empty allowlist
        audit = _FakeAuditWriter()

        try:
            try:
                enforce.check_session_provider(
                    policy_mode="strict",
                    policy_json_path=cfg,
                    active_provider="anthropic",
                    audit=audit,
                    health_probe=_noop_probe,
                )
            except Exception:
                pytest.fail("MordredSessionRefused must not be caught by `except Exception`")
        except MordredSessionRefused:
            pass


# --------------------------------------------------------------------------- #
# Cycle B — strict + no active provider (degraded refuse)                     #
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _reset_enforce_state() -> Any:
    """One-shot ``mordred.degraded.no_resolved_provider`` must not leak across tests.

    Autouse + module-scope fixture: tests in classes above that don't touch
    the degraded path are unaffected; degraded tests get a clean slate.
    """
    enforce._reset_state()
    yield
    enforce._reset_state()


class TestStrictDegraded:
    def test_strict_active_provider_none_raises(self, tmp_path: Path) -> None:
        cfg = _write_policy_json(tmp_path, policy="strict")
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused, match="could not be resolved"):
            enforce.check_session_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider=None,
                audit=audit,
                health_probe=_noop_probe,
            )

    def test_strict_degraded_no_resolved_provider_is_one_shot(self, tmp_path: Path) -> None:
        """POLICY.md row 6: ``mordred.degraded.no_resolved_provider`` is
        one-shot per process. Two consecutive degraded refusals → emitted
        exactly once.
        """
        cfg = _write_policy_json(tmp_path, policy="strict")
        audit = _FakeAuditWriter()

        for _ in range(2):
            with pytest.raises(MordredSessionRefused):
                enforce.check_session_provider(
                    policy_mode="strict",
                    policy_json_path=cfg,
                    active_provider=None,
                    audit=audit,
                    health_probe=_noop_probe,
                )

        n = sum(1 for e in audit.entries if e["reason"] == "mordred.degraded.no_resolved_provider")
        assert n == 1, f"expected exactly one no_resolved_provider audit, got {n}"

    def test_reset_state_re_arms_one_shot(self, tmp_path: Path) -> None:
        cfg = _write_policy_json(tmp_path, policy="strict")
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused):
            enforce.check_session_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider=None,
                audit=audit,
                health_probe=_noop_probe,
            )
        enforce._reset_state()
        with pytest.raises(MordredSessionRefused):
            enforce.check_session_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider=None,
                audit=audit,
                health_probe=_noop_probe,
            )
        n = sum(1 for e in audit.entries if e["reason"] == "mordred.degraded.no_resolved_provider")
        assert n == 2


# --------------------------------------------------------------------------- #
# Cycle C — strict + mordred-local (probe gates passthrough)                  #
# --------------------------------------------------------------------------- #


class TestStrictLocal:
    def test_strict_local_passthrough_audits_allow(self, tmp_path: Path) -> None:
        cfg = _write_policy_json(tmp_path, policy="strict")
        audit = _FakeAuditWriter()

        enforce.check_session_provider(
            policy_mode="strict",
            policy_json_path=cfg,
            active_provider="mordred-local",
            audit=audit,
            health_probe=_noop_probe,
        )

        assert audit.entries
        entry = audit.entries[-1]
        assert entry["decision"] == "allow"
        assert entry["provider_id"] == "mordred-local"

    def test_strict_local_probe_failure_raises_session_refused(self, tmp_path: Path) -> None:
        """Phase 2 acceptance gate row 4: strict + no local endpoint
        reachable → fails fast and ABORTS the session.

        Codex P2 round 2: ``MordredLocalUnreachable`` inherits from
        :class:`Exception`, which Hermes' hook dispatch
        (``hermes_cli/plugins.py::invoke_hook`` line 1112) catches + logs
        + continues. To actually refuse the session, strict-mode probe
        failures are translated to :class:`MordredSessionRefused`
        (``BaseException``-derived). The original
        :class:`MordredLocalUnreachable` is preserved as ``__cause__`` so
        consumers can introspect why the session was refused.

        Audit must show exactly one block entry (no allow entry — probe
        runs BEFORE the success audit append).
        """
        cfg = _write_policy_json(tmp_path, policy="strict")
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused) as excinfo:
            enforce.check_session_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider="mordred-local",
                audit=audit,
                health_probe=_failing_probe,
            )
        assert isinstance(excinfo.value.__cause__, MordredLocalUnreachable)
        assert "simulated probe failure" in str(excinfo.value.__cause__)

        # One block entry, no allow entry, reason=session_refused.
        assert len(audit.entries) == 1
        entry = audit.entries[0]
        assert entry["decision"] == "block"
        assert entry["reason"] == "policy.strict.session_refused"
        assert entry["provider_id"] == "mordred-local"

    def test_strict_local_uses_configured_endpoint(self, tmp_path: Path) -> None:
        """The injected probe receives the endpoint from policy.json."""
        cfg = _write_policy_json(
            tmp_path,
            policy="strict",
            local_llm_endpoint="http://127.0.0.1:9999/v1",
        )
        seen: list[str] = []

        def _record(endpoint: str) -> None:
            seen.append(endpoint)

        audit = _FakeAuditWriter()
        enforce.check_session_provider(
            policy_mode="strict",
            policy_json_path=cfg,
            active_provider="mordred-local",
            audit=audit,
            health_probe=_record,
        )
        assert seen == ["http://127.0.0.1:9999/v1"]

    @pytest.mark.parametrize("source", ["policy", "runtime"])
    @pytest.mark.parametrize(
        "endpoint",
        [
            "http://127.0.0.1:1234/v1",
            "https://127.0.0.1:1234/v1",
            "http://[::1]:1234/v1",
            "https://localhost:1234/v1",
        ],
    )
    def test_strict_local_accepts_loopback_http_endpoints(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        source: str,
        endpoint: str,
    ) -> None:
        def _loopback_results(host: str, port: int, **_kwargs: Any) -> list[tuple[Any, ...]]:
            assert host == "localhost"
            return [
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", port)),
                (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("::1", port, 0, 0)),
            ]

        monkeypatch.setattr(enforce.socket, "getaddrinfo", _loopback_results)
        seen: list[str] = []
        audit = _FakeAuditWriter()

        _check_strict_local_endpoint(
            tmp_path,
            source=source,
            endpoint=endpoint,
            audit=audit,
            health_probe=seen.append,
        )

        assert seen == [endpoint]
        assert not any(entry["decision"] == "block" for entry in audit.entries)

    @pytest.mark.parametrize("source", ["policy", "runtime"])
    @pytest.mark.parametrize(
        "endpoint",
        [
            "http://192.168.1.20:1234/v1",
            "https://8.8.8.8/v1",
            "http://169.254.169.254/latest",
            "http://127.0.0.2:1234/v1",
            "http://user:secret@127.0.0.1:1234/v1",
            "ftp://127.0.0.1:1234/v1",
            "http://%31%32%37.0.0.1:1234/v1",
            "http://localhost.evil:1234/v1",
            "not-a-url",
            "http://[::1",
        ],
    )
    def test_strict_local_rejects_non_loopback_or_malformed_before_probe(
        self,
        tmp_path: Path,
        source: str,
        endpoint: str,
    ) -> None:
        probed: list[str] = []
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused) as excinfo:
            _check_strict_local_endpoint(
                tmp_path,
                source=source,
                endpoint=endpoint,
                audit=audit,
                health_probe=probed.append,
            )

        assert probed == []
        assert len(audit.entries) == 1
        assert audit.entries[0]["decision"] == "block"
        assert audit.entries[0]["reason"] == "policy.strict.session_refused"
        assert audit.entries[0]["provider_id"] == "mordred-local"
        assert "secret" not in str(excinfo.value)
        assert "secret" not in json.dumps(audit.entries)

    @pytest.mark.parametrize("source", ["policy", "runtime"])
    def test_strict_local_rejects_localhost_with_any_non_loopback_dns_result_before_probe(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        source: str,
    ) -> None:
        def _mixed_results(_host: str, port: int, **_kwargs: Any) -> list[tuple[Any, ...]]:
            return [
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", port)),
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("203.0.113.7", port)),
            ]

        monkeypatch.setattr(enforce.socket, "getaddrinfo", _mixed_results)
        probed: list[str] = []
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused):
            _check_strict_local_endpoint(
                tmp_path,
                source=source,
                endpoint="http://localhost:1234/v1",
                audit=audit,
                health_probe=probed.append,
            )

        assert probed == []
        assert [entry["decision"] for entry in audit.entries] == ["block"]
        assert "non-loopback" in audit.entries[0]["cause"]

    @pytest.mark.parametrize("source", ["policy", "runtime"])
    def test_strict_local_adds_exact_proxy_bypass_before_probe(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        source: str,
    ) -> None:
        monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:8080")
        monkeypatch.setenv("NO_PROXY", "internal.example")
        monkeypatch.setenv("no_proxy", "other.example,localhost")
        seen: list[str] = []

        _check_strict_local_endpoint(
            tmp_path,
            source=source,
            endpoint="http://127.0.0.1:1234/v1",
            audit=_FakeAuditWriter(),
            health_probe=seen.append,
        )

        assert seen == ["http://127.0.0.1:1234/v1"]
        # Lowercase proxy variables take precedence on POSIX/httpx. Do not
        # union the stale uppercase entry: that can broaden direct egress.
        expected = "other.example,localhost,127.0.0.1,::1"
        assert os.environ["NO_PROXY"] == expected
        assert os.environ["no_proxy"] == expected

    @pytest.mark.parametrize("policy_mode", ["off", "lenient", "balanced", "audit"])
    @pytest.mark.parametrize("runtime", [False, True])
    def test_non_strict_modes_do_not_apply_loopback_boundary(
        self,
        tmp_path: Path,
        policy_mode: str,
        runtime: bool,
    ) -> None:
        cfg = _write_policy_json(
            tmp_path,
            policy=policy_mode,
            local_llm_endpoint="https://collector.example/v1",
        )
        probed: list[str] = []
        audit = _FakeAuditWriter()
        kwargs = {
            "policy_mode": policy_mode,
            "policy_json_path": cfg,
            "active_provider": "mordred-local",
            "audit": audit,
            "health_probe": probed.append,
        }

        if runtime:
            enforce.check_runtime_provider(**kwargs, runtime_base_url="https://collector.example/v1")
        else:
            enforce.check_session_provider(**kwargs)

        assert probed == []
        assert audit.entries == []


# --------------------------------------------------------------------------- #
# Cycle D — policy.json missing / malformed → safe defaults (failure-closed)  #
# --------------------------------------------------------------------------- #


class TestPolicyJsonFallbacks:
    def test_missing_policy_json_falls_through_to_strict_defaults(self, tmp_path: Path) -> None:
        """No policy.json + strict mode → safe defaults (allow_cloud_llm=False,
        empty allowlist). Cloud provider should be refused.
        """
        missing = tmp_path / "absent.json"
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused):
            enforce.check_session_provider(
                policy_mode="strict",
                policy_json_path=missing,
                active_provider="anthropic",
                audit=audit,
                health_probe=_noop_probe,
            )

    def test_malformed_policy_json_uses_safe_defaults(self, tmp_path: Path) -> None:
        path = tmp_path / "policy.json"
        path.write_text("this is not json", encoding="utf-8")
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused):
            enforce.check_session_provider(
                policy_mode="strict",
                policy_json_path=path,
                active_provider="anthropic",
                audit=audit,
                health_probe=_noop_probe,
            )

    def test_allow_cloud_llm_string_treated_as_false(self, tmp_path: Path) -> None:
        """Codex review P2: ``bool("false")`` is ``True`` in Python.

        If a hand-edit or migration tool writes ``allow_cloud_llm: "false"``,
        strict mode must still refuse cloud traffic — only an actual JSON
        boolean ``true`` counts as ``True`` (failure-closed coercion).
        """
        path = tmp_path / "policy.json"
        path.write_text(
            json.dumps(
                {
                    "policy": "strict",
                    "allow_cloud_llm": "false",  # string, not bool
                    "cloud_provider_allowlist": ["anthropic"],
                }
            ),
            encoding="utf-8",
        )
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused, match="allow_cloud_llm"):
            enforce.check_session_provider(
                policy_mode="strict",
                policy_json_path=path,
                active_provider="anthropic",
                audit=audit,
                health_probe=_noop_probe,
            )

    def test_allow_cloud_llm_string_true_also_treated_as_false(self, tmp_path: Path) -> None:
        """Mirror of the above: ``"true"`` (string) also must fail closed.

        We don't try to be clever about parsing user intent — anything that
        isn't a JSON ``true`` is treated as ``false``. Users who want cloud
        access rerun the wizard.
        """
        path = tmp_path / "policy.json"
        path.write_text(
            json.dumps(
                {
                    "policy": "strict",
                    "allow_cloud_llm": "true",  # string, not bool
                    "cloud_provider_allowlist": ["anthropic"],
                }
            ),
            encoding="utf-8",
        )
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused):
            enforce.check_session_provider(
                policy_mode="strict",
                policy_json_path=path,
                active_provider="anthropic",
                audit=audit,
                health_probe=_noop_probe,
            )

    def test_allow_cloud_llm_integer_treated_as_false(self, tmp_path: Path) -> None:
        """Only a real JSON ``true`` counts — ``1`` (int) is not a bool here."""
        path = tmp_path / "policy.json"
        path.write_text(
            json.dumps(
                {
                    "policy": "strict",
                    "allow_cloud_llm": 1,
                    "cloud_provider_allowlist": ["anthropic"],
                }
            ),
            encoding="utf-8",
        )
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused):
            enforce.check_session_provider(
                policy_mode="strict",
                policy_json_path=path,
                active_provider="anthropic",
                audit=audit,
                health_probe=_noop_probe,
            )

    def test_non_list_allowlist_is_treated_as_empty(self, tmp_path: Path) -> None:
        """If the user hand-edited cloud_provider_allowlist to a non-list,
        be defensive and treat it as empty (failure-closed).
        """
        path = tmp_path / "policy.json"
        path.write_text(
            json.dumps(
                {
                    "policy": "strict",
                    "allow_cloud_llm": True,
                    "cloud_provider_allowlist": "anthropic",  # str not list
                }
            ),
            encoding="utf-8",
        )
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused):
            enforce.check_session_provider(
                policy_mode="strict",
                policy_json_path=path,
                active_provider="anthropic",
                audit=audit,
                health_probe=_noop_probe,
            )

    def test_allowlist_entries_are_canonicalized_through_alias_table(self, tmp_path: Path) -> None:
        """``_read_policy_settings`` must run allowlist entries through the
        same alias table (``canonicalize_provider``) the runtime provider id
        is compared against, not a bare ``.strip().lower()``. A Hermes alias
        like ``"claude"`` resolves to the canonical ``"anthropic"`` slug.
        """
        cfg = _write_policy_json(
            tmp_path,
            policy="strict",
            cloud_provider_allowlist=("claude", "  GOOGLE  ", "aws"),
        )

        settings = enforce._read_policy_settings(cfg)

        assert settings.cloud_allowlist == frozenset({"anthropic", "gemini", "bedrock"})

    def test_allowlist_empty_string_entries_still_drop_out(self, tmp_path: Path) -> None:
        """A stray comma in the wizard's CSV (``"anthropic,"``) parses to an
        empty-string list entry; canonicalizing must not let it widen the
        allowlist into matching e.g. an unresolved/empty active_provider.
        """
        cfg = _write_policy_json(
            tmp_path,
            policy="strict",
            cloud_provider_allowlist=("anthropic", "", "   "),
        )

        settings = enforce._read_policy_settings(cfg)

        assert settings.cloud_allowlist == frozenset({"anthropic"})

    def test_allowlist_ollama_entry_does_not_grant_generic_custom_provider(self, tmp_path: Path) -> None:
        """``"ollama"`` canonicalizes to ``"custom"`` (Hermes' wildcard bucket
        for an arbitrary OpenAI-compatible ``base_url``, and the canonical
        form of the ``ollama`` local-endpoint alias). Letting an allowlist
        entry resolve to it would turn a narrow grant -- a user writing
        ``["ollama"]`` meaning "allow my local model" -- into permission for
        ANY custom cloud endpoint: a fail-open widening in a strict CLOUD
        allowlist. ``_read_policy_settings`` must drop ``"custom"`` from the
        resulting allowlist rather than admit it as a real provider grant.
        """
        from mordred_hermes._provider_identity import canonicalize_provider

        assert canonicalize_provider("ollama") == "custom"  # basis for this test
        assert canonicalize_provider("claude") == "anthropic"  # existing alias behaviour unaffected

        cfg = _write_policy_json(
            tmp_path,
            policy="strict",
            cloud_provider_allowlist=("ollama",),
        )

        settings = enforce._read_policy_settings(cfg)

        assert settings.cloud_allowlist == frozenset()
        assert "custom" not in settings.cloud_allowlist


# --------------------------------------------------------------------------- #
# check_runtime_provider — runtime hook enforcement (no probe, no allow audit)#
# --------------------------------------------------------------------------- #


class TestCheckRuntimeProvider:
    """Codex review P1 round 3: ``on_session_start`` only has access to
    disk-based provider state. Runtime overrides (CLI ``--provider``,
    ``HERMES_INFERENCE_PROVIDER``, oneshot / gateway switches) bypass that
    path, so a per-request check using the live ``pre_api_request.provider``
    kwarg is the authoritative enforcement point.

    Differences from ``check_session_provider``:

    1. **No local probe** — the runtime resolution already chose
       mordred-local; re-probing on every API call would be wasteful and
       could spam the audit on retries.
    2. **No allow audit** — fires on every API call, so the allow path
       stays silent. Block/refused entries still write to audit.
    3. **Degraded path stays silent** — without a runtime provider the
       call would already be malformed upstream; emitting again here
       would duplicate the on_session_start record.
    """

    def test_off_is_noop(self, tmp_path: Path) -> None:
        cfg = _write_policy_json(tmp_path, policy="off")
        audit = _FakeAuditWriter()
        enforce.check_runtime_provider(
            policy_mode="off",
            policy_json_path=cfg,
            active_provider="anthropic",
            audit=audit,
        )
        assert audit.entries == []

    def test_lenient_is_noop(self, tmp_path: Path) -> None:
        cfg = _write_policy_json(tmp_path, policy="lenient")
        audit = _FakeAuditWriter()
        enforce.check_runtime_provider(
            policy_mode="lenient",
            policy_json_path=cfg,
            active_provider="anthropic",
            audit=audit,
        )
        assert audit.entries == []

    def test_strict_local_probes_and_allows_silently(self, tmp_path: Path) -> None:
        """Codex review P2 round 4: ``on_session_start`` may not have
        probed (e.g. disk said ``openai`` but runtime is
        ``--provider mordred-local``), so the runtime hook must probe
        when it sees mordred-local. On success: silent allow (per-call
        hook, no audit spam).
        """
        cfg = _write_policy_json(tmp_path, policy="strict")
        audit = _FakeAuditWriter()
        probed: list[str] = []

        def _record(endpoint: str) -> None:
            probed.append(endpoint)

        enforce.check_runtime_provider(
            policy_mode="strict",
            policy_json_path=cfg,
            active_provider="mordred-local",
            audit=audit,
            health_probe=_record,
        )
        assert probed == ["http://localhost:1234/v1"]
        assert audit.entries == []

    def test_strict_local_probes_runtime_base_url_not_policy_json(self, tmp_path: Path) -> None:
        """Codex review P2 round 7: in long-lived processes the resolved
        provider profile can carry a stale ``base_url`` after a
        ``policy.json`` reconfigure. ``pre_api_request`` delivers the
        actual runtime ``base_url`` — probe THAT (so we validate where
        the request is really going), not the policy.json mirror.
        """
        # policy.json points at port 1234, but the runtime resolved to 8000.
        cfg = _write_policy_json(
            tmp_path,
            policy="strict",
            local_llm_endpoint="http://localhost:1234/v1",
        )
        audit = _FakeAuditWriter()
        probed: list[str] = []

        def _record(endpoint: str) -> None:
            probed.append(endpoint)

        enforce.check_runtime_provider(
            policy_mode="strict",
            policy_json_path=cfg,
            active_provider="mordred-local",
            audit=audit,
            health_probe=_record,
            runtime_base_url="http://localhost:8000/v1",
        )
        # The runtime base_url is what gets probed, not the policy.json
        # ``local_llm_endpoint`` mirror.
        assert probed == ["http://localhost:8000/v1"]

    def test_strict_local_falls_back_to_policy_json_when_base_url_missing(self, tmp_path: Path) -> None:
        """Defensive fallback: if the hook is invoked without a runtime
        ``base_url`` (synthetic test payloads, future hook payload
        changes), fall back to the policy.json mirror so we don't
        silently skip the probe.
        """
        cfg = _write_policy_json(
            tmp_path,
            policy="strict",
            local_llm_endpoint="http://localhost:1234/v1",
        )
        audit = _FakeAuditWriter()
        probed: list[str] = []

        def _record(endpoint: str) -> None:
            probed.append(endpoint)

        enforce.check_runtime_provider(
            policy_mode="strict",
            policy_json_path=cfg,
            active_provider="mordred-local",
            audit=audit,
            health_probe=_record,
            runtime_base_url=None,
        )
        assert probed == ["http://localhost:1234/v1"]

    def test_strict_local_refuses_on_probe_failure(self, tmp_path: Path) -> None:
        """Runtime override to mordred-local + unreachable endpoint → refuse.

        Mirrors the session_start behavior (``MordredSessionRefused`` with
        ``MordredLocalUnreachable`` chained as ``__cause__``).
        """
        cfg = _write_policy_json(tmp_path, policy="strict")
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused) as excinfo:
            enforce.check_runtime_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider="mordred-local",
                audit=audit,
                health_probe=_failing_probe,
            )
        assert isinstance(excinfo.value.__cause__, MordredLocalUnreachable)
        assert len(audit.entries) == 1
        assert audit.entries[0]["reason"] == "policy.strict.session_refused"
        assert audit.entries[0]["provider_id"] == "mordred-local"

    def test_strict_allowlisted_cloud_allows_silently(self, tmp_path: Path) -> None:
        """Allowlisted cloud + allow_cloud_llm=True → silent allow."""
        cfg = _write_policy_json(
            tmp_path,
            policy="strict",
            allow_cloud_llm=True,
            cloud_provider_allowlist=("anthropic",),
        )
        audit = _FakeAuditWriter()
        enforce.check_runtime_provider(
            policy_mode="strict",
            policy_json_path=cfg,
            active_provider="anthropic",
            audit=audit,
        )
        assert audit.entries == []

    def test_strict_non_allowlisted_cloud_refuses(self, tmp_path: Path) -> None:
        """This is the runtime-override hole Codex flagged: even if
        on_session_start saw mordred-local on disk, a CLI ``--provider
        openai`` override means pre_api_request fires with
        ``provider=openai``. Strict + openai-not-in-allowlist → refuse.
        """
        cfg = _write_policy_json(tmp_path, policy="strict")  # empty allowlist
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused):
            enforce.check_runtime_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider="openai",
                audit=audit,
            )

        reasons = [e["reason"] for e in audit.entries]
        assert "policy.strict.cloud_not_allowlisted" in reasons
        assert "policy.strict.session_refused" in reasons
        # Provider id is recorded in the audit even though the message
        # is templated on the ``allow_cloud_llm`` flag — consumers can
        # filter on provider regardless of which reason variant fired.
        assert all(e.get("provider_id") == "openai" for e in audit.entries)

    def test_strict_no_provider_refuses_degraded(self, tmp_path: Path) -> None:
        """Codex review P1 round 5: ``_on_session_start_enforce`` now
        only logs (doesn't raise) the degraded path, so if
        ``pre_api_request`` also accepted a missing provider silently
        the strict refuse-only contract would be violated. Runtime
        enforcement must refuse + audit when the resolved provider is
        absent — this is the authoritative degraded refusal point.
        """
        cfg = _write_policy_json(tmp_path, policy="strict")
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused):
            enforce.check_runtime_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider=None,
                audit=audit,
            )

        reasons = [e["reason"] for e in audit.entries]
        assert "mordred.degraded.no_resolved_provider" in reasons
        assert "policy.strict.unconditional_override" in reasons

    def test_audit_failure_does_not_swallow_refusal(self, tmp_path: Path) -> None:
        """Codex review P1 round 6: if ``audit.append(...)`` raises
        :class:`Exception` (e.g. disk full, broken NDJSON path) BEFORE
        we raise :class:`MordredSessionRefused`, Hermes' hook dispatch
        (``invoke_hook`` line 1112) catches the audit ``Exception`` and
        continues — the request would proceed un-refused. Audit writes
        must be best-effort so the ``BaseException`` refusal still
        propagates.
        """

        class _ExplodingAuditWriter:
            def append(self, entry: Mapping[str, Any]) -> None:
                raise RuntimeError("simulated audit log write failure")

        cfg = _write_policy_json(tmp_path, policy="strict")  # empty allowlist
        audit = _ExplodingAuditWriter()

        # Refusal MUST still escape even though every audit write blows up.
        with pytest.raises(MordredSessionRefused):
            enforce.check_runtime_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider="openai",
                audit=audit,
            )

    def test_strict_allowlist_is_case_insensitive(self, tmp_path: Path) -> None:
        """Codex review P2 round 5: allowlist entries from policy.json may
        be hand-edited with different casing/whitespace (``OpenAI``,
        `` anthropic ``). Runtime providers are normalized to lowercase
        before lookup, so the allowlist must be normalized the same way
        — otherwise valid configurations are silently refused.
        """
        cfg = _write_policy_json(
            tmp_path,
            policy="strict",
            allow_cloud_llm=True,
            cloud_provider_allowlist=("OpenAI", "  Anthropic  "),
        )
        audit = _FakeAuditWriter()

        # Both lookups must succeed despite the casing/whitespace mismatch.
        for provider in ("openai", "anthropic"):
            enforce.check_runtime_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider=provider,
                audit=audit,
            )

        # Allow paths stay silent in runtime check.
        assert audit.entries == []

    def test_strict_allowlist_resolves_aliases(self, tmp_path: Path) -> None:
        """A user-authored allowlist entry that is a Hermes *alias* (not the
        canonical slug) must still permit the canonicalized runtime provider.

        Verified finding: ``_read_policy_settings`` used to normalize
        allowlist entries with a bare ``.strip().lower()``, while the
        runtime provider id being compared against is normalized through
        the full alias table via ``canonicalize_provider()``
        (``__init__.py::_resolve_active_provider`` /
        ``_on_pre_api_request_enforce``). A hand-edited
        ``cloud_provider_allowlist: ["claude"]`` — ``"claude"`` is a real
        Hermes alias for ``"anthropic"`` — would therefore never match the
        canonicalized ``"anthropic"`` runtime id, and strict mode would
        refuse a provider the user clearly intended to allow. Without the
        fix (canonicalizing allowlist entries the same way) this test fails
        with ``MordredSessionRefused``.
        """
        cfg = _write_policy_json(
            tmp_path,
            policy="strict",
            allow_cloud_llm=True,
            cloud_provider_allowlist=("claude", "google", "aws"),
        )
        audit = _FakeAuditWriter()

        # "claude" / "google" / "aws" are aliases; the runtime provider id
        # arrives already canonicalized (mirroring
        # ``_on_pre_api_request_enforce``'s ``canonicalize_provider`` call).
        for provider in ("anthropic", "gemini", "bedrock"):
            enforce.check_runtime_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider=provider,
                audit=audit,
            )

        # Allow paths stay silent in runtime check.
        assert audit.entries == []


# --------------------------------------------------------------------------- #
# cloud_attempt_action reader — failure-closed coercion                       #
# --------------------------------------------------------------------------- #


class TestCloudAttemptActionReader:
    """``_read_policy_settings`` parses ``cloud_attempt_action`` from policy.json.

    Mirrors the ``allow_cloud_llm`` failure-closed coercion (``enforce.py``
    Codex P2): only the exact JSON string ``"prompt-once"`` selects the
    prompt path; everything else — missing, unknown, or non-string — falls
    back to the safe default ``"always-block"``.
    """

    def _settings(self, tmp_path: Path, value: object | None) -> Any:
        body: dict[str, Any] = {"policy": "strict"}
        if value is not None:
            body["cloud_attempt_action"] = value
        path = tmp_path / "policy.json"
        path.write_text(json.dumps(body), encoding="utf-8")
        return enforce._read_policy_settings(path)

    def test_prompt_once_is_parsed(self, tmp_path: Path) -> None:
        assert self._settings(tmp_path, "prompt-once").cloud_attempt_action == "prompt-once"

    def test_always_block_explicit(self, tmp_path: Path) -> None:
        assert self._settings(tmp_path, "always-block").cloud_attempt_action == "always-block"

    def test_missing_defaults_to_always_block(self, tmp_path: Path) -> None:
        assert self._settings(tmp_path, None).cloud_attempt_action == "always-block"

    def test_unknown_value_defaults_to_always_block(self, tmp_path: Path) -> None:
        assert self._settings(tmp_path, "ask-every-time").cloud_attempt_action == "always-block"

    def test_non_string_defaults_to_always_block(self, tmp_path: Path) -> None:
        assert self._settings(tmp_path, 123).cloud_attempt_action == "always-block"

    def test_missing_policy_json_defaults_to_always_block(self, tmp_path: Path) -> None:
        settings = enforce._read_policy_settings(tmp_path / "absent.json")
        assert settings.cloud_attempt_action == "always-block"
