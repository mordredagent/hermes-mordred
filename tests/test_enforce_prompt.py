"""Tests for ``check_runtime_provider`` prompt-once handling (cloud_attempt_action).

``prompt-once`` asks the operator once per provider whether to allow a
non-allowlisted cloud call under strict mode. The verdict is cached for the
process; an unavailable terminal fails closed to a block. Only the runtime
hook (:func:`enforce.check_runtime_provider`) prompts — the log-only
:func:`enforce.check_session_provider` disk pre-check never does.

Patterns mirror ``test_enforce.py``:

- ``_FakeAuditWriter`` captures audit appends for shape assertions.
- an autouse ``_reset_state`` fixture clears the module-level prompt cache
  between cases (mirrors the ``_no_resolved_provider_emitted`` reset contract).
- ``prompt_fn`` is injected like ``health_probe`` so no real TTY is touched.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.llm_guard import enforce
from mordred_hermes.llm_guard._exceptions import MordredSessionRefused


@pytest.fixture(autouse=True)
def _reset() -> Iterator[None]:
    enforce._reset_state()
    yield
    enforce._reset_state()


class _FakeAuditWriter:
    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    def append(self, entry: dict[str, Any]) -> None:
        self.entries.append(entry)


class _PromptSpy:
    """Records the providers it was asked about and returns a fixed verdict."""

    def __init__(self, verdict: bool | None) -> None:
        self.verdict = verdict
        self.calls: list[str] = []

    def __call__(self, provider_id: str) -> bool | None:
        self.calls.append(provider_id)
        return self.verdict


def _explode(_provider_id: str) -> bool | None:
    raise AssertionError("prompt_fn must not be called")


def _write_policy_json(
    tmp_path: Path,
    *,
    cloud_attempt_action: str = "prompt-once",
    allow_cloud_llm: bool = False,
    cloud_provider_allowlist: tuple[str, ...] = (),
) -> Path:
    body = {
        "policy": "strict",
        "allow_cloud_llm": allow_cloud_llm,
        "cloud_provider_allowlist": list(cloud_provider_allowlist),
        "cloud_attempt_action": cloud_attempt_action,
    }
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(body), encoding="utf-8")
    return path


class TestPromptAllow:
    def test_allow_passes_and_audits_once(self, tmp_path: Path) -> None:
        cfg = _write_policy_json(tmp_path)
        audit = _FakeAuditWriter()
        spy = _PromptSpy(True)

        enforce.check_runtime_provider(
            policy_mode="strict",
            policy_json_path=cfg,
            active_provider="openai",
            audit=audit,
            prompt_fn=spy,
        )

        assert spy.calls == ["openai"]
        assert len(audit.entries) == 1
        entry = audit.entries[0]
        assert entry["decision"] == "allow"
        assert entry["reason"] == "policy.strict.cloud_prompted_allow"
        assert entry["provider_id"] == "openai"

    def test_allow_is_cached_no_second_prompt(self, tmp_path: Path) -> None:
        cfg = _write_policy_json(tmp_path)
        audit = _FakeAuditWriter()
        spy = _PromptSpy(True)

        for _ in range(3):
            enforce.check_runtime_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider="openai",
                audit=audit,
                prompt_fn=spy,
            )

        assert spy.calls == ["openai"]  # asked exactly once
        assert len(audit.entries) == 1  # cached allows stay silent


class TestPromptDeny:
    def test_deny_refuses_and_audits_classification_then_action(self, tmp_path: Path) -> None:
        cfg = _write_policy_json(tmp_path)
        audit = _FakeAuditWriter()
        spy = _PromptSpy(False)

        with pytest.raises(MordredSessionRefused):
            enforce.check_runtime_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider="openai",
                audit=audit,
                prompt_fn=spy,
            )

        assert spy.calls == ["openai"]
        assert [e["reason"] for e in audit.entries] == [
            "policy.strict.cloud_prompted_deny",
            "policy.strict.cloud_not_allowlisted",
            "policy.strict.session_refused",
        ]
        assert audit.entries[0]["decision"] == "block"
        assert audit.entries[0]["provider_id"] == "openai"

    def test_deny_is_cached_no_second_prompt(self, tmp_path: Path) -> None:
        cfg = _write_policy_json(tmp_path)
        audit = _FakeAuditWriter()
        spy = _PromptSpy(False)

        for _ in range(2):
            with pytest.raises(MordredSessionRefused):
                enforce.check_runtime_provider(
                    policy_mode="strict",
                    policy_json_path=cfg,
                    active_provider="openai",
                    audit=audit,
                    prompt_fn=spy,
                )

        assert spy.calls == ["openai"]  # asked once; second call used the cache
        reasons = [e["reason"] for e in audit.entries]
        # prompted_deny audited once (decision time); refuse helper fires each call.
        assert reasons.count("policy.strict.cloud_prompted_deny") == 1
        assert reasons.count("policy.strict.session_refused") == 2


class TestPromptUnavailable:
    def test_no_terminal_fails_closed_and_is_not_cached(self, tmp_path: Path) -> None:
        cfg = _write_policy_json(tmp_path)
        audit = _FakeAuditWriter()
        unavailable = _PromptSpy(None)

        with pytest.raises(MordredSessionRefused):
            enforce.check_runtime_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider="openai",
                audit=audit,
                prompt_fn=unavailable,
            )

        deny = audit.entries[0]
        assert deny["reason"] == "policy.strict.cloud_prompted_deny"
        assert deny["prompt_unavailable"] is True

        # None must NOT be cached: a later call with a working terminal can ask.
        allow_spy = _PromptSpy(True)
        enforce.check_runtime_provider(
            policy_mode="strict",
            policy_json_path=cfg,
            active_provider="openai",
            audit=_FakeAuditWriter(),
            prompt_fn=allow_spy,
        )
        assert allow_spy.calls == ["openai"]


class TestPerProviderIsolation:
    def test_allow_one_provider_does_not_allow_another(self, tmp_path: Path) -> None:
        cfg = _write_policy_json(tmp_path)
        spy = _PromptSpy(True)

        enforce.check_runtime_provider(
            policy_mode="strict",
            policy_json_path=cfg,
            active_provider="openai",
            audit=_FakeAuditWriter(),
            prompt_fn=spy,
        )
        enforce.check_runtime_provider(
            policy_mode="strict",
            policy_json_path=cfg,
            active_provider="anthropic",
            audit=_FakeAuditWriter(),
            prompt_fn=spy,
        )
        assert spy.calls == ["openai", "anthropic"]


class TestAlwaysBlockUnchanged:
    def test_always_block_refuses_without_prompting(self, tmp_path: Path) -> None:
        cfg = _write_policy_json(tmp_path, cloud_attempt_action="always-block")
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused):
            enforce.check_runtime_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider="openai",
                audit=audit,
                prompt_fn=_explode,  # must not be called under always-block
            )

        reasons = [e["reason"] for e in audit.entries]
        assert "policy.strict.cloud_prompted_deny" not in reasons
        assert reasons == ["policy.strict.cloud_not_allowlisted", "policy.strict.session_refused"]

    def test_allowlisted_cloud_never_prompts(self, tmp_path: Path) -> None:
        cfg = _write_policy_json(
            tmp_path,
            allow_cloud_llm=True,
            cloud_provider_allowlist=("openai",),
        )
        audit = _FakeAuditWriter()

        enforce.check_runtime_provider(
            policy_mode="strict",
            policy_json_path=cfg,
            active_provider="openai",
            audit=audit,
            prompt_fn=_explode,  # allowlisted → never reaches the prompt branch
        )
        assert audit.entries == []


class TestDefaultPrompt:
    """Unit tests for the production ``_default_prompt`` TTY gate."""

    def _set_tty(self, monkeypatch: pytest.MonkeyPatch, *, stdin: bool, stdout: bool) -> None:
        monkeypatch.setattr(enforce.sys.stdin, "isatty", lambda: stdin)
        monkeypatch.setattr(enforce.sys.stdout, "isatty", lambda: stdout)

    def test_returns_none_when_stdin_not_tty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._set_tty(monkeypatch, stdin=False, stdout=True)
        assert enforce._default_prompt("openai") is None

    def test_returns_none_when_stdout_not_tty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._set_tty(monkeypatch, stdin=True, stdout=False)
        assert enforce._default_prompt("openai") is None

    def test_yes_allows(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._set_tty(monkeypatch, stdin=True, stdout=True)
        monkeypatch.setattr("builtins.input", lambda _prompt: "  Y ")
        assert enforce._default_prompt("openai") is True

    def test_blank_denies(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._set_tty(monkeypatch, stdin=True, stdout=True)
        monkeypatch.setattr("builtins.input", lambda _prompt: "")
        assert enforce._default_prompt("openai") is False

    def test_eof_fails_closed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._set_tty(monkeypatch, stdin=True, stdout=True)

        def _raise(_prompt: str) -> str:
            raise EOFError

        monkeypatch.setattr("builtins.input", _raise)
        assert enforce._default_prompt("openai") is None

    def test_keyboard_interrupt_fails_closed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._set_tty(monkeypatch, stdin=True, stdout=True)

        def _raise(_prompt: str) -> str:
            raise KeyboardInterrupt

        monkeypatch.setattr("builtins.input", _raise)
        assert enforce._default_prompt("openai") is None

    def test_closed_stdin_value_error_fails_closed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # input() raises ValueError ("I/O operation on closed file") when stdin
        # is a closed file object — a harness that closes fd 0 rather than
        # sending EOF. Must fail closed (None → block), not propagate (the
        # exception would be swallowed by Hermes' except Exception → fail-open).
        self._set_tty(monkeypatch, stdin=True, stdout=True)

        def _raise(_prompt: str) -> str:
            raise ValueError("I/O operation on closed file")

        monkeypatch.setattr("builtins.input", _raise)
        assert enforce._default_prompt("openai") is None
