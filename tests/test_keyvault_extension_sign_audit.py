"""Tests for the extension-sign audit trail (``keyvault.extension_sign._audit_sink``).

Before this fix, ``_audit_sink`` only did ``_log.debug(...)`` — the
``keyvault.unwrap_authorized`` / ``keyvault.unwrap_denied`` events the wrap
layer emits through it for every extension-driven ``personal_sign`` /
``eth_signTypedData_v4`` / ``eth_sendTransaction`` (and their Secure-Enclave
authorizations) were silently dropped, leaving no durable, tamper-evident
forensic trail for fund-moving operations initiated by a remote DApp over the
gateway WebSocket. ``_audit_sink`` now also appends to the same
encryption-aware ``audit.log`` writer ``network`` / ``llm_guard`` /
``privacy_check`` use, memoized per-process exactly like those modules.

A revert to the old debug-only body fails :class:`TestAuditSinkAppendsEntry`
and :class:`TestSignHashWiresAuditSink` immediately (the fake writer never
sees an entry).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.keyvault import extension_sign
from mordred_hermes.keyvault.ethereum import EthereumSignature


class _FakeWriter:
    """Records every entry appended to it; mirrors the ``Writer`` protocol's
    ``append`` surface (``close`` unused by ``_audit_sink``)."""

    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    def append(self, entry: dict[str, Any]) -> None:
        self.entries.append(dict(entry))

    def close(self) -> None:  # pragma: no cover - not exercised by _audit_sink
        pass


class _RaisingWriter:
    """A writer whose ``append`` always raises — proves the sink is best-effort."""

    def append(self, entry: dict[str, Any]) -> None:
        raise RuntimeError("disk full")

    def close(self) -> None:  # pragma: no cover
        pass


@pytest.fixture(autouse=True)
def _clear_audit_writer_cache() -> None:
    """``_audit_writer`` is ``functools.lru_cache``d — clear it before/after
    every test so one test's monkeypatched writer never leaks into another via
    the cache (mirrors how ``network`` / ``llm_guard`` tests drive
    ``cache_clear()``)."""
    extension_sign._audit_writer.cache_clear()
    yield
    extension_sign._audit_writer.cache_clear()


class TestAuditLogPath:
    def test_resolves_under_hermes_home_mordred_audit_log(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        import hermes_constants

        monkeypatch.setattr(hermes_constants, "get_hermes_home", lambda: tmp_path)
        assert extension_sign._audit_log_path() == tmp_path / "mordred" / "audit.log"
        # keyvault_home = path.parent.parent contract build_audit_writer relies on:
        assert extension_sign._audit_log_path().parent.parent == tmp_path


class TestAuditWriterMemoization:
    def test_same_instance_across_calls(self, monkeypatch: pytest.MonkeyPatch) -> None:
        built: list[object] = []

        def _fake_build_audit_writer(path: Path) -> _FakeWriter:
            writer = _FakeWriter()
            built.append(writer)
            return writer

        monkeypatch.setattr("mordred_hermes._audit_support.build_audit_writer", _fake_build_audit_writer)

        first = extension_sign._audit_writer()
        second = extension_sign._audit_writer()

        assert first is second
        assert len(built) == 1  # constructed exactly once (per-process memoization)


class TestAuditSinkAppendsEntry:
    def test_entry_lands_on_the_writer_with_event_intact(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake_writer = _FakeWriter()
        monkeypatch.setattr(extension_sign, "_audit_writer", lambda: fake_writer)

        entry = {
            "event": "keyvault.unwrap_dek",
            "decision": "allow",
            "reason": "keyvault.unwrap_authorized",
            "key_id_hash": "deadbeef",
        }
        extension_sign._audit_sink(entry)

        assert len(fake_writer.entries) == 1
        assert fake_writer.entries[0]["event"] == "keyvault.unwrap_dek"
        assert fake_writer.entries[0]["reason"] == "keyvault.unwrap_authorized"
        assert fake_writer.entries[0]["key_id_hash"] == "deadbeef"

    def test_denied_event_also_lands(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake_writer = _FakeWriter()
        monkeypatch.setattr(extension_sign, "_audit_writer", lambda: fake_writer)

        extension_sign._audit_sink({"event": "keyvault.unwrap_dek", "reason": "keyvault.unwrap_denied"})

        assert fake_writer.entries[0]["reason"] == "keyvault.unwrap_denied"


class TestAuditSinkIsBestEffort:
    def test_raising_writer_does_not_propagate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(extension_sign, "_audit_writer", lambda: _RaisingWriter())

        # Must not raise: a signing operation cannot fail because the audit
        # write failed.
        extension_sign._audit_sink({"event": "keyvault.unwrap_dek", "reason": "keyvault.unwrap_authorized"})

    def test_writer_construction_failure_does_not_propagate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _boom() -> _FakeWriter:
            raise RuntimeError("cannot construct writer")

        monkeypatch.setattr(extension_sign, "_audit_writer", _boom)

        extension_sign._audit_sink({"event": "keyvault.unwrap_dek", "reason": "keyvault.unwrap_authorized"})


class TestSignHashWiresAuditSink:
    """Proves the sink is actually reachable from the signing entry points, not
    just correct in isolation: ``_sign_hash`` passes ``_audit_sink`` through to
    ``ethereum.sign_hash_hd`` as ``audit_sink=``, and an ``unwrap_authorized``
    event emitted from there reaches the memoized audit writer."""

    def test_unwrap_authorized_reaches_the_audit_writer(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake_writer = _FakeWriter()
        monkeypatch.setattr(extension_sign, "_audit_writer", lambda: fake_writer)
        monkeypatch.setattr(
            extension_sign,
            "_resolve_account",
            lambda: {
                "kind": "hd",
                "key_id": "default",
                "seed_envelope_id": "env-1",
                "index": 0,
                "account": 0,
                "change": 0,
            },
        )
        monkeypatch.setattr(extension_sign, "_backend", lambda: object())

        def _fake_sign_hash_hd(
            key_id: str,
            seed_envelope_id: str,
            index: int,
            message_hash: bytes,
            *,
            backend: Any,
            audit_sink: Any,
            account: int,
            change: int,
        ) -> EthereumSignature:
            audit_sink(
                {
                    "event": "keyvault.unwrap_dek",
                    "decision": "allow",
                    "reason": "keyvault.unwrap_authorized",
                    "key_id_hash": "abc123",
                }
            )
            return EthereumSignature(v=27, r=b"\x01" * 32, s=b"\x02" * 32)

        monkeypatch.setattr(extension_sign.ethereum, "sign_hash_hd", _fake_sign_hash_hd)

        extension_sign._sign_hash(b"\x00" * 32)

        assert len(fake_writer.entries) == 1
        assert fake_writer.entries[0]["reason"] == "keyvault.unwrap_authorized"
