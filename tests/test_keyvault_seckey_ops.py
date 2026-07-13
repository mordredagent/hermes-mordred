"""Tests for ``mordred_hermes.keyvault._seckey_ops`` — the shared ``_ecdh`` helper.

LOW refactor finding: ``_PyobjcSecKeyOps.key_exchange`` (Secure-Enclave-
backed keys) and ``_SoftwareFallbackOps.key_exchange`` (software-backed
keys) used to duplicate the same ``SecKeyCreateWithData`` +
``SecKeyCopyKeyExchangeResult`` body byte-for-byte, differing only in how
the private-key ref was looked up. They now both delegate to the shared
module-level ``_ecdh`` helper.

These tests exercise ``_ecdh`` directly with a hand-rolled fake ``sec``
namespace (no pyobjc / real Security.framework needed, so they run on any
platform — real hardware key-exchange behavior is covered only by the live
integration test per the module's existing convention), and pin that both
``key_exchange`` methods still delegate to it with the exact private-key
ref their own lookup resolved, preserving the pre-refactor error-message
text via the ``variant`` parameter.
"""

from __future__ import annotations

from typing import Any

import pytest

from mordred_hermes.keyvault import _seckey_ops
from mordred_hermes.keyvault._seckey_errors import _OpsError

_PEER_PUB = b"\x04" + b"\x00" * 64  # shape doesn't matter — SecKeyCreateWithData is faked


class _FakeNSError:
    """Minimal stand-in for a pyobjc ``NSError`` (``.code()`` / ``.domain()``)."""

    def __init__(self, code: int, domain: str) -> None:
        self._code = code
        self._domain = domain

    def code(self) -> int:
        return self._code

    def domain(self) -> str:
        return self._domain


class _FakeSec:
    """Fake pyobjc ``Security`` namespace covering only what ``_ecdh`` touches."""

    kSecAttrKeyType = "kSecAttrKeyType"
    kSecAttrKeyTypeECSECPrimeRandom = "kSecAttrKeyTypeECSECPrimeRandom"
    kSecAttrKeyClass = "kSecAttrKeyClass"
    kSecAttrKeyClassPublic = "kSecAttrKeyClassPublic"
    kSecKeyAlgorithmECDHKeyExchangeStandard = "kSecKeyAlgorithmECDHKeyExchangeStandard"

    def __init__(
        self,
        *,
        peer_key: Any = "<peer-key>",
        peer_err: Any = None,
        shared: Any = b"shared-secret",
        shared_err: Any = None,
    ) -> None:
        self.peer_key = peer_key
        self.peer_err = peer_err
        self.shared = shared
        self.shared_err = shared_err
        self.calls: list[tuple[Any, ...]] = []

    def SecKeyCreateWithData(self, peer_pub: bytes, peer_attrs: dict[Any, Any], _error: Any) -> tuple[Any, Any]:
        self.calls.append(("SecKeyCreateWithData", peer_pub, peer_attrs))
        return self.peer_key, self.peer_err

    def SecKeyCopyKeyExchangeResult(
        self, private_key: Any, algorithm: Any, peer_key: Any, options: Any, _error: Any
    ) -> tuple[Any, Any]:
        self.calls.append(("SecKeyCopyKeyExchangeResult", private_key, algorithm, peer_key, options))
        return self.shared, self.shared_err


# ---------------------------------------------------------------------------
# _ecdh — happy path
# ---------------------------------------------------------------------------


def test_ecdh_returns_shared_secret_bytes() -> None:
    sec = _FakeSec(shared=b"the-shared-secret")
    result = _seckey_ops._ecdh(sec, "<resolved-priv-key>", _PEER_PUB)
    assert result == b"the-shared-secret"


def test_ecdh_passes_the_resolved_private_key_through_unchanged() -> None:
    """``_ecdh`` takes the ALREADY-RESOLVED private-key ref — it must never
    re-derive or replace it, only forward it to SecKeyCopyKeyExchangeResult."""
    sec = _FakeSec()
    _seckey_ops._ecdh(sec, "<my-private-key-ref>", _PEER_PUB)
    exchange_call = next(c for c in sec.calls if c[0] == "SecKeyCopyKeyExchangeResult")
    assert exchange_call[1] == "<my-private-key-ref>"


def test_ecdh_wraps_bytes_return_value() -> None:
    """``bytes(shared)`` — a pyobjc-returned buffer-like object must be
    coerced to a real ``bytes`` object, not passed through as-is."""

    class _BufferLike:
        def __init__(self, data: bytes) -> None:
            self._data = data

        def __bytes__(self) -> bytes:
            return self._data

        def __iter__(self) -> Any:
            return iter(self._data)

        def __len__(self) -> int:
            return len(self._data)

    sec = _FakeSec(shared=_BufferLike(b"\x01\x02\x03"))
    result = _seckey_ops._ecdh(sec, "<priv>", _PEER_PUB)
    assert result == b"\x01\x02\x03"
    assert isinstance(result, bytes)


# ---------------------------------------------------------------------------
# _ecdh — error mapping (must match the pre-refactor behavior exactly)
# ---------------------------------------------------------------------------


def test_ecdh_peer_key_creation_failure_raises_opserror() -> None:
    err = _FakeNSError(-1, "OSStatus")
    sec = _FakeSec(peer_key=None, peer_err=err)
    with pytest.raises(_OpsError) as excinfo:
        _seckey_ops._ecdh(sec, "<priv>", _PEER_PUB)
    assert "SecKeyCreateWithData(peer) failed" in str(excinfo.value)
    assert excinfo.value.status == -1
    assert excinfo.value.domain == "OSStatus"


def test_ecdh_shared_result_failure_default_variant_matches_pyobjc_message() -> None:
    """Default ``variant=""`` reproduces the exact pre-refactor
    ``_PyobjcSecKeyOps`` error text: ``"SecKeyCopyKeyExchangeResult failed"``
    with no ``(software)`` suffix."""
    err = _FakeNSError(-2, "OSStatus")
    sec = _FakeSec(shared=None, shared_err=err)
    with pytest.raises(_OpsError) as excinfo:
        _seckey_ops._ecdh(sec, "<priv>", _PEER_PUB)
    message = str(excinfo.value)
    assert "SecKeyCopyKeyExchangeResult failed" in message
    assert "(software)" not in message


def test_ecdh_shared_result_failure_software_variant_matches_software_message() -> None:
    """``variant=" (software)"`` reproduces the exact pre-refactor
    ``_SoftwareFallbackOps`` error text: ``"SecKeyCopyKeyExchangeResult
    (software) failed"``."""
    err = _FakeNSError(-2, "OSStatus")
    sec = _FakeSec(shared=None, shared_err=err)
    with pytest.raises(_OpsError) as excinfo:
        _seckey_ops._ecdh(sec, "<priv>", _PEER_PUB, variant=" (software)")
    assert "SecKeyCopyKeyExchangeResult (software) failed" in str(excinfo.value)


# ---------------------------------------------------------------------------
# key_exchange wiring — both callers must delegate to the shared _ecdh
# ---------------------------------------------------------------------------


def test_pyobjc_key_exchange_delegates_to_shared_ecdh_with_default_variant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[Any, Any, str]] = []

    def fake_lookup(_sec: Any, tag: bytes) -> Any:
        assert tag == b"enclave-tag"
        return "<enclave-priv-key>"

    def fake_ecdh(_sec: Any, private_key: Any, peer_pub: bytes, *, variant: str = "") -> bytes:
        calls.append((private_key, peer_pub, variant))
        return b"result"

    monkeypatch.setattr(_seckey_ops, "_lookup_private_key", fake_lookup)
    monkeypatch.setattr(_seckey_ops, "_ecdh", fake_ecdh)
    monkeypatch.setattr(_seckey_ops._PyobjcSecKeyOps, "_security", lambda self: "<fake-sec>")

    ops = _seckey_ops._PyobjcSecKeyOps()
    result = ops.key_exchange(b"enclave-tag", _PEER_PUB)

    assert result == b"result"
    # The hardware path must use the DEFAULT variant ("") — its error text
    # is "SecKeyCopyKeyExchangeResult failed", no suffix.
    assert calls == [("<enclave-priv-key>", _PEER_PUB, "")]


def test_software_key_exchange_delegates_to_shared_ecdh_with_software_variant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[Any, Any, str]] = []

    def fake_sw_lookup(_sec: Any, tag: bytes) -> Any:
        assert tag == b"software-tag"
        return "<software-priv-key>"

    def fake_ecdh(_sec: Any, private_key: Any, peer_pub: bytes, *, variant: str = "") -> bytes:
        calls.append((private_key, peer_pub, variant))
        return b"result"

    monkeypatch.setattr(_seckey_ops, "_sw_lookup_private_key", fake_sw_lookup)
    monkeypatch.setattr(_seckey_ops, "_ecdh", fake_ecdh)
    monkeypatch.setattr(_seckey_ops._SoftwareFallbackOps, "_security", lambda self: "<fake-sec>")

    ops = _seckey_ops._SoftwareFallbackOps()
    result = ops.key_exchange(b"software-tag", _PEER_PUB)

    assert result == b"result"
    # The software path must pass variant=" (software)" so its error text
    # stays "SecKeyCopyKeyExchangeResult (software) failed".
    assert calls == [("<software-priv-key>", _PEER_PUB, " (software)")]
