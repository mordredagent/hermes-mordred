"""Live Secure-Enclave integration test for the production ``_SecKeyBackend``.

Gated by ``MORDRED_KEYVAULT_LIVE=1``. Skipped by default so CI and a
plain ``pytest -q`` stay hermetic — CI cannot satisfy the Touch ID /
passcode prompt that ``unwrap_dek`` triggers (SPEC.md review HIGH-4), so
this exercises the real ``Security.framework`` path only on a developer
Mac with a Secure Enclave (Apple Silicon or T2 Intel).

Run manually:

.. code-block:: bash

   MORDRED_KEYVAULT_LIVE=1 pytest tests/integration/test_keyvault_macos.py -v

Approve the biometric prompt when it appears during ``unwrap_dek``.

SPEC.md review HIGH-5: when the gate is ON we do NOT silently skip on a
missing Enclave — that would let a regression that breaks capability
detection pass unnoticed. We ``pytest.fail`` instead.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

from mordred_hermes.keyvault import native, wrap
from mordred_hermes.keyvault._exceptions import WrapKeyNotFound
from mordred_hermes.keyvault._seckey_backend import _SecKeyBackend

_LIVE_GATE_ENV = "MORDRED_KEYVAULT_LIVE"


def _require_live_enclave() -> None:
    """Skip when the gate is off; fail (not skip) when on but unusable."""
    if os.environ.get(_LIVE_GATE_ENV) != "1":
        pytest.skip(f"set {_LIVE_GATE_ENV}=1 to run live Secure Enclave integration tests")
    if sys.platform != "darwin":
        pytest.fail(f"{_LIVE_GATE_ENV}=1 but platform is {sys.platform!r}; run on macOS with a Secure Enclave")
    if not native.is_secure_enclave_available():
        pytest.fail(
            f"{_LIVE_GATE_ENV}=1 but is_secure_enclave_available() is False — "
            "Secure Enclave unreachable (no SEP, locked, or pyobjc missing). "
            "Install with `pip install mordred-hermes[macos]` on Enclave-capable hardware."
        )


@pytest.fixture
def live_key_id() -> str:
    """A per-run unique key_id so repeated runs never collide in the
    Keychain. Cleanup happens in the test's ``finally`` block."""
    return f"mordred-itest-{time.time_ns()}"


def test_capability_probe_reports_true_on_enclave_hardware() -> None:
    """``is_secure_enclave_available`` runs a real generate-then-delete
    probe (``.privateKeyUsage`` only — no prompt)."""
    _require_live_enclave()
    assert native.is_secure_enclave_available() is True


def test_signed_helper_is_selected_when_present() -> None:
    """When the signed ``mordred-hermes-sekey`` helper is installed, the
    default backend ops must route through it (not the in-process pyobjc
    path). This guards the discovery + wiring so the round-trip tests below
    are actually exercising the helper. Skipped when the helper is absent.
    """
    _require_live_enclave()

    from mordred_hermes.keyvault import _seckey_backend, _seckey_helper

    if _seckey_helper._find_helper() is None:
        pytest.skip(
            "signed helper not installed; build it via "
            "native/sekey-helper/build.sh or set MORDRED_SEKEY_HELPER"
        )
    assert isinstance(_seckey_backend._default_ops(), _seckey_helper._HelperSecKeyOps)


def test_generate_wrap_unwrap_roundtrip_through_real_enclave(live_key_id: str) -> None:
    """Full Tier-1 protection path: generate an Enclave wrapping key,
    wrap a DEK offline, then unwrap it through the authorization
    boundary. The unwrap step triggers a biometric / passcode prompt —
    approve it.
    """
    _require_live_enclave()
    backend = _SecKeyBackend()
    audit: list[dict[str, object]] = []
    dek = bytes(range(32))

    try:
        public_key = wrap.generate_wrapping_key(live_key_id, backend=backend)
        assert len(public_key) == 65 and public_key[0] == 0x04

        # Public-key lookup is unprivileged — no prompt, must round-trip.
        assert wrap.get_wrapping_key_public(live_key_id, backend=backend) == public_key

        blob = wrap.wrap_dek(dek, live_key_id, backend=backend)
        assert len(blob) == wrap.HEADER_LEN

        # Authorization boundary — approve the prompt.
        recovered = wrap.unwrap_dek(blob, live_key_id, audit_sink=audit.append, backend=backend)
        assert recovered == dek
        assert audit and audit[-1]["reason"] == "keyvault.unwrap_authorized"
    finally:
        wrap.delete_wrapping_key(live_key_id, backend=backend)

    # After deletion the key is gone — public lookup must fail.
    with pytest.raises(WrapKeyNotFound):
        wrap.get_wrapping_key_public(live_key_id, backend=backend)


def test_delete_is_idempotent_on_real_keychain(live_key_id: str) -> None:
    """Deleting a never-generated key is a contractual no-op."""
    _require_live_enclave()
    backend = _SecKeyBackend()
    backend.delete_enclave_key(live_key_id)  # must not raise


def test_encrypt_decrypt_roundtrip_through_real_enclave(live_key_id: str, tmp_path: Path) -> None:
    """L453: ``api.encrypt`` / ``api.decrypt`` AES-GCM roundtrip with the
    per-envelope DEK wrapped and unwrapped through real Secure Enclave
    authorization. The ``decrypt`` step triggers a biometric / passcode
    prompt — approve it.
    """
    _require_live_enclave()
    from mordred_hermes.keyvault import api

    backend = _SecKeyBackend()
    audit: list[dict[str, object]] = []
    seed = "test seed phrase one two three four"
    passphrase = "correct horse battery staple"
    pow_bytes = bytes(range(32))
    secret = b"the-protected-secret-payload"

    try:
        _handle, expected_digest = api.prepare_generate(seed, passphrase, pow_bytes)
        api.generate(
            seed,
            passphrase,
            pow_bytes,
            expected_digest,
            key_id=live_key_id,
            backend=backend,
            audit_sink=audit.append,
            home=tmp_path,
        )
        envelope_id = api.encrypt(live_key_id, secret, "itest", backend=backend, audit_sink=audit.append, home=tmp_path)
        # Authorization boundary — approve the prompt.
        recovered = api.decrypt(
            live_key_id, envelope_id, "itest", backend=backend, audit_sink=audit.append, home=tmp_path
        )
        assert recovered == secret
        assert any(e.get("reason") == "keyvault.unwrap_authorized" for e in audit)
    finally:
        wrap.delete_wrapping_key(live_key_id, backend=backend)
