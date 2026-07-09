"""Encrypted-at-rest conversation history: persists across loads, decrypts with
the shared key, and projects to viewer turns."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from mordred_hermes.extension import extension_crypto as xc
from mordred_hermes.extension import extension_history, extension_pairing


@pytest.fixture(autouse=True)
def _paired_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    # Establish a pairing so a shared key exists for history encryption.
    code, _ = extension_pairing.generate_code()
    ext_pub = xc.b64u_encode(xc.x25519_public_raw(X25519PrivateKey.generate()))
    extension_pairing.handle_pair_init(code, ext_pub, xc.b64u_encode(b"\x00" * 32))


def test_history_roundtrip_and_persistence():
    msgs = [
        {"role": "user", "content": "hello"},
        {"role": "assistant", "content": "hi there"},
    ]
    extension_history.save_messages(msgs)
    assert extension_history.load_messages() == msgs
    # Reload (simulating a restart) — still there, not wiped.
    assert extension_history.load_messages() == msgs


def test_history_encrypted_at_rest(tmp_path):
    extension_history.save_messages([{"role": "user", "content": "secret-text"}])
    blob = (tmp_path / "extension" / "history.enc").read_text("utf-8")
    assert blob.startswith(xc.ENC_PREFIX)
    assert "secret-text" not in blob  # not stored in plaintext


def test_projection_extracts_text():
    extension_history.save_messages(
        [
            {"role": "user", "content": "q"},
            {"role": "assistant", "content": [{"type": "text", "text": "answer"}]},
            {"role": "tool", "content": "ignored"},
        ]
    )
    turns = extension_history.projected_turns()
    assert turns == [{"role": "user", "content": "q"}, {"role": "assistant", "content": "answer"}]


def test_clear():
    extension_history.save_messages([{"role": "user", "content": "x"}])
    extension_history.clear()
    assert extension_history.load_messages() == []
