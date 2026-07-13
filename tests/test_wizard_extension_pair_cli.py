"""Tests for ``hermes mordred extension pair``.

Since the #30 port, pairing-code generation is served by the plugin's own
``mordred_hermes.extension.pairing``; ``gateway.extension_pairing`` (the
Hermes-fork layout) remains only as a fallback for full-gateway checkouts
whose plugin copy predates the port. These tests pin that preference order,
the fail-closed contract when *neither* backend imports, the CLI's output
contract, and the real generate → consume → paired happy path against the
ported module.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
import types
from typing import Any

import pytest

import mordred_hermes.extension
from mordred_hermes.extension import pairing as ported_pairing
from mordred_hermes.extension.crypto import b64u_encode
from mordred_hermes.wizard import extension_pair_cli


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))


def _hide_ported_module(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make ``from mordred_hermes.extension import pairing`` raise ImportError.

    Both knobs are needed: deleting the package attribute defeats the
    from-import shortcut (the eager ``__init__`` already bound it), and the
    ``None`` sentinel makes the fresh submodule import fail.
    """
    monkeypatch.delattr(mordred_hermes.extension, "pairing")
    monkeypatch.setitem(sys.modules, "mordred_hermes.extension.pairing", None)


# --------------------------------------------------------------------------- #
# Backend selection
# --------------------------------------------------------------------------- #


def test_import_pairing_prefers_ported_module() -> None:
    assert extension_pair_cli._import_pairing() is ported_pairing


def test_import_pairing_falls_back_to_gateway(monkeypatch: pytest.MonkeyPatch) -> None:
    _hide_ported_module(monkeypatch)
    fake_pairing = types.SimpleNamespace(generate_code=lambda: ("MORT-X", 0.0))
    fake_gateway = types.SimpleNamespace(extension_pairing=fake_pairing)
    monkeypatch.setitem(sys.modules, "gateway", fake_gateway)
    monkeypatch.setitem(sys.modules, "gateway.extension_pairing", fake_pairing)

    assert extension_pair_cli._import_pairing() is fake_pairing


def test_extension_pair_fails_closed_without_any_backend(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _hide_ported_module(monkeypatch)
    monkeypatch.setitem(sys.modules, "gateway", None)
    monkeypatch.setitem(sys.modules, "gateway.extension_pairing", None)

    rc = extension_pair_cli.extension_pair(timeout=1.0)

    assert rc == 2
    err = capsys.readouterr().err
    assert "not available in this build" in err
    assert "extension` extra" in err


# --------------------------------------------------------------------------- #
# CLI output contract (backend faked via _import_pairing)
# --------------------------------------------------------------------------- #


def test_extension_pair_output_contract(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Legacy backend shape (code_consumed only, no pair_outcome) — also pins
    # the grace fallback: claimed with no recorded outcome still ends Paired.
    fake_pairing = types.SimpleNamespace(
        generate_code=lambda: ("MORT-TEST0000-TEST0000", time.time() + 5.0),
        code_consumed=lambda code: True,
    )
    monkeypatch.setattr(extension_pair_cli, "_import_pairing", lambda: fake_pairing)
    monkeypatch.setattr(extension_pair_cli, "_POLL_SECONDS", 0.01)
    monkeypatch.setattr(extension_pair_cli, "_RESULT_GRACE_SECONDS", 0.05)

    rc = extension_pair_cli.extension_pair(timeout=1.0)

    assert rc == 0
    captured = capsys.readouterr()
    out = captured.out
    # Output contract (UX review 2026-07-07): English, code shown exactly once,
    # success line carries the ok glyph (ASCII fallback off a non-UTF stream).
    assert "Mordred Extension pairing" in out
    assert out.count("MORT-TEST0000-TEST0000") == 1
    assert "Paired (" in out
    # Grace-fallback success is advisory-flagged (code review 2026-07-13): the
    # server never recorded an outcome, so the user gets a verify hint.
    assert "never recorded a pairing outcome" in captured.err


def test_extension_pair_reports_handshake_rejection(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A handshake that dies after claiming the code must NOT print Paired
    (the pre-fix behavior); the user gets the reason and a retry hint."""
    fake_pairing = types.SimpleNamespace(
        generate_code=lambda: ("MORT-TEST0000-TEST0000", time.time() + 60.0),
        pair_outcome=lambda code: ("failed", "invalid_pubkey"),
    )
    monkeypatch.setattr(extension_pair_cli, "_import_pairing", lambda: fake_pairing)
    monkeypatch.setattr(extension_pair_cli, "_POLL_SECONDS", 0.01)

    rc = extension_pair_cli.extension_pair(timeout=5.0)

    assert rc == 1
    captured = capsys.readouterr()
    assert "Paired" not in captured.out
    assert "invalid_pubkey" in captured.err
    assert "fresh code" in captured.err


def test_extension_pair_sanitizes_forged_fail_reason(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """fail_reason comes back from same-user-writable pending.json; control
    characters must be escaped before hitting the operator's terminal."""
    fake_pairing = types.SimpleNamespace(
        generate_code=lambda: ("MORT-TEST0000-TEST0000", time.time() + 60.0),
        pair_outcome=lambda code: ("failed", "bad\x1b[31mreason"),
    )
    monkeypatch.setattr(extension_pair_cli, "_import_pairing", lambda: fake_pairing)
    monkeypatch.setattr(extension_pair_cli, "_POLL_SECONDS", 0.01)

    rc = extension_pair_cli.extension_pair(timeout=5.0)

    assert rc == 1
    err = capsys.readouterr().err
    # capsys streams are not ttys, so _term emits no colour of its own: any
    # raw ESC byte here would have come from the forged reason.
    assert "\x1b" not in err
    assert "\\x1b[31m" in err  # escaped form is shown instead


def test_extension_pair_success_prints_next_step(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fake_pairing = types.SimpleNamespace(
        generate_code=lambda: ("MORT-TEST0000-TEST0000", time.time() + 60.0),
        pair_outcome=lambda code: ("paired", None),
    )
    monkeypatch.setattr(extension_pair_cli, "_import_pairing", lambda: fake_pairing)
    monkeypatch.setattr(extension_pair_cli, "_POLL_SECONDS", 0.01)

    rc = extension_pair_cli.extension_pair(timeout=5.0)

    assert rc == 0
    out = capsys.readouterr().out
    assert "Paired (" in out
    assert "extension serve" in out  # next-step hint


def test_extension_pair_expiry_warns_on_stderr(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fake_pairing = types.SimpleNamespace(
        generate_code=lambda: ("MORT-TEST0000-TEST0000", time.time() - 1.0),  # already expired
        code_consumed=lambda code: False,
    )
    monkeypatch.setattr(extension_pair_cli, "_import_pairing", lambda: fake_pairing)

    rc = extension_pair_cli.extension_pair(timeout=1.0)

    assert rc == 1
    err = capsys.readouterr().err
    # `note: QR display skipped …` may precede the warning when the optional
    # qrcode dep is absent, so match the line rather than the stream head.
    assert "warning:" in err
    assert "expired" in err
    assert "extension serve" in err


def test_cli_extension_pair_passes_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, float] = {}

    def _fake_extension_pair(*, timeout: float) -> int:
        seen["timeout"] = timeout
        return 0

    monkeypatch.setattr(extension_pair_cli, "extension_pair", _fake_extension_pair)

    rc = extension_pair_cli.cli_extension_pair(argparse.Namespace(timeout=42.0))

    assert rc == 0
    assert seen["timeout"] == 42.0


# --------------------------------------------------------------------------- #
# Real happy path against the ported backend
# --------------------------------------------------------------------------- #


def test_extension_pair_completes_against_ported_backend(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Full happy path: pair blocks, a 'browser extension' consumes the code
    via the real server-side handler, pair reports success."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    monkeypatch.setattr(extension_pair_cli, "_POLL_SECONDS", 0.02)
    pending = tmp_path / "extension" / "pending.json"
    ext_pub_b64 = b64u_encode(X25519PrivateKey.generate().public_key().public_bytes_raw())
    errors: list[BaseException] = []

    def _consume_when_visible() -> None:
        deadline = time.time() + 5
        try:
            while time.time() < deadline:
                entries: dict[str, Any] = json.loads(pending.read_text()) if pending.exists() else {}
                fresh = [c for c, e in entries.items() if not e.get("used")]
                if fresh:
                    ported_pairing.handle_pair_init(fresh[0], ext_pub_b64, b64u_encode(b"\x11" * 32))
                    return
                time.sleep(0.02)
            raise AssertionError("pair CLI never wrote a pending code")
        except BaseException as exc:  # surfaced by the main thread below
            errors.append(exc)

    consumer = threading.Thread(target=_consume_when_visible, daemon=True)
    consumer.start()
    rc = extension_pair_cli.extension_pair(timeout=10.0)
    consumer.join(timeout=5)

    # A still-alive consumer would outlive this test's HERMES_HOME monkeypatch
    # and write pairing state into the NEXT test's home — fail loudly here
    # instead of poisoning an unrelated test.
    assert not consumer.is_alive()
    assert not errors, errors
    assert rc == 0
    assert "Paired" in capsys.readouterr().out
