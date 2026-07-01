"""Tests for ``hermes mordred extension pair``.

``gateway.extension_pairing`` is the Hermes-fork counterpart to this plugin's
``keyvault``/``wizard`` pieces; it isn't published alongside this standalone
repo yet (see ``docs/dev/ROADMAP.md`` §"Browser-extension gateway counterpart
(deferred)"). These tests pin the fail-closed contract in that state, and
that the happy path still runs once the module *is* importable.
"""

from __future__ import annotations

import argparse
import sys
import time
import types
from typing import Any

import pytest

from mordred_hermes.wizard import extension_pair_cli


def test_import_pairing_raises_when_gateway_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "gateway", None)
    monkeypatch.setitem(sys.modules, "gateway.extension_pairing", None)
    with pytest.raises(extension_pair_cli.ExtensionGatewayUnavailable, match="not available in this build"):
        extension_pair_cli._import_pairing()


def test_extension_pair_fails_closed_without_gateway(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setitem(sys.modules, "gateway", None)
    monkeypatch.setitem(sys.modules, "gateway.extension_pairing", None)

    rc = extension_pair_cli.extension_pair(timeout=1.0)

    assert rc == 2
    err = capsys.readouterr().err
    assert "not available in this build" in err


def test_extension_pair_uses_pairing_once_gateway_importable(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: dict[str, Any] = {"consumed": False}

    def _generate_code() -> tuple[str, float]:
        return "MORT-TEST0000-TEST0000", time.time() + 5.0

    def _code_consumed(code: str) -> bool:
        calls["consumed"] = True
        return True

    fake_pairing = types.SimpleNamespace(generate_code=_generate_code, code_consumed=_code_consumed)
    fake_gateway = types.SimpleNamespace(extension_pairing=fake_pairing)
    monkeypatch.setitem(sys.modules, "gateway", fake_gateway)
    monkeypatch.setitem(sys.modules, "gateway.extension_pairing", fake_pairing)

    rc = extension_pair_cli.extension_pair(timeout=1.0)

    assert rc == 0
    assert calls["consumed"] is True


def test_cli_extension_pair_passes_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, float] = {}

    def _fake_extension_pair(*, timeout: float) -> int:
        seen["timeout"] = timeout
        return 0

    monkeypatch.setattr(extension_pair_cli, "extension_pair", _fake_extension_pair)

    rc = extension_pair_cli.cli_extension_pair(argparse.Namespace(timeout=42.0))

    assert rc == 0
    assert seen["timeout"] == 42.0
