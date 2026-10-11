"""Tests for the ``.env`` write-side guard (:mod:`mordred_hermes.keyvault._env_write_guard`).

The guard wraps the host ``.env`` writer (``hermes_cli.config.save_env_value``) so
a write made while the env target is *sealed* is resealed back into the vault
instead of leaving a partial plaintext at rest. These tests exercise the *wiring*
— wrap / idempotency / fail-open / early-bound rebind — with injected fakes; the
merge correctness of ``reseal`` itself lives in ``test_wizard_env_decrypt_cli.py``.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from mordred_hermes.keyvault import _env_write_guard


def _fake_config(calls: list[str]) -> SimpleNamespace:
    """A stand-in for ``hermes_cli.config`` with a recording ``save_env_value``."""

    def save_env_value(key: str, value: str) -> str:
        calls.append(f"{key}={value}")
        return "host-result"

    return SimpleNamespace(save_env_value=save_env_value)


class TestInstall:
    def test_noop_off_darwin(self) -> None:
        cfg = _fake_config([])
        assert _env_write_guard.install_env_write_guard(config_module=cfg, platform="linux") is False

    def test_noop_when_writer_missing(self) -> None:
        cfg = SimpleNamespace()  # no save_env_value attribute at all
        assert _env_write_guard.install_env_write_guard(config_module=cfg, platform="darwin") is False

    def test_wraps_and_reseals_after_write(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list[str] = []
        cfg = _fake_config(calls)
        original = cfg.save_env_value
        early = SimpleNamespace(save_env_value=original)
        monkeypatch.setitem(sys.modules, "hermes_cli._fake_early_binder", early)

        installed = _env_write_guard.install_env_write_guard(
            config_module=cfg, platform="darwin", reconcile=lambda: calls.append("reseal")
        )
        assert installed is True

        wrapped = cfg.save_env_value
        assert _env_write_guard.install_env_write_guard(config_module=cfg, platform="darwin")
        assert cfg.save_env_value is wrapped
        assert early.save_env_value is wrapped and wrapped is not original

        result = early.save_env_value("ANTHROPIC_API_KEY", "sk-x")
        assert result == "host-result"  # the host return value is preserved
        assert calls == ["ANTHROPIC_API_KEY=sk-x", "reseal"]  # exactly once, after the write

    def test_never_raises_into_host(self) -> None:
        calls: list[str] = []
        cfg = _fake_config(calls)

        def boom() -> None:
            raise RuntimeError("vault locked")

        _env_write_guard.install_env_write_guard(config_module=cfg, platform="darwin", reconcile=boom)
        # A failing reconcile must NOT turn a successful config write into an error.
        assert cfg.save_env_value("K", "v") == "host-result"
        assert calls == ["K=v"]
