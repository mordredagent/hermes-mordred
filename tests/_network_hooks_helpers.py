"""Shared fakes, file writers, and fixtures for network-hook tests."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.network._exceptions import (
    PathSwitchRequiresRestart,
)

# Re-exported so `test_network_hooks_registration.py` / `test_network_hooks_config.py`
# can keep importing `_FakeCtx` from this module under its old name.
from ._helpers import FakePluginContext as _FakeCtx  # noqa: F401

# --------------------------------------------------------------------------- #
# Fakes                                                                       #
# --------------------------------------------------------------------------- #


class _FakeAudit:
    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    def append(self, entry: Mapping[str, Any]) -> None:
        self.entries.append(dict(entry))


class _FakeRuntime:
    """Fake satisfying the runtime surface the hooks layer touches."""

    def __init__(self) -> None:
        self.use_calls: list[str] = []
        self.use_raises: BaseException | None = None
        self.stop_called: bool = False
        self.dropped: bool = False
        self._active_path: str = "clearnet"
        self._ready: bool = False
        self.isolation_token: str | None = None
        self.isolation_token_calls: list[str | None] = []
        self.process_route_frozen = False
        self.frozen_requested_path: str | None = None
        self.frozen_route_config: Any = None
        self.activation_config_fingerprint: Any = None

    def use(self, path: str) -> None:
        if self._ready and self._active_path == path:
            return
        self.use_calls.append(path)
        if self.use_raises is not None:
            raise self.use_raises
        self._active_path = path
        self._ready = True

    def status(self) -> Any:
        from mordred_hermes.network.api import NetworkStatus

        return NetworkStatus(
            active_path=self._active_path,
            ready=self._ready,
            last_health=True,
        )

    def health(self) -> bool:
        return True

    def stop(self) -> None:
        self.stop_called = True
        self._ready = False

    def is_dropped(self) -> bool:
        return self.dropped

    def update_policy_mode(self, policy_mode: str) -> None:
        # Codex r9-P1-B (2026-05-14): hooks.on_session_start now pushes
        # disk policy into the runtime before api.use. The fake records
        # the value so tests can assert propagation.
        self.policy_mode = policy_mode

    def set_isolation_token(self, token: str | None) -> None:
        self.isolation_token_calls.append(token)
        self.isolation_token = token

    def freeze_process_route(self, *, expected_path: str | None = None) -> None:
        self.process_route_frozen = True
        self.frozen_requested_path = expected_path or self._active_path
        self.frozen_route_config = self.activation_config_fingerprint

    def activate_and_freeze(self, path: str) -> None:
        self.use(path)
        self.freeze_process_route(expected_path=path)

    def assert_route_config(self, config: Any) -> None:
        if self.frozen_route_config is None:
            return
        from mordred_hermes.network.runtime import route_config_fingerprint

        if route_config_fingerprint(config) != self.frozen_route_config:
            raise PathSwitchRequiresRestart("activation configuration changed; restart Hermes")


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #


def _write_policy(
    tmp_path: Path,
    policy_mode: str = "off",
    *,
    disable_ipv6: bool | None = None,
    provider_overrides: Any | None = None,
) -> Path:
    p = tmp_path / "policy.json"
    payload: dict[str, Any] = {"policy": policy_mode}
    if disable_ipv6 is not None:
        payload["disable_ipv6"] = disable_ipv6
    if provider_overrides is not None:
        payload["provider_overrides"] = provider_overrides
    p.write_text(json.dumps(payload))
    return p


def _write_config(tmp_path: Path, default_path: str = "clearnet") -> Path:
    p = tmp_path / "config.yaml"
    p.write_text(f"plugins:\n  mordred_network:\n    default_path: {default_path}\n")
    return p


def _write_config_with_network_fields(
    tmp_path: Path,
    default_path: str,
    **fields: Any,
) -> Path:
    p = tmp_path / "config.yaml"
    lines = [
        "plugins:",
        "  mordred_network:",
        f"    default_path: {default_path}",
        *(f"    {key}: {json.dumps(value)}" for key, value in fields.items()),
    ]
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def _write_config_with_provider(tmp_path: Path, default_path: str, provider: str) -> Path:
    """config.yaml carrying both the network default_path and a
    ``model.provider`` (the transport gate resolves the provider from there)."""
    p = tmp_path / "config.yaml"
    p.write_text(f"plugins:\n  mordred_network:\n    default_path: {default_path}\nmodel:\n  provider: {provider}\n")
    return p


@pytest.fixture
def _reset_api() -> Any:
    """Make sure the global api runtime is empty before each test."""
    from mordred_hermes.network import api

    api.reset_runtime_for_tests()
    yield
    api.stop()
    api.reset_runtime_for_tests()


@pytest.fixture
def _skip_process_route_activation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Config-reader tests should not start real Tor/VPN subprocesses."""
    monkeypatch.setattr(
        "mordred_hermes.network._activate_process_route",
        lambda **_kwargs: None,
    )
