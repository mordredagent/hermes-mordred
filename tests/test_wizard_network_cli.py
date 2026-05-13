"""Tests for ``hermes mordred network {use,status}`` (Phase 3 PR2-C).

Before PR2 these handlers were ``NotImplementedError`` stubs (see
``test_wizard_cli.py::TestStubHandlersDeferProperly``). PR2-C wires them
to the real surface:

- ``network use <path>``: writes ``plugins.mordred_network.default_path``
  into ``~/.hermes/config.yaml`` so the next session brings the path
  up at ``on_session_start``. If a runtime singleton is already
  registered in *this* process (rare for standalone ``hermes-mordred``
  invocations but normal inside ``hermes`` itself), also call
  :func:`api.use` so the switch takes effect immediately.
- ``network status``: prints in-process runtime status if available,
  else falls back to the configured-but-not-active disk state.

The first invocation backs the acceptance-gate sentence "Manual
``hermes mordred network use vpn`` switches path within 2s"
(TODO.md §3 acceptance gate). The cross-process persistence model is
documented inline; live in-session switching is the path that satisfies
"within 2s".
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.network._exceptions import BringupFailed, UnknownPath

# --------------------------------------------------------------------------- #
# Fakes                                                                       #
# --------------------------------------------------------------------------- #


class _FakeRuntime:
    def __init__(self) -> None:
        self.use_calls: list[str] = []
        self.use_raises: BaseException | None = None
        self._active_path: str = "clearnet"
        self._ready: bool = False
        self.dropped: bool = False

    def use(self, path: str) -> None:
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
        pass

    def is_dropped(self) -> bool:
        return self.dropped


# --------------------------------------------------------------------------- #
# Fixtures                                                                    #
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _reset_api() -> Any:
    from mordred_hermes.network import api

    api.reset_runtime_for_tests()
    yield
    api.reset_runtime_for_tests()


def _make_args(**fields: Any) -> argparse.Namespace:
    return argparse.Namespace(**fields)


# --------------------------------------------------------------------------- #
# network use                                                                 #
# --------------------------------------------------------------------------- #


class TestNetworkUseLive:
    """In-process runtime registered - api.use is called directly."""

    def test_use_tor_calls_api_use(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        from mordred_hermes.network import api
        from mordred_hermes.wizard import cli

        rt = _FakeRuntime()
        api.set_runtime(rt)
        args = _make_args(
            path="tor",
            config_path=tmp_path / "config.yaml",
        )
        rc = cli._handle_network_use(args)
        assert rc == 0
        assert rt.use_calls == ["tor"]
        out = capsys.readouterr().out
        assert "tor" in out.lower()

    def test_use_vpn_returns_zero(self, tmp_path: Path) -> None:
        from mordred_hermes.network import api
        from mordred_hermes.wizard import cli

        rt = _FakeRuntime()
        api.set_runtime(rt)
        args = _make_args(
            path="vpn",
            config_path=tmp_path / "config.yaml",
        )
        assert cli._handle_network_use(args) == 0
        assert rt.use_calls == ["vpn"]

    def test_use_unknown_path_returns_nonzero(self, tmp_path: Path) -> None:
        from mordred_hermes.network import api
        from mordred_hermes.wizard import cli

        rt = _FakeRuntime()
        rt.use_raises = UnknownPath("bad")
        api.set_runtime(rt)
        args = _make_args(
            path="i2p",
            config_path=tmp_path / "config.yaml",
        )
        rc = cli._handle_network_use(args)
        assert rc != 0

    def test_use_bringup_failure_returns_nonzero(self, tmp_path: Path) -> None:
        from mordred_hermes.network import api
        from mordred_hermes.wizard import cli

        rt = _FakeRuntime()
        rt.use_raises = BringupFailed("tor timeout")
        api.set_runtime(rt)
        args = _make_args(
            path="tor",
            config_path=tmp_path / "config.yaml",
        )
        rc = cli._handle_network_use(args)
        assert rc != 0


class TestNetworkUsePersistence:
    """``use`` always writes ``default_path`` to config.yaml so the next
    Hermes session opens with the user's preferred path."""

    def test_use_writes_default_path_to_config(self, tmp_path: Path) -> None:
        from mordred_hermes.network import api
        from mordred_hermes.wizard import cli

        rt = _FakeRuntime()
        api.set_runtime(rt)
        config = tmp_path / "config.yaml"
        args = _make_args(path="tor", config_path=config)
        cli._handle_network_use(args)

        from ruamel.yaml import YAML

        yaml = YAML(typ="safe", pure=True)
        with config.open(encoding="utf-8") as f:
            data = yaml.load(f)
        assert data["plugins"]["mordred_network"]["default_path"] == "tor"

    def test_use_preserves_other_plugin_sections(self, tmp_path: Path) -> None:
        from mordred_hermes.network import api
        from mordred_hermes.wizard import cli

        rt = _FakeRuntime()
        api.set_runtime(rt)
        config = tmp_path / "config.yaml"
        config.write_text(
            "plugins:\n  mordred_privacy_check:\n    policy: strict\n  mordred_llm_guard:\n    harness_primary: codex\n"
        )
        args = _make_args(path="tor", config_path=config)
        cli._handle_network_use(args)

        from ruamel.yaml import YAML

        yaml = YAML(typ="safe", pure=True)
        with config.open(encoding="utf-8") as f:
            data = yaml.load(f)
        assert data["plugins"]["mordred_privacy_check"]["policy"] == "strict"
        assert data["plugins"]["mordred_llm_guard"]["harness_primary"] == "codex"
        assert data["plugins"]["mordred_network"]["default_path"] == "tor"


class TestNetworkUseAtomicity:
    """H1 fix (review 2026-05-14): writes must use PolicyWriter so they
    inherit the canonical ``_atomic_write_text`` (tempfile + os.replace).

    Detection strategy: PolicyWriter's ``_ensure_plugins_enabled`` adds
    the full 5-Mordred-plugin list to ``plugins.enabled`` on every write
    (HOOK_PAYLOADS.md §1 / TODO.md §0.5 L128). A plain ``Path.write_text``
    would not produce that side effect. Asserting the side effect proves
    the write went through PolicyWriter and therefore got atomic-rename
    semantics — without us having to interrupt a write to test atomicity
    directly.
    """

    def test_use_writes_via_policy_writer_adding_plugins_enabled(self, tmp_path: Path) -> None:
        from mordred_hermes.network import api
        from mordred_hermes.wizard import cli

        rt = _FakeRuntime()
        api.set_runtime(rt)
        config = tmp_path / "config.yaml"
        args = _make_args(path="tor", config_path=config)
        cli._handle_network_use(args)

        from ruamel.yaml import YAML

        yaml = YAML(typ="safe", pure=True)
        with config.open(encoding="utf-8") as f:
            data = yaml.load(f)
        assert "enabled" in data["plugins"], (
            "PolicyWriter must add plugins.enabled — network_cli regressed to a non-atomic write path"
        )
        enabled = data["plugins"]["enabled"]
        # All 5 Mordred plugin names must be present (PolicyWriter contract).
        for name in (
            "mordred_privacy_check",
            "mordred_wizard",
            "mordred_llm_guard",
            "mordred_network",
            "mordred_keyvault",
        ):
            assert name in enabled, f"{name} missing from plugins.enabled after network_cli write"

    def test_use_does_not_leave_tmp_artifact(self, tmp_path: Path) -> None:
        """PolicyWriter's ``_atomic_write_text`` writes to ``<name>.tmp``
        and renames; a clean run must not leave the tempfile behind."""
        from mordred_hermes.network import api
        from mordred_hermes.wizard import cli

        rt = _FakeRuntime()
        api.set_runtime(rt)
        config = tmp_path / "config.yaml"
        args = _make_args(path="tor", config_path=config)
        cli._handle_network_use(args)
        tmp_artifact = config.with_name(config.name + ".tmp")
        assert not tmp_artifact.exists()


class TestNetworkUseStandalone:
    """No runtime registered - the CLI still writes to disk and reports
    the persistence-only effect to the user."""

    def test_no_runtime_writes_disk_only_and_returns_zero(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from mordred_hermes.wizard import cli

        config = tmp_path / "config.yaml"
        args = _make_args(path="tor", config_path=config)
        rc = cli._handle_network_use(args)
        assert rc == 0

        assert config.exists()
        out = capsys.readouterr().out
        assert "next session" in out.lower() or "deferred" in out.lower()


# --------------------------------------------------------------------------- #
# network status                                                              #
# --------------------------------------------------------------------------- #


class TestNetworkStatusLive:
    def test_active_runtime_prints_status(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        from mordred_hermes.network import api
        from mordred_hermes.wizard import cli

        rt = _FakeRuntime()
        rt._active_path = "tor"
        rt._ready = True
        api.set_runtime(rt)
        args = _make_args(config_path=tmp_path / "config.yaml")
        rc = cli._handle_network_status(args)
        assert rc == 0
        out = capsys.readouterr().out
        assert "tor" in out.lower()
        assert "ready" in out.lower()

    def test_status_includes_dropped_warning_when_flagged(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from mordred_hermes.network import api
        from mordred_hermes.wizard import cli

        rt = _FakeRuntime()
        rt._active_path = "tor"
        rt._ready = True
        rt.dropped = True
        api.set_runtime(rt)
        args = _make_args(config_path=tmp_path / "config.yaml")
        cli._handle_network_status(args)
        out = capsys.readouterr().out
        assert "drop" in out.lower()


class TestNetworkStatusStandalone:
    def test_no_runtime_falls_back_to_disk(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        from mordred_hermes.wizard import cli

        config = tmp_path / "config.yaml"
        config.write_text("plugins:\n  mordred_network:\n    default_path: vpn\n")
        args = _make_args(config_path=config)
        rc = cli._handle_network_status(args)
        assert rc == 0
        out = capsys.readouterr().out
        assert "vpn" in out.lower()
        assert "not active" in out.lower() or "configured" in out.lower()

    def test_no_runtime_no_config_falls_back_to_clearnet(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from mordred_hermes.wizard import cli

        args = _make_args(config_path=tmp_path / "missing.yaml")
        rc = cli._handle_network_status(args)
        assert rc == 0
        out = capsys.readouterr().out
        assert "clearnet" in out.lower()
