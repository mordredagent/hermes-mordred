"""Tests for ``hermes-mordred plugins list``.

The wizard exposes package entry-point discovery directly because the ordinary
Hermes plugin listing does not surface it.

Primary path: query :class:`hermes_cli.plugins.PluginManager` via
:func:`get_plugin_manager`. Fallback: read ``~/.hermes/config.yaml``
``plugins.enabled`` when the manager API is unavailable (older Hermes).
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.wizard import plugins_list


class _FakeManager:
    def __init__(self, plugins: list[dict[str, Any]]) -> None:
        self._plugins = plugins
        self.discover_calls = 0

    def discover_and_load(self, force: bool = False) -> None:
        self.discover_calls += 1

    def list_plugins(self) -> list[dict[str, Any]]:
        return list(self._plugins)


class TestRunFromManager:
    def test_filters_to_mordred_prefix(
        self,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mgr = _FakeManager(
            [
                {"key": "mordred_privacy_check", "enabled": True, "version": "0.1.0a0"},
                {"key": "mordred_network", "enabled": False, "version": "0.1.0a0"},
                {"key": "some_other_plugin", "enabled": True, "version": "1.0"},
            ]
        )
        monkeypatch.setattr(plugins_list, "_get_manager", lambda: mgr)

        rc = plugins_list.run()

        assert rc == 0
        assert mgr.discover_calls == 1
        out = capsys.readouterr().out
        assert "mordred_privacy_check" in out
        assert "mordred_network" in out
        assert "some_other_plugin" not in out

    def test_zero_mordred_plugins_returns_0_with_empty_message(
        self,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mgr = _FakeManager([{"key": "unrelated", "enabled": True, "version": "1.0"}])
        monkeypatch.setattr(plugins_list, "_get_manager", lambda: mgr)

        rc = plugins_list.run()

        assert rc == 0
        out = capsys.readouterr().out
        assert "no mordred plugins" in out.lower()

    def test_backfills_package_version_when_manager_omits_it(
        self,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Hermes' entry-point discovery returns an empty (or absent) version;
        # the wizard must backfill the hermes-mordred package version, not "?".
        from mordred_hermes.__about__ import __version__

        mgr = _FakeManager(
            [
                {"key": "mordred_keyvault", "enabled": True, "version": ""},
                {"key": "mordred_network", "enabled": True},  # no version key
            ]
        )
        monkeypatch.setattr(plugins_list, "_get_manager", lambda: mgr)

        rc = plugins_list.run()

        assert rc == 0
        out = capsys.readouterr().out
        assert "?" not in out
        assert out.count(__version__) == 2


class TestYAMLFallback:
    def test_falls_back_to_yaml_when_manager_unavailable(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        config = tmp_path / "config.yaml"
        config.write_text(
            "plugins:\n  enabled:\n    - mordred_privacy_check\n    - mordred_network\n    - other_plugin\n",
            encoding="utf-8",
        )

        def raise_import() -> Any:
            raise ImportError("hermes_cli.plugins not available")

        monkeypatch.setattr(plugins_list, "_get_manager", raise_import)

        rc = plugins_list.run(config_path=config)

        assert rc == 0
        out = capsys.readouterr().out
        assert "mordred_privacy_check" in out
        assert "mordred_network" in out
        assert "other_plugin" not in out
        # Fallback path should leave a breadcrumb so users notice degraded mode.
        assert "fallback" in out.lower() or "config.yaml" in out

    def test_fallback_shows_package_version_not_placeholder(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from mordred_hermes.__about__ import __version__

        config = tmp_path / "config.yaml"
        config.write_text(
            "plugins:\n  enabled:\n    - mordred_privacy_check\n",
            encoding="utf-8",
        )

        def raise_import() -> Any:
            raise ImportError("hermes_cli.plugins not available")

        monkeypatch.setattr(plugins_list, "_get_manager", raise_import)

        rc = plugins_list.run(config_path=config)

        assert rc == 0
        out = capsys.readouterr().out
        assert __version__ in out

    def test_fallback_with_missing_config_yaml_returns_0_with_message(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        config = tmp_path / "nonexistent.yaml"

        def raise_import() -> Any:
            raise ImportError("hermes_cli not available")

        monkeypatch.setattr(plugins_list, "_get_manager", raise_import)

        rc = plugins_list.run(config_path=config)

        assert rc == 0
        # Empty fallback should still say something useful.
        captured = capsys.readouterr()
        assert (
            "no mordred plugins" in captured.out.lower()
            or "no config" in captured.err.lower()
            or "no config" in captured.out.lower()
        )

    def test_reuses_shared_load_yaml_mapping_helper(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Dedup guard (Codex review): the fallback must delegate to the
        shared ``_yaml_io.load_yaml_mapping`` -- the same "read config.yaml
        as a mapping, or degrade to {}" core hand-rolled here that the helper
        was built to consolidate (its docstring names 5 other sites; this
        was the missed 6th)."""
        config = tmp_path / "config.yaml"
        config.write_text("plugins:\n  enabled:\n    - mordred_x\n", encoding="utf-8")
        calls: list[Path] = []
        original = plugins_list.load_yaml_mapping

        def spy(path: Path, **kwargs: Any) -> dict[str, Any]:
            calls.append(path)
            return original(path, **kwargs)

        monkeypatch.setattr(plugins_list, "load_yaml_mapping", spy)
        rc = plugins_list._print_from_yaml_fallback(config)
        assert rc == 0
        assert calls == [config], "fallback must call the shared load_yaml_mapping helper exactly once"

    def test_parse_failure_still_reports_error_via_emit_error(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A malformed config.yaml must still surface via ``_term.emit_error``
        with a "Failed to read ..." message, not silently collapse to "No
        Mordred plugins discovered". ``load_yaml_mapping``'s own default
        ``catch=(OSError, YAMLError)`` would swallow the parse failure into
        ``{}`` with only a *logger* warning (this call site wires no ``log=``
        to a visible destination) -- confirming the reporting survives the
        dedup onto the shared helper (finding: catch= semantics must be
        chosen to match this call site, not just defaulted)."""
        config = tmp_path / "config.yaml"
        config.write_text("plugins: [this is not, valid: yaml: at all\n", encoding="utf-8")

        def raise_import() -> Any:
            raise ImportError("hermes_cli.plugins not available")

        monkeypatch.setattr(plugins_list, "_get_manager", raise_import)

        rc = plugins_list.run(config_path=config)

        assert rc == 0
        captured = capsys.readouterr()
        assert "Failed to read" in captured.err
        assert "no mordred plugins" not in captured.out.lower()


class TestCLIHandler:
    def test_cli_handler_returns_run_rc(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mgr = _FakeManager([{"key": "mordred_x", "enabled": True, "version": "0.1"}])
        monkeypatch.setattr(plugins_list, "_get_manager", lambda: mgr)

        ns = argparse.Namespace()
        rc = plugins_list.cli_handler(ns)

        assert rc == 0
