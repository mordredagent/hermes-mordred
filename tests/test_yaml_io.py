"""Unit tests for the shared YAML mapping loader.

Covers every branch of :func:`mordred_hermes._yaml_io.load_yaml_mapping`,
including the two failure-handling knobs the migration relies on: the
parametrized ``catch`` set and the optional ``log``.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from mordred_hermes._yaml_io import load_yaml_mapping


def test_missing_file_returns_empty(tmp_path: Path) -> None:
    assert load_yaml_mapping(tmp_path / "absent.yaml") == {}


def test_loads_top_level_mapping(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(
        "plugins:\n  mordred_network:\n    default_path: tor\n",
        encoding="utf-8",
    )
    assert load_yaml_mapping(path) == {"plugins": {"mordred_network": {"default_path": "tor"}}}


def test_non_mapping_top_level_returns_empty(tmp_path: Path) -> None:
    path = tmp_path / "list.yaml"
    path.write_text("- one\n- two\n", encoding="utf-8")
    assert load_yaml_mapping(path) == {}


def test_malformed_yaml_is_swallowed_and_logged(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("plugins: [unterminated\n", encoding="utf-8")
    logger = logging.getLogger("test.yaml_io")
    with caplog.at_level(logging.WARNING, logger="test.yaml_io"):
        assert load_yaml_mapping(path, log=logger) == {}
    assert "could not read" in caplog.text


def test_default_catch_lets_non_yaml_errors_escape(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("ok: 1\n", encoding="utf-8")
    from ruamel.yaml import YAML

    def _boom(self: YAML, stream: object) -> object:
        raise RuntimeError("boom")

    monkeypatch.setattr(YAML, "load", _boom)
    # The default narrow catch is (OSError, YAMLError); a RuntimeError must propagate.
    with pytest.raises(RuntimeError):
        load_yaml_mapping(path)


def test_broad_catch_swallows_any_exception(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("ok: 1\n", encoding="utf-8")
    from ruamel.yaml import YAML

    def _boom(self: YAML, stream: object) -> object:
        raise RuntimeError("boom")

    monkeypatch.setattr(YAML, "load", _boom)
    # catch=(Exception,) widens the net (and log=None exercises the no-logger path).
    assert load_yaml_mapping(path, catch=(Exception,)) == {}
