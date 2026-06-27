"""Unit tests for the shared policy.json mapping loader.

Covers every branch of :func:`mordred_hermes._policy_io.load_policy_mapping`:
missing file, a valid top-level object, a non-object root, a JSON parse
error (logged), and an ``OSError`` on open (the no-logger path).
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from mordred_hermes._policy_io import load_policy_mapping


def test_missing_file_returns_empty(tmp_path: Path) -> None:
    assert load_policy_mapping(tmp_path / "absent.json") == {}


def test_loads_top_level_mapping(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    path.write_text('{"policy": "strict", "allow_cloud_llm": false}', encoding="utf-8")
    assert load_policy_mapping(path) == {"policy": "strict", "allow_cloud_llm": False}


def test_non_mapping_top_level_returns_empty(tmp_path: Path) -> None:
    path = tmp_path / "list.json"
    path.write_text('["strict", "off"]', encoding="utf-8")
    assert load_policy_mapping(path) == {}


def test_malformed_json_is_swallowed_and_logged(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    path = tmp_path / "bad.json"
    path.write_text('{"policy": unquoted}', encoding="utf-8")
    logger = logging.getLogger("test.policy_io")
    with caplog.at_level(logging.WARNING, logger="test.policy_io"):
        assert load_policy_mapping(path, log=logger) == {}
    assert "could not read" in caplog.text


def test_oserror_is_swallowed_without_logger(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    # A directory ``exists()`` but opening it raises IsADirectoryError (an
    # OSError); with ``log=None`` the error is swallowed silently to ``{}``.
    a_dir = tmp_path / "policy.json"
    a_dir.mkdir()
    with caplog.at_level(logging.WARNING):
        assert load_policy_mapping(a_dir) == {}
    assert caplog.text == ""
