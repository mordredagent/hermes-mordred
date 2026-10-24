"""Actual checked export snapshots and policy-only database destinations."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from mordred_hermes.activity._gate import ActivityRefused


def test_checked_source_yields_snapshot_after_source_identity_validation(tmp_path):
    from mordred_hermes.imports._protected_destination import checked_import_source

    source = tmp_path / "export.jsonl"
    source.write_bytes(b'{"text":"original"}\n')
    with checked_import_source(source, home=tmp_path) as handle:
        source.write_bytes(b'{"text":"changed"}\n')
        assert handle.read() == b'{"text":"original"}\n'
    assert handle.closed


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "parent_symlink", "database", "sidecar", "writable"])
def test_unsafe_source_refuses_before_content_escapes(tmp_path, kind):
    from mordred_hermes.imports._protected_destination import checked_import_source

    source = tmp_path / "export.jsonl"
    source.write_bytes(b"private content")
    if kind == "symlink":
        link = tmp_path / "link.jsonl"
        link.symlink_to(source)
        source = link
    elif kind == "hardlink":
        os.link(source, tmp_path / "second.jsonl")
    elif kind == "parent_symlink":
        link = tmp_path / "link"
        link.symlink_to(tmp_path, target_is_directory=True)
        source = link / source.name
    elif kind == "database":
        source = source.rename(tmp_path / "mordred.db")
    elif kind == "sidecar":
        source = source.rename(tmp_path / "mordred.db-journal")
    elif kind == "writable":
        source.chmod(0o666)
    with pytest.raises(ActivityRefused), checked_import_source(source, home=tmp_path):
        pytest.fail("unsafe source escaped admission")


def test_source_swap_during_actual_open_is_refused(tmp_path, monkeypatch):
    from mordred_hermes.imports._protected_destination import checked_import_source

    source = tmp_path / "export.jsonl"
    source.write_bytes(b"original")
    real_open = os.open

    def swap(path, flags, *args, **kwargs):
        if Path(path).name == source.name:
            source.rename(tmp_path / "original.jsonl")
            source.write_bytes(b"replacement")
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", swap)
    with pytest.raises(ActivityRefused), checked_import_source(source, home=tmp_path):
        pytest.fail("swapped source escaped admission")


def test_database_source_is_never_raw_opened(tmp_path, monkeypatch):
    from mordred_hermes.imports._protected_destination import checked_import_source

    source = tmp_path / "plugin-data/mordred/mordred.db"

    def forbidden(*args, **kwargs):
        raise AssertionError("raw database open")

    monkeypatch.setattr(os, "open", forbidden)
    with pytest.raises(ActivityRefused), checked_import_source(source, home=tmp_path):
        pass


def test_destination_is_policy_only_and_creates_nothing(tmp_path):
    from mordred_hermes.imports._protected_destination import checked_store_destination

    expected = tmp_path / "plugin-data/mordred/mordred.db"
    assert checked_store_destination(expected, home=tmp_path) == expected
    assert not expected.parent.exists()
    with pytest.raises(ActivityRefused):
        checked_store_destination(tmp_path / "other.db", home=tmp_path)


def test_destination_rejects_planted_parent(tmp_path):
    from mordred_hermes.imports._protected_destination import checked_store_destination

    target = tmp_path / "elsewhere"
    target.mkdir()
    (tmp_path / "plugin-data").symlink_to(target, target_is_directory=True)
    with pytest.raises(ActivityRefused):
        checked_store_destination(tmp_path / "plugin-data/mordred/mordred.db", home=tmp_path)
