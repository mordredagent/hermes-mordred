"""Key destruction needs complete root-wide metadata inventory, never raw SQL reads."""

from __future__ import annotations

import os
from pathlib import Path

import pytest


@pytest.mark.parametrize(
    "relative,kind",
    [
        ("state.db", "database"),
        ("profiles/work/state.db", "database"),
        ("plugin-data/mordred/mordred.db", "database"),
        ("state.db-wal", "journal"),
        ("mordred/db-encryption.pending", "pending"),
        ("mordred/db-decryption.pending", "pending"),
        ("mordred/db-encryption.journal.json", "journal"),
        ("backups/root.tgz", "backup"),
        ("state.db.pre-update.bak", "backup"),
        ("state.db.mordred-enc", "pending"),
        ("mordred/db-unrecognized.json", "unknown"),
    ],
)
def test_scans_every_dependency_class(tmp_path: Path, relative: str, kind: str) -> None:
    from mordred_hermes._database_inventory import scan_dependencies

    path = tmp_path / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"opaque synthetic content")
    inventory = scan_dependencies(tmp_path)
    assert any(entry.path == path and entry.kind == kind and entry.generation is None for entry in inventory.entries)
    if kind == "unknown":
        assert not inventory.complete


@pytest.mark.parametrize("kind", ["database", "pending", "journal", "backup", "unknown"])
@pytest.mark.parametrize("generation", [None, "a" * 32])
def test_unknown_or_matching_generation_blocks_destruction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str, generation: str | None
) -> None:
    from mordred_hermes import _database_inventory as inventory
    from mordred_hermes._database_contracts import DatabaseRefused, Dependency, Inventory
    from mordred_hermes._database_lifecycle import acquire_exclusive

    dependency = Dependency(tmp_path / "state.db", kind, generation)
    monkeypatch.setattr(inventory, "scan_dependencies", lambda _root: Inventory((dependency,), True))
    deleted = []
    with acquire_exclusive(tmp_path) as lease, pytest.raises(DatabaseRefused):
        inventory.assert_mutation_safe(tmp_path, "a" * 32, lease)
        deleted.append("native-key")
    assert deleted == []


def test_unknown_requested_generation_means_all_dependencies(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from mordred_hermes import _database_inventory as inventory
    from mordred_hermes._database_contracts import DatabaseRefused, Dependency, Inventory
    from mordred_hermes._database_lifecycle import acquire_exclusive

    monkeypatch.setattr(
        inventory,
        "scan_dependencies",
        lambda _root: Inventory((Dependency(tmp_path / "state.db", "database", "b" * 32),), True),
    )
    with acquire_exclusive(tmp_path) as lease, pytest.raises(DatabaseRefused):
        inventory.assert_mutation_safe(tmp_path, None, lease)


def test_unreadable_inventory_blocks_deletion(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from mordred_hermes import _database_inventory as inventory
    from mordred_hermes._database_contracts import DatabaseRefused
    from mordred_hermes._database_lifecycle import acquire_exclusive

    hidden = tmp_path / "cron"
    hidden.mkdir()
    real = os.scandir

    def denied(path):
        if Path(path) == hidden:
            raise PermissionError("synthetic denied inventory")
        return real(path)

    monkeypatch.setattr(os, "scandir", denied)
    result = inventory.scan_dependencies(tmp_path)
    assert result.complete is False
    deleted = []
    with acquire_exclusive(tmp_path) as lease, pytest.raises(DatabaseRefused):
        inventory.assert_mutation_safe(tmp_path, None, lease)
        deleted.append("native-key")
    assert deleted == []


def test_unrelated_home_files_are_not_database_dependencies(tmp_path: Path) -> None:
    from mordred_hermes._database_inventory import scan_dependencies

    for relative in (
        "config.yaml",
        ".env",
        "memories/MEMORY.md",
        "mordred/memory.key.enc",
        "installs/runtime/build.db",
        "profiles/work/skills/script/cache.db",
    ):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("ordinary unrelated fixture")
    result = scan_dependencies(tmp_path)
    assert result.complete and result.entries == ()
    (tmp_path / "foreign.db.unknown").write_bytes(b"opaque")
    result = scan_dependencies(tmp_path)
    assert result.entries and any(item.path.name == "foreign.db.unknown" for item in result.entries)


def test_inventory_does_not_open_database_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from mordred_hermes._database_inventory import scan_dependencies

    (tmp_path / "state.db").write_bytes(b"opaque")
    real = Path.open

    def checked(path, *args, **kwargs):
        assert path.name != "state.db", "inventory must not close raw descriptors on live SQLite files"
        return real(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", checked)
    assert scan_dependencies(tmp_path).entries


def test_mutation_guard_requires_a_live_exclusive_lease(tmp_path: Path) -> None:
    from mordred_hermes._database_contracts import DatabaseRefused
    from mordred_hermes._database_inventory import assert_mutation_safe
    from mordred_hermes._database_lifecycle import acquire_exclusive

    with acquire_exclusive(tmp_path) as lease:
        assert_mutation_safe(tmp_path, None, lease)
    with pytest.raises(DatabaseRefused):
        assert_mutation_safe(tmp_path, None, lease)
