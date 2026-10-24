"""Key destruction needs complete root-wide metadata inventory, never raw SQL reads."""

from __future__ import annotations

import os
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

_POSIX_PATHS = pytest.mark.skipif(
    os.name != "posix", reason="POSIX alias/rename semantics; Windows sharing/rename qualification is Task 5's gate"
)


@pytest.mark.parametrize(
    "relative,kind",
    [
        ("state.db", "database"),
        ("profiles/work/state.db", "database"),
        ("plugin-data/mordred/mordred.db", "database"),
        ("state.db-wal", "journal"),
        ("state.db-shm", "journal"),
        ("state.db-journal", "journal"),
        ("profiles/work/cron/executions.db-journal", "journal"),
        ("profiles/work/plugin-data/mordred/mordred.db", "database"),
        ("mordred/db-encryption.marker", "journal"),
        ("mordred/db-encryption.pending", "pending"),
        ("mordred/db-decryption.pending", "pending"),
        ("mordred/db-encryption.journal.json", "journal"),
        ("backups/root.tgz", "backup"),
        ("profiles/work/backups/older/root.zip", "backup"),
        ("mordred/db-backups.json", "backup"),
        ("mordred/db-backups.journal.json", "journal"),
        ("state.db.pre-update.bak", "backup"),
        ("memory.sqlite3.backup", "backup"),
        ("state.db.mordred-enc", "pending"),
        ("mordred/db-unrecognized.json", "unknown"),
        ("state.db.unknown", "unknown"),
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
        "state.db.lock",
        "mordred/db-encryption.lock",
        "backups/README.txt",
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


@pytest.mark.parametrize("relative", ["installs", "profiles/work/skills", "mordred/unrelated"])
def test_denied_program_trees_are_not_traversed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, relative: str) -> None:
    from mordred_hermes._database_inventory import scan_dependencies

    excluded = tmp_path / relative
    excluded.mkdir(parents=True)
    (excluded / "state.db").write_bytes(b"unrelated program data")
    real = os.scandir

    def denied(path):
        assert Path(path) != excluded, "excluded program data must not be traversed"
        return real(path)

    monkeypatch.setattr(os, "scandir", denied)
    result = scan_dependencies(tmp_path)
    assert result.complete and result.entries == ()


@_POSIX_PATHS
def test_symlinked_in_scope_tree_is_unknown_without_following_it(tmp_path: Path) -> None:
    from mordred_hermes._database_inventory import scan_dependencies

    external = tmp_path.parent / f"{tmp_path.name}-external"
    external.mkdir()
    (external / "state.db").write_bytes(b"outside the managed root")
    link = tmp_path / "cron"
    link.symlink_to(external, target_is_directory=True)
    result = scan_dependencies(tmp_path)
    assert not result.complete
    assert [(entry.path, entry.kind) for entry in result.entries] == [(link, "unknown")]


@_POSIX_PATHS
def test_unrelated_regular_file_alias_is_not_a_database_dependency(tmp_path: Path) -> None:
    from mordred_hermes._database_inventory import scan_dependencies

    target = tmp_path / "config.yaml"
    target.write_text("ordinary configuration")
    (tmp_path / ".env").symlink_to(target)
    result = scan_dependencies(tmp_path)
    assert result.complete and result.entries == ()


@pytest.mark.parametrize("attributes", [{"st_reparse_tag": 1}, {"st_file_attributes": 0x400}])
@pytest.mark.parametrize("location", ["root", "child"])
def test_reparse_directory_metadata_is_unknown_before_traversal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, attributes: dict[str, int], location: str
) -> None:
    from mordred_hermes._database_inventory import scan_dependencies

    directory = tmp_path if location == "root" else tmp_path / "cron"
    directory.mkdir(exist_ok=True)
    info = directory.lstat()
    fields = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
    fields.update(attributes)
    real_lstat = Path.lstat

    def reparse_lstat(path):
        if path == tmp_path and location == "root":
            return SimpleNamespace(**fields)
        return real_lstat(path)

    class ReparseEntry:
        name = "cron"
        path = str(directory)

        def stat(self, *, follow_symlinks=True):
            assert not follow_symlinks
            return SimpleNamespace(**fields)

    def scan(path):
        assert location == "child" and Path(path) == tmp_path, "reparse directories must never be traversed"
        return nullcontext(iter([ReparseEntry()]))

    monkeypatch.setattr(Path, "lstat", reparse_lstat)
    monkeypatch.setattr(os, "scandir", scan)
    result = scan_dependencies(tmp_path)
    assert not result.complete
    assert [(entry.path, entry.kind) for entry in result.entries] == [(directory, "unknown")]


def test_vanished_directory_during_discovery_is_incomplete(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from mordred_hermes._database_inventory import scan_dependencies

    directory = tmp_path / "cron"
    directory.mkdir()
    real = os.scandir

    def vanished(path):
        if Path(path) == directory:
            directory.rmdir()
        return real(path)

    monkeypatch.setattr(os, "scandir", vanished)
    result = scan_dependencies(tmp_path)
    assert not result.complete
    assert any(entry.path == directory and entry.kind == "unknown" for entry in result.entries)


@pytest.mark.parametrize("root_kind", ["missing", "file", pytest.param("symlink", marks=_POSIX_PATHS)])
def test_invalid_root_is_incomplete(tmp_path: Path, root_kind: str) -> None:
    from mordred_hermes._database_inventory import scan_dependencies

    root = tmp_path / "root"
    if root_kind == "file":
        root.write_bytes(b"not a directory")
    elif root_kind == "symlink":
        root.symlink_to(tmp_path, target_is_directory=True)
    result = scan_dependencies(root)
    assert not result.complete
    assert any(entry.path == root and entry.kind == "unknown" for entry in result.entries)


def test_mutation_guard_refuses_incomplete_empty_inventory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from mordred_hermes import _database_inventory as inventory
    from mordred_hermes._database_contracts import DatabaseRefused, Inventory
    from mordred_hermes._database_lifecycle import acquire_exclusive

    monkeypatch.setattr(inventory, "scan_dependencies", lambda _root: Inventory((), False))
    with acquire_exclusive(tmp_path) as lease, pytest.raises(DatabaseRefused):
        inventory.assert_mutation_safe(tmp_path, None, lease)


def test_mutation_guard_allows_only_explicit_other_generation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from mordred_hermes import _database_inventory as inventory
    from mordred_hermes._database_contracts import Dependency, Inventory
    from mordred_hermes._database_lifecycle import acquire_exclusive

    monkeypatch.setattr(
        inventory,
        "scan_dependencies",
        lambda _root: Inventory((Dependency(tmp_path / "state.db", "database", "b" * 32),), True),
    )
    with acquire_exclusive(tmp_path) as lease:
        inventory.assert_mutation_safe(tmp_path, "a" * 32, lease)


def test_mutation_guard_rejects_a_duck_typed_lease_before_scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from mordred_hermes import _database_inventory as inventory
    from mordred_hermes._database_contracts import DatabaseRefused

    class FakeLease:
        def assert_held(self, root: Path) -> None:
            pass

    def forbidden(_root):
        pytest.fail("inventory must not scan before checking the preceding exclusive lease")

    monkeypatch.setattr(inventory, "scan_dependencies", forbidden)
    with pytest.raises(DatabaseRefused):
        inventory.assert_mutation_safe(tmp_path, None, FakeLease())


@_POSIX_PATHS
def test_mutation_guard_rechecks_the_lease_after_scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from mordred_hermes import _database_inventory as inventory
    from mordred_hermes._database_contracts import DatabaseRefused, Inventory
    from mordred_hermes._database_lifecycle import acquire_exclusive

    with acquire_exclusive(tmp_path) as lease:

        def replaced_root(_root):
            tmp_path.rename(tmp_path.with_name(f"{tmp_path.name}-old"))
            tmp_path.mkdir()
            return Inventory((), True)

        monkeypatch.setattr(inventory, "scan_dependencies", replaced_root)
        with pytest.raises(DatabaseRefused):
            inventory.assert_mutation_safe(tmp_path, None, lease)
