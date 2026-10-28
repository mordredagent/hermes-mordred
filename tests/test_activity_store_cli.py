"""``hermes-mordred activity backup|restore|retention`` and the read-only retention plan."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.activity._gate import ActivityRefused
from mordred_hermes.activity.config import ActivityConfig
from mordred_hermes.activity.store import ActivityStore
from mordred_hermes.wizard import activity_store_cli, cli
from tests._activity_episode_helpers import RAW_SECRET, make_store, rows, seed_episode
from tests._activity_protection import native_root as native_root
from tests._activity_protection import protected_runtime as protected_runtime

#: Older than the default raw-event retention (365 days).
OLD = 400 * 86400


@pytest.fixture(autouse=True)
def store(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> ActivityStore | None:
    if "protected_runtime" in request.fixturenames:  # real-path tests own tmp_path as the native root
        return None
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    activity_store = make_store(home)
    config = ActivityConfig.from_mapping({"enabled": True})
    monkeypatch.setattr(activity_store_cli, "_open", lambda _home: (activity_store, config))
    return activity_store


def _events(store: ActivityStore) -> list[tuple[Any, ...]]:
    return rows(store, "SELECT event_id FROM activity_events ORDER BY receipt")


def test_parser_wires_every_store_subcommand() -> None:
    parser = argparse.ArgumentParser()
    cli._setup_subparser(parser)
    for argv in (
        ["activity", "backup", "--output", "out.db"],
        ["activity", "restore", "--input", "in.db", "--yes"],
        ["activity", "retention", "--dry-run", "--json"],
    ):
        assert parser.parse_args(argv).func is cli._handle_activity


def test_backup_writes_a_private_copy_and_refuses_an_existing_one(
    store: ActivityStore, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    seed_episode(store)
    dest = tmp_path / "snapshot.db"

    assert cli.main(["activity", "backup", "--output", str(dest)]) == 0

    out = capsys.readouterr().out
    assert dest.stat().st_mode & 0o777 == 0o600
    assert store.meta().store_generation in out
    assert "another profile" in out
    assert RAW_SECRET not in out
    before = dest.read_bytes()
    assert cli.main(["activity", "backup", "--output", str(dest)]) == 1
    assert "refused (destination_exists)" in capsys.readouterr().err
    assert dest.read_bytes() == before


def test_retention_dry_run_deletes_nothing_and_the_real_run_deletes(
    store: ActivityStore, capsys: pytest.CaptureFixture[str]
) -> None:
    seed_episode(store)
    seed_episode(store, episode="ep-recent", seq0=10)
    with store.connection() as conn:
        conn.execute("UPDATE activity_events SET received_at = ? WHERE episode_id = 'ep-1'", (time.time() - OLD,))
    before = _events(store)

    assert cli.main(["activity", "retention", "--dry-run", "--json"]) == 0

    planned = json.loads(capsys.readouterr().out)
    assert planned["dry_run"] is True
    assert (planned["events_deleted"], planned["episodes_deleted"]) == (4, 1)
    assert _events(store) == before

    assert cli.main(["activity", "retention", "--json"]) == 0

    applied = json.loads(capsys.readouterr().out)
    assert applied["dry_run"] is False
    assert (applied["events_deleted"], applied["episodes_deleted"]) == (4, 1)
    assert len(_events(store)) == 4
    assert store.episode("ep-1") is None


def test_retention_text_output_names_counts_only(store: ActivityStore, capsys: pytest.CaptureFixture[str]) -> None:
    seed_episode(store)
    assert cli.main(["activity", "retention", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "raw events 365 days" in out
    assert "events would remove:" in out
    assert "candidates" not in out and "lessons" not in out
    assert RAW_SECRET not in out


def test_raw_retention_zero_keeps_every_raw_event(
    store: ActivityStore, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config = ActivityConfig.from_mapping({"enabled": True, "retention_raw_days": 0})
    monkeypatch.setattr(activity_store_cli, "_open", lambda _home: (store, config))
    seed_episode(store)
    with store.connection() as conn:
        conn.execute("UPDATE activity_events SET received_at = 0")
    before = _events(store)

    assert cli.main(["activity", "retention"]) == 0
    assert "raw events kept forever" in capsys.readouterr().out
    assert cli.main(["activity", "retention", "--json"]) == 0

    applied = json.loads(capsys.readouterr().out)
    assert (applied["raw_days"], applied["events_deleted"], applied["episodes_deleted"]) == (0, 0, 0)
    assert _events(store) == before


def test_plan_retention_predicts_the_pass(store: ActivityStore) -> None:
    seed_episode(store)
    seed_episode(store, episode="ep-recent", seq0=10)
    now = time.time()
    with store.connection() as conn:
        conn.execute("UPDATE activity_events SET received_at = ? WHERE episode_id = 'ep-1'", (now - OLD,))
    before = _events(store)

    planned = store.plan_retention(now, raw_days=30)

    assert _events(store) == before
    assert planned == store.apply_retention(now, raw_days=30)
    assert (planned.events_deleted, planned.episodes_deleted) == (4, 1)


def test_retention_json_has_only_raw_event_fields(store: ActivityStore, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["activity", "retention", "--dry-run", "--json"]) == 0
    assert set(json.loads(capsys.readouterr().out)) == {
        "dry_run",
        "raw_days",
        "events_deleted",
        "episodes_deleted",
        "complete",
    }


def test_gate_refusal_prints_only_the_code(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    from mordred_hermes.activity._gate import refusal

    def refuse(_home: Path) -> Any:
        raise ActivityRefused(refusal("not_armed"))

    monkeypatch.setattr(activity_store_cli, "_open", refuse)
    assert cli.main(["activity", "retention"]) == 1
    assert "refused (not_armed)" in capsys.readouterr().err


# --- real protected path (no `_open` stub: restore takes its own exclusive lease) ---------


def _protected_restore_setup(protected_runtime, monkeypatch, profile: str = ""):
    from mordred_hermes.activity._gate import open_store
    from mordred_hermes.dbcrypt import _migrate
    from tests.test_activity_store import PEER, PRODUCER, event

    root, provider, _ = protected_runtime
    home = root / profile
    live = open_store(home)
    assert live.append_batch(PEER, PRODUCER, [event(1)]).accepted == 1
    backup = root.parent / (root.name + "-snap.backup")
    live.backup(backup)
    assert live.append_batch(PEER, PRODUCER, [event(2, episode="later")]).accepted == 1
    provider.close()  # no runtime lease or handle may remain
    monkeypatch.setattr(_migrate, "holders", lambda paths: [])
    return root, home, backup


def _count_events(home: Path, protected_runtime) -> int:
    from mordred_hermes import dbcrypt
    from mordred_hermes.activity._gate import open_store
    from mordred_hermes.dbcrypt._key import KeyProvider

    fresh = KeyProvider(home=protected_runtime[0])
    dbcrypt._PROVIDER = fresh
    try:
        return int(rows(open_store(home), "SELECT count(*) FROM activity_events")[0][0])
    finally:
        fresh.close()


def test_real_restore_preview_prints_counts_and_exits_2(protected_runtime, monkeypatch, capsys) -> None:
    _, home, backup = _protected_restore_setup(protected_runtime, monkeypatch)
    monkeypatch.setenv("HERMES_HOME", str(home))
    capsys.readouterr()

    assert cli.main(["activity", "restore", "--input", str(backup)]) == 2

    out = capsys.readouterr().out
    assert "activity_events: 1" in out
    assert "backup schema version" in out and "--yes" in out


def test_real_restore_yes_replaces_rows(protected_runtime, monkeypatch, capsys) -> None:
    _, home, backup = _protected_restore_setup(protected_runtime, monkeypatch)
    monkeypatch.setenv("HERMES_HOME", str(home))
    capsys.readouterr()

    assert cli.main(["activity", "restore", "--input", str(backup), "--yes"]) == 0

    assert "Restored the activity store" in capsys.readouterr().out
    assert _count_events(home, protected_runtime) == 1


def test_real_restore_accepts_a_noncanonical_home_spelling(protected_runtime, monkeypatch, capsys) -> None:
    root, home, backup = _protected_restore_setup(protected_runtime, monkeypatch)
    link = root.parent / (root.name + "-home-link")
    link.symlink_to(home, target_is_directory=True)
    monkeypatch.setenv("HERMES_HOME", str(link))
    capsys.readouterr()

    assert cli.main(["activity", "restore", "--input", str(backup), "--yes"]) == 0

    assert _count_events(home, protected_runtime) == 1


def test_real_restore_refuses_another_profiles_backup(protected_runtime, monkeypatch, capsys) -> None:
    from mordred_hermes.activity._gate import open_store
    from tests.test_activity_store import PEER, PRODUCER, event

    root, _, _ = protected_runtime
    other = open_store(root / "profiles/work")
    assert other.append_batch(PEER, PRODUCER, [event(1)]).accepted == 1
    foreign = root.parent / (root.name + "-foreign.backup")
    other.backup(foreign)
    _, home, _ = _protected_restore_setup(protected_runtime, monkeypatch)
    monkeypatch.setenv("HERMES_HOME", str(home))
    capsys.readouterr()

    for extra in ([], ["--yes"]):
        assert cli.main(["activity", "restore", "--input", str(foreign), *extra]) == 1
        assert "refused (profile_mismatch)" in capsys.readouterr().err


def test_real_restore_of_a_missing_file_is_refused_without_creating_it(protected_runtime, monkeypatch, capsys) -> None:
    root, home, _ = _protected_restore_setup(protected_runtime, monkeypatch)
    monkeypatch.setenv("HERMES_HOME", str(home))
    missing = root.parent / (root.name + "-missing.backup")
    before = _count_events(home, protected_runtime)
    capsys.readouterr()

    for extra in ([], ["--yes"]):
        assert cli.main(["activity", "restore", "--input", str(missing), *extra]) == 1
        assert "refused (store_unavailable)" in capsys.readouterr().err
        assert not missing.exists()

    assert _count_events(home, protected_runtime) == before == 2


def _store_path(home: Path) -> Path:
    return home / "plugin-data/mordred/mordred.db"


def test_real_restore_of_a_deleted_store_reports_store_missing(protected_runtime, monkeypatch, capsys) -> None:
    _, home, backup = _protected_restore_setup(protected_runtime, monkeypatch)
    monkeypatch.setenv("HERMES_HOME", str(home))
    for suffix in ("", "-wal", "-shm", "-journal"):
        Path(str(_store_path(home)) + suffix).unlink(missing_ok=True)
    capsys.readouterr()

    for extra in ([], ["--yes"]):
        assert cli.main(["activity", "restore", "--input", str(backup), *extra]) == 1
        err = capsys.readouterr().err
        assert "refused (store_missing)" in err
        assert "start Hermes once" in err
        assert not _store_path(home).exists()


def test_real_restore_refuses_busy_while_a_runtime_lease_is_live(protected_runtime, monkeypatch, capsys) -> None:
    from mordred_hermes._database_lifecycle import acquire_runtime
    from mordred_hermes.keyvault._database_authority import resolve_database_domain

    _, home, backup = _protected_restore_setup(protected_runtime, monkeypatch)
    monkeypatch.setenv("HERMES_HOME", str(home))
    capsys.readouterr()

    with acquire_runtime(resolve_database_domain(home).root):
        for extra in ([], ["--yes"]):
            assert cli.main(["activity", "restore", "--input", str(backup), *extra]) == 1
            err = capsys.readouterr().err
            assert "refused (busy)" in err
            assert "stop Hermes first" in err
    assert _count_events(home, protected_runtime) == 2


def test_real_restore_preview_refuses_a_store_bound_to_another_home(protected_runtime, monkeypatch, capsys) -> None:
    from mordred_hermes.activity._gate import open_store
    from mordred_hermes.dbcrypt import _migrate

    root, provider, _ = protected_runtime
    live = open_store(root)
    backup = root.parent / (root.name + "-snap.backup")
    live.backup(backup)
    with live.connection() as conn:
        conn.execute("UPDATE activity_meta SET value = ? WHERE key = 'profile_home'", (str(root / "moved-away"),))
    provider.close()
    monkeypatch.setattr(_migrate, "holders", lambda paths: [])
    monkeypatch.setenv("HERMES_HOME", str(root))
    capsys.readouterr()

    for extra in ([], ["--yes"]):
        assert cli.main(["activity", "restore", "--input", str(backup), *extra]) == 1
        assert "refused (profile_mismatch)" in capsys.readouterr().err


@pytest.mark.parametrize("confirmed", [False, True])
def test_real_restore_of_an_unregistered_copy_is_refused(protected_runtime, monkeypatch, capsys, confirmed) -> None:
    """A WAL-mode keyed backup cannot be produced (the live store refuses to back up in WAL mode, and the
    maintenance scope opens backups read-only), so the closest reachable case is a byte copy that was never
    registered as a backup; it is refused as ``store_unavailable`` and nothing changes."""
    import shutil

    _, home, backup = _protected_restore_setup(protected_runtime, monkeypatch)
    monkeypatch.setenv("HERMES_HOME", str(home))
    copy = backup.with_name(backup.name + ".copy")
    shutil.copyfile(backup, copy)
    before = _count_events(home, protected_runtime)
    capsys.readouterr()

    assert cli.main(["activity", "restore", "--input", str(copy), *(["--yes"] if confirmed else [])]) == 1

    assert "refused (store_unavailable)" in capsys.readouterr().err
    assert _count_events(home, protected_runtime) == before == 2
