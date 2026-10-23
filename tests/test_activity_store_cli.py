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
from tests._activity_episode_helpers import RAW_SECRET, make_store, plain_opener, rows, seed_episode

#: Older than the default raw-event retention (365 days).
OLD = 400 * 86400


@pytest.fixture(autouse=True)
def store(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> ActivityStore:
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


def test_restore_without_yes_previews_and_changes_nothing(
    store: ActivityStore, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    seed_episode(store)
    dest = tmp_path / "snapshot.db"
    store.backup(dest)
    seed_episode(store, episode="ep-later", seq0=10)
    generation, events = store.meta().store_generation, _events(store)
    capsys.readouterr()

    assert cli.main(["activity", "restore", "--input", str(dest)]) == 2

    out = capsys.readouterr().out
    assert "activity_events: 4" in out
    assert "--yes" in out
    assert (store.meta().store_generation, _events(store)) == (generation, events)


def test_restore_with_yes_round_trips_rows_and_bumps_the_generation(
    store: ActivityStore, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    seed_episode(store)
    backed_up = _events(store)
    dest = tmp_path / "snapshot.db"
    store.backup(dest)
    seed_episode(store, episode="ep-later", seq0=10)
    generation = store.meta().store_generation

    assert cli.main(["activity", "restore", "--input", str(dest), "--yes"]) == 0

    out = capsys.readouterr().out
    new_generation = store.meta().store_generation
    assert new_generation != generation
    assert new_generation in out
    assert "session references in the restored history are marked unavailable" in out
    assert "review" not in out
    assert _events(store) == backed_up


def test_restore_refuses_another_profiles_copy(
    store: ActivityStore, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    other_home = tmp_path / "other"
    other_home.mkdir()
    other = ActivityStore(other_home / "mordred.db", plain_opener)
    other.initialize(other_home)
    dest = tmp_path / "foreign.db"
    other.backup(dest)
    generation = store.meta().store_generation

    assert cli.main(["activity", "restore", "--input", str(dest), "--yes"]) == 1

    assert "refused (profile_mismatch)" in capsys.readouterr().err
    assert store.meta().store_generation == generation


def test_restore_of_a_missing_file_is_refused_without_creating_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    missing = tmp_path / "missing.db"
    assert cli.main(["activity", "restore", "--input", str(missing)]) == 1
    assert "refused (store_unavailable)" in capsys.readouterr().err
    assert not missing.exists()


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
