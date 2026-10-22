"""``hermes-mordred activity candidates build``: the recovery path for collector corrections."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.activity import lessons
from mordred_hermes.activity.config import ActivityConfig
from mordred_hermes.activity.store import ActivityStore
from mordred_hermes.wizard import activity_lessons_cli, cli
from tests.test_activity_ingest_candidates import OPERATOR, attempt, batch, correction, make_store, receiver, task_start


@pytest.fixture(autouse=True)
def store(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> ActivityStore:
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setattr(lessons, "_audit", lambda entry: None)
    from mordred_hermes.activity import ingest

    monkeypatch.setattr(ingest, "_LAST_RETENTION", {})
    body = {"plugins": {"mordred_activity": {"enabled": True, "collection_enabled": True}}}
    (tmp_path / "config.yaml").write_text(json.dumps(body), encoding="utf-8")
    activity_store = make_store(tmp_path)
    config = ActivityConfig.from_mapping({"enabled": True})
    monkeypatch.setattr(activity_lessons_cli, "_open", lambda home: (activity_store, config))
    return activity_store


def test_parser_wires_candidates_build() -> None:
    parser = argparse.ArgumentParser()
    cli._setup_subparser(parser)
    argv = ["activity", "candidates", "build", "--episode", "e", "--correction", "c", "--json"]
    assert parser.parse_args(argv).func is cli._handle_activity


def test_build_succeeds_once_the_late_task_boundary_is_stored(
    store: ActivityStore, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    fix = correction(4)
    receiver(tmp_path).ingest(OPERATOR, batch(*attempt(2), fix))
    assert cli.main(["activity", "candidates", "build", "--episode", "ep-1"]) == 1
    assert "refused (task_unknown)" in capsys.readouterr().out

    # The boundary was observed first but delivered last.
    receiver(tmp_path).ingest(OPERATOR, batch(task_start(10, observed_at=1760950000.0)))
    # Ingestion of the boundary alone does not rebuild; the operator's explicit command does.
    assert cli.main(["activity", "candidates", "build", "--episode", "ep-1", "--json"]) == 0

    [result] = json.loads(capsys.readouterr().out)["results"]
    [lesson] = lessons.list_lessons(store)
    assert result == {"event_id": fix["event_id"], "lesson_id": lesson.lesson_id, "revision": 1}
    assert cli.main(["activity", "candidates", "build", "--episode", "ep-1", "--correction", fix["event_id"]]) == 0
    assert len(lessons.list_lessons(store)) == 1


def test_build_refuses_an_unknown_episode_or_correction(
    store: ActivityStore, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    receiver(tmp_path).ingest(OPERATOR, batch(task_start(1), *attempt(2)))

    assert cli.main(["activity", "candidates", "build", "--episode", "missing"]) == 1
    assert "refused (episode_unknown)" in capsys.readouterr().err
    assert cli.main(["activity", "candidates", "build", "--episode", "ep-1"]) == 1
    assert "refused (correction_unknown)" in capsys.readouterr().err


def test_build_prints_no_correction_text(
    store: ActivityStore, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    fix: dict[str, Any] = correction(4)
    receiver(tmp_path).ingest(OPERATOR, batch(task_start(1), *attempt(2), fix))
    assert cli.main(["activity", "candidates", "build", "--episode", "ep-1"]) == 0
    out = capsys.readouterr().out
    assert fix["text"] not in out
    assert "candidate " in out
