"""``hermes-mordred activity lessons retire``."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.activity import lessons
from mordred_hermes.activity.config import ActivityConfig
from mordred_hermes.wizard import activity_lessons_cli, cli
from tests._activity_lesson_helpers import admitted, corrected_candidate, make_store


@pytest.fixture(autouse=True)
def audited(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    monkeypatch.setattr(lessons, "_audit", entries.append)
    return entries


@pytest.fixture(autouse=True)
def store(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    activity_store = make_store(tmp_path)
    config = ActivityConfig.from_mapping({"enabled": True})
    monkeypatch.setattr(activity_lessons_cli, "_open", lambda home: (activity_store, config))
    return activity_store


def test_parser_wires_retire() -> None:
    parser = argparse.ArgumentParser()
    cli._setup_subparser(parser)
    args = parser.parse_args(["activity", "lessons", "retire", "l", "--revision", "1", "--reason", "r"])
    assert args.func is cli._handle_activity
    with pytest.raises(SystemExit):
        parser.parse_args(["activity", "lessons", "retire", "l", "--reason", "r"])


def test_retire_an_admitted_lesson(
    store: Any, audited: list[dict[str, Any]], capsys: pytest.CaptureFixture[str]
) -> None:
    _, _, candidate = corrected_candidate(store)
    lesson = admitted(store, candidate)

    code = cli.main(
        ["activity", "lessons", "retire", lesson.lesson_id, "--revision", "1", "--reason", "workflow_changed"]
    )

    assert code == 0
    assert f"Retired {lesson.lesson_id} revision 1" in capsys.readouterr().out
    retired = lessons.get(store, lesson.lesson_id, 1)
    assert (retired.state, retired.suspended_reason) == ("retired", "workflow_changed")
    assert audited[-1]["state"] == "retired"


def test_retire_a_candidate_is_refused_with_the_code_only(store: Any, capsys: pytest.CaptureFixture[str]) -> None:
    _, _, candidate = corrected_candidate(store)

    code = cli.main(["activity", "lessons", "retire", candidate.lesson_id, "--revision", "1", "--reason", "done"])

    assert code == 1
    assert "refused (wrong_state)" in capsys.readouterr().err
    assert lessons.get(store, candidate.lesson_id, 1).state == "candidate"
