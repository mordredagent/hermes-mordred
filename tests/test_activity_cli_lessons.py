"""``hermes-mordred activity`` correction and lesson commands."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.activity import lessons
from mordred_hermes.activity._gate import ActivityRefused, refusal
from mordred_hermes.activity.config import ActivityConfig
from mordred_hermes.wizard import activity_lessons_cli, cli
from tests._activity_lesson_helpers import (
    CORRECTION_TEXT,
    RAW_SECRET,
    admitted,
    corrected_candidate,
    make_store,
    seed_episode,
)


@pytest.fixture(autouse=True)
def store(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setattr(lessons, "_audit", lambda entry: None)
    activity_store = make_store(tmp_path)
    config = ActivityConfig.from_mapping({"enabled": True})
    monkeypatch.setattr(activity_lessons_cli, "_open", lambda home: (activity_store, config))
    return activity_store


def test_parser_wires_every_lesson_subcommand() -> None:
    parser = argparse.ArgumentParser()
    cli._setup_subparser(parser)
    for argv in (
        ["activity", "correct", "--episode", "e", "--text", "t", "--attempt", "a"],
        ["activity", "candidates", "list", "--json"],
        ["activity", "candidates", "show", "l", "--revision", "2", "--json"],
        ["activity", "validate", "l", "--revision", "1", "--method", "fixture", "--note", "n"],
        ["activity", "adopt", "l", "--revision", "1", "--digest", "abc"],
        ["activity", "reject", "l", "--revision", "1", "--reason", "r"],
        ["activity", "lessons", "list", "--state", "admitted", "--json"],
        ["activity", "lessons", "show", "l"],
        ["activity", "lessons", "suspend", "l", "--revision", "1", "--reason", "r"],
        ["activity", "lessons", "revise", "l", "--revision", "1", "--guidance", "g", "--applies-when", "a"],
    ):
        assert parser.parse_args(argv).func is cli._handle_activity


def test_correct_records_and_prints_the_candidate(store: Any, capsys: pytest.CaptureFixture[str]) -> None:
    seeded = seed_episode(store)

    code = cli.main(
        [
            "activity",
            "correct",
            "--episode",
            seeded.episode_id,
            "--text",
            CORRECTION_TEXT,
            "--attempt",
            seeded.attempt_id,
        ]
    )

    out = capsys.readouterr().out
    assert code == 0
    [candidate] = lessons.list_lessons(store)
    assert f"Candidate lesson {candidate.lesson_id} revision 1" in out
    assert candidate.guidance == CORRECTION_TEXT


def test_correct_unknown_episode_prints_only_the_code(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["activity", "correct", "--episode", "missing", "--text", "secret words"]) == 1
    captured = capsys.readouterr()
    assert "episode_unknown" in captured.err
    assert "secret words" not in captured.out + captured.err


def test_show_prints_fields_and_evidence_identifiers_only(store: Any, capsys: pytest.CaptureFixture[str]) -> None:
    seeded, correction, candidate = corrected_candidate(store)

    assert cli.main(["activity", "candidates", "show", candidate.lesson_id]) == 0
    out = capsys.readouterr().out

    assert CORRECTION_TEXT in out  # the lesson's own guidance is user-authored
    assert str(candidate.evidence_digest) in out
    assert RAW_SECRET not in out  # event targets are never printed
    attempt = seeded.attempt[0]
    assert f"{attempt.event_id}  intended  click  app.example.com  /reports" in out
    assert correction.event_id in out

    assert cli.main(["activity", "lessons", "show", candidate.lesson_id, "--json"]) == 0
    body = json.loads(capsys.readouterr().out)
    assert body["lesson"]["lesson_id"] == candidate.lesson_id
    assert RAW_SECRET not in json.dumps(body)
    assert {"event_id", "present", "phase", "op", "site", "route"} == set(body["evidence"][0])


def test_validate_then_adopt_with_digest_prefix(store: Any, capsys: pytest.CaptureFixture[str]) -> None:
    _, _, candidate = corrected_candidate(store)
    lesson_id = candidate.lesson_id

    assert cli.main(["activity", "validate", lesson_id, "--revision", "1", "--method", "readonly_check"]) == 0
    assert cli.main(["activity", "adopt", lesson_id, "--revision", "1", "--digest", "0" * 12]) == 1
    assert "confirmation_mismatch" in capsys.readouterr().err
    prefix = str(candidate.evidence_digest)[:12]
    assert cli.main(["activity", "adopt", lesson_id, "--revision", "1", "--digest", prefix]) == 0

    assert lessons.get(store, lesson_id, 1).state == "admitted"
    assert cli.main(["activity", "lessons", "list", "--state", "admitted", "--json"]) == 0
    listed = json.loads(capsys.readouterr().out.splitlines()[-1])
    assert [row["lesson_id"] for row in listed["lessons"]] == [lesson_id]


def test_adopt_without_digest_needs_a_terminal(
    store: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _, _, candidate = corrected_candidate(store)
    lessons.validate(store, candidate.lesson_id, 1, method="fixture")
    monkeypatch.setattr(activity_lessons_cli, "_is_tty", lambda: False)

    assert cli.main(["activity", "adopt", candidate.lesson_id, "--revision", "1"]) == 2
    assert lessons.get(store, candidate.lesson_id, 1).state == "validated"

    prompts: list[str] = []
    monkeypatch.setattr(activity_lessons_cli, "_is_tty", lambda: True)
    monkeypatch.setattr(
        activity_lessons_cli, "_read_line", lambda prompt: prompts.append(prompt) or str(candidate.evidence_digest)[:12]
    )
    assert cli.main(["activity", "adopt", candidate.lesson_id, "--revision", "1"]) == 0
    out = capsys.readouterr().out
    assert str(candidate.evidence_digest) in out
    assert CORRECTION_TEXT in out
    assert prompts and "12 characters" in prompts[0]
    assert lessons.get(store, candidate.lesson_id, 1).state == "admitted"


def test_suspend_reject_and_revise(store: Any, capsys: pytest.CaptureFixture[str]) -> None:
    _, _, first = corrected_candidate(store)
    _, _, second = corrected_candidate(store, episode="ep-2", seq0=20)
    admitted(store, first)

    assert cli.main(["activity", "lessons", "suspend", first.lesson_id, "--revision", "1", "--reason", "stale"]) == 0
    assert cli.main(["activity", "reject", second.lesson_id, "--revision", "1", "--reason", "scope_too_wide"]) == 0
    assert cli.main(["activity", "lessons", "revise", first.lesson_id, "--revision", "1", "--guidance", "New"]) == 0
    assert cli.main(["activity", "lessons", "revise", first.lesson_id, "--revision", "1"]) == 2

    assert lessons.get(store, first.lesson_id, 1).state == "suspended"
    assert lessons.get(store, second.lesson_id, 1).state == "rejected"
    assert (lessons.get(store, first.lesson_id).revision, lessons.get(store, first.lesson_id).guidance) == (2, "New")
    assert cli.main(["activity", "candidates", "list"]) == 0
    assert first.lesson_id in capsys.readouterr().out


def test_gate_refusal_exits_one_with_the_code(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def refuse(home: Path) -> Any:
        raise ActivityRefused(refusal("not_armed"))

    monkeypatch.setattr(activity_lessons_cli, "_open", refuse)

    assert cli.main(["activity", "lessons", "list"]) == 1
    assert "refused (not_armed)" in capsys.readouterr().err
