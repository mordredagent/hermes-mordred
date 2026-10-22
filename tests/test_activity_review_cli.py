"""``hermes-mordred activity review|jobs``: dry runs make no model call; explicit runs report what was spent."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.activity import _review_jobs, _review_run, review
from mordred_hermes.activity._gate import ActivityRefused, refusal
from mordred_hermes.activity.config import ActivityConfig
from mordred_hermes.activity.store import ActivityStore
from mordred_hermes.wizard import activity_review_cli as cli
from tests._activity_review_helpers import (
    FakeLessons,
    LegacyLlm,
    answer,
    config,
    correction_episode,
    make_store,
    result,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hermes-mordred")
    sub = parser.add_subparsers(dest="command")
    activity = sub.add_parser("activity")
    cli.add_parsers(activity.add_subparsers(dest="activity_command", required=True))
    return parser


def _main(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    return int(args.func(args))


@pytest.fixture
def store(tmp_path: Path) -> ActivityStore:
    return make_store(tmp_path)


@pytest.fixture
def llm(store: ActivityStore) -> LegacyLlm:
    correction_episode(store)
    evidence = [item.event_id for item in store.events_for_episode("ep-corr")]
    return LegacyLlm(result(answer(evidence)))


@pytest.fixture(autouse=True)
def wired(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, store: ActivityStore) -> dict[str, Any]:
    state: dict[str, Any] = {"config": config(), "llm": LegacyLlm()}
    monkeypatch.setattr(cli, "_home", lambda: tmp_path)
    monkeypatch.setattr(review, "open_review_store", lambda home: store)
    monkeypatch.setattr(review, "resolve_llm", lambda: state["llm"])
    monkeypatch.setattr(_review_run, "_policy_mode", lambda: "lenient")
    monkeypatch.setattr(_review_jobs, "write_audit", lambda entry: None)
    monkeypatch.setattr(ActivityConfig, "load", classmethod(lambda cls, home: state["config"]))
    FakeLessons().install(monkeypatch)
    return state


def test_dry_run_reconciles_and_makes_no_model_call(
    wired: dict[str, Any], llm: LegacyLlm, capsys: pytest.CaptureFixture[str]
) -> None:
    wired["llm"] = llm

    assert _main(["activity", "review", "--dry-run"]) == 0

    out = capsys.readouterr().out
    assert "No model call was made." in out and "correction" in out and "override" in out
    assert llm.calls == []


def test_dry_run_json_reports_the_route_refusal(
    wired: dict[str, Any], llm: LegacyLlm, capsys: pytest.CaptureFixture[str]
) -> None:
    wired["config"] = config(review_model=None)

    assert _main(["activity", "review", "--dry-run", "--json"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["model_called"] is False and payload["route"] == "route_unavailable"
    assert [item["signal"] for item in payload["eligible"]] == ["correction"]
    assert [job["state"] for job in payload["jobs"]] == ["pending"]
    assert llm.calls == []


def test_explicit_review_runs_once_and_reports_the_tokens(
    wired: dict[str, Any], llm: LegacyLlm, capsys: pytest.CaptureFixture[str]
) -> None:
    wired["llm"] = llm

    assert _main(["activity", "review", "--episode", "ep-corr"]) == 0

    captured = capsys.readouterr()
    assert "completed" in captured.out and "Candidate lesson" in captured.out
    assert "a live provider call was made (input tokens 812, output tokens 140)" in captured.err
    assert len(llm.calls) == 1
    assert "account switcher" not in captured.out + captured.err


def test_retry_makes_a_new_explicit_attempt(
    wired: dict[str, Any], store: ActivityStore, llm: LegacyLlm, capsys: pytest.CaptureFixture[str]
) -> None:
    wired["llm"] = LegacyLlm(error=TimeoutError())
    assert _main(["activity", "review", "--episode", "ep-corr", "--json"]) == 1
    job_id = json.loads(capsys.readouterr().out)["job_id"]
    assert _main(["activity", "review", "--episode", "ep-corr"]) == 1  # uncertain: not re-run implicitly
    assert "job_not_pending" in capsys.readouterr().err

    wired["llm"] = llm
    assert _main(["activity", "review", "--retry", job_id, "--json"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["state"] == "completed" and payload["provider_called"] is True
    assert len(llm.calls) == 1


def test_jobs_list_prints_identifiers_only(
    wired: dict[str, Any], store: ActivityStore, llm: LegacyLlm, capsys: pytest.CaptureFixture[str]
) -> None:
    review.enqueue(store, "ep-corr", 1, 1.0)

    assert _main(["activity", "jobs", "list", "--json"]) == 0

    (job,) = json.loads(capsys.readouterr().out)["jobs"]
    assert job["episode_id"] == "ep-corr" and job["state"] == "pending" and "snapshot_digest" not in job


@pytest.mark.parametrize(
    ("setup", "code"),
    [
        (lambda state, mp: state.update(config=ActivityConfig()), "feature_disabled"),
        (lambda state, mp: state.update(llm=refusal("route_unavailable")), "route_unavailable"),
        (
            lambda state, mp: mp.setattr(
                review, "open_review_store", lambda home: (_ for _ in ()).throw(ActivityRefused(refusal("not_armed")))
            ),
            "not_armed",
        ),
    ],
)
def test_refusals_are_codes(
    wired: dict[str, Any], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], setup: Any, code: str
) -> None:
    setup(wired, monkeypatch)

    assert _main(["activity", "review", "--json"]) == 1

    assert json.loads(capsys.readouterr().out) == {"status": "refused", "code": code}


def test_episode_and_retry_are_exclusive() -> None:
    with pytest.raises(SystemExit):
        _parser().parse_args(["activity", "review", "--episode", "a", "--retry", "b"])
