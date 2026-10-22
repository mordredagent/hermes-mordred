"""The two Hermes recall tools: availability, per-call refusal, admitted-only output, registration."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes import activity
from mordred_hermes.activity import _gate, lessons, retrieval, tools
from mordred_hermes.activity._gate import ActivityRefused, refusal
from mordred_hermes.activity.config import ActivityConfig
from tests._activity_lesson_helpers import (
    CORRECTION_TEXT,
    RAW_SECRET,
    admitted,
    corrected_candidate,
    make_store,
)

CANDIDATE_SECRET = "ZQX-CAND-4410"
ENABLED = ActivityConfig.from_mapping({"enabled": True})


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(lessons, "_audit", lambda entry: None)
    monkeypatch.setattr(tools, "_home", lambda: tmp_path)
    monkeypatch.setattr(retrieval, "_BUDGET", retrieval.SessionBudget())


def _config(monkeypatch: pytest.MonkeyPatch, config: ActivityConfig) -> None:
    monkeypatch.setattr(ActivityConfig, "load", classmethod(lambda cls, home: config))


def _payload(text: str) -> dict[str, Any]:
    note, _, body = text.partition("\n")
    assert note.startswith("Untrusted data:")
    return dict(json.loads(body))


@pytest.fixture
def seeded_store(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    store = make_store(tmp_path)
    _, _, adopted = corrected_candidate(store)
    admitted(store, adopted)
    _, _, candidate = corrected_candidate(store, episode="ep-2", seq0=20, text=f"Unadopted {CANDIDATE_SECRET}")
    _config(monkeypatch, ENABLED)
    monkeypatch.setattr(_gate, "open_store", lambda home, config=None: store)
    return store, adopted, candidate


def test_check_fn_requires_enabled_recall_and_the_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_gate, "check_protection", lambda home: None)
    _config(monkeypatch, ActivityConfig())
    assert tools.tools_available() is False
    _config(monkeypatch, ActivityConfig.from_mapping({"enabled": True, "recall_enabled": False}))
    assert tools.tools_available() is False
    _config(monkeypatch, ENABLED)
    assert tools.tools_available() is True
    monkeypatch.setattr(_gate, "check_protection", lambda home: refusal("not_armed"))
    assert tools.tools_available() is False


def test_handlers_refuse_content_free_when_disabled_or_gated(monkeypatch: pytest.MonkeyPatch) -> None:
    _config(monkeypatch, ActivityConfig())
    assert json.loads(tools.activity_search({"task": "x"})) == {"status": "unavailable", "reason": "feature_disabled"}

    _config(monkeypatch, ENABLED)

    def refuse(home: Path, config: Any = None) -> Any:
        raise ActivityRefused(refusal("no_key"))

    monkeypatch.setattr(_gate, "open_store", refuse)
    assert json.loads(tools.activity_search({"task": "x"})) == {"status": "unavailable", "reason": "no_key"}
    assert json.loads(tools.activity_get({"lesson_id": "abc"})) == {"status": "unavailable", "reason": "no_key"}


def test_invalid_arguments_are_refused(seeded_store: Any) -> None:
    for args in ({}, {"task": ""}, {"task": "x", "limit": 4}, {"task": "x", "site": 3}, {"task": "x", "limit": True}):
        assert json.loads(tools.activity_search(args)) == {"status": "unavailable", "reason": "invalid_request"}
    for args in ({}, {"lesson_id": "x" * 65}, {"lesson_id": "a", "revision": 0}):
        assert json.loads(tools.activity_get(args)) == {"status": "unavailable", "reason": "invalid_request"}


def test_unadopted_and_raw_fixture_strings_never_reach_tool_output(seeded_store: Any) -> None:
    _store, adopted, candidate = seeded_store
    outputs = [
        tools.activity_search({"task": "export the monthly finance report"}, session_id="s1"),
        tools.activity_search({"task": f"Unadopted {CANDIDATE_SECRET} {RAW_SECRET}"}, session_id="s2"),
        tools.activity_search({"task": "reports", "site": "app.example.com", "limit": 3}, session_id="s3"),
        tools.activity_get({"lesson_id": adopted.lesson_id}, session_id="s4"),
        tools.activity_get({"lesson_id": candidate.lesson_id}, session_id="s5"),
        tools.activity_get({"lesson_id": candidate.lesson_id, "revision": 1}, session_id="s6"),
    ]

    for output in outputs:
        assert CANDIDATE_SECRET not in output
        assert RAW_SECRET not in output
        assert candidate.lesson_id not in output
    assert _payload(outputs[0])["items"][0]["guidance"] == CORRECTION_TEXT
    assert _payload(outputs[3])["items"][0]["lesson_id"] == adopted.lesson_id
    assert _payload(outputs[4]) == {"status": "unavailable", "items": [], "reason": "not_admitted"}


def test_recall_disabled_at_runtime_refuses_without_schema_change(
    seeded_store: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    _config(monkeypatch, ActivityConfig.from_mapping({"enabled": True, "recall_enabled": False}))

    assert json.loads(tools.activity_search({"task": "finance report"})) == {
        "status": "unavailable",
        "reason": "recall_disabled",
    }


class _Ctx:
    def __init__(self) -> None:
        self.tools: list[dict[str, Any]] = []
        self.skills: list[tuple[str, Path]] = []
        self.hooks: list[str] = []

    def register_hook(self, name: str, callback: Any) -> None:
        self.hooks.append(name)

    def register_tool(self, **kwargs: Any) -> None:
        self.tools.append(kwargs)

    def register_skill(self, name: str, path: Path, description: str = "") -> None:
        self.skills.append((name, path))


def test_register_wires_tools_and_skills() -> None:
    ctx = _Ctx()
    activity.register(ctx)

    assert ctx.hooks == ["on_session_start", "on_session_end", "on_session_finalize"]
    assert [t["name"] for t in ctx.tools] == ["mordred_activity_search", "mordred_activity_get"]
    for registered in ctx.tools:
        assert registered["toolset"] == "mordred_activity"
        assert registered["check_fn"] is tools.tools_available
        assert registered["is_async"] is False
        properties = set(registered["schema"]["parameters"]["properties"])
        assert properties <= {"task", "site", "account", "limit", "lesson_id", "revision"}
    assert [name for name, _ in ctx.skills] == ["activity-recall", "activity-review"]
    for _, path in ctx.skills:
        text = path.read_text("utf-8")
        assert text.startswith("---\nname: ")
        assert "network_requirements: local-only" in text


def test_skill_frontmatter_parses() -> None:
    from mordred_hermes.privacy_check.skill_frontmatter import parse

    for name in ("activity-recall", "activity-review"):
        parsed = parse(tools.SKILLS_DIR / name / "SKILL.md")
        assert parsed.network_requirements == "local-only"


def test_register_tolerates_a_minimal_context() -> None:
    class Minimal:
        def register_hook(self, name: str, callback: Any) -> None:
            return None

    activity.register(Minimal())
