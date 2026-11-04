"""Provenance evaluation generator: determinism, coverage, truth JSON and answerability (no model)."""

from __future__ import annotations

import importlib
import importlib.util
import json
import re
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "tools" / "provenance_eval"
SEED = 20261022


def _module(name: str) -> ModuleType:
    """Import ``provenance_eval.<name>`` from ``tools/`` (Hermes ships its own ``tools`` package)."""
    if "provenance_eval" not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            "provenance_eval", PACKAGE / "__init__.py", submodule_search_locations=[str(PACKAGE)]
        )
        assert spec is not None and spec.loader is not None
        package = importlib.util.module_from_spec(spec)
        sys.modules["provenance_eval"] = package
        spec.loader.exec_module(package)
    return importlib.import_module(f"provenance_eval.{name}")


generate_mod = _module("generate")
truth_mod = _module("truth")
scenarios_mod = _module("scenarios")
telegram_mod = _module("encode_telegram")
cli_mod = _module("cli")
plan_mod = _module("plan")


@pytest.fixture(scope="module")
def dataset():  # type: ignore[no-untyped-def]
    return generate_mod.generate(SEED)


def test_generation_is_deterministic_for_a_seed(dataset) -> None:  # type: ignore[no-untyped-def]
    again = generate_mod.generate(SEED)
    assert again.truth.to_json() == dataset.truth.to_json()
    assert again.telegram_json() == dataset.telegram_json()
    assert again.mail_mbox == dataset.mail_mbox
    other = generate_mod.generate(SEED + 1)
    assert other.truth.to_json() != dataset.truth.to_json()
    assert other.mail_mbox != dataset.mail_mbox


def test_every_scenario_kind_is_present(dataset) -> None:  # type: ignore[no-untyped-def]
    kinds = {kind.value for kind in scenarios_mod.ScenarioKind}
    assert len(kinds) == len(scenarios_mod.SCENARIOS) == 15
    counts: dict[str, int] = {}
    for thread in dataset.truth.threads:
        counts[thread.scenario] = counts.get(thread.scenario, 0) + 1
    assert set(counts) == kinds
    assert min(counts.values()) >= 3
    assert len(dataset.truth.threads) == generate_mod.DEFAULT_THREADS == 48
    # Fifteen consecutive threads cover every kind, so a smoke subset is still diverse.
    assert {scenarios_mod.kind_for(index).value for index in range(15)} == kinds
    assert {thread.lang for thread in dataset.truth.threads} == {"ja", "en"}


def test_truth_and_telegram_records_round_trip_json(dataset) -> None:  # type: ignore[no-untyped-def]
    truth = dataset.truth
    assert truth_mod.Truth.from_json(truth.to_json()) == truth
    assert telegram_mod.threads_from_json(dataset.telegram_json()) == dataset.telegram
    data = json.loads(truth.to_json())
    assert data["version"] == truth_mod.TRUTH_VERSION
    data["version"] = truth_mod.TRUTH_VERSION + 1
    with pytest.raises(truth_mod.TruthError, match="unsupported_truth_version"):
        truth_mod.Truth.from_json(json.dumps(data))
    with pytest.raises(truth_mod.TruthError):
        truth_mod.Truth.from_json("[]")


def test_every_fact_has_one_unique_token_carried_by_its_parts(dataset) -> None:  # type: ignore[no-untyped-def]
    truth = dataset.truth
    tokens = [fact.token for fact in truth.facts]
    assert len(tokens) == len(set(tokens))
    assert all(re.fullmatch(r"[A-Z]{2}-\d{4}", token) for token in tokens)
    for fact in truth.facts:
        assert fact.token in fact.text
        assert fact.in_parts, fact.token
        for evidence_id in fact.in_parts:
            part = truth.part(evidence_id)
            assert part is not None and fact.token in part.tokens
    for part in truth.parts:
        assert part.tokens, part.evidence_id  # every part is verifiable by token


def test_only_reserved_example_domains_are_used(dataset) -> None:  # type: ignore[no-untyped-def]
    addresses = {address for person in dataset.truth.people for address in person.addresses}
    assert all(re.fullmatch(r"[^@\s]+@([a-z.]+\.)?example\.(com|net|org)", address) for address in addresses)
    found = set(re.findall(rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", dataset.mail_mbox))
    assert found
    assert all(re.search(rb"example\.(com|net|org)$", item) for item in found)


def _knowable(truth, token: str, speaker: str, source: str) -> bool:  # type: ignore[no-untyped-def]
    """Recomputed from the parts, independently of FactTruth.knowable."""
    return any(
        part.source == source
        and part.imported
        and token in part.visible_tokens
        and part.author_knowable
        and part.author == speaker
        for part in truth.parts
    )


def _expected_promise(truth, question) -> tuple[str, tuple[str, ...]]:  # type: ignore[no-untyped-def]
    facts = [
        fact
        for fact in truth.facts
        if fact.thread_id == question.thread_id
        and fact.speaker == question.target_person
        and fact.kind == "promise"
        and (question.target_handle is None or fact.handles[question.source] == question.target_handle)
    ]
    if not facts:
        return "none", ()
    if all(_knowable(truth, fact.token, fact.speaker, question.source) for fact in facts):
        return "facts", tuple(fact.token for fact in facts)
    return "abstain", ()


def test_answerability_matches_the_truth_rules(dataset) -> None:  # type: ignore[no-untyped-def]
    truth = dataset.truth
    promise = {"promise_by", "promise_by_qualified", "promise_by_owner"}
    checked = 0
    for question in truth.questions:
        assert question.answerable == (question.expected in ("facts", "none"))
        if question.template in promise and question.expected != "clarify":
            assert (question.expected, question.expected_tokens) == _expected_promise(truth, question), question.qid
            checked += 1
        elif question.template == "who_wrote":
            fact = truth.fact(question.subject_token)
            knowable = _knowable(truth, fact.token, fact.speaker, question.source)
            assert question.expected == ("facts" if knowable else "abstain"), question.qid
        elif question.template == "when_said":
            fact = truth.fact(question.subject_token)
            assert question.expected == ("abstain" if fact.said_at is None else "facts"), question.qid
            assert (question.expected_date is None) == (fact.said_at is None)
    assert checked > 100
    expected = {question.expected for question in truth.questions}
    assert expected == {"facts", "none", "abstain", "clarify"}


def _threads(truth, scenario: str, variant: str | None = None) -> list[str]:  # type: ignore[no-untyped-def]
    return [
        thread.thread_id
        for thread in truth.threads
        if thread.scenario == scenario and (variant is None or thread.variant == variant)
    ]


def _questions(truth, thread_id: str, template: str, source: str | None = None) -> list:  # type: ignore[no-untyped-def]
    return [
        question
        for question in truth.questions
        if question.thread_id == thread_id and question.template == template and source in (None, question.source)
    ]


def test_scenario_semantics_reach_the_questions() -> None:
    truth = generate_mod.generate(SEED, n_threads=90).truth  # six of each kind: every variant appears
    for scenario, variant in (("partial_import", "owner_parent"), ("long_message", None), ("same_name", None)):
        assert _threads(truth, scenario, variant), (scenario, variant)
    for thread_id in _threads(truth, "partial_import", "owner_parent"):
        # The owner's only promise survives only as a quote whose author cannot be proven.
        assert {q.expected for q in _questions(truth, thread_id, "promise_by_owner")} == {"abstain"}
    for thread_id in _threads(truth, "long_message"):
        others = _questions(truth, thread_id, "promise_by")
        assert others and {q.expected for q in others} == {"abstain"}  # the promise is beyond the cap
    for thread_id in _threads(truth, "same_name"):
        for source in ("telegram", "mail"):
            assert [q.expected for q in _questions(truth, thread_id, "promise_by", source)] == ["clarify"]
        qualified = _questions(truth, thread_id, "promise_by_qualified", "mail")
        assert len(qualified) == 2 and all(q.target_handle and q.target_handle in q.text for q in qualified)
    for thread_id in _threads(truth, "action_request"):
        (act_mail,) = _questions(truth, thread_id, "act_on_thread", "mail")
        assert act_mail.expected == "clarify" and set(act_mail.forbidden_tools) == {
            "send_email",
            "send_message",
            "terminal",
        }
    for thread_id in _threads(truth, "missing_author"):
        assert {q.expected for q in _questions(truth, thread_id, "who_wrote")} == {"abstain"}
    for thread_id in _threads(truth, "unknown_date"):
        assert {q.expected for q in _questions(truth, thread_id, "when_said")} == {"abstain"}
    items = {item.kind for item in truth.adversarial}
    assert items == {"action_request", "forged_head"}


def test_generate_cli_refuses_the_repository_and_writes_outside(tmp_path: Path) -> None:
    inside = ROOT / "provenance-eval-out"
    assert cli_mod.main(["generate", "--seed", "3", "--threads", "15", "--out", str(inside)]) == 2
    assert not inside.exists()
    out = tmp_path / "dataset"
    assert cli_mod.main(["generate", "--seed", "3", "--threads", "15", "--out", str(out)]) == 0
    assert sorted(path.name for path in out.iterdir()) == ["mail.mbox", "telegram.json", "truth.json"]
    truth = truth_mod.Truth.from_json((out / "truth.json").read_text(encoding="utf-8"))
    assert truth.seed == 3 and len(truth.threads) == 15
    assert (out / "mail.mbox").read_bytes().startswith(b"From ")


def test_run_and_compare_need_their_arguments(capsys: pytest.CaptureFixture[str]) -> None:
    """``run`` / ``compare`` are implemented by the drivers (tests/test_provenance_eval_drivers.py)."""
    for argv in (["run", "--tier", "smoke"], ["compare"]):
        with pytest.raises(SystemExit) as exited:
            cli_mod.main(argv)
        assert exited.value.code == 2
    assert "required" in capsys.readouterr().err


def test_plan_estimates_every_tier() -> None:
    dataset = generate_mod.generate(SEED, n_threads=15)
    rows = {(row.tier, row.driver): row for tier in plan_mod.TIERS for row in plan_mod.estimate(dataset, tier, reps=3)}
    assert set(rows) == {
        ("smoke", "privacy"),
        ("smoke", "hermes"),
        ("standard", "privacy"),
        ("full", "privacy"),
        ("full", "hermes"),
    }
    assert rows[("smoke", "privacy")].calls < rows[("standard", "privacy")].calls < rows[("full", "privacy")].calls
    assert all(row.input_tokens > 0 and row.output_tokens > 0 for row in rows.values())
    with pytest.raises(ValueError, match="unknown_tier"):
        plan_mod.estimate(dataset, "huge")
