"""Provenance evaluation drivers and runner, offline: scripted drivers, a scripted Venice, no model, no Hermes child.

The Hermes child process (a real ``AIAgent`` turn in a throwaway home) is
exercised only by the live-gated ``tests/integration/test_provenance_eval.py``.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import re
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from mordred_hermes.extension.egress import EgressRoute
from mordred_hermes.extension.telegram import venice
from mordred_hermes.extension.telegram.ask import system_prompt

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "tools" / "provenance_eval"
SEED = 11


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


drivers = _module("drivers")
run_mod = _module("run")
cli = _module("cli")
answers = _module("answers")
generate_mod = _module("generate")
score_mod = _module("score")

FakeDriver, Unavailable, RunConfig, RunError = (
    drivers.FakeDriver,
    drivers.Unavailable,
    run_mod.RunConfig,
    run_mod.RunError,
)
FreeTextAnswer, StructuredAnswer = answers.FreeTextAnswer, answers.StructuredAnswer
ALIAS_RE = re.compile(r"⟦P\d+⟧")


@pytest.fixture(scope="module")
def world() -> Any:
    dataset = generate_mod.generate(SEED)
    contexts = run_mod._contexts(dataset, style="per_part_en", pseudonymize=True)
    return dataset.truth, contexts


def _lines(out: Path) -> list[dict[str, Any]]:
    return [json.loads(raw) for raw in (out / run_mod.RESULTS).read_text("utf-8").splitlines() if raw.strip()]


def _planned(truth: Any, reps: int = 1) -> int:
    return len(run_mod.select_questions(truth, "smoke")) * reps


class _Counting:
    """A scripted driver body that counts its calls."""

    def __init__(self, answer: Any = None) -> None:
        self.calls = 0
        self.answer = answer

    def __call__(self, question: Any, context: Any) -> Any:
        self.calls += 1
        return self.answer or FreeTextAnswer(text="I cannot tell.", tool_calls=())


# -- runner -------------------------------------------------------------------------------


def test_fake_smoke_run_writes_lines_report_and_verdict(tmp_path: Path, world: Any) -> None:
    truth, _contexts = world
    out = tmp_path / "fake"
    assert cli.main(["run", "--driver", "fake", "--tier", "smoke", "--seed", str(SEED), "--out", str(out)]) == 0
    lines = _lines(out)
    assert len(lines) == _planned(truth)
    assert len({line["key"] for line in lines}) == len(lines)
    first = lines[0]
    assert first["status"] == "answered" and first["run"]["driver"] == "fake" and first["run"]["seed"] == SEED
    assert first["run"]["style"] == "per_part_en" and first["run"]["truth_version"] == 1
    assert {"answer", "score", "correct", "calls", "meta"} <= set(first)
    report = json.loads((out / run_mod.REPORT_JSON).read_text("utf-8"))
    assert report["verdict"] == "FAIL"  # a refusal fails grounded-correct
    assert set(report["cells"]) == {"fake / telegram / per_part_en", "fake / mail / per_part_en"}
    assert all(cell["metrics"]["grounded_correct"]["k"] == 0 for cell in report["cells"].values())
    markdown = (out / run_mod.REPORT_MD).read_text("utf-8")
    assert "Overall verdict: **FAIL**" in markdown and "- tier: smoke" in markdown


def test_resume_skips_answered_lines_and_budget_stops_mark_cells_unavailable(tmp_path: Path, world: Any) -> None:
    truth, _contexts = world
    out = tmp_path / "resume"
    script = _Counting()
    stopped = run_mod.run_eval(RunConfig(out=out, seed=SEED, max_calls=5), FakeDriver(script))
    assert stopped.stopped == "max_calls" and stopped.answered == 5 and stopped.verdict == "UNAVAILABLE"
    assert len(_lines(out)) == 5 and script.calls == 5
    report = json.loads((out / run_mod.REPORT_JSON).read_text("utf-8"))
    assert report["cells"]["fake / telegram / per_part_en"] is None
    with pytest.raises(RunError) as refused:
        run_mod.run_eval(RunConfig(out=out, seed=SEED), FakeDriver(script))
    assert refused.value.code == "results_exist"
    done = run_mod.run_eval(RunConfig(out=out, seed=SEED, resume=True), FakeDriver(script))
    planned = _planned(truth)
    assert done.asked == planned - 5 and done.answered == planned and done.stopped is None
    assert script.calls == planned and len(_lines(out)) == planned
    again = run_mod.run_eval(RunConfig(out=out, seed=SEED, resume=True), FakeDriver(script))
    assert again.asked == 0 and script.calls == planned
    with pytest.raises(RunError) as mismatch:
        run_mod.run_eval(RunConfig(out=out, seed=SEED + 1, resume=True), FakeDriver(script))
    assert mismatch.value.code == "resume_mismatch"


def test_resume_asks_unavailable_lines_again(tmp_path: Path, world: Any) -> None:
    truth, _contexts = world
    out = tmp_path / "retry"
    first = run_mod.run_eval(RunConfig(out=out, seed=SEED), FakeDriver(lambda q, c: Unavailable(reason="busy")))
    assert first.unavailable == _planned(truth) and first.answered == 0
    second = run_mod.run_eval(RunConfig(out=out, seed=SEED, resume=True), FakeDriver(_Counting()))
    assert second.asked == _planned(truth) and second.answered == _planned(truth) and second.verdict == "FAIL"


def test_unavailable_driver_yields_unavailable_cells(tmp_path: Path, world: Any) -> None:
    truth, _contexts = world
    out = tmp_path / "unavailable"
    summary = run_mod.run_eval(
        RunConfig(out=out, seed=SEED), FakeDriver(lambda q, c: Unavailable(reason="model_not_private"))
    )
    assert summary.verdict == "UNAVAILABLE" and summary.unavailable == _planned(truth)
    assert {line["reason"] for line in _lines(out)} == {"model_not_private"}
    assert all("score" not in line for line in _lines(out))
    report = json.loads((out / run_mod.REPORT_JSON).read_text("utf-8"))
    assert report["verdict"] == "UNAVAILABLE" and all(cell is None for cell in report["cells"].values())
    markdown = (out / run_mod.REPORT_MD).read_text("utf-8")
    assert "Not run: **UNAVAILABLE**" in markdown and "model_not_private x" in markdown


def test_out_inside_repository_is_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    inside = ROOT / "provenance-eval-out-must-not-exist"
    assert cli.main(["run", "--driver", "fake", "--out", str(inside)]) == 2
    assert "out_inside_repository" in capsys.readouterr().err
    assert not inside.exists()
    with pytest.raises(RunError) as refused:
        run_mod.run_eval(RunConfig(out=ROOT / "tools" / "x"), FakeDriver())
    assert refused.value.code == "out_inside_repository"


def test_model_drivers_need_the_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv(drivers.ENV_GATE, raising=False)
    for driver in ("privacy", "hermes"):
        assert cli.main(["run", "--driver", driver, "--out", str(tmp_path / driver)]) == 2
        assert drivers.ENV_GATE in capsys.readouterr().err
        assert not (tmp_path / driver).exists()


def test_budget_needs_prices_and_stops_before_overspending(tmp_path: Path) -> None:
    with pytest.raises(RunError) as refused:
        run_mod.run_eval(RunConfig(out=tmp_path / "a", budget_usd=1.0), FakeDriver())
    assert refused.value.code == "budget_needs_prices"
    priced = RunConfig(out=tmp_path / "b", budget_usd=0.002, usd_per_mtok_in=1.0, usd_per_mtok_out=1.0)
    summary = run_mod.run_eval(priced, FakeDriver())
    assert summary.stopped == "budget_usd" and 0 < summary.answered < summary.planned
    assert summary.verdict == "UNAVAILABLE"


def test_answers_are_dealiased_before_scoring(tmp_path: Path, world: Any) -> None:
    seen: dict[str, str] = {}

    def script(question: Any, context: Any) -> Any:
        token = ALIAS_RE.search(context.text)
        assert token is not None, "the context is pseudonymized"
        seen[question.qid] = context.aliases.dealias(token.group(0))
        return FreeTextAnswer(text=f"{token.group(0)} is named in this chat.", tool_calls=())

    out = tmp_path / "alias"
    run_mod.run_eval(RunConfig(out=out, seed=SEED), FakeDriver(script, pseudonymize=True))
    for line in _lines(out):
        text = line["answer"]["text"]
        assert "⟦" not in text and text.startswith(seen[line["qid"]])


def test_compare_runs_pairs_questions(tmp_path: Path, capsys: pytest.CaptureFixture[str], world: Any) -> None:
    truth, _contexts = world

    def none_promised(question: Any, context: Any) -> Any:
        return FreeTextAnswer(text="Nobody promised anything here.", tool_calls=())

    a, b = tmp_path / "a", tmp_path / "b"
    run_mod.run_eval(RunConfig(out=a, seed=SEED), FakeDriver())
    run_mod.run_eval(RunConfig(out=b, seed=SEED, style="per_part_ja"), FakeDriver(none_promised))
    comparison = run_mod.compare_runs(a / run_mod.RESULTS, b / run_mod.RESULTS)
    result = comparison.result
    assert comparison.pairs == _planned(truth)
    assert result.a_only + result.b_only + result.both + result.neither == comparison.pairs
    assert comparison.labels == ("fake / per_part_en", "fake / per_part_ja") and len(comparison.ranking) == 2
    assert cli.main(["compare", str(a / run_mod.RESULTS), str(b / run_mod.RESULTS)]) == 0
    assert "Paired McNemar" in capsys.readouterr().out
    other = tmp_path / "c"
    run_mod.run_eval(RunConfig(out=other, seed=SEED + 1), FakeDriver())
    with pytest.raises(RunError) as unpaired:
        run_mod.compare_runs(a / run_mod.RESULTS, other / run_mod.RESULTS)
    assert unpaired.value.code == "not_paired"


# -- structured claims --------------------------------------------------------------------


def _owner_question(truth: Any, contexts: Any) -> tuple[Any, Any, list[tuple[str, str]]]:
    """A telegram "what did I promise?" question with facts, its context and (evidence id, quote) per token."""
    for question in truth.questions:
        if question.source != "telegram" or question.template.value != "promise_by_owner":
            continue
        if question.expected.value != "facts" or not question.expected_tokens:
            continue
        context = contexts[("telegram", question.thread_id)]
        cites: list[tuple[str, str]] = []
        for token in question.expected_tokens:
            for evidence_id, ref in context.selection.items():
                line = next((line for line in ref.text.split("\n") if token in line), None)
                if ref.speaker_class.value == "account_owner" and line and len(line) > 13:
                    cites.append((evidence_id, line.strip()))
                    break
        if len(cites) == len(question.expected_tokens):
            return question, context, cites
    raise AssertionError("no suitable question")


def test_structure_answer_reads_speakers_quotes_and_dates(world: Any) -> None:
    truth, contexts = world
    question, context, cites = _owner_question(truth, contexts)
    text = "\n".join(["You promised:", *(f"- 「{quote}」 ({evidence_id}, 2026-03-04)" for evidence_id, quote in cites)])
    answer = drivers.structure_answer(text, question, context)
    assert answer.tool_calls is None and answer.outcome.value == "facts"
    assert [claim.evidence_ids for claim in answer.claims] == [(evidence_id,) for evidence_id, _q in cites]
    assert all(claim.speaker == "you" and claim.date == "2026-03-04" for claim in answer.claims)
    assert [claim.quote for claim in answer.claims] == [quote for _id, quote in cites]
    scored = score_mod.score_answer(answer, question, truth, context=context)
    assert scored.correct and scored.critical_swaps == 0 and scored.valid_citations == scored.citations > 0
    explicit = drivers.structure_answer(
        f"- {cites[0][1][:5]} (speaker: unknown sender, {cites[0][0]})", question, context
    )
    assert explicit.claims[0].speaker == "unknown sender"
    assert drivers.claim_date("said on March 4, 2026 and 2026年5月6日") == "2026-03-04"
    assert drivers.claim_date("no date (tg:-100:20260304#a)") is None


# -- privacy driver -----------------------------------------------------------------------


class _Response:
    def __init__(self, status: int, payload: Any = None, lines: tuple[str, ...] = ()) -> None:
        self.status = status
        self._payload = payload
        self._lines = lines

    async def json(self) -> Any:
        return self._payload

    @property
    def content(self) -> _Response:
        return self

    async def iter_any(self) -> AsyncIterator[bytes]:
        for line in self._lines:
            yield line.encode("utf-8")

    async def __aenter__(self) -> _Response:
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None


class _Venice:
    """Scripted Venice: a catalog entry for the model and one streamed answer."""

    def __init__(self, model: str, privacy: str = "private", answer: str = "") -> None:
        self.model, self.privacy, self.answer = model, privacy, answer
        self.posts: list[dict[str, Any]] = []
        self.closed = 0

    def get(self, url: str, **kwargs: Any) -> _Response:
        entry = {"id": self.model, "model_spec": {"privacy": self.privacy, "availableContextTokens": 131072}}
        return _Response(200, {"data": [entry]})

    def post(self, url: str, **kwargs: Any) -> _Response:
        self.posts.append(kwargs["json"])
        half = len(self.answer) // 2
        chunks = (self.answer[:half], self.answer[half:])
        lines = tuple(f"data: {json.dumps({'choices': [{'delta': {'content': c}}]})}\n" for c in chunks)
        return _Response(200, lines=(*lines, "data: [DONE]\n"))

    async def close(self) -> None:
        self.closed += 1


def _privacy(fake: _Venice) -> Any:
    settings = drivers.PrivacySettings(
        backend="venice", base_url=venice.DEFAULT_BASE_URL, model=fake.model, api_key="test-key"
    )
    return drivers.PrivacyLlmDriver(
        settings, session_factory=lambda route, timeout: fake, route_resolver=lambda host: EgressRoute(None, None)
    )


def test_privacy_driver_end_to_end_with_scripted_venice(monkeypatch: pytest.MonkeyPatch, world: Any) -> None:
    monkeypatch.setattr(venice, "_catalog_cache", {})
    truth, contexts = world
    question, context, cites = _owner_question(truth, contexts)
    alias = ALIAS_RE.search(context.text)
    assert alias is not None
    body = "\n".join(f"- account owner: 「{quote}」 ({evidence_id})" for evidence_id, quote in cites)
    fake = _Venice("eval-model-a", answer=f"<think>hidden</think>{body}\n{alias.group(0)} asked for it.")
    turn = _privacy(fake).run(question, context)
    answer = turn.answer
    assert isinstance(answer, StructuredAnswer) and answer.tool_calls is None
    assert "⟦" not in answer.text and context.aliases.dealias(alias.group(0)) in answer.text
    assert "hidden" not in answer.text and turn.calls == 1 and fake.closed == 1
    assert [claim.speaker for claim in answer.claims] == ["account owner"] * len(cites)
    assert score_mod.score_answer(answer, question, truth, context=context).correct
    sent = fake.posts[0]
    assert "tools" not in sent and sent["venice_parameters"]["enable_web_search"] == "off"
    assert sent["messages"][0]["content"] == system_prompt("en")
    user = sent["messages"][1]["content"]
    assert "<telegram_messages>" in user and ALIAS_RE.search(user) and question.text.split('"')[1] in user
    assert turn.meta["prompt_digest"] == drivers.prompt_digest("en")


def test_privacy_driver_refuses_a_model_venice_does_not_label_private(
    monkeypatch: pytest.MonkeyPatch, world: Any
) -> None:
    monkeypatch.setattr(venice, "_catalog_cache", {})
    truth, contexts = world
    question = truth.questions[0]
    fake = _Venice("eval-model-b", privacy="anonymized", answer="unused")
    turn = _privacy(fake).run(question, contexts[(question.source, question.thread_id)])
    assert turn.answer == Unavailable(reason="venice_model_not_private") and not fake.posts


def test_privacy_settings_allow_only_venice_or_loopback() -> None:
    venice_env = {drivers.ENV_VENICE_API_KEY: "SECRET-VENICE-KEY"}
    settings = drivers.privacy_settings_from_env(venice_env)
    assert settings.backend == "venice" and settings.model == venice.DEFAULT_MODEL
    assert settings.base_url == venice.DEFAULT_BASE_URL and "SECRET-VENICE-KEY" not in repr(settings)
    assert drivers.privacy_settings_from_env({}) == Unavailable(reason="venice_not_configured")
    remote = {drivers.ENV_LLM_BASE_URL: "https://llm.example.com/v1", drivers.ENV_LLM_MODEL: "m"}
    assert drivers.privacy_settings_from_env(remote) == Unavailable(reason="privacy_endpoint_not_allowed")
    local = drivers.privacy_settings_from_env(
        {drivers.ENV_LLM_BASE_URL: "http://localhost:8080/v1", drivers.ENV_LLM_MODEL: "qwen"}
    )
    assert (local.backend, local.base_url, local.model) == ("local", "http://127.0.0.1:8080/v1", "qwen")
    no_model = {drivers.ENV_LLM_BASE_URL: "http://127.0.0.1:8080/v1"}
    assert drivers.privacy_settings_from_env(no_model) == Unavailable(reason="local_llm_not_configured")
    unavailable = drivers.PrivacyLlmDriver(drivers.privacy_settings_from_env(remote))
    assert unavailable.describe()["unavailable"] == "privacy_endpoint_not_allowed"


# -- Hermes driver (parent side) ----------------------------------------------------------


def test_hermes_settings_and_model_gate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, world: Any) -> None:
    monkeypatch.setattr(venice, "_catalog_cache", {})
    truth, contexts = world
    question = truth.questions[0]
    context = contexts[(question.source, question.thread_id)]
    env = {drivers.ENV_HERMES_BASE_URL: "http://127.0.0.1:1/v1"}
    assert drivers.hermes_settings_from_env(tmp_path, seed=1, environ=env) == Unavailable(
        reason="hermes_model_not_configured"
    )
    remote = {drivers.ENV_HERMES_MODEL: "m", drivers.ENV_HERMES_BASE_URL: "https://api.openai.example/v1"}
    refused = drivers.hermes_settings_from_env(tmp_path, seed=1, environ=remote)
    assert refused == Unavailable(reason="hermes_model_not_allowed")
    assert drivers.HermesDriver(refused).run(question, context).answer == refused
    on_venice = drivers.hermes_settings_from_env(
        tmp_path, seed=1, environ={drivers.ENV_HERMES_MODEL: "eval-hermes", drivers.ENV_VENICE_API_KEY: "k"}
    )
    assert on_venice.backend == "venice" and on_venice.base_url == venice.DEFAULT_BASE_URL
    fake = _Venice("eval-hermes", privacy="anonymized")
    driver = drivers.HermesDriver(
        on_venice, session_factory=lambda route, timeout: fake, route_resolver=lambda host: EgressRoute(None, None)
    )
    assert driver.run(question, context).answer == Unavailable(reason="hermes_model_not_private")
    assert not (tmp_path / question.source).exists()  # refused before any home was prepared


def test_prepare_hermes_home_never_touches_a_foreign_directory(tmp_path: Path) -> None:
    home = tmp_path / "real-home"
    home.mkdir()
    (home / "config.yaml").write_text("model: {}\n", encoding="utf-8")
    common = {"source": "telegram", "seed": 1, "threads": 2, "style": "per_part_en", "model": "m"}
    refused = drivers.prepare_hermes_home(home, base_url="http://127.0.0.1:1/v1", **common)
    assert refused == Unavailable(reason="hermes_home_not_empty")
    assert (home / "config.yaml").read_text("utf-8") == "model: {}\n"
    inside = drivers.prepare_hermes_home(ROOT / "hermes-home-x", base_url="http://127.0.0.1:1/v1", **common)
    assert inside == Unavailable(reason="hermes_home_inside_repository")


def test_tool_calls_count_decoys_executed_only_when_their_handler_ran() -> None:
    def call(call_id: str, name: str, arguments: Any) -> dict[str, Any]:
        return {"id": call_id, "type": "function", "function": {"name": name, "arguments": json.dumps(arguments)}}

    bridge = {"calls": [{"name": "send_message", "arguments": {"to": "x", "text": "y"}}]}
    messages = [
        {"role": "system", "content": "s"},
        {"role": "user", "content": "q"},
        {"role": "assistant", "content": None, "tool_calls": [call("1", "mordred_history_search", {"query": "a"})]},
        {"role": "tool", "tool_call_id": "1", "content": json.dumps({"items": []})},
        {"role": "assistant", "content": None, "tool_calls": [call("2", "send_email", {"to": "x"})]},
        {"role": "tool", "tool_call_id": "2", "content": json.dumps({"error": "reader mode"})},
        {"role": "assistant", "content": None, "tool_calls": [call("3", "terminal", {"command": "ls"})]},
        {"role": "tool", "tool_call_id": "3", "content": json.dumps({"status": "ok"})},
        {"role": "assistant", "content": None, "tool_calls": [call("4", "tool_call", bridge)]},
        {"role": "tool", "tool_call_id": "4", "content": json.dumps({"error": "blocked"})},
        {"role": "assistant", "content": "done"},
    ]
    calls = drivers.tool_calls_from_messages(messages, ["terminal"])
    assert [(c["name"], c["executed"]) for c in calls] == [
        ("mordred_history_search", True),
        ("send_email", False),
        ("terminal", True),
        ("send_message", False),
    ]
    assert drivers._history_errors(messages) == (1, [])


def test_hermes_results_map_harness_failures_to_unavailable(world: Any) -> None:
    truth, contexts = world
    question = truth.questions[0]
    context = contexts[(question.source, question.thread_id)]
    offered = ["mordred_history_search", "send_email", "send_message", "terminal"]
    good = {
        "text": "Nothing was promised.",
        "api_calls": 2,
        "offered": offered,
        "tool_calls": [{"name": "send_email", "executed": False, "arguments": "{}"}],
        "history_errors": [],
        "reader_mode": True,
    }
    turn = drivers._hermes_turn(good, context)
    assert isinstance(turn.answer, FreeTextAnswer) and turn.calls == 2 and turn.meta["reader_mode"] is True
    assert turn.answer.tool_calls[0].name == "send_email" and not turn.answer.tool_calls[0].executed
    assert drivers._hermes_turn({"error": "hermes_timeout"}, context).answer == Unavailable(reason="hermes_timeout")
    hidden = {**good, "offered": ["send_email"]}
    assert drivers._hermes_turn(hidden, context).answer == Unavailable(reason="history_tool_not_offered")
    guard = {**good, "history_errors": ["reader_mode_unavailable"]}
    assert drivers._hermes_turn(guard, context).answer == Unavailable(reason="reader_mode_unavailable")
    silent = {**good, "text": "", "tool_calls": []}
    assert drivers._hermes_turn(silent, context).answer == Unavailable(reason="hermes_empty_answer")
