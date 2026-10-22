"""One evaluation run with one driver: a resumable JSONL, then ``report.md`` / ``report.json``.

``results.jsonl`` under ``--out`` holds one line per (question, repetition):
the run identity (driver, model, header style, seed, threads, truth
version), the answer, its score (:class:`~.metrics.QuestionScore`) and the
turn's accounting and metadata. A line whose driver was unavailable records
the content-free reason instead. ``--resume`` keeps every answered line and
asks the rest again (unavailable lines included); the last line for a key
wins. ``--max-calls`` and ``--budget-usd`` stop the run before a question
that could exceed them.

The report has one cell per source (``<driver> / <source> / <style>``). A cell
with any planned (question, repetition) unanswered — unavailable, not yet
run, or cut by a budget — is ``UNAVAILABLE``, never a pass.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import json
import time
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, TextIO

from mordred_hermes.imports.render import HeadStyle

from .answers import Answer, StructuredAnswer
from .context import mail_threads
from .drivers import DriverContext, EvalDriver, Turn, Unavailable, driver_context, estimate_tokens
from .generate import DEFAULT_THREADS, Dataset, generate
from .metrics import Metrics, QuestionScore, aggregate, combined_verdict
from .plan import SMOKE_THREADS, TIERS
from .report import McNemar, compare, rank_styles, render_markdown, report_json
from .score import score_answer
from .truth import SOURCES, TRUTH_VERSION, Question, Truth

__all__ = [
    "REPORT_JSON",
    "REPORT_MD",
    "RESULTS",
    "Comparison",
    "RunConfig",
    "RunError",
    "RunSummary",
    "compare_runs",
    "format_comparison",
    "inside_repo",
    "run_eval",
    "select_questions",
]

RESULTS: Final = "results.jsonl"
REPORT_MD: Final = "report.md"
REPORT_JSON: Final = "report.json"
LINE_VERSION: Final = 1
REPO_ROOT: Final = Path(__file__).resolve().parents[2]
_SYSTEM_TOKENS: Final = 600  # prompt allowance per call, as in .plan
_OUTPUT_TOKENS: Final = 300
_PER_MTOK: Final = 1_000_000


class RunError(RuntimeError):
    """A refused run; ``code`` is content-free."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def inside_repo(path: Path) -> bool:
    resolved = path.expanduser().resolve()
    return resolved == REPO_ROOT or REPO_ROOT in resolved.parents


@dataclass(frozen=True, kw_only=True)
class RunConfig:
    out: Path
    tier: str = "smoke"
    reps: int = 1
    seed: int = 0
    style: str = HeadStyle.PER_PART_EN.value
    threads: int = DEFAULT_THREADS
    max_calls: int | None = None
    budget_usd: float | None = None
    usd_per_mtok_in: float | None = None
    usd_per_mtok_out: float | None = None
    resume: bool = False


@dataclass(frozen=True)
class RunSummary:
    planned: int
    answered: int
    unavailable: int
    asked: int  # questions sent to the driver in this invocation
    calls: int  # model calls over the whole results file
    stopped: str | None
    verdict: str
    out: Path


def _check(config: RunConfig) -> None:
    if inside_repo(config.out):
        raise RunError("out_inside_repository")
    if config.tier not in TIERS:
        raise RunError("unknown_tier")
    if config.reps < 1:
        raise RunError("reps_must_be_positive")
    if config.style not in {style.value for style in HeadStyle}:
        raise RunError("unknown_style")
    if config.max_calls is not None and config.max_calls < 0:
        raise RunError("max_calls_negative")
    if config.budget_usd is not None and (config.usd_per_mtok_in is None or config.usd_per_mtok_out is None):
        raise RunError("budget_needs_prices")


def select_questions(truth: Truth, tier: str) -> list[Question]:
    """Smoke: the first :data:`~.plan.SMOKE_THREADS` threads; standard and full: every question."""
    if tier == "smoke":
        smoke = {thread.thread_id for thread in truth.threads[:SMOKE_THREADS]}
        return [question for question in truth.questions if question.thread_id in smoke]
    return list(truth.questions)


def _contexts(dataset: Dataset, *, style: str, pseudonymize: bool) -> dict[tuple[str, str], DriverContext]:
    truth = dataset.truth
    sources = {
        "telegram": {thread.thread_id: thread for thread in dataset.telegram},
        "mail": mail_threads(truth, dataset.mail_mbox),
    }
    return {
        (source, thread_id): driver_context(thread, truth, source, style=style, pseudonymize=pseudonymize)
        for source, threads in sources.items()
        for thread_id, thread in threads.items()
    }


def _key(qid: str, rep: int) -> str:
    return f"{qid}#{rep}"


# ---------------------------------------------------------------------------
# Lines


def _answer_json(answer: Answer) -> dict[str, Any]:
    calls = None if answer.tool_calls is None else [dataclasses.asdict(call) for call in answer.tool_calls]
    if isinstance(answer, StructuredAnswer):
        claims = [dataclasses.asdict(claim) for claim in answer.claims]
        return {
            "kind": "structured",
            "outcome": str(answer.outcome),
            "text": answer.text,
            "claims": claims,
            "tool_calls": calls,
        }
    return {"kind": "free_text", "text": answer.text, "tool_calls": calls}


def _jsonable(value: Mapping[str, object]) -> Any:
    return json.loads(json.dumps(dict(value), ensure_ascii=False, default=str))


def _line(
    question: Question,
    rep: int,
    turn: Turn,
    *,
    identity: Mapping[str, object],
    settings: Mapping[str, object],
    score: QuestionScore | None,
    elapsed: float,
) -> dict[str, Any]:
    line: dict[str, Any] = {
        "v": LINE_VERSION,
        "key": _key(question.qid, rep),
        "qid": question.qid,
        "rep": rep,
        "source": question.source,
        "thread_id": question.thread_id,
        "template": str(question.template),
        "lang": question.lang,
        "expected": str(question.expected),
        "run": dict(identity),
        "calls": turn.calls,
        "input_tokens": turn.input_tokens,
        "output_tokens": turn.output_tokens,
        "elapsed_s": round(elapsed, 3),
        "meta": _jsonable(turn.meta),
        "settings": _jsonable(settings),
        "recorded_at": dt.datetime.now(tz=dt.UTC).isoformat(timespec="seconds"),
    }
    if isinstance(turn.answer, Unavailable) or score is None:
        reason = turn.answer.reason if isinstance(turn.answer, Unavailable) else "unscored"
        line.update(status="unavailable", reason=reason)
        return line
    line.update(
        status="answered", answer=_answer_json(turn.answer), score=dataclasses.asdict(score), correct=score.correct
    )
    return line


def _read_lines(path: Path) -> dict[str, dict[str, Any]]:
    """The last valid line per key (a torn last line, e.g. after a crash, is ignored)."""
    found: dict[str, dict[str, Any]] = {}
    try:
        text = path.read_text("utf-8")
    except FileNotFoundError:
        return found
    for raw in text.splitlines():
        try:
            line = json.loads(raw)
        except ValueError:
            continue
        if isinstance(line, dict) and isinstance(line.get("key"), str) and line.get("v") == LINE_VERSION:
            found[line["key"]] = line
    return found


def _identity(config: RunConfig, driver: EvalDriver) -> dict[str, object]:
    model = driver.describe().get("model")
    return {
        "driver": driver.name,
        "model": None if model is None else str(model),
        "style": config.style,
        "seed": config.seed,
        "threads": config.threads,
        "truth_version": TRUTH_VERSION,
        "pseudonymize": driver.pseudonymize,
    }


def _existing(config: RunConfig, identity: Mapping[str, object]) -> dict[str, dict[str, Any]]:
    path = config.out / RESULTS
    if not path.exists():
        return {}
    if not config.resume:
        raise RunError("results_exist")
    lines = _read_lines(path)
    if any(line.get("run") != dict(identity) for line in lines.values()):
        raise RunError("resume_mismatch")
    return lines


# ---------------------------------------------------------------------------
# Budget


@dataclass
class _Ledger:
    config: RunConfig
    calls: int = 0
    tokens_in: int = 0
    tokens_out: int = 0

    def add(self, line: Mapping[str, Any]) -> None:
        self.calls += int(line.get("calls") or 0)
        self.tokens_in += int(line.get("input_tokens") or 0)
        self.tokens_out += int(line.get("output_tokens") or 0)

    def cost(self, tokens_in: int, tokens_out: int) -> float:
        price_in = self.config.usd_per_mtok_in or 0.0
        price_out = self.config.usd_per_mtok_out or 0.0
        return (tokens_in * price_in + tokens_out * price_out) / _PER_MTOK

    def spent(self) -> float | None:
        if self.config.usd_per_mtok_in is None or self.config.usd_per_mtok_out is None:
            return None
        return self.cost(self.tokens_in, self.tokens_out)

    def stop(self, driver: EvalDriver, question: Question, context: DriverContext | None) -> str | None:
        """Why the next question may not run (``None``: it may)."""
        per = max(driver.max_calls_per_question, 1)
        limit = self.config.max_calls
        if limit is not None and self.calls + per > limit:
            return "max_calls"
        budget = self.config.budget_usd
        if budget is None:
            return None
        size = estimate_tokens(question.text) + (estimate_tokens(context.text) if context is not None else 0)
        next_cost = self.cost((size + _SYSTEM_TOKENS) * per, _OUTPUT_TOKENS * per)
        return "budget_usd" if self.cost(self.tokens_in, self.tokens_out) + next_cost > budget else None


# ---------------------------------------------------------------------------
# The run


@dataclass
class _Run:
    config: RunConfig
    driver: EvalDriver
    truth: Truth
    contexts: Mapping[tuple[str, str], DriverContext]
    identity: Mapping[str, object]
    lines: dict[str, dict[str, Any]]
    ledger: _Ledger
    asked: int = 0

    def ask(self, question: Question, rep: int) -> dict[str, Any]:
        context = self.contexts.get((question.source, question.thread_id))
        started = time.monotonic()
        turn = Turn(answer=Unavailable(reason="no_context")) if context is None else self.driver.run(question, context)
        score = None
        if not isinstance(turn.answer, Unavailable):
            score = score_answer(turn.answer, question, self.truth, context=context)
        self.asked += 1
        elapsed = time.monotonic() - started
        settings = self.driver.describe()  # after the turn: catalog and runtime versions are known then
        return _line(question, rep, turn, identity=self.identity, settings=settings, score=score, elapsed=elapsed)

    def loop(self, questions: Sequence[Question], sink: TextIO) -> str | None:
        for rep in range(self.config.reps):
            for question in questions:
                key = _key(question.qid, rep)
                if self.lines.get(key, {}).get("status") == "answered":
                    continue
                stopped = self.ledger.stop(
                    self.driver, question, self.contexts.get((question.source, question.thread_id))
                )
                if stopped is not None:
                    return stopped
                line = self.ask(question, rep)
                sink.write(json.dumps(line, ensure_ascii=False) + "\n")
                sink.flush()
                self.lines[key] = line
                self.ledger.add(line)
        return None


def _open_sink(path: Path) -> TextIO:
    """Append; first terminate a torn last line so the next line stays parseable."""
    if path.exists() and path.stat().st_size and not path.read_bytes().endswith(b"\n"):
        with path.open("a", encoding="utf-8") as handle:
            handle.write("\n")
    return path.open("a", encoding="utf-8")


def run_eval(config: RunConfig, driver: EvalDriver) -> RunSummary:
    """Ask every planned (question, repetition) not yet answered, then write the reports."""
    _check(config)
    dataset = generate(config.seed, n_threads=config.threads)
    identity = _identity(config, driver)
    lines = _existing(config, identity)
    ledger = _Ledger(config)
    for line in lines.values():
        ledger.add(line)
    contexts = _contexts(dataset, style=config.style, pseudonymize=driver.pseudonymize)
    run = _Run(config, driver, dataset.truth, contexts, identity, lines, ledger)
    questions = select_questions(dataset.truth, config.tier)
    config.out.mkdir(parents=True, exist_ok=True)
    with _open_sink(config.out / RESULTS) as sink:
        stopped = run.loop(questions, sink)
    cells = build_cells(lines, questions, config, driver.name)
    meta = _meta(config, driver, questions, lines, ledger, stopped)
    (config.out / REPORT_MD).write_text(render_markdown(cells, meta=meta), encoding="utf-8")
    (config.out / REPORT_JSON).write_text(report_json(cells, meta=meta), encoding="utf-8")
    planned = _planned(questions, config.reps)
    answered = sum(1 for key in planned if lines.get(key, {}).get("status") == "answered")
    unavailable = sum(1 for key in planned if lines.get(key, {}).get("status") == "unavailable")
    return RunSummary(
        planned=len(planned),
        answered=answered,
        unavailable=unavailable,
        asked=run.asked,
        calls=ledger.calls,
        stopped=stopped,
        verdict=combined_verdict(cells).value,
        out=config.out,
    )


# ---------------------------------------------------------------------------
# Reports


def _planned(questions: Iterable[Question], reps: int) -> list[str]:
    return [_key(question.qid, rep) for rep in range(reps) for question in questions]


def _score(line: Mapping[str, Any]) -> QuestionScore:
    return QuestionScore(**line["score"])


def build_cells(
    lines: Mapping[str, Mapping[str, Any]], questions: Sequence[Question], config: RunConfig, driver_name: str
) -> dict[str, Metrics | None]:
    """One cell per source; ``None`` (UNAVAILABLE) unless every planned line of the cell is answered."""
    cells: dict[str, Metrics | None] = {}
    for source in SOURCES:
        planned = _planned([q for q in questions if q.source == source], config.reps)
        if not planned:
            continue
        found = [lines.get(key) for key in planned]
        answered = [line for line in found if line is not None and line.get("status") == "answered"]
        name = f"{driver_name} / {source} / {config.style}"
        cells[name] = aggregate([_score(line) for line in answered]) if len(answered) == len(planned) else None
    return cells


def _distinct(lines: Iterable[Mapping[str, Any]], key: str) -> str:
    values = sorted({str(line.get("meta", {}).get(key)) for line in lines if line.get("meta", {}).get(key) is not None})
    return ", ".join(values) if values else "-"


def _meta(
    config: RunConfig,
    driver: EvalDriver,
    questions: Sequence[Question],
    lines: Mapping[str, Mapping[str, Any]],
    ledger: _Ledger,
    stopped: str | None,
) -> dict[str, str]:
    planned = _planned(questions, config.reps)
    found = [lines[key] for key in planned if key in lines]
    reasons = Counter(str(line.get("reason")) for line in found if line.get("status") == "unavailable")
    settings = {key: value for key, value in driver.describe().items() if key not in {"driver", "model"}}
    spent = ledger.spent()
    return {
        "driver": driver.name,
        "model": str(driver.describe().get("model")),
        "header style": config.style,
        "tier": config.tier,
        "seed": str(config.seed),
        "threads": str(config.threads),
        "truth version": str(TRUTH_VERSION),
        "repetitions": str(config.reps),
        "planned (question, repetition)": str(len(planned)),
        "answered": str(sum(1 for line in found if line.get("status") == "answered")),
        "unavailable": ", ".join(f"{reason} x{n}" for reason, n in reasons.most_common()) or "0",
        "not run": str(len(planned) - len(found)),
        "stopped by": stopped or "-",
        "model calls": str(ledger.calls),
        "tokens in/out": f"{ledger.tokens_in}/{ledger.tokens_out} (estimated unless the driver reports usage)",
        "estimated cost USD": "-" if spent is None else f"{spent:.4f}",
        "prompt digests": _distinct(found, "prompt_digest"),
        "driver settings": json.dumps(settings, ensure_ascii=False, sort_keys=True, default=str),
        "generated": dt.datetime.now(tz=dt.UTC).isoformat(timespec="seconds"),
    }


# ---------------------------------------------------------------------------
# Paired comparison of two runs (header A/B)


@dataclass(frozen=True)
class Comparison:
    labels: tuple[str, str]
    pairs: int
    result: McNemar
    ranking: list[str]
    metrics: dict[str, Metrics]


def _label(lines: Mapping[str, Mapping[str, Any]], fallback: str) -> str:
    run = next(iter(lines.values()), {}).get("run") or {}
    return f"{run.get('driver', '?')} / {run.get('style', '?')}" if run else fallback


def compare_runs(a_path: Path, b_path: Path) -> Comparison:
    """McNemar over the (question, repetition) keys answered in both files (same seed and truth version)."""
    a, b = _read_lines(a_path), _read_lines(b_path)
    if not a or not b:
        raise RunError("no_results")
    run_a, run_b = next(iter(a.values()))["run"], next(iter(b.values()))["run"]
    if any(run_a.get(key) != run_b.get(key) for key in ("seed", "threads", "truth_version")):
        raise RunError("not_paired")
    keys = sorted(k for k in a if k in b and a[k].get("status") == "answered" and b[k].get("status") == "answered")
    if not keys:
        raise RunError("no_paired_answers")
    label_a, label_b = _label(a, "A"), _label(b, "B")
    if label_a == label_b:
        label_a, label_b = f"{label_a} (A)", f"{label_b} (B)"
    metrics = {
        label_a: aggregate([_score(a[key]) for key in keys]),
        label_b: aggregate([_score(b[key]) for key in keys]),
    }
    result = compare([bool(a[key]["correct"]) for key in keys], [bool(b[key]["correct"]) for key in keys])
    return Comparison((label_a, label_b), len(keys), result, rank_styles(metrics), metrics)


def format_comparison(comparison: Comparison) -> str:
    label_a, label_b = comparison.labels
    r = comparison.result
    test = "exact binomial" if r.exact else "chi-square, continuity-corrected"
    lines = [
        f"Paired McNemar over {comparison.pairs} (question, repetition) pairs ({test}).",
        "",
        "| A | B | A only correct | B only correct | Both | Neither | Statistic | p |",
        "|---|---|---|---|---|---|---|---|",
        f"| {label_a} | {label_b} | {r.a_only} | {r.b_only} | {r.both} | {r.neither} "
        f"| {r.statistic:.3f} | {r.p_value:.4f} |",
        "",
        "Ranking (critical swaps, grounded-correct, correct abstention, rendered size):",
    ]
    lines += [f"{n}. {label}" for n, label in enumerate(comparison.ranking, start=1)]
    return "\n".join(lines) + "\n"
