"""Call and token estimates per tier, without calling any model.

Input tokens are estimated as UTF-8 bytes / 3 of the reference rendering
plus the question and a fixed system-prompt allowance; a Hermes question is
assumed to take three model turns that each resend the context. These are
planning numbers for ``--max-calls`` / ``--budget-usd``, not measurements.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from mordred_hermes.imports.render import HeadStyle

from .context import RenderedContext, mail_threads, render_context
from .generate import Dataset
from .truth import Question

__all__ = ["SMOKE_THREADS", "TIERS", "PlanRow", "estimate", "format_plan"]

TIERS: Final = ("smoke", "standard", "full")
SMOKE_THREADS: Final = 5
_SYSTEM_TOKENS: Final = 600
_OUTPUT_TOKENS: Final = 300
_HERMES_TURNS: Final = 3
_BYTES_PER_TOKEN: Final = 3


@dataclass(frozen=True)
class PlanRow:
    tier: str
    driver: str
    styles: int
    reps: int
    questions: int
    calls: int
    input_tokens: int
    output_tokens: int


def _contexts(dataset: Dataset) -> dict[tuple[str, str], RenderedContext]:
    truth = dataset.truth
    sources = {
        "telegram": {thread.thread_id: thread for thread in dataset.telegram},
        "mail": mail_threads(truth, dataset.mail_mbox),
    }
    return {
        (source, thread_id): render_context(thread, truth, source)
        for source, threads in sources.items()
        for thread_id, thread in threads.items()
    }


def _tokens(question: Question, contexts: dict[tuple[str, str], RenderedContext]) -> int:
    context = contexts.get((question.source, question.thread_id))
    size = len(question.text.encode()) + (len(context.text.encode()) if context is not None else 0)
    return size // _BYTES_PER_TOKEN + _SYSTEM_TOKENS


def _row(tier: str, driver: str, styles: int, reps: int, questions: Sequence[Question], per_question: int) -> PlanRow:
    turns = _HERMES_TURNS if driver == "hermes" else 1
    calls = len(questions) * styles * reps * turns
    return PlanRow(
        tier=tier,
        driver=driver,
        styles=styles,
        reps=reps,
        questions=len(questions),
        calls=calls,
        input_tokens=per_question * styles * reps * turns,
        output_tokens=calls * _OUTPUT_TOKENS,
    )


def estimate(dataset: Dataset, tier: str, *, reps: int = 3) -> list[PlanRow]:
    """Rows per driver for ``tier`` (``smoke`` | ``standard`` | ``full``)."""
    if tier not in TIERS:
        raise ValueError("unknown_tier")
    contexts = _contexts(dataset)
    questions = list(dataset.truth.questions)
    if tier == "smoke":
        smoke = {thread.thread_id for thread in dataset.truth.threads[:SMOKE_THREADS]}
        questions = [question for question in questions if question.thread_id in smoke]
    total = sum(_tokens(question, contexts) for question in questions)
    if tier == "smoke":
        return [_row(tier, "privacy", 1, 1, questions, total), _row(tier, "hermes", 1, 1, questions, total)]
    if tier == "standard":
        return [_row(tier, "privacy", 1, reps, questions, total)]
    return [
        _row(tier, "privacy", len(HeadStyle), reps, questions, total),
        _row(tier, "hermes", 2, reps, questions, total),
    ]


def format_plan(rows: Sequence[PlanRow]) -> str:
    lines = [
        "| Tier | Driver | Styles | Reps | Questions | Calls | Input tokens (est.) | Output tokens (est.) |",
        "|---|---|---|---|---|---|---|---|",
    ]
    lines += [
        f"| {row.tier} | {row.driver} | {row.styles} | {row.reps} | {row.questions} | {row.calls} | "
        f"{row.input_tokens} | {row.output_tokens} |"
        for row in rows
    ]
    return "\n".join(lines)
