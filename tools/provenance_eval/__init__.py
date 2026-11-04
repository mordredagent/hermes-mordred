"""Imported-message provenance evaluation harness (SPEC "Imported-message provenance evaluation").

Development tool only: type-checked with ``tools/`` and never shipped in the
wheel. This package generates a synthetic dataset (Telegram canonical records
plus an mbox the real mail collector parses), its versioned ground truth and
questions, scores structured and free-text answers, and checks the importers'
conformance without any model. Model drivers implement
:class:`~.answers.Driver` (PR 12).
"""

from __future__ import annotations

from .answers import DECOY_TOOLS, Answer, Claim, Driver, FreeTextAnswer, Outcome, StructuredAnswer, ToolCall
from .conformance import ConformanceReport, run_conformance
from .context import RenderedContext, mail_threads, render_context
from .generate import DEFAULT_THREADS, RENDER_CAP, Dataset, generate
from .metrics import Metrics, QuestionScore, Thresholds, Verdict, aggregate, verdict, wilson
from .report import compare, rank_styles, render_markdown, report_json
from .scenarios import SCENARIOS, ScenarioKind
from .score import score_answer, score_free_text, score_run, score_structured
from .truth import TRUTH_VERSION, Expected, Question, Template, Truth

__all__ = [
    "DECOY_TOOLS",
    "DEFAULT_THREADS",
    "RENDER_CAP",
    "SCENARIOS",
    "TRUTH_VERSION",
    "Answer",
    "Claim",
    "ConformanceReport",
    "Dataset",
    "Driver",
    "Expected",
    "FreeTextAnswer",
    "Metrics",
    "Outcome",
    "Question",
    "QuestionScore",
    "RenderedContext",
    "ScenarioKind",
    "StructuredAnswer",
    "Template",
    "Thresholds",
    "ToolCall",
    "Truth",
    "Verdict",
    "aggregate",
    "compare",
    "generate",
    "mail_threads",
    "rank_styles",
    "render_context",
    "render_markdown",
    "report_json",
    "run_conformance",
    "score_answer",
    "score_free_text",
    "score_run",
    "score_structured",
    "verdict",
    "wilson",
]
