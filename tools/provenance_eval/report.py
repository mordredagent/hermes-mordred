"""Markdown and JSON reports, the paired McNemar test and the header-style ranking.

``compare(a, b)`` takes per-question correctness of two header styles on the
SAME questions in the same order (paired). It uses the exact two-sided
binomial test when there are fewer than 25 discordant pairs, else the
continuity-corrected chi-square. Styles rank by critical swaps (fewer first),
then grounded-correct, then correct abstention (higher first), then rendered
size (smaller first).
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from .metrics import DEFAULT_THRESHOLDS, Metrics, Rate, Thresholds, cell_verdicts, combined_verdict, verdict

__all__ = ["McNemar", "compare", "rank_styles", "render_markdown", "report_json"]

_EXACT_BELOW = 25
_ROWS: tuple[tuple[str, str], ...] = (
    ("critical_swaps", "Critical owner/other swaps (questions)"),
    ("other_other", "Other/other misattribution + same-name merges"),
    ("quote_forward", "Quote/forward misattribution"),
    ("unsupported_claims", "Unsupported claims"),
    ("citation_validity", "Citation validity"),
    ("grounded_correct", "Grounded-correct (answerable)"),
    ("correct_abstention", "Correct abstention (required)"),
    ("over_abstention", "Over-abstention (answerable)"),
    ("forbidden_attempted", "Forbidden tool calls attempted"),
    ("forbidden_executed", "Forbidden tool calls executed"),
)


@dataclass(frozen=True)
class McNemar:
    a_only: int  # A correct, B wrong
    b_only: int  # B correct, A wrong
    both: int
    neither: int
    statistic: float
    p_value: float
    exact: bool


def compare(a_outcomes: Sequence[bool], b_outcomes: Sequence[bool]) -> McNemar:
    """Paired McNemar test of two styles' per-question correctness."""
    if len(a_outcomes) != len(b_outcomes):
        raise ValueError("outcomes must be paired")
    a_only = sum(1 for a, b in zip(a_outcomes, b_outcomes, strict=True) if a and not b)
    b_only = sum(1 for a, b in zip(a_outcomes, b_outcomes, strict=True) if b and not a)
    both = sum(1 for a, b in zip(a_outcomes, b_outcomes, strict=True) if a and b)
    neither = len(a_outcomes) - a_only - b_only - both
    discordant = a_only + b_only
    if discordant == 0:
        return McNemar(a_only, b_only, both, neither, 0.0, 1.0, True)
    if discordant < _EXACT_BELOW:
        tail = sum(math.comb(discordant, i) for i in range(min(a_only, b_only) + 1)) / 2**discordant
        return McNemar(a_only, b_only, both, neither, float(min(a_only, b_only)), min(1.0, 2 * tail), True)
    statistic = (abs(a_only - b_only) - 1) ** 2 / discordant
    return McNemar(a_only, b_only, both, neither, statistic, math.erfc(math.sqrt(statistic / 2)), False)


def rank_styles(results: Mapping[str, Metrics]) -> list[str]:
    """Style ids, best first."""

    def key(style: str) -> tuple[int, float, float, int, str]:
        metrics = results[style]
        return (
            metrics.critical_swap_events,
            -(metrics.grounded_correct.value or 0.0),
            -(metrics.correct_abstention.value or 0.0),
            metrics.rendered_chars,
            style,
        )

    return sorted(results, key=key)


def _fmt(rate: Rate | None) -> tuple[str, str, str]:
    if rate is None:
        return "not measured", "-", "-"
    value = rate.value
    interval = rate.interval
    shown = "-" if value is None else f"{value:.3f}"
    ci = "-" if interval is None else f"[{interval[0]:.3f}, {interval[1]:.3f}]"
    return f"{rate.k}/{rate.n}", shown, ci


def _cell_markdown(name: str, metrics: Metrics | None, thresholds: Thresholds) -> list[str]:
    lines = [f"### {name}", ""]
    if metrics is None:
        return [*lines, "Not run: **UNAVAILABLE**.", ""]
    gates = cell_verdicts(metrics, thresholds)
    lines += [
        f"Questions: {metrics.questions}. Critical swap events: {metrics.critical_swap_events}. "
        f"Forbidden calls attempted/executed: {metrics.forbidden_attempt_events}/"
        f"{metrics.forbidden_execution_events}. Rendered characters: {metrics.rendered_chars}.",
        "",
        "| Metric | k/n | Rate | Wilson 95% | Gate |",
        "|---|---|---|---|---|",
    ]
    for key, label in _ROWS:
        value = getattr(metrics, key)
        count, rate, ci = _fmt(value if isinstance(value, Rate) else None)
        gate = gates.get(key)
        lines.append(f"| {label} | {count} | {rate} | {ci} | {'' if gate is None else gate.value} |")
    lines += ["", f"Cell verdict: **{verdict(metrics, thresholds).value}**", ""]
    return lines


def render_markdown(
    cells: Mapping[str, Metrics | None],
    *,
    meta: Mapping[str, str],
    thresholds: Thresholds = DEFAULT_THRESHOLDS,
    title: str = "Provenance evaluation",
) -> str:
    """A Markdown report: run metadata, one table per cell, the overall verdict."""
    lines = [f"# {title}", ""]
    lines += [f"- {key}: {value}" for key, value in meta.items()]
    lines += [
        "",
        f"Thresholds: critical swaps <= {thresholds.max_critical_swaps}, grounded-correct >= "
        f"{thresholds.min_grounded_correct:.0%}, citation validity >= {thresholds.min_citation_validity:.0%}, "
        f"correct abstention >= {thresholds.min_correct_abstention:.0%}, forbidden executed <= "
        f"{thresholds.max_forbidden_executed}. A missing cell is UNAVAILABLE.",
        "",
    ]
    for name, metrics in cells.items():
        lines += _cell_markdown(name, metrics, thresholds)
    lines.append(f"Overall verdict: **{combined_verdict(cells, thresholds).value}**")
    return "\n".join(lines) + "\n"


def report_json(
    cells: Mapping[str, Metrics | None], *, meta: Mapping[str, str], thresholds: Thresholds = DEFAULT_THRESHOLDS
) -> str:
    data = {
        "meta": dict(meta),
        "thresholds": thresholds.__dict__,
        "cells": {
            name: None
            if metrics is None
            else {
                "metrics": metrics.as_dict(),
                "gates": {key: value.value for key, value in cell_verdicts(metrics, thresholds).items()},
                "verdict": verdict(metrics, thresholds).value,
            }
            for name, metrics in cells.items()
        },
        "verdict": combined_verdict(cells, thresholds).value,
    }
    return json.dumps(data, ensure_ascii=False, indent=1, sort_keys=True) + "\n"
