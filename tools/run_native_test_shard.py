#!/usr/bin/env python3
"""Run one deterministic, duration-balanced shard of whole native test modules."""

from __future__ import annotations

import argparse
import json
import math
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

DEFAULT_SECONDS = 1.0


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate weight key: {key}")
        result[key] = value
    return result


def load_weights(path: Path) -> dict[str, float]:
    """Read measured seconds; reject corrupt inputs instead of changing coverage."""
    raw = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    if not isinstance(raw, dict) or not isinstance(raw.get("seconds"), dict) or not raw["seconds"]:
        raise ValueError("weights must contain a nonempty seconds object")
    weights: dict[str, float] = {}
    for module, value in raw["seconds"].items():
        if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value) or value <= 0:
            raise ValueError(f"invalid positive finite duration for {module}: {value!r}")
        weights[module] = float(value)
    return weights


def shard_modules(modules: Sequence[str], weights: Mapping[str, float], count: int) -> list[list[str]]:
    """LPT assignment with selector-order ties and order preserved within shards.

    Unknown modules receive one second rather than disappearing. Whole modules
    stay on one runner, so native locks, processes and fixtures never compete
    with another shard on the same host.
    """
    if not modules or len(modules) != len(set(modules)):
        raise ValueError("selector must be nonempty and contain no duplicate modules")
    if count < 1 or count > len(modules):
        raise ValueError("shard count must be positive and cannot create empty shards")
    totals = [0.0] * count
    assignments: dict[str, int] = {}
    for module in sorted(modules, key=lambda module: -weights.get(module, DEFAULT_SECONDS)):
        index = min(range(count), key=lambda index: (totals[index], index))
        assignments[module] = index
        totals[index] += weights.get(module, DEFAULT_SECONDS)
    return [[module for module in modules if assignments[module] == index] for index in range(count)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shard-index", required=True, type=int, help="one-based shard index")
    parser.add_argument("--shard-count", required=True, type=int)
    parser.add_argument("--weights", type=Path, default=Path(__file__).with_name("native_test_durations.json"))
    parser.add_argument("--junitxml", required=True, type=Path)
    parser.add_argument("modules", nargs="+")
    args = parser.parse_args(argv)
    try:
        if not 1 <= args.shard_index <= args.shard_count:
            raise ValueError("shard index must be between 1 and shard count")
        weights = load_weights(args.weights)
        shards = shard_modules(args.modules, weights, args.shard_count)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    selected = shards[args.shard_index - 1]
    estimates = [round(sum(weights.get(module, DEFAULT_SECONDS) for module in shard), 3) for shard in shards]
    unknown = [module for module in args.modules if module not in weights]
    print(
        f"Shard {args.shard_index}/{args.shard_count}: {len(selected)} modules; estimated seconds {estimates}",
        flush=True,
    )
    if unknown:
        print(f"Unmeasured modules use {DEFAULT_SECONDS}s each: {', '.join(unknown)}", flush=True)
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-o",
            "addopts=",
            "--durations=20",
            f"--junitxml={args.junitxml}",
            *selected,
        ],
        check=False,
    ).returncode


if __name__ == "__main__":
    sys.exit(main())
