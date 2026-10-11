#!/usr/bin/env python3
"""Classify CI events: known draft feedback or full regression by default."""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Mapping
from pathlib import Path

DRAFT_ACTIONS = {"opened", "synchronize", "reopened", "converted_to_draft"}


def full_suite(event_name: str, event: Mapping[str, object]) -> bool:
    pr = event.get("pull_request")
    action = event.get("action")
    return not (
        event_name == "pull_request"
        and isinstance(action, str)
        and action in DRAFT_ACTIONS
        and isinstance(pr, dict)
        and pr.get("draft") is True
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event-name", default=os.environ.get("GITHUB_EVENT_NAME"))
    parser.add_argument("--event-path", type=Path, default=os.environ.get("GITHUB_EVENT_PATH"))
    parser.add_argument("--github-output", type=Path, default=os.environ.get("GITHUB_OUTPUT"))
    args = parser.parse_args(argv)
    if not args.event_name or not args.event_path:
        parser.error("event name and event path are required")
    event = json.loads(args.event_path.read_text(encoding="utf-8"))
    if not isinstance(event, dict):
        parser.error("event payload must be an object")
    full = full_suite(args.event_name, event)
    output = f"full={str(full).lower()}\ncritical={str(not full).lower()}\n"
    print("Full regression" if full else "Draft critical feedback; full acceptance pending")
    if args.github_output is not None:
        with args.github_output.open("a", encoding="utf-8") as stream:
            stream.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
