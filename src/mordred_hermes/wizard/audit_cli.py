"""``hermes mordred audit {tail,grep}`` -- read-only audit log inspection.

Wizard owns READS over ``~/.hermes/mordred/audit.log``; privacy_check
remains the sole writer (PATHS.md). Phase 1 plaintext NDJSON only --
Phase 4 will swap the writer for an encrypted format; this reader
detects non-JSON headers and surfaces a "use audit decrypt (Phase 4)"
message instead of dumping garbage.

Naive read implementation (``read().splitlines()``) is acceptable v1
because :mod:`privacy_check.audit` enforces a 10 MB rotation cap.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Iterator
from pathlib import Path

from ._runtime import DEFAULT_AUDIT_LOG_PATH

__all__ = [
    "DEFAULT_AUDIT_LOG_PATH",
    "cli_grep",
    "cli_tail",
    "grep",
    "tail",
]


def _iter_lines(log_path: Path) -> Iterator[str] | None:
    """Yield non-empty lines from ``log_path``.

    Returns ``None`` when the log is missing or appears encrypted.
    The caller surfaces the appropriate stderr message + exit code.
    """
    if not log_path.exists():
        print(f"No audit log at {log_path}", file=sys.stderr)
        return None
    raw = log_path.read_bytes()
    if raw and raw[:1] != b"{":
        # Phase 1 plaintext NDJSON always starts with '{'. Anything else
        # is either an encrypted blob (Phase 4) or corruption.
        print(
            f"Audit log at {log_path} appears encrypted or corrupted; "
            "use `hermes mordred audit decrypt` (Phase 4) once available.",
            file=sys.stderr,
        )
        return None
    text = raw.decode("utf-8", errors="replace")
    return (ln for ln in text.splitlines() if ln.strip())


def tail(*, n: int, log_path: Path = DEFAULT_AUDIT_LOG_PATH) -> int:
    """Print the last ``n`` NDJSON entries from the audit log to stdout.

    Returns 0 on success, 1 when the log is absent or encrypted.
    """
    lines_iter = _iter_lines(log_path)
    if lines_iter is None:
        return 1
    lines = list(lines_iter)
    for line in lines[-max(n, 0) :]:
        print(line)
    return 0


def grep(*, pattern: str, log_path: Path = DEFAULT_AUDIT_LOG_PATH) -> int:
    """Print audit entries whose raw NDJSON matches ``pattern`` (Python regex).

    Returns 0 when at least one line matches, 1 on no matches / missing log,
    2 when the pattern is not a valid regex.
    """
    try:
        regex = re.compile(pattern)
    except re.error as e:
        print(f"invalid regex {pattern!r}: {e}", file=sys.stderr)
        return 2
    lines_iter = _iter_lines(log_path)
    if lines_iter is None:
        return 1
    hits = 0
    for line in lines_iter:
        if regex.search(line):
            print(line)
            hits += 1
    return 0 if hits else 1


# -----------------------------------------------------------------------------
# CLI adapters wired in cli.py.
# -----------------------------------------------------------------------------


def cli_tail(args: argparse.Namespace) -> int:
    return tail(n=int(args.lines), log_path=DEFAULT_AUDIT_LOG_PATH)


def cli_grep(args: argparse.Namespace) -> int:
    return grep(pattern=str(args.pattern), log_path=DEFAULT_AUDIT_LOG_PATH)
