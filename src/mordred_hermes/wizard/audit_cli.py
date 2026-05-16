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
from datetime import datetime
from pathlib import Path

from ..privacy_check._runtime import get_active_audit_path
from ._runtime import DEFAULT_AUDIT_LOG_PATH

__all__ = [
    "DEFAULT_AUDIT_LOG_PATH",
    "cli_grep",
    "cli_purge",
    "cli_tail",
    "grep",
    "purge",
    "tail",
]

# The active audit log file name; rotated files are ``audit.log.<date>[...]``.
_AUDIT_LOG_NAME = "audit.log"


def _resolve_active_audit_path() -> Path:
    """Indirection seam over :func:`get_active_audit_path`.

    Production: returns the same path the install hook's writer uses
    (Codex P2 fix -- tail/grep must not drift from the writer when a
    custom ``audit_log_path`` is configured). Tests can monkeypatch this
    attribute to point at a tmp_path log.
    """
    return get_active_audit_path()


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


def tail(*, n: int, log_path: Path | None = None) -> int:
    """Print the last ``n`` NDJSON entries from the audit log to stdout.

    Returns 0 on success, 1 when the log is absent or encrypted.

    ``log_path=None`` (the default) resolves the active writer path via
    :func:`_resolve_active_audit_path` so direct callers cannot drift from
    ``hermes-mordred audit tail`` when a custom ``audit_log_path`` is
    configured. Explicit paths are honoured as-is (tests / one-off probes).

    ``n <= 0`` is treated as "print nothing" -- the obvious user intent.
    Without the early return, ``lines[-max(n, 0):]`` evaluates to
    ``lines[0:]`` and dumps the whole log (Python negative-zero slice).
    """
    resolved = log_path if log_path is not None else _resolve_active_audit_path()
    if n <= 0:
        # Still surface "missing log" / "encrypted" errors even when n=0
        # so users can probe the log's readability with -n 0.
        if _iter_lines(resolved) is None:
            return 1
        return 0
    lines_iter = _iter_lines(resolved)
    if lines_iter is None:
        return 1
    lines = list(lines_iter)
    for line in lines[-n:]:
        print(line)
    return 0


def grep(*, pattern: str, log_path: Path | None = None) -> int:
    """Print audit entries whose raw NDJSON matches ``pattern`` (Python regex).

    Returns 0 when at least one line matches, 1 on no matches / missing log,
    2 when the pattern is not a valid regex.

    ``log_path=None`` (the default) resolves the active writer path -- same
    rationale as :func:`tail`.
    """
    try:
        regex = re.compile(pattern)
    except re.error as e:
        print(f"invalid regex {pattern!r}: {e}", file=sys.stderr)
        return 2
    resolved = log_path if log_path is not None else _resolve_active_audit_path()
    lines_iter = _iter_lines(resolved)
    if lines_iter is None:
        return 1
    hits = 0
    for line in lines_iter:
        if regex.search(line):
            print(line)
            hits += 1
    return 0 if hits else 1


def purge(*, before: str, audit_dir: Path | None = None) -> int:
    """Delete rotated audit-log files dated strictly before ``before``.

    ``before`` is a ``YYYY-MM-DD`` date; rotated files named
    ``audit.log.<date>[.N][.gz]`` whose date is < ``before`` are removed.
    The active ``audit.log`` is never touched, and a file whose suffix is
    not a parseable date (e.g. ``audit.log.backup``) is left alone.

    This is the manual cleanup path for pre-Phase-4 plaintext audit
    history (PATHS.md §Consumer CLI) — the operator picks the cutoff.

    Returns 0 on success (including "nothing matched"), 2 when ``before``
    is not a valid ``YYYY-MM-DD`` date.

    ``audit_dir=None`` resolves the directory of the active writer path,
    so the CLI cannot drift from where rotations actually land.
    """
    try:
        cutoff = datetime.strptime(before, "%Y-%m-%d").date()
    except ValueError:
        print(f"invalid --before date {before!r}: expected YYYY-MM-DD", file=sys.stderr)
        return 2

    directory = audit_dir if audit_dir is not None else _resolve_active_audit_path().parent
    prefix = _AUDIT_LOG_NAME + "."
    deleted = 0
    if directory.exists():
        for child in sorted(directory.iterdir()):
            if child.name == _AUDIT_LOG_NAME or not child.name.startswith(prefix):
                continue
            date_token = child.name[len(prefix) :].split(".", 1)[0]
            try:
                file_date = datetime.strptime(date_token, "%Y-%m-%d").date()
            except ValueError:
                continue  # not a dated rotation file — leave it alone
            if file_date < cutoff:
                try:
                    child.unlink()
                except OSError as exc:
                    print(f"could not purge {child.name}: {exc}", file=sys.stderr)
                    continue
                print(f"purged {child.name}")
                deleted += 1
    print(f"{deleted} rotated audit log file(s) purged.")
    return 0


# -----------------------------------------------------------------------------
# CLI adapters wired in cli.py.
# -----------------------------------------------------------------------------


def cli_tail(args: argparse.Namespace) -> int:
    return tail(n=int(args.lines))


def cli_grep(args: argparse.Namespace) -> int:
    return grep(pattern=str(args.pattern))


def cli_purge(args: argparse.Namespace) -> int:
    return purge(before=str(args.before))
