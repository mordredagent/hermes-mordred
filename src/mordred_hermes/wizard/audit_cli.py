"""``hermes-mordred audit {tail,grep,decrypt,purge}`` -- audit log CLI.

Wizard owns READS over ``~/.hermes/mordred/audit.log``; privacy_check
remains the sole writer (PATHS.md). ``tail`` / ``grep`` read the Phase 1
plaintext NDJSON format; ``decrypt`` reads the Phase 4 ``MRAL``
AES-GCM-encrypted format through the Secure Enclave authorization
boundary. The plaintext reader detects an encrypted (``MRAL``) or corrupt
log and points the operator at ``audit decrypt`` instead of dumping
garbage.

Naive read implementation (``read().splitlines()``) is acceptable v1
because :mod:`privacy_check.audit` enforces a 10 MB rotation cap.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Callable, Iterator
from datetime import UTC, date, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..privacy_check._runtime import get_active_audit_path
from ._runtime import DEFAULT_AUDIT_LOG_PATH

if TYPE_CHECKING:
    from ..keyvault.wrap import NativeBackend

#: Sink shape for the DEK-unwrap audit entry emitted by ``decrypt_log_file``.
AuditSink = Callable[[dict[str, Any]], None]

__all__ = [
    "DEFAULT_AUDIT_LOG_PATH",
    "cli_decrypt",
    "cli_grep",
    "cli_purge",
    "cli_tail",
    "decrypt",
    "grep",
    "purge",
    "tail",
]

# The active audit log file name; rotated files are ``audit.log.<date>[...]``.
_AUDIT_LOG_NAME = "audit.log"

# Phase 4 ``MRAL`` encrypted-log format tag. Mirrors
# ``keyvault.log_encryption.MAGIC`` (b"MRAL") — kept as a literal so the
# stdlib-only tail/grep read path carries no keyvault/cryptography import
# (the keyvault crypto stack is macOS-extra-gated; see this module's
# docstring on platform-independent reads).
_MRAL_FMT = "MRAL"


def _looks_like_mral_header(first_line: bytes) -> bool:
    """Return True if ``first_line`` is a Phase 4 ``MRAL`` encrypted-log header.

    The ``MRAL`` format's line 0 is a JSON header
    (``{"fmt":"MRAL","ver":...,"key_id":...,"wdek":...}``), so — unlike a
    raw binary blob — it *does* start with ``{`` and would slip past a
    first-byte check. Detection therefore keys off the ``fmt`` field. A
    genuine NDJSON audit entry is also a JSON object but never carries
    ``fmt == "MRAL"``.
    """
    if first_line[:1] != b"{":
        return False
    try:
        header = json.loads(first_line)
    except ValueError:  # JSONDecodeError / UnicodeDecodeError both subclass it
        return False
    return isinstance(header, dict) and header.get("fmt") == _MRAL_FMT


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
    if raw:
        first_line = raw.split(b"\n", 1)[0]
        # Reject anything that is not Phase 1 plaintext NDJSON. Two cases:
        # a non-``{`` first byte (a raw binary blob or corruption), and a
        # Phase 4 ``MRAL`` log — whose JSON header *also* starts with ``{``,
        # so the byte check alone would wave it through (see
        # _looks_like_mral_header).
        if first_line[:1] != b"{" or _looks_like_mral_header(first_line):
            print(
                f"Audit log at {log_path} appears encrypted or corrupted; "
                "use `hermes-mordred audit decrypt --date YYYY-MM-DD` to read an encrypted log.",
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


def _resolve_decrypt_targets(directory: Path, target: date) -> list[Path]:
    """Return the encrypted-log files holding ``target``'s entries.

    Rotated files are ``audit.log.<date>[.N][.gz]``; the active
    ``audit.log`` holds the current UTC day until it rotates, so it is
    included only when ``target`` is today.
    """
    if not directory.exists():
        return []
    rotated_prefix = f"{_AUDIT_LOG_NAME}.{target.isoformat()}"
    targets = [
        child
        for child in sorted(directory.iterdir())
        if child.is_file() and (child.name == rotated_prefix or child.name.startswith(rotated_prefix + "."))
    ]
    if target == datetime.now(UTC).date():
        active = directory / _AUDIT_LOG_NAME
        if active.is_file():
            targets.append(active)
    return targets


def _stderr_unwrap_sink(entry: dict[str, Any]) -> None:
    """Surface the DEK-unwrap authorization decision to the operator.

    ``decrypt_log_file`` records ``keyvault.unwrap_authorized`` /
    ``keyvault.unwrap_denied`` through this sink. ``audit decrypt`` is an
    explicit, biometric-gated operator action over their own log, so v1
    surfaces the decision on stderr rather than re-appending it into the
    audit log — re-appending would need the encrypted writer and risk a
    plaintext/ciphertext mismatch. Persisted decrypt-operation auditing
    is a documented v2 follow-up.
    """
    event = entry.get("event", "?")
    decision = entry.get("decision", "?")
    print(f"[audit] {event} decision={decision}", file=sys.stderr)


def decrypt(
    *,
    date: str,
    audit_dir: Path | None = None,
    backend: NativeBackend | None = None,
    audit_sink: AuditSink | None = None,
) -> int:
    """Decrypt the ``MRAL``-encrypted audit log file(s) for one UTC date.

    Prints every entry as a canonical JSON line, oldest first. Resolves
    rotated ``audit.log.<date>[.N][.gz]`` files plus — when ``date`` is
    today (UTC) — the active ``audit.log``.

    ``backend=None`` constructs the production Secure-Enclave backend;
    tests inject a software backend. ``audit_dir=None`` resolves the
    directory of the active writer path.

    Returns:
        0  every resolved file decrypted;
        1  no file for the date, a corrupt file, a denied Enclave
           prompt, or a missing wrapping key;
        2  ``date`` is not a valid ``YYYY-MM-DD`` date.
    """
    try:
        target = datetime.strptime(date, "%Y-%m-%d").date()
    except ValueError:
        print(f"invalid --date {date!r}: expected YYYY-MM-DD", file=sys.stderr)
        return 2

    directory = audit_dir if audit_dir is not None else _resolve_active_audit_path().parent
    targets = _resolve_decrypt_targets(directory, target)
    if not targets:
        print(f"No audit log file found for {date} under {directory}", file=sys.stderr)
        return 1

    from ..keyvault import log_encryption
    from ..keyvault._exceptions import WrapAuthCancelled, WrapKeyNotFound

    if backend is None:
        from ..keyvault._seckey_backend import _SecKeyBackend

        backend = _SecKeyBackend()
    sink = audit_sink if audit_sink is not None else _stderr_unwrap_sink

    rc = 0
    for path in targets:
        try:
            entries = log_encryption.decrypt_log_file(path, backend=backend, audit_sink=sink)
        except WrapAuthCancelled:
            print(f"{path.name}: Secure Enclave authorization was cancelled", file=sys.stderr)
            return 1
        except WrapKeyNotFound:
            print(
                f"{path.name}: audit-log wrapping key not found — is the keyvault initialized?",
                file=sys.stderr,
            )
            return 1
        except log_encryption.AuditLogDecryptError as exc:
            print(f"{path.name}: {exc}", file=sys.stderr)
            rc = 1
            continue
        plural = "entry" if len(entries) == 1 else "entries"
        print(f"# {path.name} — {len(entries)} {plural}")
        for entry in entries:
            print(json.dumps(entry, ensure_ascii=False, sort_keys=True))
    return rc


# -----------------------------------------------------------------------------
# CLI adapters wired in cli.py.
# -----------------------------------------------------------------------------


def cli_tail(args: argparse.Namespace) -> int:
    return tail(n=int(args.lines))


def cli_grep(args: argparse.Namespace) -> int:
    return grep(pattern=str(args.pattern))


def cli_purge(args: argparse.Namespace) -> int:
    return purge(before=str(args.before))


def cli_decrypt(args: argparse.Namespace) -> int:
    return decrypt(date=str(args.date))
