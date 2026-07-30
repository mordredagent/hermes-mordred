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
import os
import re
import stat
import sys
from collections.abc import Iterator
from datetime import UTC, date, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .._audit_io import exclusive_audit_lock as _exclusive_audit_lock
from ..privacy_check._runtime import get_active_audit_path
from . import _term
from ._defaults import resolve_backend
from ._runtime import DEFAULT_AUDIT_LOG_PATH

if TYPE_CHECKING:
    # Annotation-only: importing ``keyvault.wrap`` at runtime would pull the
    # ``cryptography`` stack, which minimal installs (no ``[keyvault]`` extra)
    # don't have — and tail/grep/purge must keep working there.
    from ..keyvault.wrap import AuditSink, NativeBackend

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
_ROTATED_AUDIT_NAME = re.compile(r"^audit\.log\.(?P<date>\d{4}-\d{2}-\d{2})(?:\.\d+)?(?:\.gz)?$")

# Phase 4 ``MRAL`` encrypted-log format tag. Mirrors
# ``keyvault.log_encryption.MAGIC`` (b"MRAL") — kept as a literal so the
# stdlib-only tail/grep read path carries no keyvault/cryptography import
# (the keyvault crypto stack is macOS-extra-gated; see this module's
# docstring on platform-independent reads).
_MRAL_FMT = "MRAL"


class _UnsafeAuditDirectoryError(RuntimeError):
    """Raised when an audit operation cannot safely bind to its directory."""


class _UnsafeAuditFileError(RuntimeError):
    """Raised when an audit read target is not a stable regular file."""


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


def _read_regular_audit_entry(*, directory_fd: int, name: str, display_path: Path) -> bytes | None:
    """Read one directory entry without following a symlink or opening a FIFO.

    ``None`` means the entry genuinely disappeared or never existed.  Both the
    pre-open metadata and the opened descriptor must identify the same regular
    inode; reads then happen through that descriptor, not through the pathname.
    """
    try:
        path_meta = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise _UnsafeAuditFileError(f"could not safely inspect audit log {display_path}: {exc}") from exc
    if not stat.S_ISREG(path_meta.st_mode):
        raise _UnsafeAuditFileError(f"refusing to read non-regular audit log: {display_path}")

    open_flags = os.O_RDONLY
    open_flags |= getattr(os, "O_CLOEXEC", 0)
    open_flags |= getattr(os, "O_NOFOLLOW", 0)
    open_flags |= getattr(os, "O_NONBLOCK", 0)
    try:
        file_fd = os.open(name, open_flags, dir_fd=directory_fd)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise _UnsafeAuditFileError(f"could not safely open audit log {display_path}: {exc}") from exc

    try:
        opened_meta = os.fstat(file_fd)
        if (
            not stat.S_ISREG(opened_meta.st_mode)
            or opened_meta.st_dev != path_meta.st_dev
            or opened_meta.st_ino != path_meta.st_ino
        ):
            raise _UnsafeAuditFileError(f"refusing to read audit log changed while opening: {display_path}")
        chunks: list[bytes] = []
        while chunk := os.read(file_fd, 65_536):
            chunks.append(chunk)
        return b"".join(chunks)
    except OSError as exc:
        raise _UnsafeAuditFileError(f"could not safely read audit log {display_path}: {exc}") from exc
    finally:
        os.close(file_fd)


def _read_audit_path(log_path: Path) -> bytes | None:
    """Securely read a standalone audit path relative to its bound parent."""
    directory_fd = _open_real_audit_directory(log_path.parent)
    if directory_fd is None:
        return None
    try:
        return _read_regular_audit_entry(
            directory_fd=directory_fd,
            name=log_path.name,
            display_path=log_path,
        )
    finally:
        os.close(directory_fd)


def _iter_lines(log_path: Path) -> Iterator[str] | None:
    """Yield non-empty lines from ``log_path``.

    Returns ``None`` when the log is missing or appears encrypted.
    The caller surfaces the appropriate stderr message + exit code.
    """
    try:
        raw = _read_audit_path(log_path)
    except (_UnsafeAuditDirectoryError, _UnsafeAuditFileError) as exc:
        _term.emit_error(str(exc))
        return None
    if raw is None:
        _term.emit_error(f"No audit log at {log_path}")
        return None
    if raw:
        first_line = raw.split(b"\n", 1)[0]
        # Reject anything that is not Phase 1 plaintext NDJSON. Two cases:
        # a non-``{`` first byte (a raw binary blob or corruption), and a
        # Phase 4 ``MRAL`` log — whose JSON header *also* starts with ``{``,
        # so the byte check alone would wave it through (see
        # _looks_like_mral_header).
        if first_line[:1] != b"{" or _looks_like_mral_header(first_line):
            _term.emit_error(
                f"Audit log at {log_path} appears encrypted or corrupted; "
                "use `hermes-mordred audit decrypt --date YYYY-MM-DD` to read an encrypted log."
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
        _term.emit_error(f"invalid regex {pattern!r}: {e}")
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


def _open_real_audit_directory(directory: Path) -> int | None:
    """Open ``directory`` without following an endpoint symlink.

    ``None`` means the directory genuinely does not exist.  The descriptor is
    bound to the inode checked by ``lstat`` so subsequent purge operations can
    remain relative to it even if the pathname is concurrently replaced.
    """
    try:
        directory_meta = directory.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise _UnsafeAuditDirectoryError(f"could not inspect audit directory {directory}: {exc}") from exc
    if not stat.S_ISDIR(directory_meta.st_mode):
        raise _UnsafeAuditDirectoryError(
            f"refusing audit operation: audit directory is not a real directory: {directory}"
        )

    open_flags = os.O_RDONLY
    open_flags |= getattr(os, "O_CLOEXEC", 0)
    open_flags |= getattr(os, "O_DIRECTORY", 0)
    open_flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        directory_fd = os.open(directory, open_flags)
    except OSError as exc:
        raise _UnsafeAuditDirectoryError(f"could not safely open audit directory {directory}: {exc}") from exc

    try:
        opened_meta = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(opened_meta.st_mode)
            or opened_meta.st_dev != directory_meta.st_dev
            or opened_meta.st_ino != directory_meta.st_ino
        ):
            raise _UnsafeAuditDirectoryError(
                f"refusing audit operation: audit directory changed while opening: {directory}"
            )
    except (OSError, _UnsafeAuditDirectoryError):
        os.close(directory_fd)
        raise
    return directory_fd


def _audit_entry_names(directory_fd: int, directory: Path) -> list[str]:
    """Return sorted entry names from the already-bound audit directory."""
    try:
        with os.scandir(directory_fd) as entries:
            return sorted(entry.name for entry in entries)
    except OSError as exc:
        raise _UnsafeAuditDirectoryError(f"could not inspect audit directory {directory}: {exc}") from exc


def _purge_rotated_entry(*, name: str, cutoff: date, directory_fd: int) -> tuple[int, int]:
    """Purge one eligible regular entry, returning ``(deleted, failed)``."""
    match = _ROTATED_AUDIT_NAME.fullmatch(name)
    if match is None:
        return 0, 0
    try:
        file_date = datetime.strptime(match.group("date"), "%Y-%m-%d").date()
    except ValueError:
        return 0, 0
    if file_date >= cutoff:
        return 0, 0

    try:
        child_meta = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return 0, 0  # another cleanup process already removed it
    except OSError as exc:
        _term.emit_error(f"could not inspect purge candidate {name}: {exc}")
        return 0, 1
    if not stat.S_ISREG(child_meta.st_mode):
        _term.emit_error(f"refusing to purge non-regular audit entry: {name}")
        return 0, 1

    try:
        os.unlink(name, dir_fd=directory_fd)
    except OSError as exc:
        _term.emit_error(f"could not purge {name}: {exc}")
        return 0, 1
    print(f"purged {name}")
    return 1, 0


def purge(*, before: str, audit_dir: Path | None = None) -> int:
    """Delete rotated audit-log files dated strictly before ``before``.

    ``before`` is a ``YYYY-MM-DD`` date; rotated files named
    ``audit.log.<date>[.N][.gz]`` whose date is < ``before`` are removed.
    The active ``audit.log`` is never touched, and a file whose suffix is
    not a parseable date (e.g. ``audit.log.backup``) is left alone.

    This is the manual cleanup path for pre-Phase-4 plaintext audit
    history (PATHS.md §Consumer CLI) — the operator picks the cutoff.

    Returns 0 on success (including "nothing matched"), 1 when the audit
    directory or a deletion candidate cannot be handled safely, and 2 when
    ``before`` is not a valid ``YYYY-MM-DD`` date.

    ``audit_dir=None`` resolves the directory of the active writer path,
    so the CLI cannot drift from where rotations actually land.
    """
    try:
        cutoff = datetime.strptime(before, "%Y-%m-%d").date()
    except ValueError:
        _term.emit_error(f"invalid --before date {before!r}: expected YYYY-MM-DD")
        return 2

    directory = audit_dir if audit_dir is not None else _resolve_active_audit_path().parent
    deleted = 0
    failed = 0

    # ``Path.exists()`` follows symlinks.  That is unsafe for a destructive
    # command: an audit-dir symlink could otherwise make purge delete matching
    # files in an unrelated directory.  Require a real directory, then keep an
    # O_NOFOLLOW directory descriptor open so a later path swap cannot redirect
    # child inspection or deletion.
    try:
        directory_fd = _open_real_audit_directory(directory)
    except _UnsafeAuditDirectoryError as exc:
        _term.emit_error(str(exc))
        return 1
    if directory_fd is None:
        print("0 rotated audit log file(s) purged.")
        return 0

    try:
        try:
            names = _audit_entry_names(directory_fd, directory)
        except _UnsafeAuditDirectoryError as exc:
            _term.emit_error(str(exc))
            return 1

        for name in names:
            entry_deleted, entry_failed = _purge_rotated_entry(
                name=name,
                cutoff=cutoff,
                directory_fd=directory_fd,
            )
            deleted += entry_deleted
            failed += entry_failed
    finally:
        os.close(directory_fd)

    print(f"{deleted} rotated audit log file(s) purged.")
    return 1 if failed else 0


def _read_decrypt_targets(directory: Path, target: date) -> list[tuple[Path, bytes]]:
    """Securely snapshot the encrypted-log files holding ``target``'s entries.

    Rotated files are ``audit.log.<date>[.N][.gz]``; the active
    ``audit.log`` holds the current UTC day until it rotates, so it is
    included only when ``target`` is today.  The directory remains bound by
    descriptor while every candidate is opened with ``O_NOFOLLOW`` and checked
    as a regular file, preventing a symlinked directory/entry or FIFO from
    redirecting or blocking the read.
    """
    directory_fd = _open_real_audit_directory(directory)
    if directory_fd is None:
        return []
    try:
        # Writers hold this stable sidecar across append rollback, rotation,
        # gzip, and retention. Snapshot the name set and every selected inode
        # under the same lock so a partial base64 line or in-progress gzip is
        # never misreported as audit-log corruption. The lock is released
        # before DEK unwrap: its audit sink may itself append to audit.log, and
        # advisory flock recursion is not supported by this helper.
        with _exclusive_audit_lock(directory / _AUDIT_LOG_NAME):
            names = _audit_entry_names(directory_fd, directory)
            target_iso = target.isoformat()
            target_names = []
            for name in names:
                match = _ROTATED_AUDIT_NAME.fullmatch(name)
                if match is not None and match.group("date") == target_iso:
                    target_names.append(name)
            if target == datetime.now(UTC).date() and _AUDIT_LOG_NAME in names:
                target_names.append(_AUDIT_LOG_NAME)

            snapshots: list[tuple[Path, bytes]] = []
            for name in target_names:
                display_path = directory / name
                raw = _read_regular_audit_entry(
                    directory_fd=directory_fd,
                    name=name,
                    display_path=display_path,
                )
                if raw is not None:
                    snapshots.append((display_path, raw))
            return snapshots
    finally:
        os.close(directory_fd)


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
    keyvault_home: Path | None = None,
    backend: NativeBackend | None = None,
    audit_sink: AuditSink | None = None,
) -> int:
    """Decrypt the ``MRAL``-encrypted audit log file(s) for one UTC date.

    Prints every entry as a canonical JSON line, oldest first. Resolves
    rotated ``audit.log.<date>[.N][.gz]`` files plus — when ``date`` is
    today (UTC) — the active ``audit.log``.

    ``backend=None`` constructs the production Secure-Enclave backend;
    tests inject a software backend. ``audit_dir=None`` resolves the
    directory of the active writer path while preserving the ambient Hermes
    home. An explicit ``audit_dir`` follows the direct-API
    ``<home>/mordred`` convention; ``keyvault_home`` overrides either case.

    Returns:
        0  every resolved file decrypted;
        1  no file for the date, a corrupt file, a denied Enclave
           prompt, or a missing wrapping key;
        2  ``date`` is not a valid ``YYYY-MM-DD`` date.
    """
    try:
        target = datetime.strptime(date, "%Y-%m-%d").date()
    except ValueError:
        _term.emit_error(f"invalid --date {date!r}: expected YYYY-MM-DD")
        return 2

    directory = audit_dir if audit_dir is not None else _resolve_active_audit_path().parent
    resolved_keyvault_home = keyvault_home
    if resolved_keyvault_home is None and audit_dir is not None:
        resolved_keyvault_home = audit_dir.parent
    # A configured custom audit path does not move the ambient keyvault.
    # Only an explicit audit_dir override carries the direct-API
    # ``<home>/mordred`` convention.
    try:
        targets = _read_decrypt_targets(directory, target)
    except (_UnsafeAuditDirectoryError, _UnsafeAuditFileError) as exc:
        _term.emit_error(str(exc))
        return 1
    if not targets:
        _term.emit_error(f"No audit log file found for {date} under {directory}")
        return 1

    from ..keyvault import log_encryption
    from ..keyvault._exceptions import WrapAuthCancelled, WrapKeyNotFound

    backend = resolve_backend(backend)
    sink = audit_sink if audit_sink is not None else _stderr_unwrap_sink

    rc = 0
    for path, raw in targets:
        try:
            entries = log_encryption.decrypt_log_file(
                path,
                backend=backend,
                audit_sink=sink,
                file_bytes=raw,
                keyvault_home=resolved_keyvault_home,
            )
        except WrapAuthCancelled:
            _term.emit_error(f"{path.name}: Secure Enclave authorization was cancelled")
            return 1
        except WrapKeyNotFound:
            _term.emit_error(f"{path.name}: audit-log wrapping key not found — is the keyvault initialised?")
            return 1
        except log_encryption.AuditLogDecryptError as exc:
            _term.emit_error(f"{path.name}: {exc}")
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
    """``audit purge --before … --yes`` — destructive; refuse without --yes.

    Mirrors ``encryption purge``, the CLI's destructive-verb convention:
    deleting rotated audit history is irreversible, so it demands the same
    explicit confirmation flag (rc 2 = usage error, like the date validation).
    """
    if not bool(getattr(args, "yes", False)):
        _term.emit_error(
            f"audit purge is destructive (deletes rotated audit-log files dated "
            f"before {args.before}). Re-run with --yes to confirm."
        )
        return 2
    return purge(before=str(args.before))


def cli_decrypt(args: argparse.Namespace) -> int:
    return decrypt(date=str(args.date))
