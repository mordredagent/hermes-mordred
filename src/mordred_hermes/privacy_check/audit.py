"""Audit log writer — single-writer NDJSON with daily + size rotation, gzip + retention.

Phase 1 implementation per SPEC.md §Audit log policy + TODO.md §1.1:

- File mode ``0o600``, parent dir mode ``0o700``
- POSIX ``O_APPEND`` open per write — atomic appends up to ``PIPE_BUF``
  (4096 bytes); we cap each entry at 4000 bytes for a safety margin (M1)
- Daily roll to ``audit.log.YYYY-MM-DD``, gzip after rotation
- 10 MB size cap forces same-day rotation (``audit.log.YYYY-MM-DD.N.gz``)
- 30-day retention swept on each rotation
- Single-writer queue via ``threading.Lock`` — multi-process unsupported v1

Phase 4 will swap :class:`NDJSONWriter` for ``EncryptedWriter`` behind the
:class:`Writer` Protocol; the Protocol is frozen here.

Why fd-per-write: keeps the writer fork-safe and tolerant of external file
deletion (e.g. user manually rm'd audit.log). The cost is a syscall pair
per entry, which is negligible at audit-log volumes.
"""

from __future__ import annotations

import contextlib
import gzip
import json
import logging
import os
import shutil
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final, Protocol

_LOG = logging.getLogger("mordred.privacy_check.audit")

# 96-byte safety margin under POSIX PIPE_BUF (4096). Larger entries cannot
# guarantee atomic appends under contention.
MAX_ENTRY_BYTES: Final = 4000

DEFAULT_ROTATE_BYTES: Final = 10 * 1024 * 1024  # 10 MB
DEFAULT_RETENTION_DAYS: Final = 30


class Writer(Protocol):
    """Frozen audit-log writer surface (Phase 1 contract for Phase 4 swap).

    Implementors MUST honor the following invariants so consumers of the
    audit log (and callers like :mod:`mordred_hermes.keyvault.recovery`)
    can rely on a uniform entry shape regardless of which writer is
    installed (plaintext NDJSON in Phase 1-3, AES-GCM-encrypted in Phase 4):

    1. **``ts`` injection**: if the caller-supplied ``entry`` does not
       carry a ``ts`` field, the writer MUST add one set to the current
       UTC time in ISO-8601 millisecond format
       (``%Y-%m-%dT%H:%M:%S.fffZ``). Callers further up the stack —
       including the keyvault ``audit_sink`` contract documented in
       :mod:`mordred_hermes.keyvault.recovery` — assume this and do not
       inject ``ts`` themselves. Code-reviewer MEDIUM-3 (2026-05-14):
       this contract was previously only enforced by the
       :class:`NDJSONWriter` implementation; documenting it on the
       Protocol prevents a future Phase 4 ``EncryptedWriter`` from
       silently shipping ``ts``-less entries.
    2. **Whole-entry atomicity**: a single :meth:`append` call either
       writes the entire serialized entry (one NDJSON line) or none of
       it. No partial-write states should be observable on disk.
    3. **0600 file mode**: any underlying file MUST be opened with
       mode ``0600`` so audit history is not readable by other local
       users.
    """

    def append(self, entry: Mapping[str, Any]) -> None: ...
    def close(self) -> None: ...


def _utcnow_iso() -> str:
    """ISO-8601 UTC timestamp with millisecond precision."""
    now = datetime.now(UTC)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def _today_utc_date() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d")


def _serialize(entry: Mapping[str, Any]) -> bytes:
    """Serialize an audit entry to NDJSON bytes (terminated with newline).

    ``sort_keys=True`` yields stable field order across processes/builds —
    ``audit grep`` users get predictable output.
    """
    line = json.dumps(entry, separators=(",", ":"), ensure_ascii=False, sort_keys=True) + "\n"
    data = line.encode("utf-8")
    if len(data) > MAX_ENTRY_BYTES:
        raise ValueError(f"audit entry exceeds {MAX_ENTRY_BYTES} bytes (got {len(data)})")
    return data


@dataclass
class NDJSONWriter:
    """Single-writer NDJSON audit logger.

    Multi-process writes are not supported in v1 — the in-process
    ``threading.Lock`` only serializes threads of one Python process.
    See TODO.md §1.1 L150 / M1 for v2 plans (Unix domain socket daemon
    or ``fcntl.flock``).
    """

    path: Path
    rotate_bytes: int = DEFAULT_ROTATE_BYTES
    retention_days: int = DEFAULT_RETENTION_DAYS
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)
    _last_date: str = field(default="", init=False, repr=False)

    def __post_init__(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # If the file pre-exists with looser perms (e.g. user touched it),
        # tighten to 0o600. Best-effort: ignore on platforms / filesystems
        # where chmod is a no-op.
        if self.path.exists():
            with contextlib.suppress(OSError):
                os.chmod(self.path, 0o600)

    def append(self, entry: Mapping[str, Any]) -> None:
        """Append one audit entry. Adds ``ts`` if caller did not."""
        merged: dict[str, Any] = {"ts": _utcnow_iso(), **dict(entry)}
        data = _serialize(merged)

        with self._lock:
            self._maybe_rotate(len(data))
            fd = os.open(str(self.path), os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
            try:
                os.write(fd, data)
            finally:
                os.close(fd)

    def close(self) -> None:
        # Each append opens+closes its own fd, so close() is a no-op.
        # Kept for the Writer Protocol contract.
        return None

    def _maybe_rotate(self, incoming_bytes: int) -> None:
        """Check whether the active file needs to be rotated.

        Two triggers:

        - **Date change**: first append on a new UTC day rotates yesterday.
        - **Size cap**: file size + incoming bytes would exceed
          ``rotate_bytes``. Same-day collisions get an ``.N`` suffix.

        Process restart resets the in-memory ``_last_date``; the file from
        a prior day continues collecting today's entries until the size
        cap or the next date change. This is acceptable for v1 (loose
        "daily roll" intent — strict midnight-UTC rotation is v2).
        """
        today = _today_utc_date()
        if self._last_date and self._last_date != today and self.path.exists():
            self._rotate(self._last_date)
        elif self.path.exists() and self.path.stat().st_size + incoming_bytes > self.rotate_bytes:
            self._rotate(today)
        self._last_date = today

    def _rotate(self, date_suffix: str) -> None:
        if not self.path.exists():
            return

        target = self.path.with_name(f"{self.path.name}.{date_suffix}")
        n = 0
        while target.exists() or target.with_suffix(target.suffix + ".gz").exists():
            n += 1
            target = self.path.with_name(f"{self.path.name}.{date_suffix}.{n}")
        os.replace(self.path, target)

        gz_target = target.with_suffix(target.suffix + ".gz")
        try:
            with target.open("rb") as src, gzip.open(gz_target, "wb") as dst:
                shutil.copyfileobj(src, dst)
            target.unlink()
        except Exception as e:
            # gzip failure does NOT lose data — `target` already holds the
            # rotated content. Leave it un-gzipped; the next rotation's
            # collision loop will pick a new suffix. Best-effort: clean up
            # any partial .gz so it doesn't read as corrupt.
            _LOG.warning("audit gzip rotation failed; raw rotated file kept at %s: %s", target, e)
            with contextlib.suppress(OSError):
                gz_target.unlink()
        else:
            with contextlib.suppress(OSError):
                os.chmod(gz_target, 0o600)

        self._sweep_retention()

    def _sweep_retention(self) -> None:
        cutoff = datetime.now(UTC) - timedelta(days=self.retention_days)
        prefix = self.path.name + "."
        for child in self.path.parent.iterdir():
            if not child.name.startswith(prefix):
                continue
            try:
                mtime = datetime.fromtimestamp(child.stat().st_mtime, tz=UTC)
            except FileNotFoundError:
                continue
            if mtime < cutoff:
                child.unlink(missing_ok=True)
