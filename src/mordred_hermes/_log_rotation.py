"""Shared audit-log rotation / timestamp / retention helpers -- root pure-stdlib module.

Single-sources logic that was independently copy-pasted, near-verbatim,
across three call sites:

* :mod:`mordred_hermes.privacy_check.audit` -- ``_utcnow_iso``,
  ``_today_utc_date``, ``_next_rotation_target`` (shared by
  :class:`NDJSONWriter`'s size/date rotation and the encrypted-log
  rotate-aside), and :class:`NDJSONWriter`'s ``_sweep_retention`` method.
* :mod:`mordred_hermes.keyvault.log_encryption` -- an identical
  ``_utcnow_iso`` / ``_today_utc_date`` pair, a ``_rotate`` that reimplemented
  the same collision-suffix loop inline instead of calling a shared helper,
  and an ``_sweep_retention`` method that was byte-for-byte identical to
  ``NDJSONWriter``'s.
* :mod:`mordred_hermes.wizard.openclaw_migration` -- a third copy of the
  ``_utcnow_iso``-shaped timestamp helper, used only for the idempotency
  marker file (its docstring said "matches privacy_check.audit format" --
  now it just imports the format).

This is the pure-stdlib sibling of :mod:`mordred_hermes._yaml_io` and
:mod:`mordred_hermes._policy_io`: no ``cryptography``, no ``ruamel``, and no
import of ``privacy_check`` or ``keyvault`` themselves, so this module stays
importable regardless of which optional extras (e.g. ``[macos]``) are
installed -- exactly the property that let ``privacy_check.audit`` host the
canonical copy without dragging the keyvault crypto stack into every
importer of ``NDJSONWriter``.

Import-shape note (load-bearing for a test): ``test_keyvault_log_encryption
.py`` monkeypatches ``log_encryption._today_utc_date`` directly (via
``monkeypatch.setattr(le, "_today_utc_date", ...)``) to pin the rotation
clock for date-change tests. An unqualified call inside a function body
resolves against *that function's own module* globals, not this module's,
so each importer must bind the name at module scope in its own namespace
(``from .._log_rotation import today_utc_date as _today_utc_date``) and call
it unqualified -- re-exporting via a qualified ``_log_rotation.today_utc_date()``
call at the use site would silently break that monkeypatch.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path


def utcnow_iso() -> str:
    """ISO-8601 UTC timestamp with 3-digit millisecond precision.

    Built by hand -- ``strftime`` ``%f`` yields 6-digit microseconds --
    literally ``"%Y-%m-%dT%H:%M:%S." + "{ms:03d}" + "Z"``. This exact shape
    is a frozen wire contract: the Phase 1 audit-log ``Writer`` Protocol
    (:mod:`mordred_hermes.privacy_check.audit`) invariant #1 requires every
    ``ts`` field written by any implementor -- plaintext ``NDJSONWriter`` or
    Phase 4 AES-GCM ``EncryptedWriter`` -- to match it byte-for-byte.
    """
    now = datetime.now(UTC)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def today_utc_date() -> str:
    """Current UTC date as ``YYYY-MM-DD`` (rotation suffix source)."""
    return datetime.now(UTC).strftime("%Y-%m-%d")


def next_rotation_target(path: Path, date_suffix: str) -> Path:
    """Pick a collision-free rotation target ``<name>.<date>[.N]``.

    Shared by every rotator that renames an active log file aside before
    gzipping it: ``NDJSONWriter._rotate`` and ``EncryptedWriter._rotate``
    (same-day size/date rotation), and the encrypted-log rotate-aside in
    ``privacy_check.audit`` (``_rotate_encrypted_log_aside``, which moves a
    stale ``MRAL`` file out of a plaintext writer's way). All three must
    skip names already taken by a prior rotation -- including rotations
    that were subsequently gzipped -- so a same-day rotation can never
    overwrite history.
    """
    target = path.with_name(f"{path.name}.{date_suffix}")
    n = 0
    while target.exists() or target.with_suffix(target.suffix + ".gz").exists():
        n += 1
        target = path.with_name(f"{path.name}.{date_suffix}.{n}")
    return target


def sweep_retention(path: Path, retention_days: int) -> None:
    """Delete rotated siblings of ``path`` older than ``retention_days``.

    ``path`` is the *active* log file (e.g. ``audit.log``); rotated siblings
    are every entry in ``path.parent`` whose name starts with
    ``path.name + "."`` (``audit.log.2026-05-16``, ``audit.log.2026-05-16.gz``,
    ``audit.log.2026-05-16.1.gz``, ...). Age is judged by mtime, not the date
    embedded in the filename, so a rotated file's on-disk age is
    authoritative even if it were manually renamed or copied in. A file that
    disappears between the ``iterdir()`` listing and the ``stat()`` call
    (e.g. a concurrent sweep, or manual cleanup) is silently skipped rather
    than raising.
    """
    cutoff = datetime.now(UTC) - timedelta(days=retention_days)
    prefix = path.name + "."
    for child in path.parent.iterdir():
        if not child.name.startswith(prefix):
            continue
        try:
            mtime = datetime.fromtimestamp(child.stat().st_mtime, tz=UTC)
        except FileNotFoundError:
            continue
        if mtime < cutoff:
            child.unlink(missing_ok=True)
