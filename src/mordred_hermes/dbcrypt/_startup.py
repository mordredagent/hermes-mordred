"""Run a scheduled encrypt conversion at interpreter startup, before any database opens.

The same conversion as ``hermes-mordred databases encrypt`` (:func:`._maintenance.convert_home`),
under the same exclusive lease. The gate only observes metadata and reads the
journal's direction; the first key operation happens under that lease.

Safety rule: a journal means a half-converted home. Startup never continues
plain over one, whatever the outcome; it refuses and the next start resumes.
Without a journal nothing was published, and unarmed + pending is a modelled
safe state: the activity store refuses ``conversion_pending`` and the monitor
reports a non-violating ``pending``.

``startup-conversion.json`` tells the page why a start postponed. Its name must
not start with ``db-``: the inventory treats an unknown ``mordred/db-*`` as an
unknown dependency. It holds closed codes only, never a path, key or exception
text. Outcomes are written under EX or SH, so a sibling's late write cannot land
after a conversion, which needs EX and removes the record.

``attempting`` is written under EX before the first custody call. Hermes Desktop
kills a backend that has not announced its port, and a prompt nobody can answer
would otherwise hang every respawn. It can only be judged under EX: there, the OS
has released the previous holder's lock, so that holder died. That becomes
``auth_interrupted``, which is sticky: no start retries it and no other outcome
replaces it until :func:`._migrate.unschedule` clears it, so cancelling and
scheduling again is the only retry. The name is neutral because the kill may also
have landed in the checkpoint or discovery that follow authentication. A handled
``source_unavailable``, such as a cancelled prompt, is retried by a normal restart.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Final

from .._core._database_contracts import DatabaseBusy, DatabaseRefused
from .._core._database_lifecycle import acquire_exclusive
from .._private_fs import PrivateFSError, open_private_directory
from ._capability import database_intent, database_status
from ._locking import runtime_lease

STARTUP_EX_WAIT: Final = 15.0
#: An earlier start already postponed, so a plain Hermes likely holds the lease and
#: every gateway or worker it spawns would otherwise lose the whole wait.
STARTUP_EX_RECHECK_WAIT: Final = 2.0
STARTUP_SIBLING_WAIT: Final = 900.0
STARTUP_CONVERSION_MAX_BYTES: Final = 512 * 1024 * 1024
RECORD_NAME: Final = "startup-conversion.json"

#: What callers can see. ``attempting`` exists only in the file.
OUTCOMES: Final = frozenset(
    {
        "auth_interrupted",
        "busy",
        "memory_not_enabled",
        "source_unavailable",
        "holders_open",
        "too_large",
        "refused",
        "unavailable",
    }
)
_ATTEMPTING: Final = "attempting"
_AUTH_INTERRUPTED: Final = "auth_interrupted"
_STICKY: Final = frozenset({_ATTEMPTING, _AUTH_INTERRUPTED})
_RECORD_MAX_BYTES: Final = 4096
_POLL_SECONDS: Final = 0.05
_NORMAL_REASON: Final = "native database authority has not been authenticated"
_INCOMPLETE: Final = (
    "an interrupted database conversion must finish first; restart Hermes to resume it or run "
    "`hermes-mordred databases encrypt`. The databases were not opened."
)


class _LeaveSharedLease(Exception):
    """Release the temporary SH lease: this process does not stay a plain runtime."""


def _read_record(root: Path) -> str | None:
    """The file's code. Only true absence is ``None``; anything else unusable fails closed."""
    try:
        with open_private_directory(root / "mordred") as directory:
            raw = directory.read_bytes(RECORD_NAME, max_bytes=_RECORD_MAX_BYTES)
    except PrivateFSError as exc:
        return None if exc.reason == "missing" else "refused"
    except FileNotFoundError:
        return None
    except OSError:
        return "refused"
    try:
        value = json.loads(raw)
    except (ValueError, RecursionError):
        return "refused"
    if not isinstance(value, dict) or type(value.get("version")) is not int or value["version"] != 1:
        return "refused"
    outcome = value.get("outcome")
    if not isinstance(outcome, str) or (outcome not in OUTCOMES and outcome != _ATTEMPTING):
        return "refused"
    return outcome


def read_outcome(root: Path) -> str | None:
    """Why startup postponed the conversion, from :data:`OUTCOMES`; ``None`` when no record exists.

    A leftover ``attempting`` reads as ``auth_interrupted``: its holder died during
    the attempt, or is still inside it.
    """
    outcome = _read_record(root)
    return _AUTH_INTERRUPTED if outcome == _ATTEMPTING else outcome


def conversion_too_large(root: Path) -> bool:
    """Whether the databases exceed the startup budget. Stat only: nothing is opened."""
    from . import _migrate

    total = 0
    for path in _migrate.database_paths(root):
        try:
            total += path.lstat().st_size
        except FileNotFoundError:
            continue
    return total > STARTUP_CONVERSION_MAX_BYTES


def _write_record(root: Path, outcome: str) -> bool:
    """Publish a code privately. Never fatal: a failure is reported and returned."""
    from . import _migrate

    value = {"version": 1, "at": int(time.time()), "outcome": outcome, "converted": None, "platform": sys.platform}
    try:
        _migrate._put_json(root, RECORD_NAME, value)
    except Exception:
        sys.stderr.write("mordred: the database encryption startup outcome could not be recorded\n")
        return False
    return True


def _remove_record(root: Path) -> None:
    """Remove a stale record, touching the disk only when one exists."""
    try:
        (root / "mordred" / RECORD_NAME).lstat()
    except OSError:
        return
    from . import _migrate

    try:
        _migrate._remove_record(root, RECORD_NAME)
    except Exception:
        sys.stderr.write("mordred: a stale database encryption startup outcome could not be removed\n")


def _encrypt_journal(root: Path) -> bool:
    """Whether the journal is one this seam may resume. No key and no database is touched."""
    from . import _migrate

    try:
        value = _migrate._read_json(root, _migrate.JOURNAL_SUBPATH[-1])
    except (DatabaseRefused, OSError):
        return False
    # Version 1 has no identities to resume from; refuse it before any custody.
    return (
        isinstance(value, dict)
        and type(value.get("version")) is int
        and value["version"] == 2
        and value.get("direction") == "encrypt"
    )


def _scheduled_work(root: Path) -> bool:
    """The gate: a conversion this seam owns. Everything else takes the strict path."""
    intent = database_intent(root)
    if intent.unsafe or not intent.encrypt_pending or intent.decrypt_pending:
        return False
    return _encrypt_journal(root) if intent.journal else not intent.armed


def _precheck(root: Path, *, resuming: bool) -> str | None:
    """Refusals that need no custody and no lease."""
    from ..keyvault._database_authority import require_database_memory_enabled

    try:
        status = database_status(root)
        if status.capability == "unavailable":
            return "unavailable"
        if status.reason != _NORMAL_REASON:
            return "refused"
        try:
            require_database_memory_enabled(root=root)
        except DatabaseRefused:
            return "memory_not_enabled"
        # An existing journal must still try to resume: refusing here would
        # strand a half-converted home behind a size that cannot shrink.
        return "too_large" if not resuming and conversion_too_large(root) else None
    except Exception:
        return "refused"


def _classify(error: Exception) -> str:
    from . import _migrate

    if isinstance(error, _migrate.NativeSourceUnavailable):
        return "source_unavailable"
    if isinstance(error, _migrate.DatabasesHeldOpen):
        return "holders_open"
    return "refused"


def _attempt(root: Path) -> str | None:
    """One conversion under EX: ``None`` when no work remains, else the outcome it recorded."""
    from ._maintenance import convert_home

    with acquire_exclusive(root, timeout=0) as lease:
        # The lease may have followed a sibling's finished conversion.
        if not _scheduled_work(root):
            if not database_intent(root).encrypt_pending:
                _remove_record(root)
            return None
        resuming = database_intent(root).journal
        if _read_record(root) in _STICKY and not resuming:
            # The OS released the previous holder's lock, so it died during its
            # attempt. Retrying here would hang every respawn.
            _write_record(root, _AUTH_INTERRUPTED)
            return _AUTH_INTERRUPTED
        if not _write_record(root, _ATTEMPTING) and not resuming:
            return "refused"  # Without the guard a hung prompt could never be detected.
        try:
            convert_home(root, lease=lease, decrypting=False)
        except Exception as error:
            # Replaced under EX: left as attempting it would read as a dead holder.
            outcome = _classify(error)
            _write_record(root, outcome)
            return outcome
        _remove_record(root)
    return None


def _refuse_incomplete(root: Path) -> None:
    intent = database_intent(root)
    if intent.journal or intent.unsafe:
        raise DatabaseRefused(_INCOMPLETE) from None


def _record_postponed(root: Path, outcome: str) -> None:
    """Publish a code under SH, where no attempt can be in flight, without losing a better one."""
    existing = _read_record(root)
    # A sticky code is only ever cleared by unschedule: replacing it would re-enable
    # the hang. Busy says less than any remedy already on record, and a stale
    # source_unavailable is replaced by the restart that retries it anyway.
    if existing in _STICKY or (outcome == "busy" and existing is not None):
        return
    _write_record(root, outcome)


def _postpone(root: Path, outcome: str, *, recorded: bool) -> bool:
    """Continue plain holding SH if that is safe. ``False`` selects the strict/armed path."""
    if outcome != "busy":
        _refuse_incomplete(root)  # Our own journal: do not wait behind a sibling first.
    try:
        with runtime_lease(root, timeout=STARTUP_SIBLING_WAIT):
            _refuse_incomplete(root)  # Busy included: a journal overrides every outcome.
            intent = database_intent(root)
            if not intent.encrypt_pending:
                _remove_record(root)
            if intent.armed or intent.decrypt_pending:
                raise _LeaveSharedLease
            if intent.encrypt_pending:
                if not recorded:
                    _record_postponed(root, outcome)
                sys.stderr.write(f"mordred: database encryption postponed ({outcome}); continuing without it\n")
            return True
    except _LeaveSharedLease:
        pass
    return False


def _convert_scheduled(root: Path, *, resuming: bool) -> bool:
    # Durable, unlike attempting, so it needs no EX to judge and no wait for one.
    if not resuming and _read_record(root) == _AUTH_INTERRUPTED:
        return _postpone(root, _AUTH_INTERRUPTED, recorded=True)
    outcome = _precheck(root, resuming=resuming)
    if outcome is not None:
        return _postpone(root, outcome, recorded=False)
    wait = STARTUP_EX_WAIT if _read_record(root) is None else STARTUP_EX_RECHECK_WAIT
    deadline = time.monotonic() + wait
    while True:
        try:
            outcome = _attempt(root)
        except DatabaseBusy:
            current = database_intent(root)
            if not current.encrypt_pending and not current.journal:
                return False  # A sibling finished, or the schedule was cancelled.
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return _postpone(root, "busy", recorded=False)
            time.sleep(min(_POLL_SECONDS, remaining))
        except (DatabaseRefused, OSError):
            return _postpone(root, "refused", recorded=False)
        else:
            return False if outcome is None else _postpone(root, outcome, recorded=True)


def run_scheduled_conversion(base: Path) -> bool:
    """Perform a scheduled conversion before ``install`` opens anything.

    Returns ``True`` when the conversion stays scheduled and this process already
    holds its runtime lease for a plain start. ``False`` selects the ordinary
    path, whose strict checks refuse every state this seam does not own.
    Raises :class:`DatabaseRefused` when a journal forbids continuing plain.
    """
    intent = database_intent(base)
    if intent.unsafe:
        return False
    if not intent.encrypt_pending:
        _remove_record(base)
        return False
    return _convert_scheduled(base, resuming=intent.journal) if _scheduled_work(base) else False
