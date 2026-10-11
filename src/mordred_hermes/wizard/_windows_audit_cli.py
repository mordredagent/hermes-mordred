"""Windows routing for ``hermes-mordred audit {tail,grep,decrypt,purge}`` (C7b part 2).

On ``win32`` the audit CLI never uses ``audit_cli``'s POSIX descriptor helpers
(``_read_audit_path``, ``_open_real_audit_directory``, directory-fd unlink):

* ``tail`` / ``grep`` read the active log through one C7a checked snapshot
  (:func:`read_audit_snapshot`, the C7a 16 MiB per-file bound) under the
  checked audit-directory admission and lock;
* ``decrypt`` first asks ``windows_capability(home, "native_audit")`` and
  refuses unavailable custody before any native call, then enumerates the
  date's dated siblings (plus the active log for today) through one checked,
  bounded C7a session, oldest first, and decrypts each with C5d
  ``decrypt_windows_log_file``, which snapshots and validates the file itself,
  then re-lists the date so a concurrent rotation or purge is reported (exit 1,
  "re-run") instead of silently omitting entries; entries are written as UTF-8;
* ``purge`` deletes only enumerated, checked dated siblings through the C7a
  session's identity-bound ``delete`` under its directory transaction.

No verb enrolls, creates or rotates a key or log, appends to the audit log or
touches a custody role (the audit key is the separate C5e ``reset_role``
ceremony). Storage refusals use a closed vocabulary (``audit-unsafe``,
``audit-unavailable``, ``audit-uncertain``, ``audit-invalid``); custody refusals
reuse the C6 capability wording. Messages carry reasons and paths, never file
bytes. Keyvault imports stay function-local, so this module imports without
the ``[keyvault]`` crypto stack.
"""

from __future__ import annotations

import codecs
import contextlib
import json
import sys
from collections.abc import Callable, Iterator
from datetime import UTC, date, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final, Literal

from .._audit_session import AuditSession, audit_session, read_audit_snapshot
from .._log_rotation import audit_rotation_names
from .._private_fs import FileIdentity, PrivateFSError
from . import _term, _windows_gates

if TYPE_CHECKING:
    from ..keyvault.wrap import AuditSink, NativeBackend

__all__ = [
    "ACTIVE_READ_LIMIT",
    "DECRYPT_TOTAL_LIMIT",
    "MAX_ENTRIES",
    "WindowsAuditRefused",
    "classify_storage",
    "decrypt",
    "decrypt_targets",
    "default_home",
    "native_audit_refusal",
    "purge",
    "read_active_log",
]

#: The active log name; dated siblings are ``audit.log.<date>[.N][.gz]``.
ACTIVE_NAME: Final = "audit.log"
# C7a defaults (SPEC "Checked Windows audit sessions"); plain module attributes
# so tests can shrink them. Readers refuse instead of truncating.
#: Per-file snapshot bound for the active log.
ACTIVE_READ_LIMIT = 16 * 1024 * 1024
#: Aggregate bound on the files one ``decrypt --date`` selects.
DECRYPT_TOTAL_LIMIT = 64 * 1024 * 1024
#: Directory enumeration bound.
MAX_ENTRIES = 4096

StorageReason = Literal["audit-unsafe", "audit-unavailable", "audit-uncertain", "audit-invalid"]
_TRANSIENT: Final = frozenset({"busy", "io", "access_denied", "missing"})
_STORAGE_REMEDIES: Final[dict[StorageReason, str]] = {
    "audit-unsafe": (
        "the audit directory or file is not private to this Windows account (broad ACL, foreign owner, "
        "hard link, junction or reparse point); Mordred never repairs ACLs or follows links — fix it by hand, "
        "then retry"
    ),
    "audit-unavailable": (
        "the audit storage is busy or could not be accessed — let other Hermes/Mordred processes finish, then retry"
    ),
    "audit-uncertain": (
        "an audit storage operation has an uncertain outcome — inspect the audit directory before retrying; "
        "nothing is retried automatically"
    ),
    "audit-invalid": "the audit path is not a valid Windows audit location",
}
_NOT_DECRYPTED: Final = "Nothing was decrypted, enrolled or written."
_AUTH_DENIED: Final = (
    "the Windows CNG helper denied the audit custody key operation (Windows custody has no per-use presence "
    "prompt); run the command as the Windows account that enrolled the key. Nothing was decrypted."
)
_KEY_MISSING: Final = (
    "the CNG key of this log's audit custody generation was not found; Mordred never regenerates it, so this "
    "history cannot be decrypted with this profile and Windows account. Nothing was decrypted."
)
_NATIVE_UNAVAILABLE: Final = (
    "the Windows CNG helper could not complete the audit key operation and nothing was regenerated — retry, "
    "and check `hermes-mordred keyvault enable-winkey` if it persists"
)

PurgeOutcome = Literal["deleted", "absent", "refused"]
_MIB: Final = 1024 * 1024
_READ_BOUNDS: Final = frozenset({"audit_read_limit", "read_limit"})


class WindowsAuditRefused(RuntimeError):
    """A classified refusal; the message names reason, path and remedy, never file bytes."""

    def __init__(self, reason: StorageReason, message: str) -> None:
        super().__init__(message)
        self.reason: StorageReason = reason


def classify_storage(exc: BaseException) -> StorageReason:
    """Map a checked storage failure onto the closed CLI refusal vocabulary."""
    if isinstance(exc, PrivateFSError):
        if exc.commit_state != "not_committed":
            return "audit-uncertain"
        return "audit-unavailable" if exc.reason in _TRANSIENT else "audit-unsafe"
    return "audit-invalid"


def _absent(exc: PrivateFSError) -> bool:
    """A definite absence (including a missing ancestor), never a security or cleanup failure."""
    return exc.reason == "missing" and exc.commit_state == "not_committed"


def _bound(limit: int) -> str:
    return f"{limit // _MIB} MiB" if limit >= _MIB and limit % _MIB == 0 else f"{limit}-byte"


def _bound_remedy(exc: BaseException) -> str | None:
    """A checked-bound refusal names its bound and a workaround, not the unsafe-object remedy."""
    if not isinstance(exc, PrivateFSError) or exc.reason != "unsafe":
        return None
    if exc.operation in _READ_BOUNDS:
        return (
            f"the active log exceeds the {_bound(ACTIVE_READ_LIMIT)} read bound and readers never truncate; the "
            "plaintext writer rotates it at 10 MB by default, so copy it elsewhere by hand to inspect it"
        )
    if exc.operation == "audit_total_limit":
        return (
            f"the files of this date exceed the {_bound(DECRYPT_TOTAL_LIMIT)} decrypt bound and readers never "
            "truncate — decrypt in parts: move some of that date's rotated files out of the audit directory by "
            "hand, re-run, then move them back and repeat with the others"
        )
    if exc.operation == "list_limit":
        return (
            f"the audit directory holds more than {MAX_ENTRIES} entries — move older rotated files out of the "
            "audit directory by hand, then retry"
        )
    return None


def _refused(action: str, path: Path, exc: BaseException, outcome: str) -> WindowsAuditRefused:
    reason = classify_storage(exc)
    remedy = _bound_remedy(exc) or _STORAGE_REMEDIES[reason]
    return WindowsAuditRefused(reason, f"refusing audit {action} at {path}: {reason} ({exc}) — {remedy}. {outcome}")


def default_home() -> Path:
    """The ambient Hermes home that owns the Windows audit custody role."""
    from .._home import hermes_home

    return hermes_home()


# --- tail / grep ----------------------------------------------------------------------


def read_active_log(log_path: Path) -> bytes | None:
    """One bounded C7a snapshot of the active log; ``None`` when it is absent.

    Raises :class:`WindowsAuditRefused` for unsafe, unavailable, uncertain or
    invalid storage. The caller applies the plaintext/MRAL classification.
    """
    try:
        snapshot = read_audit_snapshot(log_path, max_bytes=ACTIVE_READ_LIMIT)
    except PrivateFSError as exc:
        if _absent(exc):
            return None
        raise _refused("read", log_path, exc, "Nothing was read.") from exc
    except ValueError as exc:
        raise _refused("read", log_path, exc, "Nothing was read.") from exc
    return None if snapshot is None else snapshot.data


# --- decrypt --------------------------------------------------------------------------


def _active_kind(directory: Path) -> str | None:
    """The C7a probe kind of the active log, or ``None`` when it cannot be checked."""
    try:
        with audit_session(directory / ACTIVE_NAME) as session:
            return session.probe(ACTIVE_NAME).kind
    except (PrivateFSError, ValueError):
        return None


def native_audit_refusal(home: Path, directory: Path) -> str | None:
    """The C5e ``native_audit`` precondition; a refusal message unless available.

    Pure observation: no native backend, unwrap, enrollment or lock wait. An
    unenrolled profile whose active log is checked plaintext (the C7b part-1
    degraded mode) is pointed at ``audit tail``/``grep`` instead of enrollment.
    """
    from ..keyvault._windows_capability import windows_capability
    from ..keyvault._windows_profile import CustodyError

    try:
        capability = windows_capability(home, "native_audit")
    except ValueError:
        return f"audit decrypt refused: the Hermes home {home} is not a valid absolute Windows path. {_NOT_DECRYPTED}"
    except (PrivateFSError, CustodyError) as exc:
        reason = _windows_gates.classify_exception(exc)
        return (
            f"audit decrypt refused: audit custody could not be read ({reason}) — "
            f"{_windows_gates.remedy(reason)}. {_NOT_DECRYPTED}"
        )
    if capability.available:
        return None
    if capability.reason == "not-enrolled" and _active_kind(directory) == "ndjson":
        return (
            f"audit decrypt refused: audit custody is not enrolled (not-enrolled) and the active audit log "
            f"{directory / ACTIVE_NAME} is plaintext NDJSON (the degraded mode) — read it with "
            f"`hermes-mordred audit tail` or `hermes-mordred audit grep`; it needs no decryption. {_NOT_DECRYPTED}"
        )
    return f"audit decrypt refused: {_windows_gates.describe_capability(capability)}. {_NOT_DECRYPTED}"


def _today() -> date:
    return datetime.now(UTC).date()


def decrypt_targets(directory: Path, target: date) -> dict[str, FileIdentity]:
    """Checked, bounded selection of the files holding ``target``'s entries.

    Dated siblings come in C7a rotation order (date, then numeric suffix), so
    entries print oldest first; the active log is last and only for today.
    Each selected entry is checked (regular, private, single link) before any
    native call, and the selection's combined size is bounded. Returns names
    in order with their checked identities.
    """
    with audit_session(directory / ACTIVE_NAME) as session:
        names = [
            name for name, dated, _n, _gz in audit_rotation_names(session, max_entries=MAX_ENTRIES) if dated == target
        ]
        if target == _today():
            names.append(ACTIVE_NAME)
        selected: dict[str, FileIdentity] = {}
        total = 0
        for name in names:
            metadata = session.stat(name)
            if metadata is None:
                continue
            total += metadata.size
            if total > DECRYPT_TOTAL_LIMIT:
                raise PrivateFSError("unsafe", "audit_total_limit")
            selected[name] = metadata.identity
    return selected


def _history_change(directory: Path, target: date, before: dict[str, FileIdentity], date_text: str) -> str | None:
    """Re-list after decrypting: a rotation or purge in between must not go unnoticed.

    Appends to the active log keep its identity and are not a change; a new,
    removed or replaced (re-created) file is.
    """
    try:
        after = decrypt_targets(directory, target)
    except (PrivateFSError, ValueError) as exc:
        if not (isinstance(exc, PrivateFSError) and _absent(exc)):
            return (
                f"audit history for {date_text} could not be re-checked after decrypting "
                f"({classify_storage(exc)}: {exc}); the output above may be incomplete — re-run the command"
            )
        after = {}
    changes = [f"added {name}" for name in after if name not in before]
    changes += [f"removed {name}" for name in before if name not in after]
    changes += [f"replaced {name}" for name, identity in before.items() if name in after and after[name] != identity]
    if not changes:
        return None
    return (
        f"audit history for {date_text} changed during decrypt ({', '.join(changes)}): a concurrent rotation or "
        "purge moved entries, so the output above may be incomplete — re-run the command"
    )


def _is_utf8(encoding: str) -> bool:
    try:
        return codecs.lookup(encoding).name == "utf-8"
    except LookupError:
        return False


@contextlib.contextmanager
def _utf8_stdout() -> Iterator[None]:
    """Write this command's output as UTF-8, restoring the stream encoding after.

    A redirected Windows stdout uses the ANSI code page (for example cp932)
    with strict errors, which cannot encode every decrypted entry or the
    em-dash header. Streams without ``reconfigure`` are left unchanged.
    """
    previous = getattr(sys.stdout, "encoding", None)
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    restore: Callable[..., object] | None = None
    if isinstance(previous, str) and callable(reconfigure) and not _is_utf8(previous):
        with contextlib.suppress(ValueError, OSError, LookupError):
            reconfigure(encoding="utf-8")
            restore = reconfigure
    try:
        yield
    finally:
        if restore is not None:
            with contextlib.suppress(ValueError, OSError, LookupError):
                restore(encoding=previous)


def decrypt(
    *,
    target: date,
    date_text: str,
    directory: Path,
    home: Path | None,
    backend: NativeBackend | None,
    sink: AuditSink,
) -> int:
    """Windows ``audit decrypt``: capability gate, checked enumeration, C5d decrypt.

    Exit codes match POSIX: 0 every file decrypted; 1 refused, missing,
    corrupt, denied or missing key. The caller validated the date (2).
    """
    custody_home = home if home is not None else default_home()
    refusal = native_audit_refusal(custody_home, directory)
    if refusal is not None:
        _term.emit_error(refusal)
        return 1
    try:
        listed = decrypt_targets(directory, target)
    except PrivateFSError as exc:
        if not _absent(exc):
            _term.emit_error(str(_refused("decrypt", directory, exc, _NOT_DECRYPTED)))
            return 1
        listed = {}
    except ValueError as exc:
        _term.emit_error(str(_refused("decrypt", directory, exc, _NOT_DECRYPTED)))
        return 1
    if not listed:
        _term.emit_error(f"No audit log file found for {date_text} under {directory}")
        return 1
    with _utf8_stdout():
        rc, finished = _decrypt_files(
            [directory / name for name in listed], home=custody_home, backend=backend, sink=sink
        )
    if finished:
        change = _history_change(directory, target, listed, date_text)
        if change is not None:
            _term.emit_error(change)
            rc = 1
    return rc


def _decrypt_failure(path: Path, exc: Exception) -> tuple[str, bool] | None:
    """One file's classified failure message and whether it stops the run.

    ``None`` means an unexpected exception, which propagates unchanged. Missing
    or denied keys and storage/native refusals stop (as POSIX stops on a denied
    prompt or missing key); a corrupt, foreign or vanished file is reported and
    the remaining files are still decrypted.
    """
    from .._config_io import PolicyPendingError
    from ..keyvault._exceptions import WrapAuthCancelled, WrapError, WrapKeyNotFound
    from ..keyvault._windows_profile import CustodyError
    from ..keyvault.log_encryption import AuditLogDecryptError

    name = path.name
    if isinstance(exc, WrapAuthCancelled):
        return f"{name}: {_AUTH_DENIED}", True
    if isinstance(exc, WrapKeyNotFound):
        return f"{name}: {_KEY_MISSING}", True
    if isinstance(exc, WrapError):
        return f"{name}: native-unavailable ({type(exc).__name__}) — {_NATIVE_UNAVAILABLE}", True
    if isinstance(exc, AuditLogDecryptError):
        return f"{name}: {exc}", False
    if isinstance(exc, CustodyError):
        # A selector this profile does not own (copied/foreign history) or custody drift.
        return f"{name}: custody-broken — {_windows_gates.remedy('custody-broken')}", False
    if isinstance(exc, FileNotFoundError):
        return f"{name}: rotated or removed after it was listed; re-run the command", False
    if isinstance(exc, PolicyPendingError):
        return f"{name}: custody-uncertain — {_windows_gates.remedy('custody-uncertain')}", True
    if isinstance(exc, (PrivateFSError, ValueError)):
        return str(_refused("decrypt", path, exc, _NOT_DECRYPTED)), True
    return None


def _decrypt_files(
    targets: list[Path], *, home: Path, backend: NativeBackend | None, sink: AuditSink
) -> tuple[int, bool]:
    """Decrypt each file in order; returns the exit code and whether every file was attempted."""
    from ..keyvault import windows_audit

    rc = 0
    for path in targets:
        try:
            # C5d snapshots and validates the file itself; raw bytes are never passed.
            entries = windows_audit.decrypt_windows_log_file(path, home=home, audit_sink=sink, backend=backend)
        except Exception as exc:
            failure = _decrypt_failure(path, exc)
            if failure is None:
                raise
            message, stop = failure
            _term.emit_error(message)
            if stop:
                return 1, False
            rc = 1
            continue
        plural = "entry" if len(entries) == 1 else "entries"
        print(f"# {path.name} — {len(entries)} {plural}")
        for entry in entries:
            print(json.dumps(entry, ensure_ascii=False, sort_keys=True))
    return rc, True


# --- purge ----------------------------------------------------------------------------


def _purge_entry(session: AuditSession, directory: Path, name: str) -> PurgeOutcome:
    """Identity-bound checked delete of one enumerated entry; uncertainty propagates."""
    try:
        metadata = session.stat(name)
        if metadata is None:
            return "absent"
        session.delete(name, expected_identity=metadata.identity)
    except PrivateFSError as exc:
        if exc.commit_state != "not_committed":
            raise
        if _absent(exc):
            return "absent"
        _term.emit_error(str(_refused("purge", directory / name, exc, "It was kept.")))
        return "refused"
    print(f"purged {name}")
    return "deleted"


def purge(*, cutoff: date, directory: Path) -> int:
    """Windows ``audit purge``: delete dated siblings strictly before ``cutoff``.

    Exit codes match POSIX: 0 success (including nothing to purge); 1 when the
    directory or an entry cannot be handled safely. An uncertain deletion stops
    the purge immediately. The active log and custody files are never touched.
    """
    deleted = refused = 0
    try:
        with audit_session(directory / ACTIVE_NAME) as session:
            for name, dated, _number, _gzip in audit_rotation_names(session, max_entries=MAX_ENTRIES):
                if dated >= cutoff:
                    continue
                outcome = _purge_entry(session, directory, name)
                deleted += outcome == "deleted"
                refused += outcome == "refused"
    except (PrivateFSError, ValueError) as exc:
        if deleted == 0 and isinstance(exc, PrivateFSError) and _absent(exc):
            print("0 rotated audit log file(s) purged.")
            return 0
        _term.emit_error(str(_refused("purge", directory, exc, f"{deleted} file(s) had been purged when it stopped.")))
        return 1
    print(f"{deleted} rotated audit log file(s) purged.")
    return 1 if refused else 0
