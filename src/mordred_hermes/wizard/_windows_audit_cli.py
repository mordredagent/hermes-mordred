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
  ``decrypt_windows_log_file``, which snapshots and validates the file itself;
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

import json
from datetime import UTC, date, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final, Literal

from .._audit_session import AuditSession, audit_session, read_audit_snapshot
from .._log_rotation import audit_rotation_names
from .._private_fs import PrivateFSError
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
        "hard link, junction or reparse point) or exceeds a checked bound; Mordred never repairs ACLs, "
        "follows links or truncates — fix it by hand, then retry"
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


def _refused(action: str, path: Path, exc: BaseException, outcome: str) -> WindowsAuditRefused:
    reason = classify_storage(exc)
    return WindowsAuditRefused(
        reason, f"refusing audit {action} at {path}: {reason} ({exc}) — {_STORAGE_REMEDIES[reason]}. {outcome}"
    )


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


def native_audit_refusal(home: Path) -> str | None:
    """The C5e ``native_audit`` precondition; a refusal message unless available.

    Pure observation: no native backend, unwrap, enrollment or lock wait.
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
    return f"audit decrypt refused: {_windows_gates.describe_capability(capability)}. {_NOT_DECRYPTED}"


def _today() -> date:
    return datetime.now(UTC).date()


def decrypt_targets(directory: Path, target: date) -> list[Path]:
    """Checked, bounded selection of the files holding ``target``'s entries.

    Dated siblings come in C7a rotation order (date, then numeric suffix), so
    entries print oldest first; the active log is last and only for today.
    Each selected entry is checked (regular, private, single link) before any
    native call, and the selection's combined size is bounded.
    """
    with audit_session(directory / ACTIVE_NAME) as session:
        names = [
            name for name, dated, _n, _gz in audit_rotation_names(session, max_entries=MAX_ENTRIES) if dated == target
        ]
        if target == _today():
            names.append(ACTIVE_NAME)
        selected: list[Path] = []
        total = 0
        for name in names:
            metadata = session.stat(name)
            if metadata is None:
                continue
            total += metadata.size
            if total > DECRYPT_TOTAL_LIMIT:
                raise PrivateFSError("unsafe", "audit_total_limit")
            selected.append(directory / name)
    return selected


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
    refusal = native_audit_refusal(custody_home)
    if refusal is not None:
        _term.emit_error(refusal)
        return 1
    try:
        targets = decrypt_targets(directory, target)
    except PrivateFSError as exc:
        if not _absent(exc):
            _term.emit_error(str(_refused("decrypt", directory, exc, _NOT_DECRYPTED)))
            return 1
        targets = []
    except ValueError as exc:
        _term.emit_error(str(_refused("decrypt", directory, exc, _NOT_DECRYPTED)))
        return 1
    if not targets:
        _term.emit_error(f"No audit log file found for {date_text} under {directory}")
        return 1
    return _decrypt_files(targets, home=custody_home, backend=backend, sink=sink)


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


def _decrypt_files(targets: list[Path], *, home: Path, backend: NativeBackend | None, sink: AuditSink) -> int:
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
                return 1
            rc = 1
            continue
        plural = "entry" if len(entries) == 1 else "entries"
        print(f"# {path.name} — {len(entries)} {plural}")
        for entry in entries:
            print(json.dumps(entry, ensure_ascii=False, sort_keys=True))
    return rc


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
