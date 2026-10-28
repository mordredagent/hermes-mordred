"""``hermes-mordred activity backup|restore|retention`` — activity store maintenance.

- ``backup --output PATH`` — a consistent encrypted snapshot to a new ``0600`` file (refuses an
  existing destination).
- ``restore --input PATH [--yes]`` — without ``--yes`` print what the restore would do and exit 2;
  with it replace the store's content (new store generation, Hermes session references marked
  unavailable). A copy bound to another profile is refused.
- ``retention [--dry-run] [--json]`` — one bounded retention pass with the configured raw-event
  window; ``--dry-run`` reports the same counts from read-only queries.

Every command except ``restore`` opens the store through the protection gate; ``restore`` runs
offline under the exclusive lease. A refusal prints only its code (exit 1).
Identifiers and counts only; event content is never printed.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .. import _term

if TYPE_CHECKING:
    from ..activity.config import ActivityConfig
    from ..activity.store import ActivityStore, StoreStatus


# --------------------------------------------------------------------------- #
# Seams (module-level so tests can replace them)
# --------------------------------------------------------------------------- #


def _home() -> Path:
    from .._home import hermes_home

    return hermes_home()


def _open(home: Path) -> tuple[ActivityStore, ActivityConfig]:
    from ..activity._gate import open_store
    from ..activity.config import ActivityConfig

    return open_store(home), ActivityConfig.load(home)


def _display(value: object, limit: int = 300) -> str:
    """Same-user-writable state is escaped before it reaches the terminal."""
    text = "-" if value is None else str(value)[:limit]
    return text if text.isprintable() else text.encode("unicode_escape").decode("ascii")


_HINTS = {
    "busy": "stop Hermes first (a runtime holds the database lease)",
    "store_missing": "start Hermes once so a fresh store is created, stop it, then restore",
}
_UNAVAILABLE_RESTORE_HINT = (
    "the backup must be a readable registered copy; if the current store is corrupt, move it aside, start Hermes "
    "once to create a fresh store, stop it, then restore"
)


def _refused(code: object, *, hint: str | None = None) -> int:
    _term.emit_error(f"refused ({_display(code if isinstance(code, str) else 'store_unavailable', 64)})")
    if hint:
        _term.emit_error(hint)
    return 1


def _refusal_code(exc: BaseException) -> str:
    from .._database_contracts import DatabaseBusy
    from ..activity._gate import ActivityRefused

    if isinstance(exc, ActivityRefused):
        return exc.code
    return "busy" if isinstance(exc, DatabaseBusy) else "store_unavailable"


def _catching(
    run_body: Callable[[argparse.Namespace], int], *, unavailable_hint: str | None = None
) -> Callable[[argparse.Namespace], int]:
    def run(args: argparse.Namespace) -> int:
        from .._database_contracts import DatabaseRefused
        from .._private_fs import PrivateFSError
        from ..activity._gate import ActivityRefused

        try:
            return run_body(args)
        except (ActivityRefused, DatabaseRefused, PrivateFSError, OSError) as exc:  # DatabaseBusy is a DatabaseRefused
            code = _refusal_code(exc)
            return _refused(code, hint=_HINTS.get(code) or (unavailable_hint if code == "store_unavailable" else None))

    return run


def _guarded(handler: Callable[[argparse.Namespace, ActivityStore, ActivityConfig], int]) -> Callable[..., int]:
    def body(args: argparse.Namespace) -> int:
        store, config = _open(_home())
        return handler(args, store, config)

    return _catching(body)


def _path(raw: object) -> Path:
    return Path(str(raw)).expanduser()


# --------------------------------------------------------------------------- #
# backup
# --------------------------------------------------------------------------- #


def _backup(args: argparse.Namespace, store: ActivityStore, config: ActivityConfig) -> int:
    dest = _path(args.output)
    try:
        store.backup(dest)
    except OSError:
        # Missing directory or no permission; the store itself was not touched.
        return _refused("destination_unavailable")
    print(f"Backup written to {_display(dest)}")
    print(f"  store generation: {_display(store.meta().store_generation, 64)}")
    print("The copy is encrypted with this profile's database key; keep the key to restore it.")
    print("Restoring it into another profile's activity store is refused.")
    return 0


# --------------------------------------------------------------------------- #
# restore
# --------------------------------------------------------------------------- #


def _backup_status(src: Path, home: Path, lease: Any) -> StoreStatus:
    """The backup's status through the retained maintenance scope; refuses a missing or foreign copy."""
    from ..activity import _schema
    from ..activity._gate import ActivityRefused, refusal
    from ..activity.store import ActivityStore, StoreStatus, require_store_file
    from ..dbcrypt._maintenance import maintenance_scope
    from ..imports._protected_destination import checked_store_destination

    if not src.is_file():  # never let the opener create an empty database at ``src``
        raise ActivityRefused(refusal("store_unavailable"))
    destination = checked_store_destination(home / "plugin-data/mordred/mordred.db", home=home)
    require_store_file(destination)
    with maintenance_scope(home, lease=lease) as scope:
        with scope.connection(destination, readonly=True) as current:
            target = ActivityStore._checked_meta(ActivityStore._read_meta(current))
            if target.profile_home != str(home):
                raise ActivityRefused(refusal("profile_mismatch"))
        with scope.connection(src, readonly=True) as backup:
            meta = ActivityStore._checked_meta(ActivityStore._read_meta(backup))
            if meta.profile_home != target.profile_home:
                raise ActivityRefused(refusal("profile_mismatch"))
            counts = {
                table: int((backup.execute(f"SELECT count(*) FROM {table}").fetchone() or (0,))[0])
                for table in _schema.TABLES
                if table != "activity_meta"
            }
    return StoreStatus(schema_version=meta.schema_version, store_generation=meta.store_generation, counts=counts)


def _print_counts(title: str, values: Mapping[str, int]) -> None:
    print(title)
    for key, value in values.items():
        print(f"    {_display(key, 64)}: {value}")


def _restore(args: argparse.Namespace) -> int:
    """Offline restore: takes the exclusive lease itself; never opens the shared runtime store."""
    from .._database_lifecycle import acquire_exclusive
    from ..activity._gate import ActivityRefused, refusal
    from ..activity.store import restore_activity_store
    from ..keyvault._database_authority import resolve_database_domain

    src = _path(args.input)
    home = Path(os.path.realpath(_home()))
    src_abs = Path(os.path.realpath(src))
    base = resolve_database_domain(home).root
    with acquire_exclusive(base) as lease:
        if not args.yes:
            source = _backup_status(src_abs, home, lease)
            print(f"Restore from {_display(src)} would replace the current activity store content.")
            print(f"  backup schema version: {source.schema_version}")
            print(f"  backup generation:     {_display(source.store_generation, 64)}")
            _print_counts("  backup rows:", source.counts)
            print("Nothing changed. Run again with --yes to restore.")
            return 2
        if not src_abs.is_file():
            raise ActivityRefused(refusal("store_unavailable"))
        meta = restore_activity_store(src_abs, home=home, lease=lease)
    print(f"Restored the activity store from {_display(src)}")
    print(f"  new store generation: {_display(meta.store_generation, 64)}")
    print("Hermes session references in the restored history are marked unavailable.")
    return 0


# --------------------------------------------------------------------------- #
# retention
# --------------------------------------------------------------------------- #


def _retention(args: argparse.Namespace, store: ActivityStore, config: ActivityConfig) -> int:
    raw_days = config.retention_raw_days
    run = store.plan_retention if args.dry_run else store.apply_retention
    report = run(time.time(), raw_days=raw_days)
    body: dict[str, Any] = {"dry_run": bool(args.dry_run), "raw_days": raw_days, **dataclasses.asdict(report)}
    if args.json:
        print(json.dumps(body, sort_keys=True))
        return 0
    verb = "would remove" if args.dry_run else "removed"
    mode = "dry run" if args.dry_run else "one pass"
    raw = f"{raw_days} days" if raw_days > 0 else "kept forever"
    print(f"Retention ({mode}; raw events {raw}):")
    print(f"  events {verb}:    {report.events_deleted}")
    print(f"  episodes {verb}:  {report.episodes_deleted}")
    if not report.complete:
        print("A step hit its per-pass limit; run `hermes-mordred activity retention` again.")
    return 0


# --------------------------------------------------------------------------- #
# Dispatch and parsers (called from ``activity_cli`` / ``_cli_parsers._add_activity``)
# --------------------------------------------------------------------------- #

_HANDLERS: Mapping[str, Callable[[argparse.Namespace], int]] = {
    "backup": _guarded(_backup),
    "restore": _catching(_restore, unavailable_hint=_UNAVAILABLE_RESTORE_HINT),
    "retention": _guarded(_retention),
}
COMMANDS = frozenset(_HANDLERS)


def dispatch(command: str, args: argparse.Namespace) -> int:
    return _HANDLERS[command](args)


def add_parsers(asub: Any, handler: Callable[[argparse.Namespace], int]) -> None:
    p = asub.add_parser("backup", help="Write an encrypted snapshot of the activity store to a new file")
    p.add_argument("--output", required=True, help="Destination file (must not exist)")
    p.set_defaults(func=handler)
    p = asub.add_parser("restore", help="Replace the activity store with a backup of this profile's store")
    p.add_argument("--input", required=True, help="Backup file written by `activity backup`")
    p.add_argument("--yes", action="store_true", help="Restore; without it only show what would happen")
    p.set_defaults(func=handler)
    p = asub.add_parser("retention", help="Run one bounded retention pass with the configured windows")
    p.add_argument("--dry-run", action="store_true", help="Only count what one pass would remove")
    p.add_argument("--json", action="store_true", help="Print one JSON object")
    p.set_defaults(func=handler)
