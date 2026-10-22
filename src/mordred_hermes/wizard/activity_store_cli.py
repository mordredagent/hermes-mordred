"""``hermes-mordred activity backup|restore|retention`` — activity store maintenance.

- ``backup --output PATH`` — a consistent encrypted snapshot to a new ``0600`` file (refuses an
  existing destination).
- ``restore --input PATH [--yes]`` — without ``--yes`` print what the restore would do and exit 2;
  with it replace the store's content (new store generation, Hermes session references marked
  unavailable). A copy bound to another profile is refused.
- ``retention [--dry-run] [--json]`` — one bounded retention pass with the configured raw-event
  window; ``--dry-run`` reports the same counts from read-only queries.

Every command opens the store through the protection gate and prints only the refusal code when
it refuses (exit 1). Identifiers and counts only; event content is never printed.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
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


def _refused(code: object) -> int:
    _term.emit_error(f"refused ({_display(code if isinstance(code, str) else 'store_unavailable', 64)})")
    return 1


def _guarded(handler: Callable[[argparse.Namespace, ActivityStore, ActivityConfig], int]) -> Callable[..., int]:
    def run(args: argparse.Namespace) -> int:
        from ..activity._gate import ActivityRefused

        try:
            store, config = _open(_home())
            return handler(args, store, config)
        except ActivityRefused as exc:
            return _refused(exc.code)

    return run


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


def _source_status(store: ActivityStore, src: Path) -> StoreStatus:
    """The backup's status through the keyed copy opener; refuses a missing, plaintext or foreign copy."""
    from ..activity._gate import ActivityRefused, refusal
    from ..activity.store import ActivityStore

    if not src.is_file():  # never let the opener create an empty database at ``src``
        raise ActivityRefused(refusal("store_unavailable"))
    store._check_copy(src)
    source = ActivityStore(src, store._copy_opener)
    if source.meta().profile_home != store.meta().profile_home:
        raise ActivityRefused(refusal("profile_mismatch"))
    return source.status()


def _print_counts(title: str, values: Mapping[str, int]) -> None:
    print(title)
    for key, value in values.items():
        print(f"    {_display(key, 64)}: {value}")


def _restore(args: argparse.Namespace, store: ActivityStore, config: ActivityConfig) -> int:
    src = _path(args.input)
    source = _source_status(store, src)
    if not args.yes:
        print(f"Restore from {_display(src)} would replace the current activity store content.")
        print(f"  backup schema version: {source.schema_version}")
        print(f"  backup generation:     {_display(source.store_generation, 64)}")
        _print_counts("  backup rows:", source.counts)
        print("Nothing changed. Run again with --yes to restore.")
        return 2
    meta = store.restore(src)
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
    "restore": _guarded(_restore),
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
