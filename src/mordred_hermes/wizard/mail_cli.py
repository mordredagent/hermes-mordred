"""``hermes-mordred mail import|status`` — file-based mail import into the encrypted ``mordred.db``.

::

    hermes-mordred mail import (--mbox PATH [PATH ...] | --eml PATH [PATH ...])...
        --own-address ADDR [--own-address ADDR ...] [--own-addresses-file FILE]
        --account LABEL [--sent-label LABEL] [--dry-run] [--json] [--preview-labels N]
    hermes-mordred mail status [--json]
    hermes-mordred mail setup|fetch|forget ...   (IMAP sync: :mod:`.mail_sync_cli`)

- ``--account`` is a short opaque label (``work``), never an address: ``@``, ``:`` and
  whitespace are refused. At least one own address (``--own-address`` or one per line in
  ``--own-addresses-file``) is required; addresses are validated and lowercased.
- ``--dry-run`` never opens the store (it works on Linux, Windows and an unarmed macOS
  home) and prints the counts-only :class:`~..imports.mail.DryRunReport`.
- A real import opens the store through the protection gate (a refusal prints only its
  code, exits 1 and writes nothing), merges the account's recorded own addresses with
  the given ones, plans with the store-backed quote linker, writes one transaction per
  thread under one run and commits it; any failure fails the run (nothing published).
- ``--preview-labels N`` prints up to N conversation labels and part head lines (names
  and subjects, escaped; never bodies). It is refused together with ``--json``.
- ``mail status`` prints mail row and run counts and the NUMBER of recorded own
  addresses per account label — never the addresses — and the IMAP sync state
  (account label, path, last fetch, cursor positions).
- A real import holds the per-home mail writer lock that ``mail fetch`` uses, so a
  fetch never marks a running import's run as crashed (``sync_in_progress``).

Privacy: subjects, names, addresses and bodies never reach stdout, stderr or logs
outside ``--preview-labels`` (the dry-run report's ``sent_from_not_own`` lists only
Sent-mail ``From`` addresses missing from the own list — the owner's own addresses).
Errors print content-free codes; exceptions map to their class name. One ``mail.import``
audit event with counts only is written per real import run (committed or failed).
"""

from __future__ import annotations

import argparse
import contextlib
import json
import logging
import os
import re
import stat
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from .. import _term

if TYPE_CHECKING:
    from ..imports.mail import ImportPlan, MailSource
    from ..imports.store import ImportStore, WriteResult

_LOG: Final = logging.getLogger(__name__)
_MAX_ADDRESS_CHARS: Final = 254
_MAX_ADDRESSES_FILE_BYTES: Final = 1024 * 1024
_MAX_PREVIEW: Final = 10_000
_MAX_SENT_LABEL_CHARS: Final = 128
_ACCOUNT_FORBIDDEN_RE: Final = re.compile(r"[@:\s]")
_ADDRESS_ATOM: Final = r"[^@\s<>()\[\],;:\"\\]+"
_ADDRESS_RE: Final = re.compile(rf"{_ADDRESS_ATOM}@{_ADDRESS_ATOM}\.{_ADDRESS_ATOM}")
#: A refusal code (``not_armed``) or an exception class name (``RuntimeError``): never message text.
_CODE_RE: Final = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}")


class _UsageError(Exception):
    """A bad argument. The message is fixed text plus a position, never the argument's value."""


class _Failed(Exception):
    """A content-free failure code raised inside the import run."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


# --------------------------------------------------------------------------- #
# Seams (module-level so tests can replace them)
# --------------------------------------------------------------------------- #


def _home() -> Path:
    from .._home import hermes_home

    return hermes_home()


def _open_store(home: Path) -> ImportStore:
    """``open_import_store(home)``: the activity protection gate, then the ``import_*`` tables."""
    from ..imports import store as store_module

    return store_module.open_import_store(home)


def _writer_lock(home: Path) -> contextlib.AbstractContextManager[None]:
    """The per-home mail writer lock shared with ``mail fetch`` (``sync_in_progress`` when held)."""
    from ..imports.mail.imap_sync import fetch_lock

    return fetch_lock(home)


def _audit(entry: Mapping[str, Any]) -> None:
    """Best-effort audit entry through the shared encryption-aware writer (counts and codes only)."""
    try:
        from .._audit_support import build_audit_writer, safe_audit_append

        writer = build_audit_writer(_home() / "mordred" / "audit.log")
        safe_audit_append(writer, entry, logger=_LOG)
    except Exception as exc:
        _LOG.debug("mail import audit append failed (%s)", type(exc).__name__)


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #


def _code(exc: BaseException) -> str:
    """A content-free code: a known exception's stable ``code``, else its class name."""
    code = getattr(exc, "code", None)
    if isinstance(exc, Exception) and isinstance(code, str) and _CODE_RE.fullmatch(code):
        return code
    return type(exc).__name__


def _display(value: object, limit: int = 2000) -> str:
    """Same-user-writable or imported text is escaped before it reaches the terminal."""
    text = str(value)[:limit]
    return text if text.isprintable() else text.encode("unicode_escape").decode("ascii")


def _refused(code: str) -> int:
    _term.emit_error(f"mail store refused ({_display(code, 64)})")
    return 1


def _timestamp(value: object) -> str:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return "-"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(value))


# --------------------------------------------------------------------------- #
# Argument validation
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class _Request:
    sources: tuple[MailSource, ...]
    account: str
    own: tuple[str, ...]
    sent_label: str
    dry_run: bool
    json: bool
    preview: int


def _account(raw: object) -> str:
    from ..imports.records import RecordError, mail_conv_uid

    value = "" if raw is None else str(raw)
    if not value or _ACCOUNT_FORBIDDEN_RE.search(value):
        raise _UsageError("--account must be a short opaque label such as 'work' (no '@', ':' or whitespace)")
    try:
        mail_conv_uid(value, "probe")
    except RecordError:
        raise _UsageError(
            "--account must be 1-64 letters, digits, '.', '_' or '-', starting with a letter or digit"
        ) from None
    return value


def _own_address(raw: str, where: str) -> str:
    from ..imports.mail import OwnAddresses

    value = raw.strip().lower()
    if len(value) > _MAX_ADDRESS_CHARS or not value.isprintable() or not _ADDRESS_RE.fullmatch(value):
        raise _UsageError(f"{where} is not a valid email address")
    try:
        OwnAddresses.of([value])
    except ValueError:
        raise _UsageError(f"{where} is not a valid email address") from None
    return value


def _addresses_file(raw: str) -> list[str]:
    path = Path(raw).expanduser()
    try:
        info = os.stat(path)
    except OSError:
        raise _UsageError("--own-addresses-file cannot be read (not_found)") from None
    if not stat.S_ISREG(info.st_mode):
        raise _UsageError("--own-addresses-file is not a regular file")
    if info.st_size > _MAX_ADDRESSES_FILE_BYTES:
        raise _UsageError("--own-addresses-file is larger than 1 MiB")
    try:
        with path.open("rb") as handle:
            text = handle.read(_MAX_ADDRESSES_FILE_BYTES + 1).decode("utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        raise _UsageError(f"--own-addresses-file cannot be read ({type(exc).__name__})") from None
    found: list[str] = []
    for number, line in enumerate(text.splitlines(), start=1):
        item = line.split("#", 1)[0].strip()
        if item:
            found.append(_own_address(item, f"--own-addresses-file line {number}"))
    return found


def _own_addresses(args: argparse.Namespace) -> tuple[str, ...]:
    given = [
        _own_address(str(raw), f"--own-address #{index}")
        for index, raw in enumerate(getattr(args, "own_address", None) or [], start=1)
    ]
    path = getattr(args, "own_addresses_file", None)
    if path:
        given.extend(_addresses_file(str(path)))
    if not given:
        raise _UsageError("give at least one --own-address (or --own-addresses-file)")
    return tuple(sorted(set(given)))


def _check_source(kind: str, path: Path) -> None:
    """Fail before the store is opened: a missing or non-regular source never starts a run."""
    from ..imports.mail import SourceError

    try:
        info = os.lstat(path)
    except FileNotFoundError:
        raise SourceError("not_found") from None
    except OSError:
        raise SourceError("read_error") from None
    if not (stat.S_ISREG(info.st_mode) or (kind == "eml" and stat.S_ISDIR(info.st_mode))):
        raise SourceError("not_regular_file")


def _sources(args: argparse.Namespace) -> tuple[MailSource, ...]:
    from ..imports.mail import EmlSource, MboxSource, SourceError

    raw = getattr(args, "mail_sources", None) or []
    if not raw:
        raise _UsageError("give at least one --mbox PATH or --eml PATH")
    sources: list[MailSource] = []
    for index, (kind, value) in enumerate(raw, start=1):
        path = Path(value).expanduser()
        try:
            _check_source(kind, path)
        except SourceError as exc:
            raise _UsageError(f"mail source #{index} (--{kind}) cannot be read ({exc.code})") from None
        sources.append(MboxSource(path) if kind == "mbox" else EmlSource(path))
    return tuple(sources)


def _request(args: argparse.Namespace) -> _Request:
    preview = int(getattr(args, "preview_labels", 0) or 0)
    as_json = bool(getattr(args, "json", False))
    if preview and as_json:
        raise _UsageError("--preview-labels cannot be combined with --json")
    sent_label = str(getattr(args, "sent_label", "Sent") or "").strip()
    if not sent_label or len(sent_label) > _MAX_SENT_LABEL_CHARS or not sent_label.isprintable():
        raise _UsageError("--sent-label must be a non-empty label of at most 128 printable characters")
    account = _account(getattr(args, "account", None))
    return _Request(
        sources=_sources(args),
        account=account,
        own=_own_addresses(args),
        sent_label=sent_label,
        dry_run=bool(getattr(args, "dry_run", False)),
        json=as_json,
        preview=preview,
    )


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #


@dataclass
class _Written:
    inserted: int = 0
    duplicates: int = 0
    revised: int = 0
    conflicts: int = 0

    def add(self, result: WriteResult) -> None:
        self.inserted += result.inserted
        self.duplicates += result.duplicates
        self.revised += result.revised
        self.conflicts += result.conflicts

    def as_dict(self) -> dict[str, int]:
        return {
            "inserted": self.inserted,
            "duplicates": self.duplicates,
            "revised": self.revised,
            "conflicts": self.conflicts,
        }


def _print_result(request: _Request, plan: ImportPlan, written: _Written | None) -> None:
    if request.json:
        if written is None:
            print(plan.report.as_json())
        else:
            body = {**plan.report.as_dict(), "written": written.as_dict()}
            print(json.dumps(body, ensure_ascii=False, sort_keys=True, indent=2))
        return
    if written is None:
        print("Mail import dry run: nothing was written and the store was not opened.")
    else:
        print("Mail import committed.")
    for line in plan.report.as_text().splitlines():
        print(_display(line))
    if written is not None:
        print("written:")
        for key, value in written.as_dict().items():
            print(f"  {key}: {value}")
    if request.preview:
        print(f"preview (first {request.preview} conversations; labels and head lines only):")
        for line in plan.preview(request.preview):
            print(f"  {_display(line)}")


# --------------------------------------------------------------------------- #
# import
# --------------------------------------------------------------------------- #


def _dry_run(request: _Request) -> int:
    from ..imports.mail import plan_import

    try:
        plan = plan_import(
            request.sources, account=request.account, own_addresses=request.own, sent_label=request.sent_label
        )
    except Exception as exc:
        _term.emit_error(f"mail import dry run failed ({_code(exc)})")
        return 1
    _print_result(request, plan, None)
    return 0


def _run_counts(plan: ImportPlan | None, written: _Written) -> dict[str, int]:
    """Counts only (the run's ``counts_json`` and the audit event)."""
    report = plan.report if plan is not None else None
    return {
        "parsed": report.parsed if report else 0,
        "conversations": report.conversations if report else 0,
        "skipped": sum(report.skipped.values()) if report else 0,
        "source_duplicates": report.duplicates if report else 0,
        "source_conflicts": report.conflicts if report else 0,
        **written.as_dict(),
    }


def _audit_entry(decision: str, counts: Mapping[str, int], error: str | None = None) -> dict[str, Any]:
    entry: dict[str, Any] = {"event": "mail.import", "decision": decision, "reason": None, **counts}
    if error is not None:
        entry["error"] = error
    return entry


@dataclass
class _Progress:
    """What a real import run has done so far (its counts are reported even when it fails)."""

    plan: ImportPlan | None = None
    written: _Written = field(default_factory=_Written)

    def counts(self) -> dict[str, int]:
        return _run_counts(self.plan, self.written)


def _write_plan(store: ImportStore, run_id: str, request: _Request, own: Sequence[str], progress: _Progress) -> None:
    from ..imports.mail import StoreLinker, plan_import, remember_own_addresses

    linker = StoreLinker(store, request.account)
    progress.plan = plan_import(
        request.sources, account=request.account, own_addresses=own, sent_label=request.sent_label, linker=linker
    )
    if linker.error is not None:
        raise _Failed(linker.error)  # a store failure while linking: never publish weaker attributions
    for thread in progress.plan.threads:
        progress.written.add(store.write_thread(run_id, thread.messages, conversation=thread.conversation))
    remember_own_addresses(store, request.account, own)


def _real_import(request: _Request) -> int:
    try:
        store = _open_store(_home())
    except Exception as exc:
        return _refused(_code(exc))
    lock = _writer_lock(_home())
    try:
        lock.__enter__()
    except Exception as exc:
        return _refused(_code(exc))
    try:
        return _locked_import(store, request)
    finally:
        lock.__exit__(None, None, None)


def _locked_import(store: ImportStore, request: _Request) -> int:
    from ..imports.mail import stored_own_addresses

    try:
        own = tuple(sorted(set(request.own) | stored_own_addresses(store, request.account)))
        run_id = store.run_begin("mail")
    except Exception as exc:
        return _refused(_code(exc))
    progress = _Progress()
    try:
        _write_plan(store, run_id, request, own, progress)
        store.run_commit(run_id, progress.counts())
    except BaseException as exc:
        with contextlib.suppress(Exception):
            store.run_fail(run_id, progress.counts())
        code = _code(exc)
        _audit(_audit_entry("failed", progress.counts(), code))
        if not isinstance(exc, Exception):
            raise
        _term.emit_error(f"mail import failed ({code}); nothing was published")
        return 1
    _audit(_audit_entry("committed", progress.counts()))
    if progress.plan is not None:
        _print_result(request, progress.plan, progress.written)
    return 0


def cmd_import(args: argparse.Namespace) -> int:
    try:
        request = _request(args)
    except _UsageError as exc:
        _term.emit_error(str(exc))
        return 2
    return _dry_run(request) if request.dry_run else _real_import(request)


# --------------------------------------------------------------------------- #
# status
# --------------------------------------------------------------------------- #


def _print_status(report: Mapping[str, Any]) -> None:
    print("Mordred mail import")
    print(f"  schema version: {_display(report.get('schema_version'), 16)}")
    for key, value in (report.get("mail") or {}).items():
        print(f"  {_display(key, 40)}: {_display(value, 20)}")
    runs = report.get("runs") or {}
    rendered = ", ".join(f"{_display(state, 20)}={_display(count, 20)}" for state, count in runs.items())
    print(f"  runs: {rendered or 'none'}")
    last = report.get("last_run")
    if last:
        counts = ", ".join(f"{_display(k, 40)}={_display(v, 20)}" for k, v in (last.get("counts") or {}).items())
        print(f"  last run: {_display(last.get('state'), 20)} at {_timestamp(last.get('started_at'))}")
        if counts:
            print(f"    {counts}")
    accounts = report.get("accounts") or {}
    print("  accounts:" + ("" if accounts else " none"))
    for label, info in accounts.items():
        print(f"    {_display(label, 64)}: {_display(info.get('own_addresses'), 20)} own address(es)")


def _imap_flags() -> Mapping[str, Any] | None:
    try:
        from ..imports.mail.secrets import MailSecretStore

        flags: Mapping[str, Any] | None = MailSecretStore().flags()
        return flags
    except Exception:
        return None


def cmd_status(args: argparse.Namespace) -> int:
    from ..imports.mail import mail_store_status
    from .mail_sync_cli import imap_status, print_imap_status

    try:
        store = _open_store(_home())
        report = mail_store_status(store)
        report["imap"] = imap_status(store, _imap_flags())
    except Exception as exc:
        return _refused(_code(exc))
    if getattr(args, "json", False):
        print(json.dumps(report, sort_keys=True))
    else:
        _print_status(report)
        print_imap_status(report["imap"])
    return 0


# --------------------------------------------------------------------------- #
# Dispatch and parsers (called from ``_cli_parsers._add_mail``)
# --------------------------------------------------------------------------- #


def _sync_command(name: str) -> Callable[[argparse.Namespace], int]:
    def run(args: argparse.Namespace) -> int:
        from . import mail_sync_cli

        handler: Callable[[argparse.Namespace], int] = getattr(mail_sync_cli, f"cmd_{name}")
        return handler(args)

    return run


_COMMANDS: Mapping[str, Callable[[argparse.Namespace], int]] = {
    "import": cmd_import,
    "status": cmd_status,
    "setup": _sync_command("setup"),
    "fetch": _sync_command("fetch"),
    "forget": _sync_command("forget"),
}


def cli_mail(args: argparse.Namespace) -> int:
    handler = _COMMANDS.get(str(getattr(args, "mail_command", None)))
    if handler is None:
        _term.emit_error(f"unknown mail command {_display(getattr(args, 'mail_command', None), 40)}")
        return 2
    return handler(args)


class _AppendSources(argparse.Action):
    """``--mbox`` / ``--eml`` append ``(kind, path)`` to one list, keeping command-line order."""

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: str | Sequence[Any] | None,
        option_string: str | None = None,
    ) -> None:
        kind = "mbox" if "--mbox" in self.option_strings else "eml"
        items = list(getattr(namespace, self.dest, None) or [])
        paths = [values] if isinstance(values, str) else list(values or [])
        items.extend((kind, str(path)) for path in paths)
        setattr(namespace, self.dest, items)


def _preview_count(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError:
        raise argparse.ArgumentTypeError("N must be a whole number") from None
    if not 0 <= value <= _MAX_PREVIEW:
        raise argparse.ArgumentTypeError(f"N must be between 0 and {_MAX_PREVIEW}")
    return value


def add_parsers(msub: Any, handler: Callable[[argparse.Namespace], int]) -> None:
    p = msub.add_parser(
        "import",
        help="Import Gmail Takeout mbox / .eml files into the encrypted store (--dry-run: counts only)",
    )
    p.add_argument("--mbox", dest="mail_sources", nargs="+", action=_AppendSources, metavar="PATH", help="mbox file(s)")
    p.add_argument(
        "--eml",
        dest="mail_sources",
        nargs="+",
        action=_AppendSources,
        metavar="PATH",
        help=".eml file(s) or directories of .eml files",
    )
    p.add_argument("--own-address", action="append", metavar="ADDR", help="One of your own addresses (repeatable)")
    p.add_argument("--own-addresses-file", metavar="FILE", help="More own addresses, one per line ('#' comments)")
    p.add_argument("--account", required=True, metavar="LABEL", help="Short opaque account label, e.g. 'work'")
    p.add_argument("--sent-label", default="Sent", metavar="LABEL", help="Gmail label of sent mail (default: Sent)")
    p.add_argument("--dry-run", action="store_true", help="Counts only; never opens or writes the store")
    p.add_argument("--json", action="store_true", help="Print one JSON object")
    p.add_argument(
        "--preview-labels",
        type=_preview_count,
        default=0,
        metavar="N",
        help="Also print up to N conversation labels and head lines (names and subjects; never bodies)",
    )
    p.set_defaults(func=handler)
    p_status = msub.add_parser("status", help="Show mail row and run counts and own-address counts (no content)")
    p_status.add_argument("--json", action="store_true", help="Print one JSON object")
    p_status.set_defaults(func=handler)
    from .mail_sync_cli import add_parsers as add_sync_parsers

    add_sync_parsers(msub, handler)
