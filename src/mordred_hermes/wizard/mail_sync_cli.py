"""``hermes-mordred mail setup|fetch|forget`` — IMAP sync into the encrypted ``mordred.db`` (macOS).

::

    hermes-mordred mail setup [--imap-host H] [--imap-port 993] [--account LABEL] [--no-touch-id]
    hermes-mordred mail fetch [--max N] [--mailbox all|inbox|sent] [--since YYYY-MM-DD] [--dry-run] [--json]
    hermes-mordred mail forget [--rows] [--account LABEL] --yes

- ``setup`` reads the address and the app password on a TTY (never from argv or
  the environment) and drives :class:`~mordred_hermes.imports.mail.setup_flow.MailSetupFlows`,
  the flow the Desktop page uses too: one read-only login (``CAPABILITY``,
  ``LIST``), the mailboxes (Gmail: All Mail by its ``\\All`` special use or its
  usual name, else the operator's pick; other servers: INBOX plus the ``\\Sent``
  special-use folder, or the operator's pick, or none), sealed with the Secure
  Enclave (:mod:`mordred_hermes.imports.mail.secrets`). It prints the account
  label and the path, never the address; a refusal prints its code and, for a
  refused login, the hint (``mail refused (imap_auth_failed:
  authentication_failed)``). Sealed credentials are never replaced
  (``mail_already_configured``: run ``forget`` first). Port 993 (implicit TLS)
  is the only port. The probe and the sealing run under the per-home mail writer
  lock, the lock ``fetch``, ``mail import`` and ``forget`` take
  (``sync_in_progress`` when held).
- ``fetch`` runs :func:`mordred_hermes.imports.mail.imap_sync.run_fetch`, the same
  function as the Hermes tool ``mordred_mail_sync``, with a 10 minute budget, and
  prints the fixed counts-only result (``--json``: exactly
  :meth:`~mordred_hermes.imports.mail.imap_sync.FetchResult.as_dict`) plus, in
  text mode, the cursor positions. Exit 0 on success (a partial fetch included),
  1 on a refusal or failure, 2 on bad arguments. A refused login's hint follows
  the code in the text output (``mail fetch failed (imap_auth_failed:
  authentication_failed)``), never in ``--json``.
- ``forget --yes`` runs :func:`mordred_hermes.imports.mail.forget.forget` (shared
  with the Desktop page): it deletes the account's cursors and then the sealed
  credentials and the Enclave key; ``--rows`` first deletes the account's mail
  rows (``delete_source``) and stops (exit 1, nothing touched) if the store
  refuses. The account label is resolved once, before the lock; under the lock
  the credentials must still be the same setup (``setup_id``), else nothing is
  deleted (``credentials_changed``): a concurrent ``mail setup`` is never
  undone. Rows and cursors go first and the credentials last, so a failed
  forget is retried; ``--account LABEL`` deletes a label's rows and cursors
  when its credentials are already gone (``account_mismatch`` when it names
  another label than the sealed one). The sealed file, the flags and the
  Enclave key are deleted whatever the flags say: credentials whose flags are
  missing or corrupt (a setup or forget interrupted between its two files) are
  still deleted, their label is reported as unknown (``account_unknown``, exit
  1: rows and cursors need ``--account LABEL``), and forget never reports
  success while a sealed file remains (``credentials_left``) or when the
  Enclave key could not be deleted (``key_left``, exit 1; a retry deletes it).

Nothing here prints a subject, name, address, label or body.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import getpass
import json
import logging
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from .. import _term

if TYPE_CHECKING:
    from ..imports.mail.forget import Forgotten
    from ..imports.mail.imap import ImapSession
    from ..imports.mail.imap_sync import FetchEnv, FetchResult
    from ..imports.mail.setup_flow import SetupFolder

_LOG: Final = logging.getLogger(__name__)
_ROLES: Final = ("all", "inbox", "sent")
#: Input codes of the shared setup flow; the prompts check each answer first, so these are a backstop.
_INPUT_CODES: Final = frozenset(
    {"invalid_address", "invalid_host", "invalid_account", "invalid_password", "too_many_addresses"}
)

InputFn = Callable[[str], str]


class _Usage(Exception):
    """Bad input (exit 2). The message is fixed text, never the value typed."""


class _Refused(Exception):
    """A content-free refusal code (exit 1)."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


# --------------------------------------------------------------------------- #
# Seams (module-level so tests can replace them)
# --------------------------------------------------------------------------- #


def _home() -> Path:
    from .._home import hermes_home

    return hermes_home()


def _platform() -> str:
    return sys.platform


def _isatty() -> bool:
    try:
        return sys.stdin.isatty()
    except (AttributeError, ValueError):
        return False


def _input(prompt: str) -> str:
    return input(prompt)


def _secret(prompt: str) -> str:
    return getpass.getpass(prompt)


def _secret_store() -> Any:
    from ..imports.mail.secrets import MailSecretStore

    return MailSecretStore()


def _connect(host: str, port: int) -> ImapSession:
    from ..imports.mail.imap import connect

    return connect(host, port)


def _fetch_env() -> FetchEnv:
    from ..imports.mail.imap_sync import default_env

    return default_env(_home())


def _open_store(home: Path) -> Any:
    from ..imports import store as store_module

    return store_module.open_import_store(home)


def _lock(home: Path) -> contextlib.AbstractContextManager[None]:
    from ..imports.mail.imap_sync import fetch_lock

    return fetch_lock(home)


def _audit(entry: Mapping[str, Any]) -> None:
    try:
        from .._audit_support import build_audit_writer, safe_audit_append

        writer = build_audit_writer(_home() / "mordred" / "audit.log")
        safe_audit_append(writer, entry, logger=_LOG)
    except Exception as exc:
        _LOG.debug("mail audit append failed (%s)", type(exc).__name__)


def _refused(code: str, hint: str | None = None) -> int:
    _term.emit_error(f"mail refused ({code}: {hint})" if hint else f"mail refused ({code})")
    return 1


# --------------------------------------------------------------------------- #
# setup
# --------------------------------------------------------------------------- #


def _address(raw: str, where: str) -> str:
    from ..imports.mail.setup_flow import MailSetupError, check_address

    try:
        return check_address(raw)
    except MailSetupError:
        raise _Usage(f"{where} is not a valid email address") from None


def _host(raw: str | None, address: str) -> str:
    from ..imports.mail.setup_flow import MailSetupError, check_host, default_host

    value = (raw or "").strip()
    if not value:
        value = default_host(address) or _input("IMAP server host (e.g. imap.example.com): ")
    try:
        return check_host(value)
    except MailSetupError:
        raise _Usage("the IMAP host must be a DNS name such as imap.example.com") from None


def _password(host: str) -> str:
    from ..imports.mail.setup_flow import MailSetupError, check_password

    try:  # Google shows app passwords in groups of four: the spaces are dropped on Gmail's host
        return check_password(_secret("App password (hidden; sealed by the Secure Enclave): "), host)
    except MailSetupError:
        raise _Usage("the app password must be 1-256 printable characters") from None


def _extra_addresses() -> list[str]:
    from ..imports.mail.setup_flow import MAX_EXTRA_ADDRESSES

    raw = _input("Other own addresses, comma-separated (Enter for none): ")
    items = [item.strip() for item in raw.split(",") if item.strip()]
    if len(items) > MAX_EXTRA_ADDRESSES:
        raise _Usage(f"give at most {MAX_EXTRA_ADDRESSES} other own addresses")
    return [_address(item, f"own address #{n}") for n, item in enumerate(items, start=1)]


def _pick(folders: Sequence[SetupFolder], what: str, *, allow_none: bool) -> str | None:
    """Ask the operator to choose a folder by number (folder names are not mail content; shown sanitised)."""
    if not folders:
        return None
    print(f"The server does not mark a {what} folder. Folders:")
    for number, folder in enumerate(folders, start=1):
        print(f"  {number}. {folder.display}")
    hint = " (Enter for none)" if allow_none else ""
    raw = _input(f"Number of your {what} folder{hint}: ").strip()
    if not raw and allow_none:
        return None
    if not raw.isdigit() or not 1 <= int(raw) <= len(folders):
        raise _Usage(f"choose a folder number between 1 and {len(folders)}")
    return folders[int(raw) - 1].name


def _setup_values(args: argparse.Namespace) -> tuple[str, str, str, list[str]]:
    """(account, host, address, other own addresses), each checked as it is typed."""
    from ..imports.mail.secrets import ACCOUNT_RE, IMAPS_PORT

    account = str(getattr(args, "account", None) or "mail")
    if not ACCOUNT_RE.fullmatch(account):
        raise _Usage("--account must be 1-32 lowercase letters, digits or '_', starting with a letter")
    port = int(getattr(args, "imap_port", IMAPS_PORT) or IMAPS_PORT)
    if port != IMAPS_PORT:
        raise _Usage("--imap-port must be 993 (implicit TLS); other ports are not supported")
    if _platform() != "darwin":
        raise _Refused("unsupported_platform")
    if not _isatty():
        raise _Refused("tty_required")
    address = _address(_input("Mail address: "), "the mail address")
    host = _host(getattr(args, "imap_host", None), address)
    return account, host, address, _extra_addresses()


def cmd_setup(args: argparse.Namespace) -> int:
    from ..imports.mail.setup_flow import MailSetupError, MailSetupFlows

    try:
        account, host, address, extra = _setup_values(args)
        password = _password(host)
        flows = MailSetupFlows(_secret_store(), connect=_connect, lock=_lock, home=_home)
        flow = flows.start(
            address=address,
            imap_host=host,
            account=account,
            extra_addresses=extra,
            app_password=password,
            presence=not bool(getattr(args, "no_touch_id", False)),
        )
        if flow.step == "folders":
            try:
                what = "All Mail" if flow.question == "all_mail" else "sent"
                choice = _pick(flow.folders, what, allow_none=flow.question == "sent")
                flow = flows.finish(flow.flow_id, selection=choice)
            finally:
                flows.cancel(flow.flow_id)  # a no-op once finished; otherwise the password leaves memory now
    except _Usage as exc:
        _term.emit_error(str(exc))
        return 2
    except _Refused as exc:
        return _refused(exc.code)
    except MailSetupError as exc:
        if exc.code in _INPUT_CODES:
            _term.emit_error(f"mail setup input is not valid ({exc.code})")
            return 2
        return _refused(exc.code, exc.hint)
    except (EOFError, KeyboardInterrupt):
        _term.emit_error("mail setup cancelled; nothing was stored")
        return 1
    path = "Gmail (All Mail with labels)" if flow.gmail else "IMAP (" + ", ".join(sorted(flow.roles)) + ")"
    print(f"Mail account '{flow.account}' is set up: {path}. The credentials are sealed by the Secure Enclave.")
    if not flow.gmail and "sent" not in flow.roles:
        print("No sent folder was chosen: your own messages are recognised only by your addresses.")
    print("Fetch new mail with `hermes-mordred mail fetch`, or say 'sync my mail' in a Hermes chat.")
    return 0


# --------------------------------------------------------------------------- #
# fetch
# --------------------------------------------------------------------------- #


def imap_cursors(store: Any, account: str) -> dict[str, dict[str, Any]]:
    """Forward and backfill cursor positions per role (numbers and role names only)."""
    from ..imports.mail.imap_sync import CURSOR_PREFIX

    found: dict[str, dict[str, Any]] = {}
    for key, raw in store.meta_items(f"{CURSOR_PREFIX}.{account}.").items():
        try:
            value = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(value, dict) or value.get("role") not in _ROLES:
            continue
        kind = "backfill" if key.endswith(".back") else "forward"
        entry = found.setdefault(str(value["role"]), {})
        numbers = {name: value.get(name) for name in ("uidvalidity", "epoch", "uid", "low")}
        entry[kind] = {name: number for name, number in numbers.items() if type(number) is int and number >= 0}
    return found


def imap_status(store: Any, flags: Mapping[str, Any] | None) -> dict[str, Any]:
    """The IMAP part of ``mail status``: label, path, scope, last attempt and success, cursors — never the address.

    An explicit projection: every field is type-checked (the label against the
    label grammar, roles and codes against their closed sets, numbers as
    non-negative ints) and anything else in the flags or the store is dropped.
    ``{"residue": "credentials_left"}`` (a sealed file without readable flags,
    or flags without a sealed file) is reported as such, not as "not set up".
    """
    from ..imports.mail.imap_sync import last_fetch_key, last_fetch_status
    from ..imports.mail.secrets import ACCOUNT_RE

    if flags and flags.get("residue") == "credentials_left":
        return {"configured": False, "residue": "credentials_left"}
    account = flags.get("account") if flags else None
    if not flags or not isinstance(account, str) or not ACCOUNT_RE.fullmatch(account):
        return {"configured": False}
    raw: Any = None
    with contextlib.suppress(Exception):
        raw = store.get_meta(last_fetch_key(account))
    attempt, success = last_fetch_status(raw if isinstance(raw, str) else None)
    roles = flags.get("roles")
    return {
        "configured": True,
        "account": account,
        "gmail": flags.get("gmail") is True,
        "scope": [role for role in _ROLES if isinstance(roles, list) and role in roles],
        "touch_id": flags.get("touch_id") is not False,
        "last_fetch": attempt,
        "last_success": success,
        "cursors": imap_cursors(store, account),
    }


def print_imap_status(info: Mapping[str, Any]) -> None:
    if info.get("residue") == "credentials_left":
        print("  imap sync: credentials without their flags (credentials_left); run `hermes-mordred mail forget --yes`")
        return
    if not info.get("configured"):
        print("  imap sync: not set up (hermes-mordred mail setup)")
        return
    path = "Gmail All Mail" if info.get("gmail") else "IMAP " + ", ".join(info.get("scope") or [])
    print(f"  imap sync: account {info.get('account')} ({path}; other folders are not fetched)")
    last = info.get("last_fetch") or {}
    if last:
        state = last.get("error") or ("partial" if last.get("partial") else "complete")
        print(f"    last fetch: {_when(last.get('at'))} ({state})")
    else:
        print("    last fetch: never")
    success = info.get("last_success") or {}
    print(f"    last successful fetch: {_when(success.get('at')) if success else 'never'}")
    for role, cursors in (info.get("cursors") or {}).items():
        forward = cursors.get("forward") or {}
        back = cursors.get("backfill") or {}
        validity, epoch = forward.get("uidvalidity", "-"), forward.get("epoch", 0)
        text = f"uid {forward.get('uid', '-')} (validity {validity}, epoch {epoch})"
        if back:
            text += f", backfilled down to uid {back.get('low', '-')}"
        print(f"    {role}: {text}")


def _when(value: object) -> str:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return "-"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(value))


def _since(raw: str | None) -> dt.date | None:
    if not raw:
        return None
    try:
        return dt.date.fromisoformat(raw)
    except ValueError:
        raise _Usage("--since must be a date YYYY-MM-DD") from None


def _print_fetch(result: FetchResult, as_json: bool) -> None:
    data = result.as_dict()
    if as_json:
        print(json.dumps(data, sort_keys=True))
        return
    if result.dry_run:
        print("Mail fetch dry run: nothing was written and no cursor moved.")
    elif result.error is None:
        print("Mail fetch partial: run it again to continue." if result.partial else "Mail fetch complete.")
    for key, value in data.items():
        if value is not None and key != "dry_run":
            print(f"  {key}: {value}")


def cmd_fetch(args: argparse.Namespace) -> int:
    from ..imports.mail.imap_sync import CLI_BUDGET_S, FetchOptions, run_fetch

    try:
        role = getattr(args, "mailbox", None)
        options = FetchOptions(
            max_messages=int(getattr(args, "max", 2000)),
            roles=None if not role else (str(role),),
            since=_since(getattr(args, "since", None)),
            dry_run=bool(getattr(args, "dry_run", False)),
            budget_s=CLI_BUDGET_S,
            via="cli",
        )
    except _Usage as exc:
        _term.emit_error(str(exc))
        return 2
    except ValueError:
        _term.emit_error("--max must be between 1 and 2000")
        return 2
    env = _fetch_env()
    result = run_fetch(options, env)
    as_json = bool(getattr(args, "json", False))
    if result.error is not None:
        hint = None if as_json else result.hint  # text output only: --json stays exactly the fixed serializer
        _term.emit_error(
            f"mail fetch failed ({result.error}: {hint})" if hint else f"mail fetch failed ({result.error})"
        )
    _print_fetch(result, as_json)
    if not as_json and result.error is None:
        _print_cursors(env)
    return 1 if result.error is not None else 0


def _print_cursors(env: FetchEnv) -> None:
    try:
        flags = env.secret_store.flags()
        if not flags:
            return
        cursors = imap_cursors(env.open_store(env.home), str(flags.get("account")))
    except Exception:
        return
    for role, kinds in cursors.items():
        forward = kinds.get("forward") or {}
        print(f"  cursor {role}: uid {forward.get('uid', '-')} (epoch {forward.get('epoch', 0)})")


# --------------------------------------------------------------------------- #
# forget
# --------------------------------------------------------------------------- #


def cmd_forget(args: argparse.Namespace) -> int:
    from ..imports.mail import forget as forget_module

    if not getattr(args, "yes", False):
        _term.emit_error("mail forget deletes the sealed mail credentials; confirm with --yes")
        return 2
    rows = bool(getattr(args, "rows", False))
    if _platform() != "darwin":
        return _refused("unsupported_platform")
    named = getattr(args, "account", None)
    try:
        done = forget_module.forget(
            _secret_store(),
            _home(),
            account=None if named is None else str(named),
            rows=rows,
            open_store=_open_store,
            lock=_lock,
        )
    except forget_module.MailForgetError as exc:
        if exc.code == "invalid_account":
            _term.emit_error("--account must be 1-32 lowercase letters, digits or '_', starting with a letter")
            return 2
        return _refused(exc.code)
    _audit(forget_module.audit_entry(done, rows=rows))
    return _report_forget(done, rows)


def _report_forget(done: Forgotten, rows: bool) -> int:
    """What forget did and what it could not do (exit 1 whenever something the operator asked for remains)."""
    print("Mail credentials removed." if done.had_credentials else "No mail credentials were set up.")
    status = 0
    if not done.key_gone:  # whatever files there were: a key left behind is reported until a retry deletes it
        _term.emit_error(
            "the Enclave key could not be deleted (key_left); run `hermes-mordred mail forget --yes` again"
        )
        status = 1
    if done.unidentified and done.account is None:
        what = "rows and cursors were" if rows else "cursors were"
        _term.emit_error(
            f"the account label of the removed credentials could not be read (account_unknown); its {what} "
            "kept: run `hermes-mordred mail forget" + (" --rows" if rows else "") + " --yes --account LABEL`"
        )
        return 1
    if rows and done.account:
        print(f"Deleted {done.deleted_messages} imported mail message(s) of account '{done.account}'.")
    if done.cursors_left is not None:
        _term.emit_error(
            f"the mail cursors were left in the store ({done.cursors_left}); retry with --account {done.account}"
        )
        return 1
    if done.account:
        print(f"Removed {done.cursors_deleted} cursor record(s).")
    return status


# --------------------------------------------------------------------------- #
# parsers (called from ``mail_cli.add_parsers``)
# --------------------------------------------------------------------------- #


def _max_messages(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError:
        raise argparse.ArgumentTypeError("N must be a whole number") from None
    if not 1 <= value <= 2000:
        raise argparse.ArgumentTypeError("N must be between 1 and 2000")
    return value


def _port(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError:
        raise argparse.ArgumentTypeError("P must be a port number") from None
    if value != 993:
        raise argparse.ArgumentTypeError("only port 993 (implicit TLS) is supported")
    return value


def add_parsers(msub: Any, handler: Callable[[argparse.Namespace], int]) -> None:
    p = msub.add_parser("setup", help="Seal IMAP credentials (address and app password typed on a TTY)")
    p.add_argument("--imap-host", metavar="H", help="IMAP server (default imap.gmail.com for Gmail addresses)")
    p.add_argument("--imap-port", type=_port, default=993, metavar="P", help="Implicit-TLS port (993 only)")
    p.add_argument("--account", default="mail", metavar="LABEL", help="Short lowercase account label (default mail)")
    p.add_argument("--no-touch-id", action="store_true", help="Create the Enclave key without Touch ID (cron use)")
    p.set_defaults(func=handler)
    p_fetch = msub.add_parser("fetch", help="Fetch new mail over IMAP into the encrypted store (counts only)")
    p_fetch.add_argument("--max", type=_max_messages, default=2000, metavar="N", help="At most N messages (1-2000)")
    p_fetch.add_argument("--mailbox", choices=_ROLES, help="Only this configured mailbox role")
    p_fetch.add_argument("--since", metavar="YYYY-MM-DD", help="Also backfill older mail received since this day")
    p_fetch.add_argument("--dry-run", action="store_true", help="Fetch and plan, write nothing, move no cursor")
    p_fetch.add_argument("--json", action="store_true", help="Print one JSON object (counts only)")
    p_fetch.set_defaults(func=handler)
    p_forget = msub.add_parser("forget", help="Delete the sealed mail credentials and cursors (--rows: also mail rows)")
    p_forget.add_argument("--rows", action="store_true", help="Also delete the account's imported mail rows")
    p_forget.add_argument(
        "--account", metavar="LABEL", help="The label whose rows and cursors to delete when its credentials are gone"
    )
    p_forget.add_argument("--yes", action="store_true", help="Confirm the deletion")
    p_forget.set_defaults(func=handler)
