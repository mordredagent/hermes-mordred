"""``hermes-mordred telegram migrate-tee|migrate-store``, and ``logout --forget``'s ``mordred.db`` step.

- ``migrate-tee`` — move vault-stored credentials into the hardware seal
  (refused on Windows, where the file vault is excluded).
- ``migrate-store`` — move the ``.enc`` archive into ``mordred.db``
  (:mod:`mordred_hermes.extension.telegram.migrate`): a dry run by default,
  ``--commit`` writes it under one import run and retires ``index.enc``
  (version 2), ``--finalize --yes`` deletes the ``.enc`` message files once
  every archived message is verified in ``mordred.db``.
- The reverse of ``migrate-store`` for ``logout --forget``
  (:func:`forget_import_rows`): this account's Telegram rows in ``mordred.db``
  are deleted FIRST; when that fails, :func:`.telegram_cli.telegram_logout`
  removes nothing else unless ``--force`` is given.

The parsers are registered by ``_cli_parsers._add_telegram`` and dispatched by
:func:`.telegram_cli.cli_telegram` (which hardens the process first). The
credential store and the shared error messages are :mod:`.telegram_cli`'s,
looked up there at call time.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable, Mapping
from typing import Any, Final

from . import _term

#: Messages for the codes only these commands raise; every other code is ``telegram_cli._report``'s.
_MESSAGES: Final[Mapping[str, str]] = {
    "no_legacy_credentials": "there are no vault-stored Telegram credentials to migrate.",
    "not_migrated": "the archive has not been migrated yet (not_migrated). Run "
    "`hermes-mordred telegram migrate-store --commit` first; nothing was deleted.",
    "finalize_mismatch": "mordred.db does not hold every archived message (finalize_mismatch; see the counts "
    "above), so nothing was deleted. Run `hermes-mordred telegram migrate-store --commit` again, then retry.",
    "account_unknown": "the archive does not record its Telegram account yet (account_unknown). Run "
    "`hermes-mordred telegram sync` once, then migrate.",
    "archive_empty": "there is no Telegram archive to migrate (archive_empty).",
}


def _report(code: str) -> int:
    message = _MESSAGES.get(code)
    if message is None:
        from . import telegram_cli

        return telegram_cli._report(code)
    _term.emit_error(message)
    return 1


def _secret_store() -> Any:
    from . import telegram_cli

    return telegram_cli._secret_store()  # looked up per call: tests replace it there


# -- migrate-tee ---------------------------------------------------------------------


def telegram_migrate_tee(*, require_presence: bool = True, store: Any = None, legacy: Any = None) -> int:
    """Move credentials from the software-keyed file vault into the Enclave seal."""
    from ._windows_gates import excluded_refusal

    # Windows: the file vault is excluded and there is no Enclave seal; refuse first.
    refused = excluded_refusal("file_vault", "telegram migrate-tee")
    if refused is not None:
        return refused
    from ..extension.telegram.secrets import VAULT_FILE, TelegramSecretsError, VaultSecretStore

    target = store if store is not None else _secret_store()
    source = legacy if legacy is not None else VaultSecretStore()
    try:
        value = source.load(fresh=True)
        if value is None:
            return _report("no_legacy_credentials")
        target.ensure_key(require_presence=require_presence)
        target.store(value)
        if target.load() != value:  # read back through the Enclave before deleting the old copy
            return _report("secrets_corrupt")
        source.update(lambda _old: None)
    except TelegramSecretsError as exc:
        return _report(exc.code)
    print(f"Moved the Telegram credentials into the Secure Enclave seal and removed {VAULT_FILE} from the vault.")
    return 0


# -- migrate-store -------------------------------------------------------------------


def telegram_migrate_store(
    *, commit: bool = False, finalize: bool = False, yes: bool = False, as_json: bool = False, store: Any = None
) -> int:
    """Move the ``.enc`` archive into ``mordred.db``: dry run, ``--commit``, or ``--finalize --yes``.

    Usage errors exit 2 before anything is opened. The import store gate runs
    first (a refusal exits 1 with its code, before any unseal); then the
    credentials are unsealed once, exactly like ``telegram sync``. Output and
    the one ``telegram.migrate_store`` audit event carry counts and codes only.
    """
    from .._home import hermes_home
    from ..extension.telegram import migrate
    from ..extension.telegram.secrets import TelegramSecretsError
    from ..extension.telegram.store import ArchiveStore, StoreError

    if commit and finalize:
        _term.emit_error("choose one of --commit and --finalize.")
        return 2
    if finalize and not yes:
        _term.emit_error("--finalize deletes the archive's .enc message files; add --yes to confirm. Nothing changed.")
        return 2
    try:
        imports = migrate.open_store(hermes_home())
    except Exception as exc:
        _term.emit_error(f"mordred.db refused ({migrate.error_code(exc)}); nothing was read or written.")
        return 1
    secrets_store = store if store is not None else _secret_store()
    try:
        value = secrets_store.load(fresh=True)  # one unseal, like `telegram sync`
        if value is None:
            return _report("telegram_not_configured")
        archive = ArchiveStore(value.store_key)
    except (TelegramSecretsError, StoreError) as exc:
        return _report(exc.code)
    del value
    outcome = migrate.execute("finalize" if finalize else "commit" if commit else "dry_run", archive, imports)
    if as_json:
        print(json.dumps(outcome.as_dict(), sort_keys=True))
    else:
        for line in outcome.lines():
            print(line)
    return 0 if outcome.error is None else _report(outcome.error)


# -- logout --forget: this account's rows in mordred.db --------------------------------


def forget_import_rows(current: Any) -> str | None:
    """Delete the account's Telegram ``import_*`` rows in ``mordred.db``; ``None`` or a content-free code.

    Only an index retired to ``mordred.db`` names rows to delete (see
    :func:`~mordred_hermes.extension.telegram.history.forget_imported_history`).
    Needs the archive key and index, so it runs before either is wiped.
    """
    from .._home import hermes_home
    from ..extension.telegram.history import forget_imported_history
    from ..extension.telegram.store import ArchiveStore, StoreError

    try:
        archive = ArchiveStore(current.store_key)
    except StoreError as exc:
        return exc.code
    return forget_imported_history(archive, home=hermes_home())


def rows_not_deleted(code: str) -> int:
    """``logout --forget`` without ``--force`` whose row deletion failed: nothing else was touched."""
    _term.emit_error(
        f"import rows NOT deleted ({code}); nothing else was removed. Fix the store (for example run databases "
        "encrypt or check the mordred.db gate) and retry, or pass --force to forget the credentials anyway and "
        "leave the rows."
    )
    return 1


def forgotten(rows_kept: str | None) -> int:
    """Report ``logout --forget``; rows left behind by ``--force`` are a failure, never a success line."""
    deleted = "the API credentials, the archive key, the hardware key, and the local archive"
    if rows_kept is None:
        print(f"Deleted {deleted}, and this account's Telegram rows in mordred.db (if any).")
        return 0
    print(f"Deleted {deleted} (--force).")
    _term.emit_error(
        f"this account's Telegram rows in mordred.db were NOT deleted (import_rows_not_deleted:{rows_kept}); "
        "--force left them behind in the encrypted mordred.db."
    )
    return 1


# -- dispatch and parsers (called from ``telegram_cli`` / ``_cli_parsers._add_telegram``) -----


def _migrate_tee(args: argparse.Namespace) -> int:
    return telegram_migrate_tee(require_presence=not getattr(args, "no_touch_id", False))


def _migrate_store(args: argparse.Namespace) -> int:
    return telegram_migrate_store(
        commit=bool(getattr(args, "commit", False)),
        finalize=bool(getattr(args, "finalize", False)),
        yes=bool(getattr(args, "yes", False)),
        as_json=bool(getattr(args, "json", False)),
    )


_HANDLERS: Mapping[str, Callable[[argparse.Namespace], int]] = {
    "migrate-tee": _migrate_tee,
    "migrate-store": _migrate_store,
}
COMMANDS = frozenset(_HANDLERS)


def dispatch(command: str, args: argparse.Namespace) -> int:
    return _HANDLERS[command](args)


def add_parsers(tsub: Any, handler: Callable[[argparse.Namespace], int]) -> None:
    """Register ``migrate-tee`` then ``migrate-store`` (the ``telegram --help`` order)."""
    p_migrate = tsub.add_parser("migrate-tee", help="Move vault-stored credentials into the Secure Enclave seal")
    p_migrate.add_argument(
        "--no-touch-id",
        action="store_true",
        help="Create the Enclave key without a per-use Touch ID / passcode requirement",
    )
    p_migrate.set_defaults(func=handler)
    p_store = tsub.add_parser(
        "migrate-store",
        help="Move the encrypted .enc archive into mordred.db (dry run by default; counts only)",
    )
    store_mode = p_store.add_mutually_exclusive_group()
    store_mode.add_argument(
        "--commit",
        action="store_true",
        help="Write the archive into mordred.db under one import run and retire index.enc (version 2)",
    )
    store_mode.add_argument(
        "--finalize",
        action="store_true",
        help="After --commit: verify every archived message is in mordred.db, then delete the .enc message files",
    )
    p_store.add_argument("--yes", action="store_true", help="Confirm --finalize")
    p_store.add_argument("--json", action="store_true", help="Print one JSON object (counts and codes only)")
    p_store.set_defaults(func=handler)


__all__ = [
    "COMMANDS",
    "add_parsers",
    "dispatch",
    "forget_import_rows",
    "forgotten",
    "rows_not_deleted",
    "telegram_migrate_store",
    "telegram_migrate_tee",
]
