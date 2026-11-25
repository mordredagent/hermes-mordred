"""Local reset coordinator: EX -> durable intent -> SQL -> custody -> files."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

from .._core._database_contracts import DatabaseRefused
from .._core._database_lifecycle import ExclusiveLease
from ..keyvault import _storage
from ..keyvault._reset_files import (
    STAGES,
    check_observations,
    known_directory,
    observation,
    remove_known_files,
    snapshot_files,
)
from ..keyvault._reset_journal import _encode_reset_journal, _load_reset_journal, _ResetJournal
from ..keyvault._uninstall_authority import UninstallAuthorization, check_authorization
from . import _term


def _save(root: Path, journal: _ResetJournal) -> None:
    # Preserve root identity even after bounded cleanup removed the directory.
    payload = {
        "version": 3,
        "root_identity": {"device": journal.root_identity[0], "inode": journal.root_identity[1]},
        "targets": [{"key_id": k, "native_key_id": v} for k, v in journal.key_ids.items()],
        "retained_legacy": journal.retained_legacy,
        "metadata_incomplete": journal.metadata_incomplete,
        "connected": journal.connected,
    }
    with _storage.keyvault_lifecycle_lock(root):
        _storage.write_reset_journal(root, json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())


def _credential_observations(home: Path, key_ids: dict[str, str]) -> dict[str, Any]:
    names = (
        "mail",
        "mail/credentials.sealed",
        "mail/credentials.meta.json",
        "mail/enclave-key.json",
        "telegram",
        "telegram/credentials.sealed",
        "telegram/credentials.meta.json",
    )
    result = {name: observation(home / "mordred" / name) for name in names}
    for staged in (home / "mordred/mail").glob(".credentials.*.staged"):
        result["mail/" + staged.name] = observation(staged)
    for selector in (*key_ids.values(), *_component_selectors().values()):
        result.update(_native_observations(home, selector))
    return result


def _component_selectors() -> dict[str, str]:
    from ..keyvault._mail_key import KEY_ID as MAIL
    from ..keyvault._telegram_custody import KEY_ID as TELEGRAM

    return {"mail": MAIL, "telegram": TELEGRAM}


def _native_observations(home: Path, selector: str) -> dict[str, Any]:
    from ..keyvault._seckey_errors import _application_tag

    tag = _application_tag(selector).hex()
    return {
        f"keyvault/{leaf}/{tag}.bin": observation(home / "mordred/keyvault" / leaf / f"{tag}.bin")
        for leaf in ("sekey", "tpm")
    }


def _check_orphan(home: Path, component: str) -> None:
    directory = home / "mordred" / component
    if not (directory / "credentials.sealed").exists():
        journal = directory / "mail-forget.json" if component == "mail" else home / "mordred/telegram-forget.json"
        if not journal.exists() and any(
            v is not None for v in _native_observations(home, _component_selectors()[component]).values()
        ):
            raise DatabaseRefused("native credential key has no authenticated source; ownership repair required")


def _sources(home: Path) -> tuple[Path, dict[str, Any]]:
    from ..keyvault._database_authority import resolve_database_domain

    domain = resolve_database_domain(home)
    names = (
        "mordred/db-key-source.json",
        "mordred/db-encryption.marker",
        "mordred/memory-key.wrapped",
        "mordred/memory-vault.marker",
    )
    return domain.root, {name: observation(domain.root / name) for name in names}


def _check(root: Path, journal: _ResetJournal) -> None:
    state = journal.connected
    assert state is not None
    home = root.parent.parent
    if observation(home) != state["home_identity"]:
        raise DatabaseRefused("reset profile was replaced")
    current = observation(root)
    if current is not None and tuple(current[:2]) != journal.root_identity:
        raise DatabaseRefused("reset keyvault root was replaced")
    base, sources = _sources(home)
    if sources != state["sources"]:
        raise DatabaseRefused("retained database or memory source changed")
    check_observations(base, state["sources"])
    for name, value in state["keep"].items():
        layout = name.endswith("/") and known_directory(name.rstrip("/"), journal.key_ids)
        check_observations(root, {name: value}, missing_ok=layout and state["stage"] in {"files", "complete"})


def _retire_mail(home: Path, authorization: Any, *, acknowledged: bool) -> None:
    from ..imports.mail.imap_sync import fetch_lock
    from ..imports.mail.secrets import MailSecretStore
    from ..keyvault._mail_custody import (
        JOURNAL,
        KEY_RECORD,
        META,
        SEALED,
        authenticate_mail_source,
        mail_credential_transaction,
        read,
    )

    _check_orphan(home, "mail")
    directory = home / "mordred/mail"
    if not directory.exists():
        return
    # A writer excludes pending setup and synchronizers until the checked
    # retirement has invalidated the setup generation and removed its source.
    with fetch_lock(home, _reset=authorization):
        if not any((directory / name).exists() for name in (JOURNAL, META, SEALED, KEY_RECORD)):
            return
        backend = MailSecretStore(directory, audit_sink=lambda _e: None)._backend()
        if acknowledged:
            with mail_credential_transaction(home=home, backend=backend, resume=True, _reset=authorization) as custody:
                if read(custody.transaction, SEALED) is not None or read(custody.transaction, META) is not None:
                    raise DatabaseRefused("mail source appeared after acknowledged reset")
                if read(custody.transaction, JOURNAL) is not None:
                    custody.cleanup()
            return
        pending = (directory / JOURNAL).exists()
        snapshot = (
            (None, None)
            if pending
            else authenticate_mail_source(home=home, backend=backend, entries=[], _reset=authorization)
        )
        with mail_credential_transaction(
            home=home, backend=backend, authenticated=snapshot[1], resume=True, _reset=authorization
        ) as custody:
            if read(custody.transaction, JOURNAL) is not None:
                custody.cleanup(keep_journal=True)
            elif snapshot[0] is not None:
                custody.retire(_reset=authorization)
            else:
                raise DatabaseRefused("mail has no authenticated source; reconcile ownership before reset")


def _clear_mail_staging(home: Path, state: dict[str, Any], authorization: Any) -> None:
    from ..imports.mail.imap_sync import fetch_lock

    staged = {
        name: seen
        for name, seen in state["credentials"].items()
        if name.startswith("mail/.credentials.") and name.endswith(".staged")
    }
    if not staged:
        return
    with fetch_lock(home, _reset=authorization):
        for name, seen in staged.items():
            check_observations(home / "mordred", {name: seen}, missing_ok=True)
            path = home / "mordred" / name
            if path.exists():
                path.unlink()
                _storage.fsync_keyvault_parent(path)


def _retire_telegram(home: Path, authorization: Any, *, acknowledged: bool) -> None:
    from ..extension.telegram.store import _posix_archive_lock, _prepare_archive_wipe, _wipe_archive_locked
    from ..extension.telegram.tee import TeeSecretStore
    from ..keyvault._telegram_custody import (
        authenticate_telegram_source,
        pending_telegram_forget,
        telegram_credential_transaction,
    )

    _check_orphan(home, "telegram")
    directory = home / "mordred/telegram"
    if not directory.exists():
        return
    store = TeeSecretStore(directory, audit_sink=lambda _entry: None)
    if acknowledged:
        if (directory / "credentials.sealed").exists() or (directory / "credentials.meta.json").exists():
            raise DatabaseRefused("Telegram source appeared after acknowledged reset")
        if pending_telegram_forget(home):
            with telegram_credential_transaction(
                home=home, backend=store._backend(), _resume=True, _reset=authorization
            ) as custody:
                custody.finish_forget()
        return
    pending = pending_telegram_forget(home)
    if not (directory / "credentials.sealed").exists() and not pending:
        if (directory / "credentials.meta.json").exists():
            raise DatabaseRefused("Telegram metadata has no authenticated source")
        # History can outlive credentials. The bounded archive wipe retains
        # unknown files and does not infer authority over an orphan native key.
        with _posix_archive_lock(directory, _reset=authorization) as archive:
            _prepare_archive_wipe(archive)
            _wipe_archive_locked(archive)
        return
    snapshot = (
        (None, None)
        if pending
        else authenticate_telegram_source(
            home=home, backend=store._backend(), audit_sink=lambda _e: None, _reset=authorization
        )
    )
    store.forget_from_snapshot(snapshot, _reset=authorization)


def _prepare(home: Path, assume_yes: bool, prompt_io: Any) -> _ResetJournal | None:
    from . import keyvault_cli
    from ._defaults import resolve_prompt_io

    root = home / "mordred/keyvault"
    with _storage.keyvault_lifecycle_lock(root):
        try:
            journal = _load_reset_journal(root)
        except FileNotFoundError:
            journal = None
        resuming = journal is not None
        if journal is not None:
            if journal.connected is None:
                # v2 authorized only keyvault keys. Never turn an old retry
                # into consent to delete newly included component material.
                credentials = _credential_observations(home, journal.key_ids)
                database = home / "plugin-data/mordred/mordred.db"
                added_scope = {
                    name
                    for name in credentials
                    if name in {"mail", "telegram"} or name.startswith(("mail/", "telegram/"))
                }
                for selector in _component_selectors().values():
                    added_scope.update(_native_observations(home, selector))
                if any(credentials[name] is not None for name in added_scope) or database.exists():
                    raise DatabaseRefused(
                        "v2 reset cannot authorize Mail/Telegram deletion; explicit recovery required"
                    )
                remove, keep = snapshot_files(root, journal.key_ids)
                _, sources = _sources(home)
                state = dict(
                    home=str(home),
                    home_identity=observation(home),
                    stage="keys",
                    remove=remove,
                    keep=keep,
                    sources=sources,
                    credentials=credentials,
                    native={"key:" + k: "pending" for k in journal.key_ids},
                )
                journal = replace(journal, connected=state)
            _check(root, journal)
        else:
            if root.exists() or root.is_symlink():
                _storage._check_dir_mode(root)
            else:
                root.mkdir(mode=0o700)
            if (root / "meta.json").exists():
                keys, retained, incomplete = keyvault_cli._collect_reset_key_ids(root)
            else:
                keys, retained, incomplete = {}, [], False
            remove, keep = snapshot_files(root, keys)
            _, sources = _sources(home)
            state = dict(
                home=str(home),
                home_identity=observation(home),
                stage="database",
                remove=remove,
                keep=keep,
                sources=sources,
                credentials=_credential_observations(home, keys),
                native={"key:" + k: "pending" for k in keys},
            )
            journal, _ = _encode_reset_journal(root, keys, retained, incomplete, connected=state)
        if not assume_yes and not keyvault_cli._confirm_reset(resolve_prompt_io(prompt_io), list(journal.key_ids)):
            print(
                "Reset aborted — earlier progress is kept in the reset journal; nothing further was deleted."
                if resuming
                else "Reset aborted — nothing was deleted."
            )
            return None
        _save(root, journal)
        _storage.ensure_generation_epoch(root, force_new=True)
        return journal


def coordinate_reset(  # noqa: C901, PLR0912, PLR0915 - explicit destructive stage machine
    *,
    home: Path,
    backend: Any,
    prompt_io: Any,
    assume_yes: bool,
    database_lease: ExclusiveLease,
    uninstall: UninstallAuthorization | None = None,
) -> int:
    from ..imports._reset import erase_reset_history
    from ..keyvault._reset_authority import reset_authorization
    from . import keyvault_cli

    root = home / "mordred/keyvault"
    candidates = (
        root,
        _storage.reset_journal_path(root),
        home / "mordred/mail",
        home / "mordred/telegram",
        home / "plugin-data/mordred/mordred.db",
    )
    if not any(p.exists() or p.is_symlink() for p in candidates):
        print("No keyvault found — nothing to reset.")
        return 0
    try:
        journal = _prepare(home, assume_yes, prompt_io)
        if journal is None:
            return 1
        state = journal.connected
        assert state is not None
        while state["stage"] != "complete":
            _check(root, journal)
            stage = state["stage"]
            if stage == "database":
                if uninstall is not None:
                    # Uninstall has restored and retains this database in
                    # plaintext, so its adopted marker is gone by design. Only
                    # live authority may skip the erasure; it never adds targets.
                    check_authorization(uninstall, root=_sources(home)[0], lease=database_lease, purpose="delete")
                else:
                    with reset_authorization(home, database_lease) as authorization:
                        erase_reset_history(home, lease=database_lease, _reset=authorization)
            elif stage in {"mail", "telegram"}:
                handler = _retire_mail if stage == "mail" else _retire_telegram
                component_journal = (
                    home / "mordred" / ("mail/mail-forget.json" if stage == "mail" else "telegram-forget.json")
                )
                expected = {
                    name: seen
                    for name, seen in state["credentials"].items()
                    if name == stage or name.startswith(stage + "/")
                }
                for name in _native_observations(home, _component_selectors()[stage]):
                    expected[name] = state["credentials"][name]
                check_observations(
                    home / "mordred",
                    expected,
                    missing_ok=component_journal.exists() or state["native"].get(stage) == "deleted",
                )
                with reset_authorization(home, database_lease) as authorization:
                    acknowledged = state["native"].get(stage) == "deleted"
                    handler(home, authorization, acknowledged=acknowledged)
                    if not acknowledged:
                        state["native"][stage] = "deleted"
                        _save(root, journal)
                        handler(home, authorization, acknowledged=True)
                    if stage == "mail":
                        _clear_mail_staging(home, state, authorization)
            elif stage == "keys":
                with _storage.keyvault_lifecycle_lock(root):
                    for key_id, selector in journal.key_ids.items():
                        progress = state["native"]["key:" + key_id]
                        if progress == "deleted":
                            continue
                        expected_native = {
                            name: state["credentials"][name] for name in _native_observations(home, selector)
                        }
                        # "deleting" means an earlier attempt failed or stopped
                        # at an unknown point. Deletion is idempotent under the
                        # checked owner, so repeat it: a missing target may be
                        # that attempt's result, but a replaced one still refuses.
                        check_observations(home / "mordred", expected_native, missing_ok=progress == "deleting")
                        from ..keyvault._native_key_id import bind_backend_to_root

                        try:
                            prepared_backend = bind_backend_to_root(keyvault_cli.resolve_backend(backend), root)
                        except Exception as exc:
                            raise DatabaseRefused(
                                "could not initialize reset backend; no native deletion attempted"
                            ) from exc
                        state["native"]["key:" + key_id] = "deleting"
                        _save(root, journal)
                        if keyvault_cli._delete_wrapping_keys(
                            {key_id: selector},
                            root=root,
                            backend=prepared_backend,
                            database_lease=database_lease,
                            _prepared=True,
                        ):
                            raise DatabaseRefused("native key deletion is incomplete; outcome retained for repair")
                        state["native"]["key:" + key_id] = "deleted"
                        _save(root, journal)
            elif stage == "files":
                with _storage.keyvault_lifecycle_lock(root):
                    remove_known_files(root, journal.key_ids, state)
            _check(root, journal)
            state["stage"] = STAGES[STAGES.index(stage) + 1]
            _save(root, journal)
        with _storage.keyvault_lifecycle_lock(root):
            _check(root, journal)
            _storage.clear_reset_journal(root)
    except Exception as exc:
        _term.emit_error(f"Keyvault reset is incomplete ({exc}); recovery evidence retained. Retry reset after repair.")
        return 1
    if uninstall is not None:
        print("Keyvault reset — profile keys and Mail and Telegram credentials removed.")
        print("Restored databases keep their imported history.")
        return 0
    print("Keyvault reset — profile keys, Mail and Telegram credentials and all their local history removed.")
    print("Run `hermes-mordred keyvault init` to create a new key.")
    return 0
