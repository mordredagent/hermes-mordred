"""``hermes-mordred telegram`` — read-only import of the operator's own account.

Subcommands:

- ``login``  — store the my.telegram.org API credentials and create a user
  session (phone code, then the 2FA password if the account has one). The
  password is read with ``getpass`` and never stored; the resulting session is
  sealed in the keyvault file vault (``telegram.json``), never in ``.env``.
- ``sync``   — import every dialog's new messages into the encrypted archive.
- ``status`` — show login state and archive counts.
- ``logout`` — revoke the session at Telegram and drop it from the vault;
  ``--forget`` also deletes the API credentials, the archive key, and the
  archive files.
- ``venice`` — store the Venice.ai API key (read with ``getpass``) and the
  model used for questions.

Everything that talks to Telegram goes through the allowlist-guarded client
in :mod:`mordred_hermes.extension.telegram.client`; login is the only time the
auth requests are unlocked.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import getpass
import os
import sys
from collections.abc import Callable
from dataclasses import replace
from typing import Any

from . import _term

InputFn = Callable[[str], str]

# Optional one-time source for `telegram login`; the values are then sealed in
# the vault and the variables are no longer needed.
API_ID_ENV = "TELEGRAM_MORDRED_APP_ID"
API_HASH_ENV = "TELEGRAM_MORDRED_APP_HASH"


def _secret_store() -> Any:
    from ..extension.telegram.secrets import VaultSecretStore

    return VaultSecretStore()


def _report(code: str) -> int:
    messages = {
        "vault_not_initialized": "no keyvault file vault exists. Run `hermes-mordred vault init` first: the Telegram "
        "session is an account credential and is only ever stored sealed in the vault.",
        "vault_unavailable": "the keyvault file vault could not be opened (see `hermes-mordred vault status`).",
        "telegram_not_installed": "Telethon is not installed. "
        "Install the extra: pip install 'hermes-mordred[telegram]'",
        "telegram_not_configured": "Telegram is not configured. Run `hermes-mordred telegram login` first.",
        "telegram_not_logged_in": "no Telegram session. Run `hermes-mordred telegram login` first.",
        "telegram_session_revoked": "the Telegram session was revoked (terminated from another device?). "
        "Run `hermes-mordred telegram login` again.",
        "telegram_rate_limited": "Telegram asked us to slow down (FloodWait). "
        "Try again later; progress so far is kept.",
        "routing_unavailable": "the selected network route (Tor/VPN) is not available, so nothing was sent.",
        "invalid_api_credentials": "api_id must be a number and api_hash a 32-character hex string "
        "(from https://my.telegram.org → API development tools).",
        "sync_in_progress": "another sync is already running.",
        "telegram_already_logged_in": "a Telegram session is already stored. Run `hermes-mordred telegram logout` "
        "first so the old session is revoked instead of being left behind.",
    }
    _term.emit_error(messages.get(code, f"telegram operation failed ({code})."))
    return 1


# -- login ---------------------------------------------------------------------


def _read_api_credentials(input_fn: InputFn, secret_fn: InputFn) -> tuple[int, str]:
    from ..extension.telegram.secrets import validate_api_credentials

    env_id = os.environ.get(API_ID_ENV, "").strip()
    env_hash = os.environ.get(API_HASH_ENV, "").strip()
    if env_id and env_hash:
        print(f"Using api_id / api_hash from {API_ID_ENV} / {API_HASH_ENV}.")
        return validate_api_credentials(env_id, env_hash)
    print("Create an application at https://my.telegram.org → API development tools.")
    api_id = input_fn("api_id: ").strip()
    api_hash = secret_fn("api_hash (hidden): ").strip()
    return validate_api_credentials(api_id, api_hash)


async def _interactive_sign_in(client: Any, input_fn: InputFn, secret_fn: InputFn) -> Any:
    await client.connect()
    phone = input_fn("Phone number (international format, e.g. +81…): ").strip()
    await client.send_code_request(phone)
    code = input_fn("Login code sent by Telegram: ").strip()
    try:
        return await client.sign_in(phone=phone, code=code)
    except Exception as exc:
        if type(exc).__name__ != "SessionPasswordNeededError":
            raise
    password = secret_fn("Two-step verification password (hidden, not stored): ")
    return await client.sign_in(password=password)


def telegram_login(
    *,
    input_fn: InputFn = input,
    secret_fn: InputFn = getpass.getpass,
    store: Any = None,
    client_factory: Callable[..., Any] | None = None,
) -> int:
    from ..extension.telegram.client import TelegramClientError, build_client, save_session, telethon_available
    from ..extension.telegram.readonly import RequestPolicy
    from ..extension.telegram.secrets import TelegramSecrets, TelegramSecretsError, new_store_key
    from ..extension.telegram.service import error_code

    factory = client_factory or build_client
    if client_factory is None and not telethon_available():
        return _report("telegram_not_installed")
    secrets_store = store if store is not None else _secret_store()
    try:
        current = secrets_store.load(fresh=True)
    except TelegramSecretsError as exc:
        return _report(exc.code)
    if current is not None and current.session is not None:
        return _report("telegram_already_logged_in")
    try:
        if current is None:
            if _orphaned_archive_present():
                # Its key went with the old vault entry, so it can never be
                # decrypted again; a fresh key would otherwise fail on it.
                from ..extension.telegram.store import wipe_archive

                wipe_archive()
                _term.emit_warn("removed an undecryptable archive left by a previous setup.")
            api_id, api_hash = _read_api_credentials(input_fn, secret_fn)
            base = TelegramSecrets(api_id=api_id, api_hash=api_hash, store_key=new_store_key())
        else:
            base = current
            print(f"Using the stored API application (api_id {base.api_id}).")
        policy = RequestPolicy(login=True)
        me, session = asyncio.run(
            _login_and_disconnect(
                lambda: factory(base.api_id, base.api_hash, None, policy=policy),
                input_fn,
                secret_fn,
                save_session,
                policy,
            )
        )
    except (TelegramSecretsError, TelegramClientError) as exc:
        return _report(exc.code)
    except Exception as exc:
        return _report(error_code(exc, "telegram_login_failed"))
    if me is None:
        return _report("telegram_login_failed")
    try:
        secrets_store.update(lambda _old: replace(base, session=session))
    except TelegramSecretsError as exc:
        return _report(exc.code)
    print("Logged in. The session is sealed in the keyvault file vault (telegram.json).")
    print(
        "Telegram will show a new-login notice on your other devices. Keep Two-Step Verification enabled; "
        "revoke this session any time with `hermes-mordred telegram logout` or Settings → Devices."
    )
    return 0


async def _login_and_disconnect(
    make_client: Callable[[], Any],
    input_fn: InputFn,
    secret_fn: InputFn,
    save: Callable[[Any], str],
    policy: Any,
) -> tuple[Any, str]:
    # Built inside the running loop: Telethon binds a client to its loop.
    client = make_client()
    try:
        me = await _interactive_sign_in(client, input_fn, secret_fn)
        return me, save(client)
    except BaseException:
        # If Telegram already accepted the sign-in, the new authorization would
        # otherwise stay on the account with no stored session to revoke it.
        with contextlib.suppress(Exception):
            if getattr(client, "_authorized", False):
                policy.logout = True
                await client.log_out()
        raise
    finally:
        with contextlib.suppress(Exception):
            await client.disconnect()


def _orphaned_archive_present() -> bool:
    from ..extension.telegram.store import telegram_dir

    base = telegram_dir()
    return base.is_dir() and not base.is_symlink() and any(base.rglob("*.enc"))


# -- sync / status ---------------------------------------------------------------


def _progress_line(progress: dict[str, Any]) -> str:
    return (
        f"dialogs {progress.get('dialogs_done', 0)}/{progress.get('dialogs_total', 0)}, "
        f"messages imported {progress.get('messages_imported', 0)}"
    )


async def _run_sync(service: Any, options: Any, *, poll: float = 1.0) -> int:
    await service.start_sync(options)
    last = ""
    while service.syncing:
        await asyncio.sleep(poll)
        status = await service.status()
        line = _progress_line(status["progress"])
        if line != last:
            print(f"  {line}", flush=True)
            last = line
    await service.wait_for_sync()
    status = await service.status()
    if status["last_error"]:
        return _report(str(status["last_error"]))
    print(f"Done: {_progress_line(status['progress'])}. Archive: {status['message_count']} messages.")
    return 0


def telegram_sync(
    *,
    include_channels: bool = True,
    include_archived: bool = True,
    limit_per_dialog: int | None = None,
    service: Any = None,
) -> int:
    from ..extension.telegram.client import SyncOptions
    from ..extension.telegram.service import TelegramService, error_code

    svc = service if service is not None else TelegramService()
    options = SyncOptions(
        include_channels=include_channels,
        include_archived=include_archived,
        limit_per_dialog=limit_per_dialog,
    )
    try:
        return asyncio.run(_run_sync(svc, options))
    except Exception as exc:
        return _report(error_code(exc, "telegram_sync_failed"))


def telegram_status(*, service: Any = None) -> int:
    from ..extension.telegram.service import TelegramService

    svc = service if service is not None else TelegramService()
    status = asyncio.run(svc.status())
    if status["last_error"] and not status["configured"]:
        return _report(str(status["last_error"]))
    print(f"Telethon installed: {'yes' if status['installed'] else 'no'}")
    print(f"Logged in: {'yes' if status['logged_in'] else 'no'}")
    if status["account_label"]:
        print(f"Account: {status['account_label']}")
    print(f"Dialogs: {status['dialog_count']}  Messages: {status['message_count']}")
    print(f"Venice: {'configured' if status['venice_configured'] else 'not configured'} ({status['venice_model']})")
    return 0


# -- logout / venice ---------------------------------------------------------------


async def _revoke(make_client: Callable[[], Any]) -> None:
    client = make_client()
    await client.connect()
    try:
        if await client.is_user_authorized():
            await client.log_out()
    finally:
        await client.disconnect()


def telegram_logout(
    *, forget: bool = False, store: Any = None, client_factory: Callable[..., Any] | None = None
) -> int:
    from ..extension.telegram.client import build_client
    from ..extension.telegram.readonly import RequestPolicy
    from ..extension.telegram.secrets import TelegramSecretsError
    from ..extension.telegram.store import wipe_archive

    secrets_store = store if store is not None else _secret_store()
    try:
        current = secrets_store.load(fresh=True)
    except TelegramSecretsError as exc:
        return _report(exc.code)
    if current is None:
        print("Telegram is not configured; nothing to do.")
        return 0
    if current.session is not None:
        factory = client_factory or build_client
        try:
            asyncio.run(
                _revoke(
                    lambda: factory(
                        current.api_id, current.api_hash, current.session, policy=RequestPolicy(logout=True)
                    )
                )
            )
            print("Revoked the session at Telegram.")
        except Exception:
            _term.emit_warn(
                "could not reach Telegram to revoke the session; it is removed locally. "
                "Also terminate it in Telegram → Settings → Devices."
            )
    try:
        if forget:
            secrets_store.update(lambda _old: None)
        else:
            secrets_store.update(lambda old: replace(old, session=None) if old is not None else None)
    except TelegramSecretsError as exc:
        return _report(exc.code)
    if forget:
        wipe_archive()
        print("Deleted the API credentials, the archive key, and the local archive.")
    else:
        print("Logged out. The encrypted archive is kept (use --forget to delete it).")
    return 0


def telegram_venice(*, model: str | None, secret_fn: InputFn = getpass.getpass, store: Any = None) -> int:
    from ..extension.telegram.secrets import TelegramSecretsError

    secrets_store = store if store is not None else _secret_store()
    key = secret_fn("Venice API key (hidden; Enter keeps the stored key): ").strip()
    try:
        current = secrets_store.load(fresh=True)
        if current is None:
            return _report("telegram_not_configured")
        if not key and current.venice_api_key is None:
            _term.emit_error("no Venice API key given.")
            return 1
        secrets_store.update(
            lambda old: replace(
                old,
                venice_api_key=key or old.venice_api_key,
                venice_model=model if model else old.venice_model,
            )
        )
    except TelegramSecretsError as exc:
        return _report(exc.code)
    print("Stored the Venice settings in the keyvault file vault. Only models Venice labels 'private' are used.")
    print(
        'Under llm_guard strict mode, allow it: set allow_cloud_llm to true and add "venice" to '
        "cloud_provider_allowlist in <home>/mordred/policy.json."
    )
    return 0


# -- argparse ------------------------------------------------------------------------


def cli_telegram(args: argparse.Namespace) -> int:
    command = getattr(args, "telegram_command", None)
    if command == "login":
        return telegram_login()
    if command == "sync":
        return telegram_sync(
            include_channels=not args.skip_channels,
            include_archived=not args.skip_archived,
            limit_per_dialog=args.limit_per_dialog,
        )
    if command == "status":
        return telegram_status()
    if command == "logout":
        return telegram_logout(forget=bool(args.forget))
    if command == "venice":
        return telegram_venice(model=args.model)
    print("usage: hermes-mordred telegram {login,sync,status,logout,venice}", file=sys.stderr)
    return 2


__all__ = [
    "cli_telegram",
    "telegram_login",
    "telegram_logout",
    "telegram_status",
    "telegram_sync",
    "telegram_venice",
]
