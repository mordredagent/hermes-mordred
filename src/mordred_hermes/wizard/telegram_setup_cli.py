"""``hermes-mordred telegram setup`` and ``telegram doctor``.

``setup`` walks a first-time user through everything in one command: the
Secure Enclave helper, the Telegram login, the privacy LLM (Venice or a local
model) and a first import with conservative defaults, then says how to use it
from Hermes Desktop and the browser extension.

``doctor`` reports health from metadata only. It never unseals the credentials
(no Touch ID), never decrypts the archive, and never prints the account name
or any chat title.
"""

from __future__ import annotations

import argparse
import getpass
import json
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any

from . import _term

InputFn = Callable[[str], str]

RECOMMENDED_LIMIT = 500


# -- doctor ------------------------------------------------------------------------


@dataclass
class Check:
    name: str
    ok: bool
    detail: str
    fix: str = ""


def _check_telethon() -> Check:
    from ..extension.telegram.client import telethon_available

    ok = telethon_available()
    return Check(
        "telethon", ok, "installed" if ok else "missing", "" if ok else "pip install 'hermes-mordred[telegram]'"
    )


def _check_enclave() -> Check:
    from ..extension.telegram.secrets import TelegramSecretsError
    from ..extension.telegram.tee import KEY_ID, hardware_backend

    try:
        backend = hardware_backend()
    except TelegramSecretsError:
        return Check("secure_enclave", False, "helper not installed", "hermes-mordred keyvault enable-se")
    from ..keyvault import wrap
    from ..keyvault._exceptions import WrapError, WrapKeyNotFound

    try:
        wrap.get_wrapping_key_public(KEY_ID, backend=backend)  # public key only: no prompt
    except WrapKeyNotFound:
        return Check(
            "secure_enclave", True, "helper ready; Telegram key not created yet", "hermes-mordred telegram setup"
        )
    except WrapError:
        return Check("secure_enclave", False, "helper present but not working", "hermes-mordred keyvault enable-se")
    return Check("secure_enclave", True, "helper ready; Telegram key present")


def _check_credentials(flags: dict[str, Any] | None) -> list[Check]:
    if flags is None:
        return [Check("login", False, "not configured", "hermes-mordred telegram setup")]
    checks = [
        Check(
            "login",
            flags.get("logged_in") is True,
            "logged in (credentials sealed by the Secure Enclave)" if flags.get("logged_in") else "logged out",
            "" if flags.get("logged_in") else "hermes-mordred telegram setup",
        )
    ]
    backend = flags.get("llm_backend")
    model = flags.get("llm_model")
    checks.append(
        Check(
            "privacy_llm",
            backend in ("venice", "local"),
            f"{backend} ({model})" if backend else "not configured",
            "" if backend else "hermes-mordred telegram venice   (or: telegram local-llm)",
        )
    )
    return checks


def _check_archive() -> Check:
    from ..extension.telegram.store import telegram_dir

    base = telegram_dir()
    if not (base / "index.enc").exists():
        return Check("archive", False, "nothing imported yet", "hermes-mordred telegram sync")
    segments = list((base / "dialogs").glob("*.enc")) if (base / "dialogs").is_dir() else []
    size = sum(p.stat().st_size for p in segments)
    ignored = (base / ".gitignore").exists()
    return Check(
        "archive",
        True,
        f"{len(segments)} encrypted segment file(s), {size // 1024} KiB; git-ignored: {'yes' if ignored else 'no'}",
    )


def _check_hermes() -> Check:
    from ..extension.telegram.hermes_tools import _classify_endpoint, _configured_model

    model, base_url = _configured_model()
    kind = _classify_endpoint(base_url)
    if kind is None:
        return Check(
            "hermes_integration",
            False,
            "the Hermes model is not Venice or local, so the Telegram tools are hidden",
            "switch Hermes to a Venice private model or a local model",
        )
    return Check("hermes_integration", True, f"Hermes model {model} ({kind}): telegram_ask is offered")


def run_checks() -> list[Check]:
    from ..extension.telegram.tee import TeeSecretStore

    try:
        flags = TeeSecretStore().flags()
    except Exception:
        flags = None
    return [_check_telethon(), _check_enclave(), *_check_credentials(flags), _check_archive(), _check_hermes()]


def telegram_doctor(*, as_json: bool = False) -> int:
    checks = run_checks()
    if as_json:
        print(json.dumps([asdict(c) for c in checks], indent=2))
    else:
        for c in checks:
            mark = "OK " if c.ok else "!! "
            print(f"{mark}{c.name:20} {c.detail}")
            if c.fix:
                print(f"    -> {c.fix}")
    return 0 if all(c.ok for c in checks) else 1


# -- setup -------------------------------------------------------------------------


def _yes(input_fn: InputFn, prompt: str, default: bool = True) -> bool:
    suffix = " [Y/n] " if default else " [y/N] "
    answer = input_fn(prompt + suffix).strip().casefold()
    return default if not answer else answer in {"y", "yes"}


def _ensure_enclave(input_fn: InputFn) -> bool:
    check = _check_enclave()
    if check.ok:
        return True
    print("Telegram credentials are sealed by the Secure Enclave. Its helper must be built once (a few minutes).")
    if not _yes(input_fn, "Build the Secure Enclave helper now?"):
        return False
    from .keyvault_native_cli import enable_se

    return enable_se() == 0


def _choose_llm(input_fn: InputFn, secret_fn: InputFn) -> int:
    from .telegram_cli import telegram_local_llm, telegram_venice

    print("Questions are answered by a privacy LLM. Choose one:")
    print("  1) Venice.ai private model (no retention; needs a Venice API key)")
    print("  2) A model running on this Mac (e.g. Ollama / LM Studio on 127.0.0.1)")
    choice = input_fn("Choice [1]: ").strip() or "1"
    if choice == "2":
        endpoint = input_fn("Local endpoint (e.g. http://127.0.0.1:11434/v1): ").strip()
        model = input_fn("Model name: ").strip()
        return telegram_local_llm(endpoint=endpoint, model=model)
    return telegram_venice(model=None, secret_fn=secret_fn)


def telegram_setup(
    *,
    input_fn: InputFn = input,
    secret_fn: InputFn = getpass.getpass,
    require_presence: bool = True,
) -> int:
    from .telegram_cli import telegram_login, telegram_sync

    print("Mordred Telegram setup — read-only, Secure-Enclave-sealed, Venice/local only.\n")
    print("Step 1/4  Secure Enclave")
    if not _ensure_enclave(input_fn):
        _term.emit_error("the Secure Enclave helper is required; setup stopped.")
        return 1

    from ..extension.telegram.tee import TeeSecretStore

    flags = TeeSecretStore().flags()
    print("\nStep 2/4  Telegram login")
    if flags and flags.get("logged_in"):
        print("Already logged in.")
    elif telegram_login(input_fn=input_fn, secret_fn=secret_fn, require_presence=require_presence) != 0:
        return 1

    flags = TeeSecretStore().flags() or {}
    print("\nStep 3/4  Privacy LLM")
    if flags.get("llm_backend") in ("venice", "local"):
        print(f"Already configured: {flags.get('llm_backend')} ({flags.get('llm_model')}).")
    elif _choose_llm(input_fn, secret_fn) != 0:
        return 1

    print("\nStep 4/4  First import")
    print(
        f"Recommended: personal chats and groups only, the newest {RECOMMENDED_LIMIT} messages per chat. "
        "Later imports fetch only new messages."
    )
    recommended = {"include_channels": False, "include_archived": False, "limit_per_dialog": RECOMMENDED_LIMIT}
    if _yes(input_fn, "Use this scope for imports (saved for later `telegram sync` runs)?"):
        TeeSecretStore().save_sync_scope(recommended)
    if _yes(input_fn, "Import now?"):
        rc = telegram_sync()
        if rc != 0:
            return rc
    else:
        print("Skipped. Run `hermes-mordred telegram sync` any time.")

    print(
        "\nDone. How to use it:\n"
        "  • Hermes Desktop: restart it (⌘Q, reopen), then ask e.g. “What did we decide on Telegram last week?”.\n"
        "    The agent uses telegram_ask; approve the Touch ID prompt.\n"
        "  • Browser extension: ⚙ → ✈️ Telegram.\n"
        "  • Health check any time: hermes-mordred telegram doctor"
    )
    return 0


def cli_setup(args: argparse.Namespace) -> int:
    return telegram_setup(require_presence=not getattr(args, "no_touch_id", False))


def cli_doctor(args: argparse.Namespace) -> int:
    return telegram_doctor(as_json=bool(getattr(args, "json", False)))
