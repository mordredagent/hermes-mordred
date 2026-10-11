"""``hermes-mordred telegram setup`` and ``telegram doctor``.

``setup`` walks a first-time user through everything in one command: the
hardware key helper, the Telegram login, the privacy LLM (Venice or a local
model) and a first import with conservative defaults, then says how to use it
from Hermes Desktop and the browser extension.

``doctor`` reports health from metadata only. It never unseals the credentials
(no Touch ID), never decrypts the archive, and never prints the account name
or any chat title.

On Windows (C6-telegram) setup checks ``windows_capabilities`` instead of the
Enclave/TPM helper, offers the explicit ``keyvault native init --role
telegram`` ceremony (explicit yes), runs the C6 Windows memory enable, and
login asks for the machine-bound acknowledgement before anything is unsealed.
``doctor`` adds one informational line per Windows capability (no aggregate
readiness) and reads the role, credentials and archive load-only through the
C10b checked seams. macOS/Linux behaviour is unchanged.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import _term, _windows_telegram

if TYPE_CHECKING:
    from ..keyvault._windows_capability import WindowsCapability

InputFn = Callable[[str], str]

RECOMMENDED_LIMIT = 500
DEFAULT_SINCE_DAYS = 3  # mirrors extension.telegram.client.DEFAULT_SINCE_DAYS (no Telethon import here)


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
        return Check("secure_enclave", False, "helper not installed", _hardware_fix())
    from ..keyvault import wrap
    from ..keyvault._exceptions import WrapError, WrapKeyNotFound

    try:
        wrap.get_wrapping_key_public(KEY_ID, backend=backend)  # public key only: no prompt
    except WrapKeyNotFound:
        return Check(
            "secure_enclave", True, "helper ready; Telegram key not created yet", "hermes-mordred telegram setup"
        )
    except WrapError:
        return Check("secure_enclave", False, "helper present but not working", _hardware_fix())
    return Check("secure_enclave", True, "helper ready; Telegram key present")


def _check_credentials(flags: dict[str, Any] | None, *, sealed_by: str = "device hardware") -> list[Check]:
    if flags is None:
        return [Check("login", False, "not configured", "hermes-mordred telegram setup")]
    checks = [
        Check(
            "login",
            flags.get("logged_in") is True,
            f"logged in (credentials sealed by {sealed_by})" if flags.get("logged_in") else "logged out",
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


def _check_memory() -> Check:
    if _windows_telegram.routed():
        ok = _windows_telegram.memory_active()
        return Check(
            "memory_encryption",
            ok,
            "agent memory sealed (Windows CNG memory custody)"
            if ok
            else "agent memory is not sealed (required for Telegram)",
            "" if ok else "hermes-mordred encryption enable memory",
        )
    from ..extension.telegram.memory_guard import memory_encryption_active

    ok = memory_encryption_active()
    return Check(
        "memory_encryption",
        ok,
        "agent memory sealed" if ok else "agent memory is plaintext (required for Telegram)",
        ""
        if ok
        else (
            "hermes-mordred encryption enable memory"
            if sys.platform == "linux"
            else "hermes-mordred encryption enable env && hermes-mordred encryption enable memory"
        ),
    )


def run_checks() -> list[Check]:
    if _windows_telegram.routed():
        return _windows_checks()
    from ..extension.telegram.tee import TeeSecretStore

    try:
        flags = TeeSecretStore().flags()
    except Exception:
        flags = None
    hardware = _check_enclave()
    return [
        _check_telethon(),
        hardware,
        Check("hardware", hardware.ok, hardware.detail, hardware.fix),
        _check_memory(),
        *_check_credentials(flags),
        _check_archive(),
        _check_hermes(),
    ]


def telegram_doctor(*, as_json: bool = False) -> int:
    checks = run_checks()
    if as_json:
        print(json.dumps([asdict(c) for c in checks], indent=2))
    else:
        for c in checks:
            mark = "-- " if _informational(c) else ("OK " if c.ok else "!! ")
            print(f"{mark}{c.name:20} {c.detail}")
            if c.fix:
                print(f"    -> {c.fix}")
    # Per-capability rows are information, never an aggregate readiness verdict.
    return 0 if all(c.ok for c in checks if not _informational(c)) else 1


def _informational(check: Check) -> bool:
    return check.name.startswith(_CAPABILITY_PREFIX)


# -- doctor on Windows ---------------------------------------------------------------

_CAPABILITY_PREFIX = "capability."


def _windows_checks() -> list[Check]:
    """Telegram checks plus one informational row per Windows capability; load-only."""
    from .._home import hermes_home
    from ._windows_gates import describe_capability
    from ._windows_status import capability_rows

    home = hermes_home()
    rows, error = capability_rows(home)
    custody = _windows_custody_check(home, rows, error)
    flags, code = _windows_flags()
    login = (
        _check_credentials(flags, sealed_by="this profile's Windows CNG Telegram custody key")
        if code is None
        else [Check("login", False, f"credential metadata unreadable ({code})", _windows_telegram.message(code) or "")]
    )
    checks = [
        _check_telethon(),
        custody,
        Check("hardware", custody.ok, custody.detail, custody.fix),
        _check_memory(),
        *login,
        _windows_archive_check(),
        _check_hermes(),
    ]
    if error is not None:
        return [*checks, Check(f"{_CAPABILITY_PREFIX}unavailable", False, f"capabilities unavailable: {error}")]
    return [*checks, *(Check(_CAPABILITY_PREFIX + row.name, row.available, describe_capability(row)) for row in rows)]


def _windows_custody_check(home: Path, rows: tuple[WindowsCapability, ...], error: str | None) -> Check:
    from ._windows_gates import remedy

    row = next((item for item in rows if item.name == "telegram_hardware"), None)
    if row is None:
        return Check("telegram_custody", False, f"capabilities unavailable: {error}", remedy("custody-uncertain"))
    detail = f"supported, {'available' if row.available else 'unavailable'} ({row.reason})"
    if row.reason != "enrolled":
        fix = _windows_telegram.CEREMONY if row.reason == "not-enrolled" else remedy(row.reason)
        return Check("telegram_custody", False, detail, fix)
    status = _windows_telegram.telegram_role(home)
    current = None if status is None else status.current
    metadata = (
        f": generation {current.generation}, public key SHA-256 {current.public_sha256}" if current is not None else ""
    )
    return Check("telegram_custody", True, f"{detail}; machine-bound CNG key, no per-use presence{metadata}")


def _windows_flags() -> tuple[dict[str, Any] | None, str | None]:
    """``(flags, None)`` through the checked store, or ``(None, classified code)``; never unseals."""
    try:
        return _windows_telegram.secret_store().flags(), None
    except (OSError, RuntimeError) as exc:
        return None, str(getattr(exc, "code", "telegram_unavailable"))


def _windows_archive_check() -> Check:
    """Index presence and the sync lock through the C10b checked seams; nothing is decrypted or scanned."""
    from datetime import UTC, datetime

    from ..extension.telegram.store import archive_busy, archive_updated, telegram_dir

    root = telegram_dir()
    try:
        updated = archive_updated(root)
        busy = archive_busy(root)
    except (OSError, RuntimeError) as exc:
        code = str(getattr(exc, "code", "store_unavailable"))
        return Check("archive", False, f"archive state unreadable ({code})", _windows_telegram.message(code) or "")
    if updated is None:
        return Check("archive", False, "nothing imported yet", "hermes-mordred telegram sync")
    when = datetime.fromtimestamp(updated, UTC).strftime("%Y-%m-%d %H:%M UTC")
    return Check(
        "archive",
        True,
        f"encrypted archive present (index updated {when}); sync running: {'yes' if busy else 'no'}",
    )


# -- setup -------------------------------------------------------------------------


def _yes(input_fn: InputFn, prompt: str, default: bool = True) -> bool:
    suffix = " [Y/n] " if default else " [y/N] "
    answer = input_fn(prompt + suffix).strip().casefold()
    return default if not answer else answer in {"y", "yes"}


def _ensure_enclave(input_fn: InputFn) -> bool:
    check = _check_enclave()
    if check.ok:
        return True
    label = "TPM 2.0" if sys.platform == "linux" else "Secure Enclave"
    print(f"Telegram credentials are sealed by {label}. Its helper must be built once (a few minutes).")
    if not _yes(input_fn, f"Build the {label} helper now?"):
        return False
    from .keyvault_native_cli import enable_se, enable_tpm

    return (enable_tpm() if sys.platform == "linux" else enable_se()) == 0


def _ensure_memory_encryption(input_fn: InputFn) -> bool:
    from ..extension.telegram.memory_guard import memory_encryption_active

    if memory_encryption_active():
        return True
    if sys.platform == "linux":
        print(
            "Memory and Telegram keys are bound to this TPM, without per-use user presence. "
            "There is no portable key recovery. Losing TPM state loses access; disable memory "
            "encryption while the TPM works to restore plaintext before moving hosts."
        )
        if not _yes(input_fn, "Turn on TPM memory encryption now?"):
            return False
        from .encryption_cli import _dispatch

        return _dispatch("enable", "memory") == 0 and memory_encryption_active()
    print(
        "Telegram requires agent-memory encryption, so nothing Hermes remembers about your chats is stored "
        "in plaintext. This turns on the sealed .env and sealed memory (Touch ID may be requested)."
    )
    if not _yes(input_fn, "Turn on memory encryption now?"):
        return False
    from ._flow_session import FlowSession
    from .encryption_cli import _dispatch

    # One flow: a new vault's passphrase is asked once, and the vault is
    # unlocked at most once (one Touch ID) for both targets.
    with FlowSession() as flow:
        for target in ("env", "memory"):
            if _dispatch("enable", target, flow_session=flow) != 0:
                return False
    ok = memory_encryption_active()
    if ok:
        print("Memory encryption is on. Restart Hermes Desktop so it picks up the key.")
    return ok


def _choose_llm(input_fn: InputFn, secret_fn: InputFn) -> int:
    from .telegram_cli import telegram_local_llm, telegram_venice

    print("Questions are answered by a privacy LLM. Choose one:")
    print("  1) Venice.ai private model (no retention; needs a Venice API key)")
    print("  2) A model running on this host (e.g. Ollama / LM Studio on 127.0.0.1)")
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
    acknowledge_machine_bound: bool = False,
) -> int:
    from .telegram_cli import telegram_login

    if _windows_telegram.routed():
        return _windows_setup(input_fn=input_fn, secret_fn=secret_fn, acknowledged=acknowledge_machine_bound)
    if not _supported_platform():
        return 1
    label = "TPM 2.0" if sys.platform == "linux" else "Secure Enclave"
    require_presence = require_presence and sys.platform != "linux"
    print(f"Mordred Telegram setup — read-only, {label}-sealed, Venice/local only.\n")
    print(f"Step 1/5  {label}")
    if not _ensure_enclave(input_fn):
        _term.emit_error(f"the {label} helper is required; setup stopped.")
        return 1

    print("\nStep 2/5  Memory encryption")
    if not _ensure_memory_encryption(input_fn):
        _term.emit_error("memory encryption is required for Telegram; setup stopped.")
        return 1

    from ..extension.telegram.tee import TeeSecretStore

    flags = TeeSecretStore().flags()
    print("\nStep 3/5  Telegram login")
    if flags and flags.get("logged_in"):
        print("Already logged in.")
    elif telegram_login(input_fn=input_fn, secret_fn=secret_fn, require_presence=require_presence) != 0:
        return 1

    flags = TeeSecretStore().flags() or {}
    print("\nStep 4/5  Privacy LLM")
    if flags.get("llm_backend") in ("venice", "local"):
        print(f"Already configured: {flags.get('llm_backend')} ({flags.get('llm_model')}).")
    elif _choose_llm(input_fn, secret_fn) != 0:
        return 1

    if _first_import(input_fn) != 0:
        return 1

    print(
        "\nDone. How to use it:\n"
        "  • Restart Hermes Desktop or the gateway, then ask e.g. “What did we decide on Telegram last week?”.\n"
        "    The agent uses telegram_ask; approve a hardware prompt if requested.\n"
        "  • Browser extension: ⚙ → ✈️ Telegram.\n"
        "  • Health check any time: hermes-mordred telegram doctor"
    )
    return 0


def cli_setup(args: argparse.Namespace) -> int:
    return telegram_setup(
        require_presence=not getattr(args, "no_touch_id", False),
        acknowledge_machine_bound=bool(getattr(args, "acknowledge_machine_bound", False)),
    )


def cli_doctor(args: argparse.Namespace) -> int:
    return telegram_doctor(as_json=bool(getattr(args, "json", False)))


def _hardware_fix() -> str:
    return "hermes-mordred keyvault " + ("enable-tpm" if sys.platform == "linux" else "enable-se")


def _supported_platform() -> bool:
    if sys.platform in ("darwin", "linux"):
        return True
    _term.emit_error("Private Telegram requires macOS Secure Enclave or Linux TPM 2.0.")
    return False


def _first_import(input_fn: InputFn) -> int:
    from .telegram_cli import telegram_sync

    print("\nStep 5/5  First import")
    print(
        f"Recommended: the last {DEFAULT_SINCE_DAYS} days of personal chats and groups; archived chats and "
        "groups over 100 members skipped; pinned chats first. Later imports fetch only new messages."
    )
    recommended = {
        "include_channels": False,
        "include_archived": False,
        "since_days": DEFAULT_SINCE_DAYS,
        "limit_per_dialog": RECOMMENDED_LIMIT,
    }
    if _yes(input_fn, "Use this scope for imports (saved for later `telegram sync` runs)?"):
        if _windows_telegram.routed():
            refused = _windows_save_scope(recommended)
            if refused is not None:
                return refused
        else:
            from ..extension.telegram.tee import TeeSecretStore

            TeeSecretStore().save_sync_scope(recommended)
    if _yes(input_fn, "Import now?"):
        rc = telegram_sync()
        if rc != 0:
            return rc
    else:
        print("Skipped. Run `hermes-mordred telegram sync` any time.")

    return 0


# -- setup on Windows ----------------------------------------------------------------


def _windows_setup(*, input_fn: InputFn, secret_fn: InputFn, acknowledged: bool) -> int:
    """custody (explicit ceremony) -> C6 memory enable -> acknowledged login -> LLM -> first import."""
    from .telegram_cli import _report, telegram_login

    print("Mordred Telegram setup — read-only, sealed by this profile's Windows CNG custody key, Venice/local only.\n")
    print("Step 1/5  Windows Telegram custody")
    if not _ensure_windows_custody(input_fn):
        _term.emit_error("Windows Telegram custody is required; setup stopped.")
        return 1

    print("\nStep 2/5  Memory encryption")
    if not _ensure_windows_memory(input_fn):
        _term.emit_error("memory encryption is required for Telegram; setup stopped.")
        return 1

    print("\nStep 3/5  Telegram login")
    flags, code = _windows_flags()
    if code is not None:
        return _report(code)
    if flags and flags.get("logged_in"):
        print("Already logged in.")
    elif telegram_login(input_fn=input_fn, secret_fn=secret_fn, acknowledge_machine_bound=acknowledged) != 0:
        return 1

    flags, code = _windows_flags()
    if code is not None:
        return _report(code)
    print("\nStep 4/5  Privacy LLM")
    current = flags or {}
    if current.get("llm_backend") in ("venice", "local"):
        print(f"Already configured: {current.get('llm_backend')} ({current.get('llm_model')}).")
    elif _choose_llm(input_fn, secret_fn) != 0:
        return 1

    if _first_import(input_fn) != 0:
        return 1

    print(WINDOWS_DONE)
    return 0


#: What works on Windows today; agent, extension and Desktop access are separate slices.
WINDOWS_DONE = (
    "\nDone. What works on Windows now:\n"
    "  • hermes-mordred telegram sync     import new messages into the encrypted archive\n"
    "  • hermes-mordred telegram status   login state and archive counts\n"
    "  • hermes-mordred telegram doctor   health check from metadata only\n"
    "Asking through the Hermes agent (telegram_ask), the browser extension and Hermes Desktop is not available "
    "on Windows yet: it is pending the extension memory-guard follow-up and the Desktop slice (C11)."
)


def _ensure_windows_custody(input_fn: InputFn) -> bool:
    """Enrolled -> continue; not enrolled -> offer the explicit ceremony; anything else refuses."""
    from .._home import hermes_home
    from ._windows_gates import remedy
    from .keyvault_windows_cli import native_init

    home = hermes_home()
    capability = _windows_telegram.telegram_capability(home)
    reason = capability if isinstance(capability, str) else capability.reason
    if reason == "enrolled":
        print("This profile's Windows Telegram custody key is enrolled (machine-bound CNG, no per-use presence).")
        return True
    if reason != "not-enrolled":
        _term.emit_error(f"Telegram custody refused ({reason}): {remedy(reason)}. Nothing was generated or changed.")
        return False
    present = _windows_telegram.credentials_present()
    if present is not False:
        # Sealed credentials without their key can never be opened by a new key,
        # so no ceremony is offered; unreadable metadata is not guessed at either.
        _term.emit_error(
            _windows_telegram.message("credentials_without_custody") or ""
            if present
            else "the Telegram credential metadata could not be read; run `hermes-mordred telegram doctor`."
        )
        return False
    print("This profile has no Windows Telegram custody key yet. Only this explicit ceremony creates it:")
    print(f"  {_windows_telegram.CEREMONY}")
    print(_windows_telegram.TELEGRAM_NOTICE)
    if not _windows_telegram.explicit_yes(input_fn, "Create this profile's Windows Telegram custody key now?"):
        print(f"Run `{_windows_telegram.CEREMONY}` yourself, then re-run `hermes-mordred telegram setup`.")
        return False
    return native_init(home=home, roles=("telegram",)) == 0


def _ensure_windows_memory(input_fn: InputFn) -> bool:
    """The C6 Windows memory enable (capabilities -> gate -> ceremony -> proof -> lifecycle)."""
    from .._home import hermes_home
    from . import _windows_memory

    home = hermes_home()
    if _windows_telegram.memory_active(home):
        return True
    print(
        "Telegram requires agent-memory encryption, so nothing Hermes remembers about your chats is stored in "
        "plaintext. On Windows `hermes-mordred encryption enable memory` enrolls the CNG memory key if needed, "
        "proves the installed Hermes runtime and seals the memories; every Hermes gateway must be stopped."
    )
    if not _windows_telegram.explicit_yes(input_fn, "Turn on Windows memory encryption now?"):
        return False
    if _windows_memory.enable(home=home) != 0:
        return False
    ok = _windows_telegram.memory_active(home)
    if ok:
        print("Memory encryption is on. Restart the Hermes gateways so they load the armed hook.")
    return ok


def _windows_save_scope(scope: dict[str, Any]) -> int | None:
    from .telegram_cli import _report

    try:
        _windows_telegram.secret_store().save_sync_scope(scope)
    except (OSError, RuntimeError) as exc:
        return _report(str(getattr(exc, "code", "store_unavailable")))
    return None
