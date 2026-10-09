"""Windows routing for the wizard ``telegram`` commands (C6-telegram).

macOS and Linux keep the Secure Enclave / TPM flows of :mod:`.telegram_cli`
and :mod:`.telegram_setup_cli` unchanged. On ``win32`` (the wizard's
``host_platform()`` seam):

- the credential store is the C10b seam ``tee.default_secret_store()``
  (``WindowsCustodySecretStore`` on the independent custody ``telegram``
  role), which never generates a key;
- the role is created only by the explicit ceremony
  ``hermes-mordred keyvault native init --role telegram``; the other commands
  read ``windows_capability(home, "telegram_hardware")`` first and refuse
  ``telegram_not_enrolled`` / ``custody_*`` / ``tee_unavailable`` before any
  native call;
- login requests ``require_presence=False`` only after the machine-bound
  disclosure (:data:`CUSTODY_NOTICE` plus :data:`TELEGRAM_NOTICE`) is
  acknowledged with ``--acknowledge-machine-bound`` or an explicit yes;
- memory encryption is the C6 Windows memory target (a load-only
  observation), never the macOS/Linux marker check;
- archive presence, busy state and credential flags come from the C10b
  checked seams (``archive_updated``, ``archive_busy``,
  ``directory_present``, ``flags()``), never from raw ``telegram_dir`` scans.

Heavy imports stay function-local so this module imports on any platform.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import _windows_gates
from ._windows_gates import WINDOWS, classify_exception, remedy

if TYPE_CHECKING:
    from ..keyvault._windows_capability import WindowsCapability
    from ..keyvault._windows_custody import GenerationLease

__all__ = [
    "ACK_FLAG",
    "CEREMONY",
    "FORGET_DESPITE",
    "FORGET_PHRASE",
    "TELEGRAM_NOTICE",
    "TelegramState",
    "acknowledge",
    "archive_present",
    "custody_code",
    "disclosure",
    "explicit_yes",
    "forget_plan",
    "login_refusal",
    "logout_refusal",
    "memory_active",
    "memory_guard",
    "message",
    "observe",
    "outcome_lines",
    "role_leases",
    "routed",
    "secret_store",
    "telegram_capability",
    "typed_confirmation",
]

InputFn = Callable[[str], str]

#: The only command that creates the Windows Telegram custody key.
CEREMONY = "hermes-mordred keyvault native init --role telegram"
ACK_FLAG = "--acknowledge-machine-bound"
FORGET_PHRASE = "forget telegram"
#: Telegram-specific sentence of the machine-bound disclosure (after ``CUSTODY_NOTICE``).
TELEGRAM_NOTICE = (
    "Telegram credentials (the API application, the Telegram session, the archive key and the LLM key) are "
    "sealed by this profile's Windows CNG telegram custody key: any program running as this Windows account on "
    "this machine can use them without a confirmation prompt, and losing the TPM, this Windows account or this "
    "profile directory loses the credentials and the local archive (log in again and re-import from Telegram)."
)
#: Unseal failures after which ``logout --forget`` may still delete everything (no revocation possible).
FORGET_DESPITE = frozenset({"secrets_corrupt", "telegram_not_enrolled"})

#: Capability reason -> the C10b store code reported through ``telegram_cli._report``.
_CODES: dict[str, str] = {
    "not-enrolled": "telegram_not_enrolled",
    "custody-unsafe": "custody_unsafe",
    "custody-uncertain": "custody_uncertain",
    "custody-broken": "custody_broken",
    "helper-missing": "tee_unavailable",
    "helper-uncertain": "tee_unavailable",
}
_RECONCILE_GAP = (
    "There is no `keyvault native reconcile` command yet: an unresolved Telegram custody journal (for example an "
    "ambiguous key deletion during `telegram logout --forget`) is kept and keeps refusing until explicit "
    "reconciliation exists; nothing is deleted or regenerated in its place meanwhile."
)


def routed() -> bool:
    """Whether the wizard takes the Windows Telegram flows on this host (the C6 ``host_platform`` seam)."""
    return _windows_gates.host_platform() == WINDOWS


def _home() -> Path:
    from .._home import hermes_home

    return hermes_home()


def secret_store() -> Any:
    """The C10b production store for this platform (the custody store on Windows)."""
    from ..extension.telegram.tee import default_secret_store

    return default_secret_store()


def _archive_root() -> Path:
    from ..extension.telegram.store import telegram_dir

    return telegram_dir()


# -----------------------------------------------------------------------------
# Memory encryption (C6 Windows memory target)
# -----------------------------------------------------------------------------
def memory_active(home: Path | None = None) -> bool:
    """Armed Windows memory encryption with no plaintext, broken seal or staging; load-only."""
    from ._windows_memory import observe as observe_memory
    from ._windows_status import memory_target_status

    return memory_target_status(observe_memory(home or _home(), blocking=False)).active


def memory_guard() -> None:
    """``TelegramService`` memory guard on Windows (the POSIX marker check never reports Windows active)."""
    from ..extension.telegram.memory_guard import MemoryEncryptionRequired

    if not memory_active():
        raise MemoryEncryptionRequired()


# -----------------------------------------------------------------------------
# Custody capability and the machine-bound acknowledgement
# -----------------------------------------------------------------------------
def telegram_capability(home: Path | None = None) -> WindowsCapability | str:
    """``telegram_hardware`` from the C5e predicates, or a classified reason when unreadable."""
    from ..keyvault._windows_capability import windows_capability

    try:
        return windows_capability(home or _home(), "telegram_hardware")
    except (OSError, RuntimeError, ValueError) as exc:
        return classify_exception(exc)


def custody_code(home: Path | None = None) -> str | None:
    """``None`` when the telegram role is enrolled and the helper present, else a C10b code. Load-only."""
    capability = telegram_capability(home)
    reason = capability if isinstance(capability, str) else capability.reason
    if reason == "enrolled":
        return None
    return _CODES.get(reason, "custody_uncertain")


def disclosure() -> str:
    from .keyvault_windows_cli import CUSTODY_NOTICE

    return f"{CUSTODY_NOTICE} {TELEGRAM_NOTICE}"


def explicit_yes(input_fn: InputFn, prompt: str) -> bool:
    """A ``[y/N]`` question: only an explicit yes counts; end of input is a no."""
    try:
        answer = input_fn(prompt + " [y/N] ")
    except EOFError:
        return False
    return answer.strip().casefold() in {"y", "yes"}


def acknowledge(input_fn: InputFn, *, flag: bool) -> bool:
    """Show the machine-bound disclosure; ``flag`` or an explicit yes acknowledges it."""
    print("Windows Telegram custody is machine-bound:")
    print(f"  {disclosure()}")
    if flag:
        print(f"Acknowledged ({ACK_FLAG}).")
        return True
    return explicit_yes(input_fn, "Acknowledge the machine-bound Telegram custody and continue?")


def login_refusal(input_fn: InputFn, *, acknowledged: bool, home: Path | None = None) -> str | None:
    """Custody first (load-only), then the acknowledgement; a code, or ``None`` to continue."""
    code = custody_code(home)
    if code is not None:
        return code
    return None if acknowledge(input_fn, flag=acknowledged) else "machine_bound_not_acknowledged"


# -----------------------------------------------------------------------------
# Checked archive / credential / role observation (logout, forget, doctor)
# -----------------------------------------------------------------------------
def archive_present(root: Path | None = None) -> bool:
    """A checked ``index.enc`` exists (``StoreError`` on unsafe or uncertain state)."""
    from ..extension.telegram.store import archive_updated

    return archive_updated(root if root is not None else _archive_root()) is not None


def role_leases(home: Path | None = None) -> tuple[GenerationLease, ...] | None:
    """Owned telegram generations (retained first, current last); ``None`` when unreadable.

    Load-only and non-blocking: no native call, no unwrap, no lock wait.
    """
    from .._config_io import CanonicalPaths, canonical_session
    from ..keyvault._windows_custody import windows_custody_session

    path = home or _home()
    try:
        with (
            canonical_session(CanonicalPaths(path), scope="policy", blocking=False) as canonical,
            windows_custody_session(path, canonical=canonical) as session,
        ):
            status = session.role_status("telegram")
    except (OSError, RuntimeError, ValueError):
        return None
    return status.retained + (() if status.current is None else (status.current,))


@dataclass(frozen=True)
class TelegramState:
    """Checked, load-only Telegram state; ``None`` means it could not be read."""

    credentials: bool | None
    directory: bool | None
    archive: bool | None
    generations: tuple[str, ...] | None

    @property
    def empty(self) -> bool:
        return self.credentials is False and self.directory is False and self.generations == ()


def observe(secrets_store: Any, root: Path, home: Path | None = None) -> TelegramState:
    """Credential flags, archive index and owned telegram generations; never unseals."""
    from ..extension.telegram._windows_archive import directory_present

    def checked(read: Callable[[], bool]) -> bool | None:
        try:
            return read()
        except (OSError, RuntimeError, ValueError):
            return None

    leases = role_leases(home)
    return TelegramState(
        credentials=checked(lambda: secrets_store.flags() is not None),
        directory=checked(lambda: directory_present(root)),
        archive=checked(lambda: archive_present(root)),
        generations=None if leases is None else tuple(lease.generation for lease in leases),
    )


def logout_refusal(root: Path, *, home: Path | None = None) -> str | None:
    """Refuse a running sync, then custody that cannot be used or reset; before any change."""
    from ..extension.telegram.store import StoreError, archive_busy

    try:
        if archive_busy(root):
            return "sync_in_progress"
    except StoreError as exc:
        return exc.code
    code = custody_code(home)
    # Without a role there is nothing to reset; sealed credentials then refuse
    # telegram_not_enrolled on load, and forget may still delete the files.
    return None if code in (None, "telegram_not_enrolled") else code


def forget_plan(state: TelegramState) -> str:
    generations = f" (generation(s) {', '.join(state.generations)})" if state.generations else ""
    return (
        "telegram logout --forget revokes the Telegram session (when the credentials can be opened) and "
        "permanently deletes this profile's sealed Telegram credentials (API application, session, archive key "
        f"and LLM key), the local encrypted archive and the Windows Telegram custody key{generations}. Memory and "
        "audit custody, directories, locks and unknown files are kept. This cannot be undone."
    )


def typed_confirmation(input_fn: InputFn) -> bool:
    try:
        answer = input_fn(f"Type '{FORGET_PHRASE}' to delete them: ")
    except EOFError:
        return False
    return answer.strip() == FORGET_PHRASE


def _gone(before: bool | None, after: bool | None) -> bool:
    return before is True and after is False


def outcome_lines(before: TelegramState, after: TelegramState, *, forget: bool) -> list[str]:
    """What the logout actually deleted (re-checked after the operation) and what it kept."""
    archive = "the local encrypted archive (index.enc and its dialog segments)"
    if not forget:
        if _gone(before.archive, after.archive):
            deleted = f"Deleted {archive}."
        elif before.archive is False:
            deleted = "No local archive was present."
        else:
            deleted = "The local archive could not be re-checked; run `hermes-mordred telegram doctor`."
        return [
            f"Logged out. {deleted} The API credentials, the archive key and this profile's Windows Telegram "
            "custody key are kept (use --forget to delete them)."
        ]
    items = []
    if _gone(before.credentials, after.credentials):
        items.append("the sealed Telegram credentials (credentials.sealed, credentials.meta.json)")
    if _gone(before.archive, after.archive):
        items.append(archive)
    removed = [
        generation
        for generation in before.generations or ()
        if after.generations is not None and generation not in after.generations
    ]
    if removed:
        items.append(f"this profile's Windows Telegram custody key (generation(s) {', '.join(removed)})")
    lines = ["Deleted:", *(f"  - {item}" for item in items)] if items else ["Nothing was deleted."]
    if None in (after.credentials, after.archive, after.generations):
        lines.append("Some state could not be re-checked; run `hermes-mordred telegram doctor`.")
    lines.append("Kept: memory and audit custody, directories, locks and unknown files.")
    return lines


# -----------------------------------------------------------------------------
# Classified messages
# -----------------------------------------------------------------------------
_UNSAFE = remedy("custody-unsafe")
#: Windows wording (with a remedy) for every classified Telegram code; the rest use the shared text.
_MESSAGES: dict[str, str] = {
    "telegram_not_enrolled": (
        "this profile has no Windows Telegram custody key yet. Create it with the explicit ceremony "
        f"`{CEREMONY}` (`hermes-mordred telegram setup` offers to run it), then retry. Nothing was unsealed "
        "or sent to Telegram."
    ),
    "machine_bound_not_acknowledged": (
        "Telegram login on Windows needs the machine-bound custody acknowledged (no per-use presence, no "
        f"portable recovery): answer yes when asked, or pass {ACK_FLAG}. Nothing was unsealed or sent to "
        "Telegram."
    ),
    "presence_unsupported": (
        "per-use presence (a confirmation for each use of the key) is excluded on Windows "
        "(excluded-on-windows): the Telegram custody key is machine-bound and used without a prompt. "
        f"Acknowledge that with {ACK_FLAG} (or answer yes when asked); nothing was unsealed."
    ),
    "custody_unsafe": f"Telegram custody refused (custody-unsafe): {_UNSAFE}.",
    "custody_uncertain": (
        f"Telegram custody refused (custody-uncertain): {remedy('custody-uncertain')}. {_RECONCILE_GAP}"
    ),
    "custody_broken": f"Telegram custody refused (custody-broken): {remedy('custody-broken')}.",
    "tee_unavailable": (
        "the Windows CNG helper or this profile's Telegram custody key is not available (tee_unavailable). "
        "Install or repair the helper with `hermes-mordred keyvault enable-winkey`, then check "
        "`hermes-mordred telegram doctor`. A missing key is never regenerated in its place; the sealed "
        "credentials and the archive are kept."
    ),
    "tee_auth_cancelled": "the Windows CNG operation was cancelled, so the credentials stayed sealed.",
    "secrets_corrupt": (
        "the sealed Telegram credentials could not be authenticated with this profile's Telegram custody key "
        "(a copied or restored file, another profile's seal, or a rotated custody key) (secrets_corrupt). "
        "They are never repaired: delete them with `hermes-mordred telegram logout --forget`, then run "
        "`hermes-mordred telegram setup` again."
    ),
    "store_path_unsafe": (
        "a file or directory under <home>\\mordred\\telegram is not private to this Windows account "
        f"(store_path_unsafe): {_UNSAFE}."
    ),
    "store_write_uncertain": (
        "a Telegram credential or archive write has an uncertain outcome (store_write_uncertain); nothing is "
        "retried or rolled back automatically. Re-run the command after checking `hermes-mordred telegram "
        "doctor`."
    ),
    "store_unavailable": (
        "the Telegram archive storage could not be opened (store_unavailable); retry, and check "
        "`hermes-mordred telegram doctor`."
    ),
    "store_missing": "a Telegram file or directory disappeared during the operation (store_missing); retry.",
    "store_io": "the Telegram storage reported an I/O error (store_io); nothing was changed — retry.",
    "store_busy": ("the Telegram storage is busy (store_busy); retry when the other Hermes/Mordred processes finish."),
    "store_undecryptable": (
        "the local Telegram archive cannot be decrypted with the stored archive key (store_undecryptable); it "
        "is never repaired. Delete it with `hermes-mordred telegram logout` (the credentials and the custody "
        "key are kept), log in again and re-import with `hermes-mordred telegram sync`."
    ),
    "store_key_invalid": (
        "the stored archive key is invalid (store_key_invalid). Delete the credentials and the archive with "
        "`hermes-mordred telegram logout --forget`, then run `hermes-mordred telegram setup` again."
    ),
    "sync_in_progress": (
        "another Telegram sync is running (sync_in_progress): wait for it to finish (CLI, Desktop or the "
        "Hermes gateway), then retry; nothing was changed."
    ),
    "vault_unavailable": (
        "the keyvault file vault is excluded on Windows (excluded-on-windows); Windows Telegram credentials "
        "are sealed by the CNG custody key instead — run `hermes-mordred telegram setup`."
    ),
    "vault_not_initialized": (
        "the keyvault file vault is excluded on Windows (excluded-on-windows); Windows Telegram credentials "
        "are sealed by the CNG custody key instead — run `hermes-mordred telegram setup`."
    ),
    "memory_encryption_required": (
        "Telegram needs agent-memory encryption on, so nothing Hermes remembers about your chats is stored "
        "in plaintext. Run `hermes-mordred encryption enable memory` (Windows CNG memory custody, proven "
        "against the installed Hermes runtime), restart the Hermes gateways, then try again "
        "(`hermes-mordred telegram setup` does this for you)."
    ),
}


def message(code: str) -> str | None:
    """The Windows wording for a classified Telegram code; ``None`` falls back to the shared text."""
    return _MESSAGES.get(code)
